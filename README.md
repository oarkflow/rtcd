# rtcd: the call service

Audio and video calls as an independent service: peer-to-peer or through a Pion **SFU** (simulcast, VP9 SVC, active speaker, recording), **end-to-end encrypted** by default, with users' own **groups** and a complete, tamper-evident **audit log**. It knows nothing about the applications that use it. [`contrib/rtc`](https://github.com/oarkflow/ref/tree/main/contrib/rtc) is REF's client; [`client/`](client) is a Go client; the protocol below works from anything.

```
git clone git@github.com:oarkflow/rtcd.git && cd rtcd
go build -o rtcd ./cmd/rtcd
./rtcd -config rtcd.bcl
```

A `Dockerfile` is included (`docker build -t rtcd .`, mount `rtcd.bcl` at `/etc/rtcd/`, publish the signaling port and exactly the UDP range from the config).

Build from a checkout. `go install github.com/oarkflow/rtcd/cmd/rtcd@…` does not work: `go.mod` replaces `pion/ice` with a fork (see *ICE restarts*), and Go refuses to install a module that has a `replace`.

## How applications use it

There are two kinds of caller.

- **A backend service** holds an **API key** that belongs to one **tenant**. It acts for any user of that tenant by naming the user in `X-RTC-User`, it mints tokens, and it reads the audit log. Keep the key on the server.
- **An end user** holds a **token** their backend minted for them: signed, short-lived (default 15 min, capped by `max_token_ttl`), good for one user of one tenant and for the scopes it was minted with (`calls`, `groups`; both by default). It is safe in a browser.

Tenants are isolated completely: calls, groups, events, SFU rooms and audit entries are reachable only inside the tenant, so two tenants can both have a user called `ada`. This is tested in both directions.

## The WebSocket is the interface

A user opens **one WebSocket** to `/v1/ws?token=…` and does everything over it. It is built on `github.com/oarkflow/fh/pkg/websocket`'s `EventHub`.

A request is an envelope with an `id`; the answer has the same id:

```
→ {"type":"emit","id":"7","event":"call.start","payload":{"to":["bob"],"mode":"sfu"}}
← {"type":"ack","replyTo":"7","payload":{"call":{…},"ice":[…]}}
← {"type":"error","replyTo":"7","code":"internal_error","error":"e2ee_required"}   // error is "code" or "code: message"
```

Events are pushed on the same socket:

```
← {"type":"emit","event":"call.incoming","payload":{…},"from":"ada","ts":1760000000000}
```

The first event, `ready`, says who you are and when your token ends. Send `{"type":"ping"}` every 25 s or the service closes a silent connection. Requests on one connection are handled in order.

### Operations

| | |
|---|---|
| `call.start` `{to[], kind, mode, e2ee}` · `call.get` · `call.answer` · `call.decline` · `call.end` · `call.invite {users[]}` | calls. All take `call` (the id) except `call.start` |
| `call.signal {call, to, type, data}` | relay SDP/ICE in a p2p call |
| `call.e2ee {call, to, data}` | relay an opaque key-exchange message (≤ 16 KiB) |
| `sfu.join {call, sdp, e2ee}` · `sfu.answer` · `sfu.candidate` · `sfu.ready` · `sfu.restart` · `sfu.resync` · `sfu.prefs` · `sfu.stats` · `sfu.sample` · `sfu.leave` · `sfu.record.start/stop/status` | group-call media signaling (see [docs/calls.md](docs/calls.md)) |
| `group.create {name, members[]}` · `group.get` · `group.list` · `group.rename` · `group.add` · `group.remove` · `group.role {user, role}` · `group.transfer {to}` · `group.delete` | groups; the others take `group` |
| `group.call {group, kind, mode}` | start a call with the group, or join the one under way |
| `ice` | STUN/TURN servers with a short-lived TURN credential |
| `auth.refresh {token}` | extend the connection with a new token for the same user |

Service-key only: `token.mint {user, ttl_seconds, scopes[]}`, `audit.query`, `audit.verify`, `stats`.

Events: `call.incoming`, `call.answered`, `call.declined`, `call.left`, `call.invited`, `call.ended`, `call.signal`, `call.e2ee`, `sfu.offer`, `sfu.candidate`, `sfu.speaker`, `sfu.recording`, `group.added`, `group.removed`, `group.updated`, `group.members_added`, `group.members_removed`, `group.role`, `group.owner`, `group.deleted`.

### HTTP

Every operation is also an HTTP route under `/v1`, for backends that only need a request and an answer, and for minting tokens (`POST /v1/tokens`):

`POST /calls` · `GET /calls/{id}` · `POST /calls/{id}/{answer,decline,end,invite,signal,e2ee}` · `POST /calls/{id}/sfu/{op}` · `POST|GET /groups` · `GET /groups/{id}` · `POST /groups/{id}/{rename,add,remove,role,transfer,delete,call}` · `POST /ice` · `POST /audit/query` · `POST /audit/verify` · `GET /stats` · `GET /healthz`, `/readyz`.

Errors are `{"error":{"code":"…","message":"…"}}`. Both interfaces go through the same code: authentication, scope, rate limit, the operation, an audit entry.

```go
svc := client.New("https://calls.example.com", os.Getenv("RTCD_API_KEY"))
tok, _ := svc.Token(ctx, "bob", 10*time.Minute)            // give this to bob's browser
conn, _ := client.NewUser(url, tok.Token).Dial(ctx)         // or hold a socket yourself
var started struct{ Call client.Call }
conn.Call(ctx, "group.call", map[string]any{"group": id}, &started)
for ev := range conn.Events() { … }
```

## Managed rooms (for a backend that owns membership)

A backend that already knows who may be in a call, because it has its own groups, permissions and ringing, should not use `call.start` and `group.*`. It opens a **managed room** instead (service key only):

| | |
|---|---|
| `room.open {id, kind, members[], e2ee, max_peers, last_n_video, last_n_audio}` | creates the room under the backend's own id, or admits `members` to it if it is open. `POST /v1/rooms/open` |
| `room.admit {id, members[]}` | lets more people in, or back in |
| `room.remove {id, members[]}` | takes people out **and disconnects them from the media at once**; they get a `room.removed` event |
| `room.close {id}` | ends the room for everyone |
| `room.get {id}` | who is admitted and who is connected to the media |

An admitted user goes straight to `sfu.join`: no ringing, no answering step. A user who was not admitted is told what a stranger is told. Nobody but the backend can end the room (`call.end` from a member only leaves the media). The `max_invitees` cap does not apply; `max_room_members` (default 1000) does. Encryption is required exactly as for any call, and `sfu.record.*` is unavailable (there is no caller to own a recording). Ids are unique across tenants: another tenant opening a live id is refused.

## Large rooms: last N

Sending a hundred people to a hundred people is neither possible (a hundred media sections in every connection) nor useful (nobody watches a hundred tiles). A room can set `last_n_video` and `last_n_audio` (or the service defaults, `last_n_video` / `last_n_audio` in `rtcd.bcl`): each viewer is then sent only the people who **spoke most recently**, plus whoever the viewer pinned (`sfu.prefs {pinned}`) and the current speaker. Speaking brings a person in; whoever has been quiet longest leaves. Everyone remains in the room and nobody is excluded from speaking. A change in the set is negotiated with every viewer, and changes close together (a hundred people arriving) are coalesced into one offer per viewer, with a wait that grows with the size of the room and none in a room of sixteen or fewer.

Measured in-process with 100 real Pion peers, each publishing a microphone, `last_n_audio 16`: all connected and negotiated in about 0.7 s, 2.4 offers per person (`go test -run AHundredPeopleShare -v ./sfu`). That proves the control plane and the selection; it is loopback, audio only, and says nothing about bandwidth or CPU under real video. Measure that with your own load.

## Messages and attachments

Both work inside **groups**: a conversation is a group (a direct message is a group of two), so only its members can send, read or fetch, and a removed member is cut off on their next request. Both need the `chat` scope, which tokens carry by default.

The service stores and forwards **opaque** data. A message `body` is ciphertext your client made (the audit log records its size, never its content); an attachment is a ciphertext blob, and its key travels inside an encrypted message. What the server enforces is who, how big, how fast, and how long.

| | |
|---|---|
| `msg.send {conv, id, body}` | `id` is yours and unique per sender: a retry returns the stored message (`duplicate: true`) instead of a second one. Answers `{seq}`; every member (the sender's other devices too) gets `msg.new`. Body ≤ 32 KiB (`max_message_bytes`). `POST /v1/messages` |
| `msg.history {conv, after, before, limit}` | oldest first from `after`, or newest first before `before`. ≤ 100. `POST /v1/messages/history` |
| `msg.read {conv, seq}` · `msg.delete {conv, seq}` | read position (members get `msg.read`); delete by the sender or a group admin (the number stays, the body goes; `msg.deleted`) |
| `file.init {conv, size, sha256, chunk}` | registers an upload of the **encrypted** bytes; `sha256` is of those bytes. Chunk ≤ 4 MiB (default 1 MiB), file ≤ `max_file_bytes` (256 MiB), 10 uploads under way per user, `tenant_file_bytes` per tenant |
| `PUT /v1/files/{id}/parts/{n}` | raw bytes of part `n`, exactly the chunk size (the last part is the remainder). Parts may be sent in any order and repeated |
| `file.status {file}` | which parts have arrived, to resume after a dropped connection |
| `file.complete {file}` | checks every part is there and the stored bytes hash to `sha256`. A mismatch deletes the file (`checksum_mismatch`). Until then it cannot be downloaded |
| `GET /v1/files/{id}/blob` | members only; supports `Range`. Served as `application/octet-stream`, `nosniff`, `attachment`, `no-store` |
| `file.link {file}` | a 5-minute URL for one user (an `<a href>` or a download manager that cannot send a header). Membership is checked again when it is used |
| `file.delete {file}` | owner or group admin |

Unfinished uploads are removed after 24 h; finished files after `file_retention` (30 days); messages after `message_retention` (never, by default). Settings: `attach_dir` (empty turns attachments off), `max_file_bytes`, `tenant_file_bytes`, `file_retention`, `message_retention`, `max_message_bytes`.

## Security additions

- **WebSocket tickets.** `POST /v1/ws/ticket` (or the `ws.ticket` operation) trades a token for a ticket good for one connection within 30 s: `wss://…/v1/ws?ticket=…`. Prefer it to `?token=`, which ends up in proxy logs. Tickets are kept (as a hash) in the database, so any node can redeem one.
- **Revocation.** A backend calls `token.revoke {user}` (`POST /v1/tokens/revoke`): tokens already minted for that user stop working and their open connections close. Tokens minted afterwards work. It is stored in the database: every node learns of it within about 2 s and closes that user's connections, and a restart forgets nothing. A ticket issued before the revocation is refused too.
- **Failed sign-ins are throttled per address**: after a burst of 20 (then one every 2 s) a bad credential is answered `429 rate_limited` and stops being logged entry by entry. A *good* credential is never held back, so people behind a shared address are not locked out by someone else's mistakes.
- **`rate_limited` answers are logged in summary.** The first refusal for a user and operation is written at once; the rest are counted and written as one entry every few seconds. A client that retries in a tight loop therefore cannot fill the audit log and stall everyone behind it (this was measured: 120 000 refusals in a load run made every other operation wait on the audit queue).
- **Header and idle timeouts** on the HTTP server (10 s, 2 min), so slow-header connections cannot be held open. A WebSocket is not affected.
- `limits { max_connections_per_tenant }` stops one tenant filling the node.

## Large rooms

In a room of more than 16 people, `sfu.peer` and `sfu.speaker` events are batched (250 ms): the room hears one `sfu.peers {joined[], left[], count}` and one `sfu.speaker` for what changed, not an event per person per change. A hundred people arriving no longer send each of them a hundred events, which used to fill a writer queue and disconnect someone who had done nothing wrong. Rooms of 16 or fewer are unchanged. `room.get` is the snapshot.

Recording: `record_min_free_bytes` refuses to start (`disk_full`, 507) and stops a recording under way when the recording directory runs low; `record_max_duration` stops one after that long. Everyone is told when it stops.

## Several nodes

Run any number of rtcd nodes on one shared database and give each a `node_id` (`node_id "n1"`). Then:

- **Events reach people on any node.** Call, group, message and room events are written to an outbox table that the other nodes poll every 200 ms and deliver to their own connections. A message sent on one node reaches a member connected to another; group changes drop every node's membership cache.
- **Revocations and tickets are shared** (see Security additions).
- **Media stays on one node.** An SFU room lives on the node that holds it, so `sfu.*` events are not replicated. The load balancer must send every request for a call (`/v1/calls/{id}/…`, and the WebSocket of anyone in it) to the same node, e.g. by hashing the call id. Spreading the SFU over nodes is the cascade in `sfu`, which is not wired to HTTP yet.
- **Files** need `attach_dir` on a volume every node mounts, or one node serving them.
- The database must be shared: SQLite works only for nodes on one machine; use PostgreSQL or MySQL for nodes on different machines (see *Databases*).
- Cross-node delivery costs up to ~200 ms plus a database write per event, so a single node (no `node_id`) is still the fastest setup.

## Browser side: chat

`web/chat-core.js` (global `ChatCrypto`) encrypts messages and attachments in the browser, with the keys and formats described at its top. Messages are `encryptMessage(key, {conv, sender, id}, text)`; files are `encryptFile(conv, bytes)` then `uploadFile(api, conv, enc)` (resumable), and `downloadFile(api, conv, id, meta)`. Put `{file: id, meta: enc.meta}` in an encrypted message. A message over `MAX_INLINE` (22 000 bytes) must go as a file. Conversation keys are handed to each member with `wrapKey` / `unwrapKey` (ECDH P-256); compare `safetyCode` out of band. `node --test web/test/chat-core.test.js`.

## Databases

rtcd runs on SQLite, PostgreSQL or MySQL, chosen by `database { driver … dsn … }`. All three are tested: the server suite runs on each (`RTCD_TEST_DB=postgres|mysql go test ./server`, against servers named by `RTCD_PG_DSN` / `RTCD_MYSQL_DSN`; the defaults match `docker run -p 55432:5432 postgres` and `-p 53306:3306 mysql`).

Designed so that a node never has several queries of the same kind in flight:

- **Messages: one statement, and often one for many.** A message is one `INSERT`: its number comes from a counter held in memory under the conversation's lock, and a collision with another node is a primary-key error that reloads the counter and retries. Messages that arrive for one conversation while a write is under way are **group-committed** into the next `INSERT`.
- **Membership: one query, once.** The roster of a group is a single join. It is cached for 5 s, dropped at once by any group change (on every node within the poll interval), and a miss that many requests hit together is loaded **once** (the others wait for it).
- **Cross-node events: one writer, one reader.** Events from a burst are gathered for 20 ms and written with multi-row `INSERT`s; one message to a 200-member group is one row, not 200, even when other events interleave. Each node polls the outbox with one query every 200 ms (and ids that committed late are looked for again for 3 s, which matters on PostgreSQL and MySQL where concurrent writers' ids become visible out of order).
- **Attachments:** a file's record is read once per few seconds, not for each of its parts.
- **The pool is a hard bound.** `max_open` caps the statements a node runs at once whatever the load.

Measured on PostgreSQL 16 (Docker, same machine), 200 members each sending 5 messages to one group with the cross-node outbox on: 200 000 deliveries in 1.8 s (about 110 000/s), **at most 3 statements running at once** (sampled from `pg_stat_activity`), **0.2 transactions per message** counting the outbox and the audit log, nothing dropped. The same run on MySQL 8 and SQLite also completes with none lost. Reproduce: `RTCD_TEST_DB=postgres RTCD_CHAT_LOAD=1 go test -run ChatFanOut -v ./server`.

## Browser example

`go run ./examples/demo` starts rtcd with a complete browser client ([`examples/demo`](examples/demo)): sign in with any name, end-to-end encrypted group chat, encrypted attachments with progress and previews, group video calls with per-frame encryption, safety codes, and a **Diagnostics** page that checks the service from the browser (20 checks: tickets, encryption, resume, rate limits, revocation, call signalling). Open it in two windows with two names. See its README, including how to run it against PostgreSQL or MySQL and how to run the automated browser test.

## Groups

A user can make groups, and call them. The creator owns the group; the owner can make members admins; owners and admins add and remove members; anyone can leave except the owner, who must hand the group over or delete it. Only members can see a group, and a group that exists looks exactly like one that does not. `group.call` rings every other member, or, if the group already has a call under way, puts the caller into it. Two members calling at the same moment end up in one call. Limits: `groups.max_owned` (100 per user), `groups.max_members` (200).

## Audit log

Every operation, from either interface, leaves an entry: **who** (user, and the API key's name if a service did it), **what** (the operation), **to what** (the call or group), **the outcome** (`ok`, `denied`, `error`) with the reason, **from where** (IP, transport, connection), and small facts (who was invited, how many bytes were relayed, a role). It also records connections opening and closing, tokens minted, tokens expiring, slow clients dropped, calls timing out, and failed authentication (under the tenant `_none`, within a budget so an attacker cannot fill the log).

- **No contents.** A key message is logged as "this many bytes from ada to bob", never what was in it.
- **Quiet operations** (ICE candidates, stats polls, preferences) are logged only when they fail or are refused; they are the constant background of a call and a join already says who is in the room.
- **Tamper-evident.** Each tenant has its own numbered sequence, and every entry carries the hash of the one before it. `audit.verify` walks the chain and reports where an entry was changed, removed or inserted. A chain cannot show that the newest entries were cut off the end, so keep the head (`head_seq`, `head_hash`, returned by `audit.verify`) somewhere the database's administrator cannot reach, or ship the JSONL file (`audit.file`).
- **Never on the request path.** Entries go to per-connection buffers and a single writer commits them in batches. If the store stalls, calls carry on while the backlog (default 16 384 entries) absorbs it; only when the backlog is full does an operation wait, for up to 2 s. If the log still cannot take an entry, the entry is written to standard error and counted in `audit_refused` (visible in `stats`). It is never dropped silently.
- **Order.** Entries are in the order operations finished; one connection's entries are always in order.
- `audit.query` takes `actor`, `action` (exact, or a prefix ending in `.`), `target`, `outcome`, `from`, `to`, `after_seq`, `limit`, `newest`. It is limited to the caller's tenant and to service keys.
- **Retention is yours.** Nothing is deleted. Archive and prune from outside; pruning the oldest entries is fine for the chain only if you note the sequence number you pruned up to.

## Performance and limits

Designed so that relaying costs nothing shared:

- **No database on the relay path.** Signals, key messages and SFU preconditions are checked against an in-memory copy of the call (sharded, updated at once by any change). Only a call starting, being answered or ending touches the database.
- **Sharded delivery.** Connections are spread over independent hubs. Pushing an event to a user takes one shard's read lock for one map lookup, then queues a single shared buffer on each of their connections, without waiting. Connecting and disconnecting on one shard never blocks delivery on another.
- **A slow reader costs only itself.** A connection whose queue (256 events) is full is closed from its own goroutine, and the sender and everyone else carry on.
- **Per-user limits** answer `rate_limited` and keep the connection: 200 operations a second (burst 400), and 100 relayed messages a second per call (burst 200). fh's own hard cutoff, which closes the socket, is set above them. One user's connections share the budget.

Measured on one 10-core laptop (Apple silicon), SQLite, loopback; reproduce with `go test -bench RelayOperation -benchtime 300000x -cpu 1,2,4,8,10 ./server` and `go test -v -run Throughput ./server`:

| | |
|---|---|
| Server cost of relaying one key message, no network | 6.5 µs on 1 core → 0.68 µs on 10 (9.5× on 10 cores), i.e. about 1.4 million a second; 26–31 allocations |
| Same, real WebSockets, 100 pairs (200 sockets) | ~44 000 messages/s, ack p50 0.9 ms, p99 18 ms |
| Same, 400 pairs (800 sockets) | ~37 000 messages/s, p50 7.8 ms, p99 42 ms. Here the 1 600 test goroutines and the server share the machine, and 70% of CPU is socket syscalls: this is a floor, not the service's ceiling |
| A slow reader fed 15 KiB messages until dropped | sender's worst wait 4 ms; an unrelated user's 0.3 ms |
| Audit store stalled completely | 500 relays take the same time as when healthy; the backlog absorbs them |
| Audit store sustained write rate (SQLite) | roughly 13 000–70 000 entries/s depending on batching; sustained relaying above that fills the backlog and then waits. Real call traffic is far below this: a relay happens a few times per participant per join or leave |

Group chat, measured the same way (`RTCD_CHAT_LOAD=1 go test -run ChatFanOut -v ./server`): 200 members each sending 5 messages to the group, 200 000 deliveries over real WebSockets in 1.6 s (about 120 000 deliveries/s) with none lost or dropped; ack p50 0.3 s, p99 0.44 s, which is 200 senders queueing on SQLite's single writer.

Defaults: 32 shards, 20 000 connections per node, 8 per user, 256-event writer queue (all under `limits`).

## Configuration (`rtcd.bcl`)

The service is configured in [BCL](https://github.com/oarkflow/bcl), the same language as REF applications. A setting the service does not know, or has the wrong type, is an error at startup, not a silent default. Secrets come from the environment: `env.required("NAME")` refuses to start without the variable, and `env("NAME", "default")` supplies a default, so no secret has to be written in the file.

```bcl
listen "127.0.0.1:8480"

database { driver "sqlite" dsn "file:.data/rtcd.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" }
audit    { dsn "file:.data/rtcd-audit.db?_pragma=busy_timeout(5000)" file ".data/rtcd-audit.jsonl" }

key "my-backend" { key env.required("RTCD_API_KEY") tenant "acme" }
token_secret env.required("RTCD_TOKEN_SECRET")

allowed_origins ["https://app.example.com"]
stun_urls ["stun:stun.l.google.com:19302"]
groups { max_owned 50 max_members 100 }
limits { ops_per_second 200 max_connections 20000 }
udp_port_min 50000
udp_port_max 50100
```

| setting | |
|---|---|
| `listen` | default `:8480` |
| `tls_cert`, `tls_key` | serve TLS directly |
| `insecure_http` | accept non-local plain HTTP (only behind a proxy that ends TLS and sets `X-Forwarded-Proto: https`, or for development). Off by default: without TLS, only requests from this machine are accepted |
| `database { driver dsn max_open max_idle max_lifetime }` | `driver` is `sqlite`, `postgres` or `mysql`. `max_open` (default 20; SQLite is always 1) is the most connections this node holds, so the most statements it runs at once; `max_lifetime` default 30m |
| `audit { dsn file queue }` | a database of its own for the log (recommended with SQLite; same driver as `database`), a JSONL file, and the backlog size |
| `key "name" { key tenant }` | one block per backend service; keys are at least 24 characters. Repeat the block for more services |
| `token_secret` | signs tokens, at least 24 characters |
| `max_token_ttl` | default `"1h"` |
| `allowed_origins` | browser origins |
| `stun_urls`, `turn_urls`, `turn_secret`, `turn_ttl` | TURN needs a secret |
| `allow_plaintext` | allow calls without end-to-end encryption (default false) |
| `ring_timeout`, `max_invitees` | `"45s"`, 20 |
| `groups { max_owned max_members }` | |
| `node_id` | names this node when several share a database |
| `attach_dir`, `max_file_bytes`, `tenant_file_bytes`, `file_retention`, `message_retention`, `max_message_bytes` | messages and attachments |
| `record_min_free_bytes`, `record_max_duration` | recording safeguards |
| `limits { conv_messages_per_second conv_message_burst }` | messages a conversation accepts per second in all (default 50, burst 100). A sender over it gets `rate_limited` and retries the same message; it keeps every member's queue (`writer_queue`, 256) from being overrun by a burst. Keep the burst below the queue |
| `limits { shards max_connections max_connections_per_user writer_queue ops_per_second ops_burst relay_per_second relay_burst }` | |
| `last_n_video`, `last_n_audio`, `max_room_members` | large rooms (above) |
| `udp_port_min`, `udp_port_max`, `public_ips`, `max_peers`, `max_rooms`, `reconnect_grace`, `offer_timeout`, `initial_kbps` | SFU |
| `interfaces` | only offer addresses on these network interfaces, e.g. `["eth0"]`. Default: all |
| `network_types` | `["udp4"]`, `["udp6"]` or both (default). A server with no usable IPv6 should say `["udp4"]`: every candidate pair that cannot work is a connectivity check wasted |
| `record_dir`, `record_layer` | recording (plain calls only) |

## ICE restarts

A client moves a call to a new network with `sfu.restart`, and it may do so at any moment, including on a connection that is working perfectly. The server keeps the call going.

This needed a change to Pion. Upstream `pion/ice` closes every local socket and forgets every remote candidate the instant it applies a restart offer. A browser, correctly, keeps sending on its old path until it has switched to the new one, which took about 4.6 s in the logs, and everything it sent in that time went to a closed port (the kernel counted about 500 datagrams "dropped due to no socket" in each stalled run). The loss also made the browser cut its bandwidth estimate, which then took many seconds to climb back. In real Chrome, restarting a healthy connection froze a viewer's video for 3 to 10 seconds in 9 of 14 runs.

[`github.com/oarkflow/ice`](https://github.com/oarkflow/ice) is a fork of `pion/ice` v4.4.8 (branch `v4.4.8-oarkflow`, tag `v4.4.8-oarkflow.1`) with a small patch (`retire.go` and six marked lines; see its `PATCH.md`) that makes the restart make-before-break, as RFC 8445 section 9 intends. The old generation is retired, not closed: its sockets stay open, media from its remote addresses is still accepted, and its selected pair still carries outgoing RTP and RTCP, until a pair of the new generation is selected. It is closed 3 s after that, or 20 s after the restart if none is. Connectivity checks and state reporting use the new generation only.

Measured, with real Chrome forcing a restart of a healthy connection: **9 of 14 runs stalled before, 0 of 14 after** (a few single half-second blips). In Go, with a publisher that stays on its old path through the restart, 230 packets reach the viewer in the next 1.5 s, against 0, 1 and 0 with upstream. When the old path really is gone, video is back in about 190 ms. The server also asks the publisher for a keyframe itself after a restart, and keeps asking until one arrives.

Things that did **not** help, each measured and removed: asking for keyframes harder, a larger ICE check budget, filtering candidates by interface name (it made things worse: on one machine the name `bridge100` was the browser's own network), hiding sequence gaps from the viewer, and a shorter keepalive.

Maintenance: `go.mod` uses `replace github.com/pion/ice/v4 => github.com/oarkflow/ice/v4 v4.4.8-oarkflow.1`. The fork keeps upstream's module path, which is what makes the `replace` work. When pion/webrtc is updated to need a newer pion/ice v4, re-apply the patch to that version on a new branch and tag (upstream's `main` is already `ice/v5`), or propose it upstream. `network_types` and `interfaces` are available if a deployment wants to offer fewer candidates.

**If you embed the `sfu` or `server` packages in your own program**, add the same line to *your* `go.mod`: a `replace` in a dependency is not inherited, and without it you get upstream `pion/ice` and the stall. (Programs that only use `client` or `auth` do not build the SFU and need nothing.)

Server candidates can reach the client before the restart's answer does (they travel on the same socket and gathering is fast). A client must hold them until it has applied the answer, as the demo page does.

## Browser side

`web/e2ee-core.js` and `web/e2ee-worker.js` are the encryption a browser needs for group calls. A worker must be served from the page's own origin, so the application copies both files next to its page (the [REF demo](https://github.com/oarkflow/ref/tree/main/examples/realtime-platform/static) does). `web/test` has the Node tests: `node --test web/test/e2ee-core.test.js`.

## Security model

See the end-to-end encryption section of [docs/calls.md](docs/calls.md): what is protected (media content, against the service itself), what is not (membership, timing, sizes, microphone loudness), and that the safety code is what defeats a service that is a man in the middle from first contact.

Service-level: keys are compared in constant time over their hashes; tokens are HMAC-SHA256 signed, carry their scopes and expire, and a connection is closed when its token runs out unless refreshed; a browser must connect from an allowed origin; the service refuses to start with short secrets, duplicate keys, TURN without a secret, or half a UDP range; request bodies are capped at 64 KiB. The token travels in the WebSocket URL (browsers cannot set headers on one), so keep tokens short-lived and do not log query strings.

## Not done yet

- **SFU across nodes.** A room lives on one node (see *Several nodes*). The cascade exists in `sfu` and passes its tests in one process, but has no HTTP link between nodes.
- Webhooks to the backend (it learns of events by holding a socket as a user).
- No per-tenant quotas, only per-user limits.
- Safari and Firefox: the managed-room flow and encrypted group calls were run in Playwright's WebKit and Firefox (three browsers, key rotation on a leave, a removal) from the Aura repository's `web/e2e/sfu`, with fake cameras. That is the engines, not Safari itself, and not a phone.

## Tests

```
go test -race ./...                       # auth, calls, groups, audit, API (real HTTP and WebSocket), SFU with real Pion clients
node --test web/test/e2ee-core.test.js    # the browser cryptography against real WebCrypto
```

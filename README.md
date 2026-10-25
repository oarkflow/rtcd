# rtcd: the call service

Audio and video calls as an independent service: peer-to-peer or through a Pion **SFU** (simulcast, VP9 SVC, active speaker, recording), **end-to-end encrypted** by default, with users' own **groups** and a complete, tamper-evident **audit log**. It knows nothing about the applications that use it. [`contrib/rtc`](https://github.com/oarkflow/ref/tree/main/contrib/rtc) is REF's client; [`client/`](client) is a Go client; the protocol below works from anything.

```
git clone git@github.com:oarkflow/rtcd.git && cd rtcd
go build -o rtcd ./cmd/rtcd
./rtcd -config rtcd.bcl
```

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
| `database { driver dsn }` | `driver` is `sqlite` |
| `audit { dsn file queue }` | a database of its own for the log (recommended with SQLite), a JSONL file, and the backlog size |
| `key "name" { key tenant }` | one block per backend service; keys are at least 24 characters. Repeat the block for more services |
| `token_secret` | signs tokens, at least 24 characters |
| `max_token_ttl` | default `"1h"` |
| `allowed_origins` | browser origins |
| `stun_urls`, `turn_urls`, `turn_secret`, `turn_ttl` | TURN needs a secret |
| `allow_plaintext` | allow calls without end-to-end encryption (default false) |
| `ring_timeout`, `max_invitees` | `"45s"`, 20 |
| `groups { max_owned max_members }` | |
| `limits { shards max_connections max_connections_per_user writer_queue ops_per_second ops_burst relay_per_second relay_burst }` | |
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

- **Several nodes.** Events, connections and SFU rooms are per node; there is no backplane, node registry or HTTP cascade link, so run one rtcd (or route a user's and a call's traffic to one node). The call cache is also only coherent with writes made through the same node. The cascade exists in `sfu` and passes its tests in one process.
- **Only SQLite** is linked into the binary (the stores speak postgres/mysql dialects).
- Webhooks to the backend (it learns of events by holding a socket as a user).
- No per-tenant quotas, only per-user limits.
- Safari and Firefox are untested.

## Tests

```
go test -race ./...                       # auth, calls, groups, audit, API (real HTTP and WebSocket), SFU with real Pion clients
node --test web/test/e2ee-core.test.js    # the browser cryptography against real WebCrypto
```

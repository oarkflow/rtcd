# Chat for a backend that owns its membership

This is the part of rtcd an application like Aura builds on. It adds to the
messages and attachments in the README:

- **managed conversations**: the backend, with a service key, decides who is in a conversation;
- **a key directory and epochs**: end-to-end keys for conversations whose members have several devices, handed on through the service without the service holding any;
- **message lifetimes, per-conversation retention and a delete window**;
- **a webhook**, so the backend can push a notification for a message while nobody is connected.

The service still stores and forwards only ciphertext.

## Managed conversations

A conversation is a group underneath, but one nobody can see or change through
`group.*`: to a user it does not exist as a group, only as a conversation they
can send to and read. Service key only.

| | |
|---|---|
| `conv.open {id, members[], admins[], retention, default_ttl, delete_window}` | creates it under your id, or admits `members` if it is open. `admins` are made administrators (they can delete anyone's message). Durations are seconds. `POST /v1/conversations/open` |
| `conv.admit {id, members[], admins[]}` | lets more people in, and can promote existing members to admin |
| `conv.remove {id, members[]}` | takes people out **at once** (their next request is refused); see *Removal* below |
| `conv.role {id, user, role}` | `admin` or `member` |
| `conv.close {id}` | deletes the conversation with its messages, read positions, keys and files |
| `conv.get {id}` | members with roles, and the key state |
| `conv.policy {id, retention, default_ttl, delete_window}` | change any of them; absent ones are left alone |

Ids are 1 to 128 characters, must not start with `grp_` (those are users'), and are unique across tenants:
another tenant opening a live id gets `id_taken`, which is also what a clash with a user-made group gives.
A user-made group (`group.create`) works with everything below too; only the `conv.*` operations are for managed ones.

Events to users: `conv.added` (you are in), `conv.members {added | removed}` (to the others),
`conv.removed`, `conv.closed`, `conv.rekey` (see below).

## Key directory and epochs

A conversation key is a random 256-bit AES key. Its **epoch** is a counter; epoch 0
means the conversation does not use the directory (the older behaviour: messages
need no `epoch`, the application distributes keys itself). Once a conversation
has an epoch, every message must carry the current one.

Each **device** publishes a P-256 public key, with an opaque `cert`. The service
keeps the directory but does not decide what is genuine: the application checks
`cert` against its own identity system (for Aura, the certificate its identity
key signed). A key the application does not vouch for is never wrapped for, so a
service that invents a device gains nothing.

| | |
|---|---|
| `key.publish {device, pub, cert}` | announces a device. A device's key never changes (a different key under the same id is `conflict`); a revoked device stays revoked (`device_revoked`). At most `max_devices_per_user` (32) active. Members hear `key.added` |
| `key.revoke {device}` | retires one of the caller's devices; a backend names the user in `X-RTC-User`, and may revoke a device that never published. Its wraps are deleted and every conversation that used epochs needs a new one. Members hear `key.revoked` |
| `key.list {conv}` | active devices of everyone in the conversation (members only) |
| `epoch.get {conv, device}` | `{epoch, rekey_required, wraps[]}`: the wraps made for this device, each with who made it (`by`, `by_device`, `by_pub`, `by_cert`) |
| `epoch.rotate {conv, device, epoch, wraps[{user, device, w}]}` | starts epoch `epoch` (must be current + 1, else `stale_epoch`). Wraps must be for active devices of current members only, and must cover every member (else `members_without_keys`, naming who). Members hear `epoch.new` |
| `epoch.missing {conv}` | devices of members that hold no wrap of the current epoch |
| `epoch.grant {conv, device, epoch, wraps[]}` | adds wraps for an existing epoch (a new member, a new device); one already stored is left as it is. The recipients hear `epoch.granted` |
| `msg.send {…, epoch}` | `epoch` must equal the conversation's current one: `stale_epoch` (the message names the current one) otherwise |

A wrap is an opaque string up to 1 KiB; see `web/chat-core.js` for the format the
provided clients use (ECDH P-256 + HKDF-SHA-256 + AES-256-GCM, with the
conversation and epoch bound in). Rotation bodies may be up to 1 MiB over HTTP
(`POST /v1/epochs/rotate`); over a WebSocket the limit is 192 KiB, roughly a thousand wraps (members × devices); a larger conversation rotates over HTTP.

### Removal

When anyone leaves or is removed (by `conv.remove`, `group.remove`, leaving), their
wraps are deleted and the conversation is marked **`rekey_required`**: `msg.send` is
refused (`rekey_required`) until a member makes the next epoch, which can include
nobody who left. Members hear `conv.rekey`, and so does the webhook. So a removed
person's key stops being the one anything is sealed under, and a service that
wanted to keep sending them ciphertext would be sending what they cannot open.
Revoking a device does the same for every conversation it could read.

A rejected `msg.send` costs a client a few round trips: it fetches the new epoch (or makes it) and
sends again with the same id, which is safe.

What the service does *not* do: it cannot check a wrap is the key (it is
ciphertext). A member who is malicious can grant a bad wrap to a new device; that
device cannot open it and a member must grant again. Members are inside the
conversation's trust boundary; the key directory is there to keep the service and
outsiders out of it.

A member added later receives the current key only (`epoch.grant`), so cannot read
what was sent before. A member who holds older keys may pass them on
(`ChatClient.grant(conv, {history: true})`) if the product wants new members to see history.

## Messages

Additions to `msg.*` (see the README):

- `msg.send {conv, id, body, epoch, ttl}`: `ttl` (seconds, up to 366 days) makes the message disappear. A conversation can set a `default_ttl`. The answer and `msg.new` carry `expires_at`; clients should hide the message then, and the service stops serving it and deletes it within about a minute.
- `msg.delete`: a sender may delete only within the conversation's `delete_window` (else the service's `message_delete_window`; 0 is always) or the answer is `too_late`. An admin may always.
- `msg.typing {conv}`: tells the others; nothing is stored, a few a second at most, not sent to the typist.
- `msg.cursors {conv}`: every member's read position.
- `msg.summary {convs[]}`: for up to 100 conversations, `last_seq`, `last_at`, the caller's `read_seq` and an `unread` count (to 100): a conversation list without fetching history.
- Retention: `message_retention` (service-wide) and `conv.policy retention` (per conversation) both apply; the shorter wins.

## Webhook

```
webhook { url "https://app.example.com/rtcd-hook"  secret env.required("RTCD_WEBHOOK_SECRET") }
```

rtcd POSTs batches of events, signed:

```
X-RTC-Timestamp: <unix seconds>
X-RTC-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>
{"events":[{"id":"…","type":"msg.new","tenant":"acme","at":1760000000000,"conv":"…","seq":7,"msg":"<sender's id>","sender":"ada","recipients":["bob","cy"],"connected":["bob"],"size":412,"epoch":3}]}
```

| type | when | fields |
|---|---|---|
| `msg.new` | a message was stored | `conv seq msg sender recipients connected size epoch` |
| `msg.deleted` | a message was deleted | `conv seq sender recipients` |
| `conv.rekey` | a new epoch is required | `conv recipients` |
| `key.added`, `key.revoked` | a device was published or revoked | `user device` |

There is **never any content**; a push says "something arrived", and the app fetches `msg.history`.
`connected` are the recipients with a live connection *to the node that handled the message*;
in a cluster others may be connected elsewhere, so it is a hint for skipping a push, not a promise.

Delivery is batched (100 events or 200 ms), tried up to six times with doubling waits, then dropped
and counted (`WebhookDropped` in `stats`). Events are held in memory, so a node that stops
loses what it had not delivered; nothing depends on one arriving, because a client catches up
from `msg.history` when it connects. Verify the signature and a recent timestamp
(`client.VerifyWebhook` does both); `id` lets you ignore a repeat.

## Settings

| | |
|---|---|
| `webhook { url secret }` | secret at least 16 characters |
| `max_devices_per_user` | active device keys per user (32) |
| `max_conversation_members` | people in one managed conversation (1000) |
| `message_delete_window` | e.g. `"2m"`; default 0 (any time) |

## Clients

| | |
|---|---|
| Go | `client`: `OpenConv`, `AdmitToConv`, `RemoveFromConv`, `SetConvRole`, `CloseConv`, `GetConv`, `SetConvPolicy`, `RevokeDevice`, `VerifyWebhook` |
| Browser, Node | `web/chat-core.js` (the cryptography; large files a chunk at a time with `prepareFile` / `uploadStream` / `downloadStream`) and `web/chat-client.js` (`ChatClient`: the directory and rotation protocol, over any `call(op, payload)`) |
| Dart, Flutter | `clients/dart` (`package:rtcd_chat`): the same, wire-compatible, including a connection. The default P-256 is pure Dart; set `P256.impl` to use the platform's in a release build |

`web/test/vectors.json` (made by JavaScript) and `vectors-dart.json` (made by Dart) are
opened by both, so the formats cannot drift apart unnoticed. `web/test/live.test.js` and
`clients/dart/test/live_test.dart` run the clients against a real `rtcd`, including one
conversation between a Dart client and a JavaScript one.

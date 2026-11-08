# MLS delivery service

rtcd can be the delivery service (RFC 9420 §14) for a conversation's end-to-end encrypted
group. It holds no group secret and parses no MLS structure; every payload is opaque base64url.
A conversation is either on per-device epochs (`epoch.*`, see chat.md) or on MLS, decided once by
`mls.group.create` while its epoch is 0. There is no in-place migration.

## Operations

All are also `POST /v1/mls/<op with / for .>` (and the message operations `msg.send`, `msg.history`, ... are `POST /v1/msg/send`, `/v1/msg/history`, ...) (e.g. `mls.kp.put` -> `/v1/mls/kp/put`).
A WebSocket frame is limited to 64 KiB and a WebSocket reply to 128 KiB: send anything larger
(a GroupInfo with the ratchet tree, a commit with many welcomes) over REST.

| op | body | what it does |
|---|---|---|
| `mls.kp.put` | `device, conv?, kps[{kp, last_resort?, ttl?}]` | Publish KeyPackages. At most 100 single-use per device plus one last-resort (a new one replaces the old). `ttl` seconds, default 30 days, max 90. Re-publishing a held package adds nothing. |
| `mls.kp.count` | `device, conv?` | `{available, last_resort}` - top up when low. |
| `mls.kp.claim` | `conv, users[]` | One KeyPackage per active device of each user, in one transaction. Caller and users must be in the roster. Single-use are consumed; a device with none left yields its last-resort package (not consumed). Rate limited per caller and person claimed. Returns `{key_packages, missing}`. |
| `mls.group.create` | `conv, group_id, suite, group_info?` | Bind the conversation to a group at epoch 0. `suite` must be allowed (`Options.MLSSuites`, default 1, 2, 3). |
| `mls.group.get` | `conv` | `{group_id, suite, epoch, seq, rekey_required, pending_removals, group_info, group_info_epoch}`. Over a socket an oversized `group_info` is omitted (`group_info_omitted`, `group_info_bytes`). |
| `mls.commit` | `conv, device, epoch, id, body, welcomes[{user,device,w}], group_info?, removed[]` | `epoch` is the current epoch + 1. Stores the commit and its welcomes and moves the group, in one transaction. |
| `mls.propose` | `conv, device, epoch, id, body` | Store a proposal for the current epoch. Does not move the epoch. |
| `mls.sync` | `conv, device, after, limit` | Handshake messages with `seq > after`, in the one order every member applies them. A welcome is returned only to its device. `more` means ask again. |
| `mls.groupinfo.put` | `conv, epoch, group_info` | Refresh the stored GroupInfo for the current epoch. |

Application messages are the ordinary `msg.send` with `epoch` = the MLS epoch the body was sealed
under. The current epoch and the one before are accepted (a message sealed just before a commit
still lands just after). History, `ttl`, delete and read cursors are unchanged.

## Guarantees

- **One commit per epoch.** Of N concurrent commits at epoch E+1, exactly one is stored. The rest
  get `409 mls_epoch_conflict` with message `current_epoch=N`: apply what was stored, rebuild, retry.
  A commit is never stored without its welcomes, nor its welcomes without it.
- **Retry-safe.** Resend a commit with the same `id` after a lost answer and you get the stored one
  back with `duplicate: true`, not a conflict with yourself.
- **Removal fence.** Taking someone out of the roster (`group.remove`, leaving) raises
  `rekey_required` and lists them in `pending_removals`. `msg.send` answers `409 rekey_required`
  until a commit whose `removed` names all of them. Handshakes are still carried: they are the way out.
  A removed person can no longer sync.
- **No gap.** A commit may not skip an epoch; a welcome goes only to a current member.
- An MLS group with members in the roster but no commit yet (epoch 0, more than one member) takes no
  application messages.

## What clients must check (the service cannot)

The service cannot read a commit, so it cannot know a commit really removed the people it names, or
that a KeyPackage is well formed. Every member checks: KeyPackage signature, lifetime, credential and
cipher suite; that a commit applies and that its removes match the public roster; that the group's
suite is one they accept (it is fixed at creation, so a client refuses to join a group with a suite it
considers too weak - that is the downgrade protection).

## Events

`mls.commit {conv, epoch, seq, by, by_device, id, body?, rekey_required?}` to every member (`body` is
inline when <= 16 KiB), `mls.welcome {conv, epoch}` to each person welcomed, `mls.proposal`.
`conv.rekey` (existing) is sent when the removal fence goes up.

## Retention

Handshake messages are kept 30 days (the newest 1000 per conversation always). A member offline longer
rejoins by external commit from the stored GroupInfo. Expired KeyPackages are swept hourly.

## Storage

`rtc_mls_kp`, `rtc_mls_group`, `rtc_mls_hs`, `rtc_mls_removed`, and `rtc_conv.mls`. The group's epoch
is `rtc_conv.epoch`. SQLite, PostgreSQL and MySQL; MySQL uses MEDIUMTEXT for payloads.

## Post-quantum suite

A group is created with one cipher suite and never changes it. Allowed by default: 1, 2, 3 and
79 (`0x004F`, `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`: ML-KEM-768 and X25519 together, so
the group stays safe if either is broken; signatures stay Ed25519). Set `mls_suites [79]` in
`rtcd.bcl` to make a deployment post-quantum only. A post-quantum key package is ~2.7 KB and a
Welcome grows with the group (it carries the ratchet tree), so `MaxWelcome` is 1 MiB and a Welcome
for several devices is stored once.

## Sealed send (sender-anonymous messages)

`mls.sealed.set {conv, epoch, verifier}` (or `sealed_verifier` on `mls.commit`) stores the SHA-256
(hex) of the epoch's **group send token**: a 32-byte secret every member derives from the MLS
exporter (label `aura/rtcd/sealed/v1`, context the conversation id) and the service never sees.

`POST /v1/sealed/send {tenant, conv, id, body, epoch, token}` needs **no sign-in**. The service
checks `SHA-256(token)` against the verifier for the current or previous epoch, stores the message
with sender `~sealed`, and tells every member (`msg.new`, `from` empty). It learns that someone in
the group spoke, not who; the sender is authenticated inside the MLS message, to the members.

- Every failure (unknown conversation, not MLS, wrong epoch, wrong token) is the same `403`.
- The token changes with the epoch, so a removed member's token stops working with the commit that
  removes them. The removal fence applies (`409 rekey_required`).
- Rate limited per address and per conversation; body limited.
- Not hidden: the sender's network address (use a proxy), and the roster.

## Packages for a conversation

An MLS client holds one group, and a KeyPackage's private half lives in the client that made it. A
device that is in several conversations therefore makes each conversation's packages in that
conversation's own client. Publish them with `conv` set: the caller must be in the conversation, its
other members get `mls.kp.ready {conv, user, device}` (so whoever is adding people knows to), and
`mls.kp.claim {conv}` hands out the conversation's own packages. A device with none for that
conversation falls back to packages it published for no conversation (the behaviour before this
existed); it never gets another conversation's. A last-resort package is per device and conversation.

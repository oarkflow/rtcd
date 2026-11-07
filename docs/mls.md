# MLS delivery service

rtcd can be the delivery service (RFC 9420 §14) for a conversation's end-to-end encrypted
group. It holds no group secret and parses no MLS structure; every payload is opaque base64url.
A conversation is either on per-device epochs (`epoch.*`, see chat.md) or on MLS, decided once by
`mls.group.create` while its epoch is 0. There is no in-place migration.

## Operations

All are also `POST /v1/mls/<op with / for .>` (e.g. `mls.kp.put` -> `/v1/mls/kp/put`).
A WebSocket frame is limited to 64 KiB and a WebSocket reply to 128 KiB: send anything larger
(a GroupInfo with the ratchet tree, a commit with many welcomes) over REST.

| op | body | what it does |
|---|---|---|
| `mls.kp.put` | `device, kps[{kp, last_resort?, ttl?}]` | Publish KeyPackages. At most 100 single-use per device plus one last-resort (a new one replaces the old). `ttl` seconds, default 30 days, max 90. Re-publishing a held package adds nothing. |
| `mls.kp.count` | `device` | `{available, last_resort}` - top up when low. |
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

# Calls

How rtcd runs a call: the model, the group-call (SFU) operations, how bandwidth is kept low, network changes, operating notes and the end-to-end encryption design. The [README](../README.md) has the API, configuration and limits.

## One WebSocket for everything

The browser keeps **one WebSocket** to rtcd (`/v1/ws?token=…`) and does everything over it: starting, answering and ending calls, groups, key exchange, p2p signaling, group-call media signaling. Requests are envelopes with an `id` and an operation name and are answered with the same id; events are pushed on the same socket. The full list of operations and events is in [the [README](../README.md)](../rtcd/README.md). The demo page ([`examples/realtime-platform/static/index.html`](https://github.com/oarkflow/ref/blob/main/examples/realtime-platform/static/index.html) in the REF repository) is a working client: `rtcdApi("call.start", {...})` is a request, `callEvent(name, data)` receives events.

A call that rings longer than `ring_timeout` (45 s) is *missed*. A connection that drops reconnects with a fresh token, reads the call (`call.get`) and, in a group call, asks for any offer it missed (`sfu.resync`). Keep the socket alive with `{"type":"ping"}` every 25 s.

## p2p (mode `p2p`, exactly two people)

Media flows directly between the browsers. rtcd only relays signaling (`call.signal`, type offer, answer, candidate, renegotiate, mute or unmute). The sender is stamped by the service, the payload (≤ 16 KiB) is opaque, and only participants can send to participants. The demo does p2p (the *Video call* button in a DM) and group calls (the *Group call* button in a channel).

## Group calls (mode `sfu`)

Each participant sends their media to the service once; it forwards it to the others, and **everyone always sees everyone**. After answering, a participant talks to the SFU with these operations (each takes the `call` id):

| | |
|---|---|
| `sfu.join` `{sdp, e2ee}` | the first offer → `{type:"answer", sdp}` |
| `sfu.ready` | the join answer has been applied; the server may now send its offers |
| `sfu.answer` `{sdp}` | answer to a server offer |
| `sfu.candidate` | a client ICE candidate |
| `sfu.prefs` | tile sizes, hidden tiles, a pinned speaker, a data-saver cap (below) |
| `sfu.restart` `{sdp}` | an ICE-restart offer after a network change → answer |
| `sfu.resync` | send the outstanding server offer again |
| `sfu.stats` | what the server is sending this participant |
| `sfu.sample` | the start of your own media as the server holds it |
| `sfu.record.start`, `.stop`, `.status` | recording (not available in encrypted calls) |
| `sfu.leave` | leave the room |

The server answers back as events: `sfu.offer` `{call_id, type, sdp}` (the room's tracks changed: answer it) and `sfu.candidate`. Each incoming video arrives in a section of its own, and its stream id is the publisher's user id, set by the server, so a publisher cannot pose as someone else. People can also be added to a call under way (`call.invite`), and users can make **groups** and call them (`group.call`); see the [README](../README.md).

Errors carry a code: `negotiating` (answer the server's offer, then retry), `not_in_room` (join again), `call_ended`, `room_full`, `bad_preferences`, `e2ee_required`, `rate_limited`, `token_expired`, `scope_missing`.

### Simulcast: how bandwidth stays low

A browser publishes the same camera as up to three layers, named `q`, `h` and `f` (small, medium, full: about 150, 500 and 1200 kbps):

```js
pc.addTransceiver(videoTrack, { direction: "sendonly", streams: [stream], sendEncodings: [
  { rid: "q", scaleResolutionDownBy: 4, maxBitrate: 150000 },
  { rid: "h", scaleResolutionDownBy: 2, maxBitrate: 500000 },
  { rid: "f", maxBitrate: 1200000 } ] });
```

The server sends each viewer, for each person, **one** of those layers, chosen from the viewer's own situation:

- **Their link.** A bandwidth estimate per viewer (Google congestion control over transport-wide feedback) sets a budget, 85% of it less audio. The viewer starts on the smallest layer so a picture appears at once and climbs one step at a time. A drop is immediate; a rise waits for the link to look steady, and after a rise that did not hold the wait doubles (10 s up to 90 s). When the estimator is held down only by how little is being sent, a single trial step up probes it.
- **Their screen.** The page tells the server each tile's size (`prefs.streams[user].max`): a thumbnail gets `q`, a large or pinned tile `f`. Pinned tiles are raised first when bandwidth is short.
- **Their choice.** `max_kbps` is a data-saver ceiling. A tile that is genuinely not visible can be `paused`; that is the only way anyone's video is withheld.
- **The publisher's uplink.** If a publisher's browser stops sending its top layer, viewers move down instead of staring at a freeze, and go back up when it returns.

**Nobody disappears.** However little bandwidth a viewer has, every visible person keeps at least the smallest live layer. Pressure lowers quality, never the number of people on screen.

Switching layers is invisible to the viewer's decoder: the server moves only at a keyframe of the new layer (asking the publisher for one), and renumbers sequence numbers, RTP time, VP8 picture ids and TL0PICIDX so the stream carries on where the old one stopped. Video is **VP8** (all browsers can send it); audio is Opus.

For 12 people with cameras on, a viewer who would have downloaded about 16 Mbps now downloads about 1.7 Mbps with the others as thumbnails, and the server's upload falls from about 200 Mbps to about 20 Mbps (arithmetic from the layer rates, not a measurement of your network).

### Network changes

A phone moving from Wi-Fi to cellular, a laptop waking up, a tunnel: the participant's address changes and the connection stalls. The call carries on:

1. The browser (see the demo page) notices (`online`, `navigator.connection` change, ICE `disconnected` or `failed`) and sends `restart` with an **ICE-restart offer**. The same connection moves to the new path; nobody's screen changes, and the viewer's quality re-adapts from what the new link supports. A restart is safe at any moment, even on a connection that is working: the server keeps the old path alive until the new one is selected (see the [README](../README.md), which also explains the patched `pion/ice` that makes this so). The demo page still restarts only when the call has really stopped, because a restart that is not needed is wasted work.
2. A connection that ICE declares failed is **not** dropped. The participant keeps their place, and their video stays in the room, for `reconnect_grace` (45 s) while they reconnect.
3. If the signaling channel dropped a server offer, the server resends it, with growing gaps, until it is answered; `resync` asks for it immediately after a reconnect. A restart that collides with a server offer gets `negotiating` and is retried after the answer.
4. Only if the server has forgotten the participant (`not_in_room`) does the page join again from scratch.

The server waits for `ready` before sending its first offer, so an offer can never overtake the join answer on the way to a client.

## Operating it

- **One room lives on one node, and so do its events.** Media is not split across nodes in a deployment yet: route every request for a call, and every event connection of its participants, to one rtcd (hash the call id at the load balancer). The SFU has an in-process cascade between nodes (`sfu.Cascade`, tested with two servers in one process) but rtcd has no HTTP link, node registry or cluster authentication for it yet.
- Open the UDP range (`udp_port_min`–`max`) in the firewall; behind static NAT set `public_ips`.
- **TURN:** rtcd refuses `turn_urls` without a `turn_secret`. Clients get a credential that expires (`turn_ttl`, default 1 h), derived by HMAC from the secret; the secret is never sent.
- Limits: `max_peers` (50) per room, `max_rooms` (1000), `max_invitees` (20). Timing: `reconnect_grace` (45 s), `offer_timeout` (6 s), `initial_kbps` (600). Implemented: recording (plain calls only), active-speaker detection, VP9 SVC, VP8/VP9/H.264 (H.264 not in encrypted calls). Each downstream video takes a media section of its own; closed sections are reused, and a link is rebuilt at 48 sections.
- Cost: the SFU's own work is about 230 ns per packet per viewer; SRTP encryption and the network dominate. Measure with your own load before relying on a capacity number.

## End-to-end encryption

Calls are end-to-end encrypted by default (`allow_plaintext` is false in rtcd). A service running with the default refuses to create a plaintext call.

**p2p calls.** The two browsers encrypt media with DTLS-SRTP, so the server never holds the keys. Each side also signs the DTLS fingerprints it sends with a long-term ECDSA identity key, and the other side verifies them. Without that, the signaling server could swap the fingerprints and sit in the middle.

**Group (SFU) calls.** Each browser encrypts every encoded frame in a worker (`RTCRtpScriptTransform`, AES-GCM). The SFU forwards frames it cannot read. A few leading bytes stay in the clear so it can still find keyframes and switch simulcast or SVC layers: 1 byte for Opus, 3 for a VP8 delta frame, 10 for a VP8 keyframe, 0 for VP9. Keys are exchanged between browsers as signed, pairwise-wrapped messages relayed through `call.e2ee`. Every join and leave rotates every member's key. A browser without `RTCRtpScriptTransform` refuses to join; there is no plaintext fallback.

**Server enforcement.** The server cannot verify that media is encrypted, but it:
- requires the join to declare `e2ee:true` (otherwise 400 `e2ee_required`), and refuses a plain join to an encrypted room;
- refuses to record an encrypted call (409 `recording_unavailable_e2ee`);
- drops H.264 in encrypted rooms and tells the publisher why (ciphertext can contain start codes). Use VP8 or VP9;
- requires TLS on every request, including the WebSocket (`insecure_http` turns that off), except from loopback;
- offers `POST /v1/calls/{id}/sfu/sample`, which shows you the bytes the server holds of your own media, so you can check they are ciphertext.

**Threat model.**
- Protects the content of audio and video against an honest-but-curious or compromised SFU, hub, database or network.
- Does not hide metadata: who is in a call, when, packet sizes and timing, layer choice, and microphone loudness (the SFU uses it to name the active speaker).
- Does not protect against compromised endpoints or a malicious participant.
- A server that is a man in the middle from a person's very first contact can only be detected by comparing the **safety code** (shown in the UI) out of band. After first contact, identities are pinned and a changed key blocks that person's media with a warning.

Verified with Node tests against real WebCrypto (`examples/realtime-platform/test`, mutation-checked), Go tests for the policy, and real Chrome with three profiles: encrypted VP8 and VP9 group calls, rekeying after a leave, and refusal in a browser without the transform. Not tested: Safari and Firefox, and encrypted calls across cascaded nodes.

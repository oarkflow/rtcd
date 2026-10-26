# rtcd browser example

A complete browser client for rtcd, to try the service and to read as a reference. No build step, no dependencies: plain JavaScript that talks to the service over one WebSocket.

```
go run ./examples/demo                      # http://127.0.0.1:8480
go run ./examples/demo -addr :9000 -db postgres -dsn 'postgres://user:pw@localhost/rtcd?sslmode=disable'
go run ./examples/demo -db mysql -dsn 'user:pw@tcp(localhost:3306)/rtcd'
```

Open it in **two windows** (or a window and a private window) and sign in with two different names. Then:

1. **New group** with the other name as a member. The first person to open it makes the group's key; the second receives it, wrapped for them alone. Both show *End-to-end encrypted*.
2. **Send messages, drag in files, paste images.** Files are encrypted in the browser, uploaded in 1 MiB parts (an interrupted upload resumes), and decrypted on download. The *Safety code* in the group info is the same on both sides; compare it out of band.
3. **Call** starts a group video call through the SFU. Every frame is encrypted in a worker before it leaves the browser; the call screen shows the safety code and how many frames were encrypted, decrypted and dropped.
4. **Diagnostics → Run all checks** runs 20 checks from the page against the service, using throwaway users and groups.
5. Try removing a member (the key is replaced so they cannot read what follows), a second device (the key change warning and *Trust new key*), the dark theme, and a phone-sized window.

## What is where

| file | |
|---|---|
| `main.go` | runs rtcd and serves the page. `/demo/login` signs anyone in and `/demo/revoke` revokes a user: **demonstration only**, a real backend authenticates its own users and calls rtcd with a service key |
| `ui/rtc.js` | the connection: ticket sign-in, requests and events, token refresh, reconnect |
| `ui/chat.js` | encrypted group chat: key distribution through ordinary messages, pinning of identities, key rotation |
| `ui/call.js` | the SFU call: negotiation, per-frame encryption in a worker, key exchange between participants |
| `ui/selftest.js` | the diagnostics |
| `ui/app.js`, `app.css`, `index.html` | the interface (light and dark, responsive). Message text is only ever put in the page with `textContent`, and the page is served with a strict Content-Security-Policy |
| `../../web/chat-core.js`, `e2ee-core.js`, `e2ee-worker.js` | the cryptography the client uses |

## Automated browser test

`test/e2e.js` drives two real Chrome windows (with a fake camera and microphone) through the whole flow above and fails on any problem: chat both ways, HTML in a message staying text, a 2.3 MB file downloaded byte for byte, an image preview, matching safety codes, all 20 diagnostics, and a live encrypted call with decrypted video on both sides.

```
go run ./examples/demo -addr 127.0.0.1:8481 &
npm i playwright            # anywhere; or point PLAYWRIGHT at an existing install
BASE=http://127.0.0.1:8481 node examples/demo/test/e2e.js
```

It uses the installed Google Chrome (`channel: 'chrome'`). Screenshots go to `SHOTS` if set.

// A JavaScript chat peer for clients/dart/test/live_test.dart:
//   node js_peer.js BASE TOKEN USER DEVICE CONV
// Publishes a device, prints READY, waits for one message in CONV, prints
// "GOT <text>", answers "pong from js" and prints "SENT".
const C = require('../chat-core.js'), ChatClient = require('../chat-client.js');
const [base, token, user, device, conv] = process.argv.slice(2);
(async () => {
  const ws = new WebSocket(base.replace('http', 'ws') + '/v1/ws?token=' + token);
  const pending = new Map(); let n = 0, chat;
  const inbox = [], waiters = [];
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws')); });
  const call = (op, payload) => new Promise((res, rej) => { const id = String(++n); pending.set(id, { res, rej }); ws.send(JSON.stringify({ type: 'emit', id, event: op, payload })); });
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.type === 'ack') pending.get(m.replyTo)?.res(m.payload);
    else if (m.type === 'error') { const e = String(m.error || m.code); pending.get(m.replyTo)?.rej(Object.assign(new Error(e), { code: e.split(':')[0] })); }
    else if (m.type === 'emit') { chat?.handleEvent(m.event, m.payload); if (m.event === 'msg.new') { inbox.push(m.payload); waiters.splice(0).forEach(w => w()); } }
  };
  chat = new ChatClient({ call, user, device, identity: await C.newIdentity(), cert: 'vouched', jitterMs: 0, verifyDevice: async d => d.cert === 'vouched' });
  await chat.start();
  console.log('READY');
  while (!inbox.length) await new Promise(r => { waiters.push(r); setTimeout(r, 200); });
  console.log('GOT ' + await chat.open(conv, inbox[0]));
  await chat.send(conv, 'pong from js');
  console.log('SENT');
  setTimeout(() => process.exit(0), 300);
})().catch(e => { console.error('PEER FAILED', e); process.exit(1); });

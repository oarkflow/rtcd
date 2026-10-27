// Drives ChatClient against a real rtcd process: node --test web/test/live.test.js
// (builds ./cmd/rtcd; set RTCD_LIVE=0 to skip).
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http'), net = require('node:net');
const C = require('../chat-core.js');
const ChatClient = require('../chat-client.js');

const SKIP = process.env.RTCD_LIVE === '0';
const KEY = 'live-test-service-key-0123456789', SECRET = 'live-test-token-secret-0123456789ab', HOOK = 'live-test-webhook-secret-01234';
const root = path.join(__dirname, '..', '..');

const freePort = () => new Promise(r => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const sleep = ms => new Promise(r => setTimeout(r, ms));

let proc, base, dir, hookEvents = [], hookServer;
const dirKeys = new Map(); // what the application's own system vouches for: "user/device" -> pub

async function svc(method, p, body, user) {
  const r = await fetch(base + p, { method, headers: Object.assign({ Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' }, user ? { 'X-RTC-User': user } : {}), body: body && JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error((j.error && j.error.code) || r.status), { code: j.error && j.error.code });
  return j;
}

test.before(async () => {
  if (SKIP) return;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rtcd-live-'));
  execFileSync('go', ['build', '-o', path.join(dir, 'rtcd'), './cmd/rtcd'], { cwd: root, stdio: 'inherit' });
  const port = await freePort(), hookPort = await freePort();
  hookServer = http.createServer((req, res) => {
    let b = ''; req.on('data', d => b += d); req.on('end', () => { try { hookEvents.push(...JSON.parse(b).events); } catch (e) {} res.end('ok'); });
  }).listen(hookPort, '127.0.0.1');
  fs.writeFileSync(path.join(dir, 'rtcd.bcl'), `
listen "127.0.0.1:${port}"
insecure_http true
database { driver "sqlite"  dsn "file:${dir}/r.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" }
key "chat" { key "${KEY}"  tenant "acme" }
token_secret "${SECRET}"
allowed_origins ["http://localhost"]
attach_dir "${dir}/att"
webhook { url "http://127.0.0.1:${hookPort}/hook"  secret "${HOOK}" }
`);
  proc = spawn(path.join(dir, 'rtcd'), ['-config', path.join(dir, 'rtcd.bcl')], { cwd: dir, stdio: ['ignore', 'ignore', 'inherit'] });
  base = 'http://127.0.0.1:' + port;
  for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/healthz')).ok) return; } catch (e) {} await sleep(100); }
  throw new Error('rtcd did not start');
});
test.after(() => { if (proc) proc.kill(); if (hookServer) hookServer.close(); });

/* One user with one device: a WebSocket, and a ChatClient on it. */
async function person(user, device, opts = {}) {
  const tok = (await svc('POST', '/v1/tokens', { user, ttl_seconds: 600 })).token;
  const ws = new WebSocket(base.replace('http', 'ws') + '/v1/ws?token=' + tok);
  const pending = new Map(), inbox = [], waiters = [];
  let n = 0;
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws error')); });
  const identity = await C.newIdentity();
  dirKeys.set(user + '/' + device, C.b64(identity.publicRaw));
  const call = (op, payload) => new Promise((res, rej) => { const id = String(++n); pending.set(id, { res, rej }); ws.send(JSON.stringify({ type: 'emit', id, event: op, payload: payload || {} })); });
  const me = { user, device, identity, inbox, ws, call };
  const chat = new ChatClient({
    call, user, device, identity, cert: 'vouched', jitterMs: 0,
    verifyDevice: opts.verify || (async d => d.cert === 'vouched' && dirKeys.get(d.user + '/' + d.device) === d.pub),
    api: { base, headers: () => ({ Authorization: 'Bearer ' + tok }) },
  });
  me.chat = chat;
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.type === 'ack' || m.type === 'error') {
      const p = pending.get(m.replyTo); if (!p) return; pending.delete(m.replyTo);
      if (m.type === 'ack') p.res(m.payload);
      else { const code = String(m.error || m.code).split(':')[0].trim(); p.rej(Object.assign(new Error(m.error || m.code), { code: m.code && m.code !== 'internal_error' ? m.code : code })); }
    } else if (m.type === 'emit') {
      const e = { name: m.event, data: m.payload };
      inbox.push(e);
      chat.handleEvent(m.event, m.payload);
      for (const w of waiters.splice(0)) w();
    }
  };
  me.next = async (name, ms = 5000) => {
    const end = Date.now() + ms;
    for (;;) {
      const i = inbox.findIndex(e => e.name === name);
      if (i >= 0) return inbox.splice(i, 1)[0].data;
      if (Date.now() > end) throw new Error(me.user + ': no ' + name + ' event');
      await new Promise(r => { waiters.push(r); setTimeout(r, 100); });
    }
  };
  await chat.start();
  return me;
}

const live = SKIP ? { skip: 'RTCD_LIVE=0' } : {};

test('keys are made, handed on, and replaced when someone leaves', live, async () => {
  const conv = 'live-1';
  const ada = await person('ada', 'a1'), bob = await person('bob', 'b1'), cy = await person('cy', 'c1');
  await svc('POST', '/v1/conversations/open', { id: conv, members: ['ada', 'bob', 'cy'] });

  // The first message makes epoch 1, wrapped for everybody.
  const sent = await ada.chat.send(conv, 'hello all');
  assert.equal(sent.epoch, 1);
  for (const p of [bob, cy]) {
    const ev = await p.next('msg.new');
    assert.equal(await p.chat.open(conv, ev), 'hello all');
  }

  // A forged sender is refused by the cryptography, not by trust in the service.
  const ev = (await bob.call('msg.history', { conv })).messages[0];
  await assert.rejects(bob.chat.open(conv, { ...ev, sender: 'cy' }), { code: 'forged' });

  // cy is removed: bob is told a new key is needed, and the next message uses it.
  await svc('POST', '/v1/conversations/remove', { id: conv, members: ['cy'] });
  await cy.next('conv.removed');
  const s2 = await ada.chat.send(conv, 'cy cannot read this');
  assert.equal(s2.epoch, 2);
  const ev2 = await bob.next('msg.new');
  assert.equal(await bob.chat.open(conv, ev2), 'cy cannot read this');
  await assert.rejects(cy.call('msg.history', { conv }), { code: 'forbidden' });
  await assert.rejects(C.decryptMessage(await cy.chat.store.get(conv, 1), { conv, sender: 'ada', id: s2.id }, ev2.body), { code: 'forged' }, 'the old key does not open the new epoch');

  // dee joins later: a member hands her the current key, and she reads from here on.
  const dee = await person('dee', 'd1');
  await svc('POST', '/v1/conversations/admit', { id: conv, members: ['dee'] });
  await dee.next('conv.added');
  await bob.next('conv.members'); // bob's client grants dee the key in reaction
  for (let i = 0; i < 50 && !(await dee.chat.sync(conv), await dee.chat.store.get(conv, 2)); i++) await sleep(100);
  const s3 = await bob.chat.send(conv, 'welcome dee');
  const ev3 = await dee.next('msg.new');
  assert.equal(await dee.chat.open(conv, ev3), 'welcome dee');
  const old = (await dee.call('msg.history', { conv })).messages.find(m => m.id === sent.id);
  await assert.rejects(dee.chat.open(conv, old), { code: 'no_key' }, 'she cannot read what was sent before she joined');
  assert.equal(s3.epoch, 2);

  // A device revoked by the backend: the conversation needs a new epoch.
  await svc('POST', '/v1/keys/revoke', { device: 'b1' }, 'bob');
  await ada.next('conv.rekey');
  await assert.rejects(ada.call('msg.send', { conv, id: 'raw', body: 'x', epoch: 2 }), { code: 'rekey_required' });
});

test('a device the application does not vouch for is never wrapped for', live, async () => {
  const conv = 'live-2';
  const ada = await person('ada2', 'a1'), mal = await person('bob2', 'evil', { verify: async () => true });
  dirKeys.delete('bob2/evil'); // the application's directory has never heard of this key
  await svc('POST', '/v1/conversations/open', { id: conv, members: ['ada2', 'bob2'] });
  // bob2's only device is untrusted, so there is nobody to wrap for: it fails closed.
  await assert.rejects(ada.chat.send(conv, 'secret'), { code: 'members_without_keys' });
  assert.equal(await mal.chat.store.get(conv, 1), null);
});

test('a large file goes up and down a chunk at a time, byte for byte', live, async () => {
  const conv = 'live-3';
  const ada = await person('ada3', 'a1'), bob = await person('bob3', 'b1');
  await svc('POST', '/v1/conversations/open', { id: conv, members: ['ada3', 'bob3'] });
  const data = new Uint8Array(require('node:crypto').randomBytes(C.CHUNK * 2 + 4321));
  const d = await ada.chat.attach(conv, new Blob([data])); // the server checks the SHA-256 of the stored bytes
  await ada.chat.send(conv, JSON.stringify({ t: 'file', ...d }));
  const m = await bob.next('msg.new');
  const got = JSON.parse(await bob.chat.open(conv, m));
  const parts = [];
  for await (const chunk of bob.chat.fetchAttachment(conv, got)) parts.push(chunk);
  assert.deepEqual(Buffer.concat(parts), Buffer.from(data));
  // The same bytes the in-memory path would have made.
  assert.deepEqual(await C.decryptFile(conv, got.meta, new Uint8Array(await (await fetch(base + '/v1/files/' + got.file + '/blob', { headers: bob.chat.api.headers() })).arrayBuffer())), data);
});

test('the webhook told the backend about the messages, without their contents', live, async () => {
  await sleep(500);
  const m = hookEvents.filter(e => e.type === 'msg.new' && e.conv === 'live-1');
  assert.ok(m.length >= 2, JSON.stringify(hookEvents.slice(0, 3)));
  assert.ok(m[0].recipients.includes('bob') && !m[0].recipients.includes('ada'));
  assert.ok(hookEvents.some(e => e.type === 'conv.rekey' && e.conv === 'live-1'));
  assert.ok(!JSON.stringify(hookEvents).includes('hello all'));
});

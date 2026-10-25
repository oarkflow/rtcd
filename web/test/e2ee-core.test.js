// Run with: node --test examples/realtime-platform/test
const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../e2ee-core.js');

const rnd = n => require('node:crypto').randomBytes(n);
const store = () => { const m = new Map(); return { get: async k => m.get(k), set: async (k, v) => { m.set(k, v); } }; };
const frame = (n, fill = 0x55) => new Uint8Array(n).fill(fill);
const keys = async (a, b, kid = 1) => { const s = rnd(32); const A = new E.KeyRing(a), B = new E.KeyRing(b); await A.setOwn(kid, s); await B.setPeer(a, kid, s); return { A, B, s }; };

test('a frame round-trips, and the leading bytes the SFU needs stay readable', async () => {
  const { A, B } = await keys('ada', 'bob');
  const vp8Key = new Uint8Array([0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00, ...frame(500, 7)]);
  const out = await E.encryptFrame(A, 'video', 'video/VP8', true, vp8Key);
  assert.deepEqual(out.slice(0, 10), vp8Key.slice(0, 10), 'the VP8 keyframe tag must be readable by the SFU');
  assert.equal(out.length, vp8Key.length + E.HEADER + E.TAG);
  assert.notDeepEqual(out.slice(10 + 8, 40), vp8Key.slice(10, 32), 'the picture data must not be readable');
  assert.deepEqual(await E.decryptFrame(B, 'ada', 'video', 'video/VP8', true, out), vp8Key);

  const delta = new Uint8Array([0x31, 0x00, 0x00, ...frame(300, 9)]);
  const d = await E.encryptFrame(A, 'video', 'video/VP8', false, delta);
  assert.deepEqual(d.slice(0, 3), delta.slice(0, 3));
  assert.deepEqual(await E.decryptFrame(B, 'ada', 'video', 'video/VP8', false, d), delta);

  const opus = new Uint8Array([0xfc, ...frame(80, 3)]);
  const a = await E.encryptFrame(A, 'audio', 'audio/opus', false, opus);
  assert.equal(a[0], 0xfc, 'the Opus TOC byte stays readable');
  assert.deepEqual(await E.decryptFrame(B, 'ada', 'audio', 'audio/opus', false, a), opus);

  const vp9 = frame(400, 1);
  const v = await E.encryptFrame(A, 'video', 'video/VP9', false, vp9); // VP9's descriptor is outside the frame: nothing needs to stay clear
  assert.equal(v.length, 400 + E.HEADER + E.TAG);
  assert.deepEqual(await E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, v), vp9);
});

test('the same frame encrypts differently every time', async () => {
  const { A } = await keys('ada', 'bob');
  const f = frame(200);
  const x = await E.encryptFrame(A, 'video', 'video/VP9', false, f), y = await E.encryptFrame(A, 'video', 'video/VP9', false, f);
  assert.notDeepEqual(x, y);
});

test('any change to a frame is detected, including the bytes left in the clear', async () => {
  const { A, B } = await keys('ada', 'bob');
  const f = new Uint8Array([0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00, ...frame(100)]);
  const good = await E.encryptFrame(A, 'video', 'video/VP8', true, f);
  for (const [name, at] of [['a ciphertext byte', good.length - 20], ['the tag', good.length - 1], ['a clear prefix byte', 4], ['the counter', 14]]) {
    const bad = good.slice(); bad[at] ^= 1;
    await assert.rejects(E.decryptFrame(B, 'ada', 'video', 'video/VP8', true, bad), e => ['tampered', 'replay'].includes(e.code), name + ' was accepted');
  }
  await assert.rejects(E.decryptFrame(B, 'ada', 'video', 'video/VP8', true, good.slice(0, 20)), e => e.code === 'malformed');
  const plain = f.slice(); // a frame that was never encrypted
  await assert.rejects(E.decryptFrame(B, 'ada', 'video', 'video/VP8', true, plain), e => e.code === 'malformed', 'plaintext must not pass as encrypted');
  // The genuine frame still decrypts after all those failures: bad frames burn nothing.
  assert.deepEqual(await E.decryptFrame(B, 'ada', 'video', 'video/VP8', true, good), f);
});

test('a frame cannot be passed off as another sender\'s', async () => {
  const s = rnd(32);
  const A = new E.KeyRing('ada'), B = new E.KeyRing('bob'); await A.setOwn(1, s);
  await B.setPeer('ada', 1, s); await B.setPeer('mallory', 1, s); // even if the same key were somehow shared
  const f = await E.encryptFrame(A, 'audio', 'audio/opus', false, new Uint8Array([1, 2, 3, 4, 5]));
  await assert.rejects(E.decryptFrame(B, 'mallory', 'audio', 'audio/opus', false, f), e => e.code === 'tampered');
  await E.decryptFrame(B, 'ada', 'audio', 'audio/opus', false, f);
});

test('wrong or missing keys cannot decrypt', async () => {
  const { A } = await keys('ada', 'bob');
  const f = await E.encryptFrame(A, 'video', 'video/VP9', false, frame(100));
  const eve = new E.KeyRing('eve');
  await assert.rejects(E.decryptFrame(eve, 'ada', 'video', 'video/VP9', false, f), e => e.code === 'nokey');
  await eve.setPeer('ada', 1, rnd(32));
  await assert.rejects(E.decryptFrame(eve, 'ada', 'video', 'video/VP9', false, f), e => e.code === 'tampered');
  const noOwn = new E.KeyRing('x');
  await assert.rejects(E.encryptFrame(noOwn, 'audio', 'audio/opus', false, frame(5)), e => e.code === 'nokey');
});

test('replays are refused, reordering within a window is allowed', async () => {
  const { A, B } = await keys('ada', 'bob');
  const fs = []; for (let i = 0; i < 80; i++) fs.push(await E.encryptFrame(A, 'video', 'video/VP9', false, frame(50, i)));
  await E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, fs[10]);
  await assert.rejects(E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, fs[10]), e => e.code === 'replay');
  await E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, fs[12]);
  await E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, fs[11]); // late but inside the window
  await E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, fs[70]);
  await assert.rejects(E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, fs[5]), e => e.code === 'replay', 'older than the window');
  await E.decryptFrame(B, 'ada', 'video', 'video/VP9', false, fs[69]); // inside the window still
});

test('a sending key is retired before its counter can wrap', async () => {
  const { A } = await keys('ada', 'bob');
  A.own.counter = 0x7FFFFFFF;
  await assert.rejects(E.encryptFrame(A, 'audio', 'audio/opus', false, frame(5)), e => e.code === 'exhausted');
});

test('old keys keep working briefly after a rekey, and only a few are kept', async () => {
  const A = new E.KeyRing('ada'), B = new E.KeyRing('bob');
  const secrets = [1, 2, 3, 4, 5, 6].map(() => rnd(32));
  const sent = [];
  for (let i = 0; i < 6; i++) { await A.setOwn(i + 1, secrets[i]); await B.setPeer('ada', i + 1, secrets[i]); sent.push(await E.encryptFrame(A, 'audio', 'audio/opus', false, frame(20, i))); }
  await E.decryptFrame(B, 'ada', 'audio', 'audio/opus', false, sent[5]);
  await E.decryptFrame(B, 'ada', 'audio', 'audio/opus', false, sent[3]);
  await assert.rejects(E.decryptFrame(B, 'ada', 'audio', 'audio/opus', false, sent[0]), e => e.code === 'nokey', 'long-retired keys are forgotten');
});

// ---- the key exchange through a hostile server ---------------------------------------

function network(callId, users, hostile) {
  const sessions = {}, rings = {}, transcript = [], warnings = [];
  const pins = {};
  const queue = [];
  const deliver = async (from, to, text) => { transcript.push({ from, to, text }); const t = hostile ? hostile({ from, to, text }) : text; if (t != null) queue.push(async () => sessions[to] && sessions[to].receive(from, t)); };
  const drain = async () => { while (queue.length) await queue.shift()(); };
  const setup = async u => {
    rings[u] = new E.KeyRing(u); pins[u] = pins[u] || new Map();
    const identity = await E.Identity.load(u, store());
    sessions[u] = new E.Session({
      callId, identity, send: (to, text) => deliver(u, to, text),
      pins: { get: async x => pins[u].get(x), set: async (x, v) => { pins[u].set(x, v); } },
      onKey: async (who, kid, secret) => { if (who === null) await rings[u].setOwn(kid, secret); else if (secret === null) rings[u].dropPeer(who); else await rings[u].setPeer(who, kid, secret); },
      onWarning: w => warnings.push({ at: u, ...w }),
    });
  };
  return { sessions, rings, transcript, warnings, pins, setup, drain };
}

const canTalk = async (net, from, to) => {
  const f = await E.encryptFrame(net.rings[from], 'audio', 'audio/opus', false, new Uint8Array([9, 8, 7, 6]));
  try { await E.decryptFrame(net.rings[to], from, 'audio', 'audio/opus', false, f); return true; } catch { return false; }
};

test('three people exchange keys through a server that sees every message but learns no key', async () => {
  const users = ['ada', 'bob', 'cy'], n = network('call_1', users);
  for (const u of users) await n.setup(u);
  for (const u of users) await n.sessions[u].start(users);
  await n.drain();
  for (const a of users) for (const b of users) if (a !== b) assert.ok(await canTalk(n, a, b), a + ' -> ' + b);

  // Everything the server relayed, searched for any key it could use.
  const blob = JSON.stringify(n.transcript);
  for (const u of users) {
    const secret = n.sessions[u].secret;
    for (const form of [Buffer.from(secret).toString('hex'), Buffer.from(secret).toString('base64'), E.b64(secret)])
      assert.ok(!blob.includes(form), 'the server saw ' + u + '\'s sender key');
  }
  assert.ok(n.transcript.length >= 6, 'messages really travelled');
  // The safety code agrees for everybody.
  const codes = await Promise.all(users.map(u => n.sessions[u].safetyCode()));
  assert.equal(new Set(codes).size, 1);
  assert.match(codes[0], /^\d{5}( \d{5}){5}$/);
});

test('when someone leaves they cannot read what comes next; when someone joins they cannot read what came before', async () => {
  const n = network('call_2', []);
  const users = ['ada', 'bob', 'cy'];
  for (const u of users) await n.setup(u);
  for (const u of users) await n.sessions[u].start(users);
  await n.drain();
  const before = await E.encryptFrame(n.rings.ada, 'audio', 'audio/opus', false, new Uint8Array([1, 2, 3]));

  // cy leaves: the others rotate among themselves.
  for (const u of ['ada', 'bob']) await n.sessions[u].membersChanged(['ada', 'bob']);
  await n.drain();
  assert.ok(await canTalk(n, 'ada', 'bob'));
  assert.equal(await canTalk(n, 'ada', 'cy'), false, 'a member who left can read the next frames');
  assert.equal(await canTalk(n, 'bob', 'cy'), false);
  await E.decryptFrame(n.rings.cy, 'ada', 'audio', 'audio/opus', false, before).catch(() => {}); // what cy already had is cy's to keep

  // dan joins: everyone rotates, dan gets the new keys only.
  await n.setup('dan');
  const now = ['ada', 'bob', 'dan'];
  await n.sessions.dan.start(now);
  for (const u of ['ada', 'bob']) await n.sessions[u].membersChanged(now);
  await n.drain();
  assert.ok(await canTalk(n, 'ada', 'dan'));
  assert.ok(await canTalk(n, 'dan', 'bob'));
  await assert.rejects(E.decryptFrame(n.rings.dan, 'ada', 'audio', 'audio/opus', false, before), e => ['nokey', 'tampered'].includes(e.code), 'a newcomer read an old frame');
});

test('a server that swaps keys in transit is ignored', async () => {
  // The server replaces bob\'s ephemeral key in his hello with its own.
  const mitm = await E.Identity.create('bob');
  const n = network('call_3', [], ({ from, to, text }) => {
    const m = JSON.parse(text);
    if (m.t === 'hello' && from === 'bob') { m.e = E.b64(new Uint8Array(65).fill(4)); return JSON.stringify(m); }
    return text;
  });
  for (const u of ['ada', 'bob']) await n.setup(u);
  for (const u of ['ada', 'bob']) await n.sessions[u].start(['ada', 'bob']);
  await n.drain();
  assert.equal(await canTalk(n, 'bob', 'ada'), false, 'a tampered hello was accepted');
});

test('a server that replaces a person\'s identity is caught by the pinned key', async () => {
  const n = network('call_4', []);
  for (const u of ['ada', 'bob']) await n.setup(u);
  for (const u of ['ada', 'bob']) await n.sessions[u].start(['ada', 'bob']);
  await n.drain();
  assert.ok(await canTalk(n, 'bob', 'ada'));
  // Later (a new call, a new device) "bob" shows up with a different identity key.
  const m2 = network('call_5', []);
  m2.pins.ada = n.pins.ada; // ada remembers bob's key
  for (const u of ['ada', 'bob']) await m2.setup(u);
  for (const u of ['ada', 'bob']) await m2.sessions[u].start(['ada', 'bob']);
  await m2.drain();
  assert.ok(m2.warnings.some(w => w.at === 'ada' && w.type === 'identity-changed' && w.user === 'bob'), 'no warning was raised');
  assert.equal(await canTalk(m2, 'bob', 'ada'), false, 'ada accepted keys from a changed identity');
});

test('a server that is in the middle from the start is exposed by the safety code', async () => {
  // First contact (nothing pinned yet): a perfect man in the middle gives each
  // side the other\'s forged identity. Nothing can stop that cryptographically; the
  // safety codes the two people compare out loud are what expose it.
  const a = network('call_6', []), b = network('call_6', []);
  const attackerId = await E.Identity.create('bob');
  const honest = network('call_6', []);
  for (const u of ['ada', 'bob']) await honest.setup(u);
  for (const u of ['ada', 'bob']) await honest.sessions[u].start(['ada', 'bob']);
  await honest.drain();
  const honestCode = await honest.sessions.ada.safetyCode();
  const forged = await E.safetyCode([{ userId: 'ada', pub: honest.sessions.ada.identity.raw }, { userId: 'bob', pub: attackerId.raw }]);
  assert.notEqual(forged, honestCode, 'swapping an identity key must change the code people compare');
});

test('key messages that are forged, misaddressed, stale or garbage are dropped quietly', async () => {
  const n = network('call_7', []);
  for (const u of ['ada', 'bob', 'cy']) await n.setup(u);
  for (const u of ['ada', 'bob', 'cy']) await n.sessions[u].start(['ada', 'bob', 'cy']);
  await n.drain();
  const keyMsg = n.transcript.find(t => JSON.parse(t.text).t === 'key' && t.from === 'ada' && t.to === 'bob');
  const m = JSON.parse(keyMsg.text);
  const bob = n.sessions.bob;
  let installed = 0;
  const orig = bob.o.onKey; bob.o.onKey = async (...a) => { installed++; return orig(...a); };
  const tries = {
    'tampered ciphertext': { ...m, ct: m.ct.slice(0, -4) + 'AAAA' },
    'tampered key id': { ...m, kid: m.kid + 1 },
    'wrong call': { ...m, c: 'other' },
    'addressed to cy': { ...m, to: 'cy' },
    'wrong sender field': { ...m, f: 'cy' },
    'unsigned': { ...m, sig: '' },
    'a different ephemeral key': { ...m, e: E.b64(new Uint8Array(65).fill(2)) },
    'unknown version': { ...m, v: 2 },
  };
  for (const [name, msg] of Object.entries(tries)) { await bob.receive(msg.f, JSON.stringify(msg)); }
  for (const junk of ['', 'null', '{', '[]', '{"v":1}', 'x'.repeat(100000), 42, null, undefined]) await bob.receive('ada', junk);
  assert.equal(installed, 0, 'a bad key message installed a key');
  // The genuine one still works afterwards.
  await bob.receive('ada', keyMsg.text);
  assert.equal(installed, 1);
});

test('a key from someone who never said hello is not accepted', async () => {
  const n = network('call_8', []);
  for (const u of ['ada', 'bob']) await n.setup(u);
  await n.sessions.ada.start(['ada']);
  await n.sessions.bob.start(['bob']);
  // ada gets bob's identity only by hello; fake a key message with no hello.
  const eve = await E.Identity.create('eve');
  await n.sessions.ada.receive('eve', JSON.stringify({ v: 1, t: 'key', c: 'call_8', f: 'eve', to: 'ada', kid: 1, e: 'x', iv: 'x', ct: 'x', sig: 'x' }));
  assert.equal(n.rings.ada.hasPeer('eve'), false);
});

// ---- p2p authentication ------------------------------------------------------------------

const SDP = (fp) => 'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 ' + fp + '\r\na=setup:actpass\r\n';

test('p2p: a signed fingerprint verifies; a swapped one is refused', async () => {
  const bob = await E.Identity.create('bob');
  const pins = new Map(), p = { get: async k => pins.get(k), set: async (k, v) => { pins.set(k, v); } };
  const sdp = SDP('AA:BB:CC');
  const proof = await E.signSDP(bob, 'call_p', sdp);
  assert.deepEqual(await E.verifySDP('bob', 'call_p', sdp, proof, p), bob.raw);
  await assert.rejects(E.verifySDP('bob', 'call_p', SDP('11:22:33'), proof, p), e => e.code === 'badsignature', 'a swapped DTLS fingerprint was accepted');
  await assert.rejects(E.verifySDP('bob', 'other_call', sdp, proof, p), e => e.code === 'badsignature', 'a signature was replayed into another call');
  await assert.rejects(E.verifySDP('cy', 'call_p', sdp, proof, p), e => e.code === 'badsignature', 'a signature was attributed to someone else');
  await assert.rejects(E.verifySDP('bob', 'call_p', sdp, undefined, p), e => e.code === 'unsigned');
  const other = await E.Identity.create('bob'); // the same name, a different key
  await assert.rejects(E.verifySDP('bob', 'call_p', sdp, await E.signSDP(other, 'call_p', sdp), p), e => e.code === 'identity-changed');
  await assert.rejects(E.signSDP(bob, 'c', 'v=0\r\n'), e => e.code === 'nofingerprint');
});

test('the safety code changes with the people and not with the order', async () => {
  const a = await E.Identity.create('ada'), b = await E.Identity.create('bob'), c = await E.Identity.create('cy');
  const m = x => ({ userId: x.userId, pub: x.raw });
  const ab = await E.safetyCode([m(a), m(b)]), ba = await E.safetyCode([m(b), m(a)]), abc = await E.safetyCode([m(a), m(b), m(c)]);
  assert.equal(ab, ba);
  assert.notEqual(ab, abc);
});

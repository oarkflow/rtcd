const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../chat-core.js');
const rnd = n => new Uint8Array(require('node:crypto').randomBytes(n));
const ctx = { conv: 'grp_1', sender: 'ada', id: 'm1' };

test('a message round-trips, and is bound to its conversation, sender and id', async () => {
  const k = C.newKey();
  const body = await C.encryptMessage(k, ctx, 'héllo 👋');
  assert.ok(body.startsWith('m1.') && !body.includes('llo'));
  assert.equal(await C.decryptMessage(k, ctx, body), 'héllo 👋');
  for (const bad of [{ ...ctx, conv: 'grp_2' }, { ...ctx, sender: 'eve' }, { ...ctx, id: 'm2' }])
    await assert.rejects(C.decryptMessage(k, bad, body), { code: 'forged' });
  await assert.rejects(C.decryptMessage(C.newKey(), ctx, body), { code: 'forged' });
  const flipped = body.slice(0, -2) + (body.endsWith('AA') ? 'BB' : 'AA');
  await assert.rejects(C.decryptMessage(k, ctx, flipped), { code: 'forged' });
  assert.notEqual(await C.encryptMessage(k, ctx, 'x'), await C.encryptMessage(k, ctx, 'x'), 'a nonce is never reused');
});

test('a message too large for the socket must go as an attachment', async () => {
  await assert.rejects(C.encryptMessage(C.newKey(), ctx, new Uint8Array(C.MAX_INLINE + 1)), { code: 'too_large' });
  const body = await C.encryptMessage(C.newKey(), ctx, new Uint8Array(C.MAX_INLINE));
  assert.ok(body.length < 32 * 1024, 'the largest inline message fits the 32 KiB body limit');
});

test('a file of several chunks round-trips, with parts of exactly the stored chunk size', async () => {
  const data = rnd(C.CHUNK * 2 + 12345);
  const enc = await C.encryptFile('grp_1', data);
  assert.equal(enc.chunk, 1048576);
  assert.equal(enc.cipher.length, data.length + 3 * 16);
  assert.equal(enc.meta.count, 3);
  assert.deepEqual(await C.decryptFile('grp_1', enc.meta, enc.cipher), data);
  await assert.rejects(C.decryptFile('grp_2', enc.meta, enc.cipher), { code: 'forged' }, 'another conversation');
});

test('an altered, reordered, cut or swapped file is refused', async () => {
  const data = rnd(C.CHUNK + 500);
  const enc = await C.encryptFile('c', data);
  const flip = enc.cipher.slice(); flip[100] ^= 1;
  await assert.rejects(C.decryptFile('c', enc.meta, flip), { code: 'corrupt' });
  // The server could recompute the hash it was given, so the chunks must stand on their own.
  const m = { ...enc.meta };
  const sha = async u => require('node:crypto').createHash('sha256').update(u).digest('hex');
  const swapped = new Uint8Array(enc.cipher.length);
  swapped.set(enc.cipher.subarray(enc.chunk), 0); swapped.set(enc.cipher.subarray(0, enc.chunk), enc.cipher.length - enc.chunk);
  await assert.rejects(C.decryptFile('c', { ...m, sha256: await sha(swapped) }, swapped), { code: 'forged' });
  const cut = enc.cipher.subarray(0, enc.chunk);
  await assert.rejects(C.decryptFile('c', { ...m, sha256: await sha(cut) }, cut), { code: 'forged' });
  await assert.rejects(C.encryptFile('c', new Uint8Array(0)), { code: 'empty' });
});

test('a conversation key is wrapped for one member and no one else', async () => {
  const ada = await C.newIdentity(), bob = await C.newIdentity(), eve = await C.newIdentity();
  const key = C.newKey();
  const w = await C.wrapKey(ada.privateKey, ada.publicRaw, bob.publicRaw, 'g', key);
  assert.deepEqual(await C.unwrapKey(bob.privateKey, bob.publicRaw, ada.publicRaw, 'g', w), key);
  await assert.rejects(C.unwrapKey(eve.privateKey, eve.publicRaw, ada.publicRaw, 'g', w), { code: 'forged' });
  await assert.rejects(C.unwrapKey(bob.privateKey, bob.publicRaw, eve.publicRaw, 'g', w), { code: 'forged' }, 'claimed to be from eve');
  await assert.rejects(C.unwrapKey(bob.privateKey, bob.publicRaw, ada.publicRaw, 'other', w), { code: 'forged' }, 'another conversation');
  const a = await C.safetyCode([ada.publicRaw, bob.publicRaw]);
  assert.equal(a, await C.safetyCode([bob.publicRaw, ada.publicRaw]));
  assert.notEqual(a, await C.safetyCode([ada.publicRaw, eve.publicRaw]));
});

// ---- epochs, identities, streaming files -----------------------------------

test('an epoch key is bound to its conversation, its epoch and its recipient', async () => {
  const ada = await C.newIdentity(), bob = await C.newIdentity(), eve = await C.newIdentity();
  const key = C.newKey();
  const w = await C.wrapEpochKey(ada.privateKey, ada.publicRaw, bob.publicRaw, 'grp_1', 3, key);
  assert.ok(w.startsWith('k2.'));
  assert.deepEqual(await C.unwrapEpochKey(bob.privateKey, bob.publicRaw, ada.publicRaw, 'grp_1', 3, w), key);
  for (const [conv, epoch] of [['grp_2', 3], ['grp_1', 4]])
    await assert.rejects(C.unwrapEpochKey(bob.privateKey, bob.publicRaw, ada.publicRaw, conv, epoch, w), { code: 'forged' });
  await assert.rejects(C.unwrapEpochKey(eve.privateKey, eve.publicRaw, ada.publicRaw, 'grp_1', 3, w), { code: 'forged' }, 'another device');
  await assert.rejects(C.unwrapEpochKey(bob.privateKey, bob.publicRaw, eve.publicRaw, 'grp_1', 3, w), { code: 'forged' }, 'claimed to be from someone else');
});

test('an identity survives being stored as text', async () => {
  const ada = await C.newIdentity(), bob = await C.newIdentity();
  const back = await C.importIdentity(await C.exportIdentity(bob));
  const w = await C.wrapEpochKey(ada.privateKey, ada.publicRaw, bob.publicRaw, 'c', 1, C.newKey());
  assert.equal((await C.unwrapEpochKey(back.privateKey, back.publicRaw, ada.publicRaw, 'c', 1, w)).length, 32);
});

test('the incremental SHA-256 agrees with the platform for every length that matters', async () => {
  const nc = require('node:crypto');
  for (const n of [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 128, 1000, 70000]) {
    const b = rnd(n), h = new C.Sha256();
    for (let i = 0; i < n; i += 37) h.update(b.subarray(i, Math.min(n, i + 37)));
    assert.equal(C.hex(h.digest()), nc.createHash('sha256').update(b).digest('hex'), 'length ' + n);
  }
});

test('a file prepared a chunk at a time is the same bytes as one encrypted whole', async () => {
  const data = rnd(C.CHUNK + 999);
  const prep = await C.prepareFile('grp_1', new Blob([data]));
  const parts = [];
  for (let n = 0; n < prep.count; n++) parts.push(await prep.part(n));
  const cipher = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0; for (const p of parts) { cipher.set(p, o); o += p.length; }
  assert.equal(prep.size, cipher.length);
  assert.equal(prep.sha256, require('node:crypto').createHash('sha256').update(cipher).digest('hex'));
  assert.equal(parts[0].length, prep.chunk);
  assert.deepEqual(await C.decryptFile('grp_1', prep.meta, cipher), data);
});

test('what other implementations must open still opens', async () => {
  const v = require('./vectors.json');
  assert.equal(await C.decryptMessage(C.unb64(v.message.key), v.message, v.message.body), v.message.plaintext);
  const { webcrypto } = require('node:crypto');
  const priv = async (side) => webcrypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', d: side.d, x: C.b64(C.unb64(side.pub).slice(1, 33)), y: C.b64(C.unb64(side.pub).slice(33)) }, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const got = await C.unwrapEpochKey(await priv(v.wrap.recipient), C.unb64(v.wrap.recipient.pub), C.unb64(v.wrap.sender.pub), v.wrap.conv, v.wrap.epoch, v.wrap.wrapped);
  assert.equal(C.b64(got), v.wrap.key);
  assert.equal(C.b64(await C.unwrapKey(await priv(v.wrap.recipient), C.unb64(v.wrap.recipient.pub), C.unb64(v.wrap.sender.pub), v.wrap.conv, v.wrap.legacy)), v.wrap.key);
  assert.deepEqual(await C.decryptFile(v.file.conv, v.file.meta, C.unb64(v.file.cipher)), C.unb64(v.file.plain));
  assert.equal(await C.safetyCode(v.safety.pubs.map(C.unb64)), v.safety.code);
});

test('what the Dart client made opens here', async () => {
  const v = require('./vectors-dart.json');
  assert.equal(await C.decryptMessage(C.unb64(v.message.key), v.message, v.message.body), v.message.plaintext);
  const { webcrypto } = require('node:crypto');
  const pub = C.unb64(v.wrap.recipient.pub);
  const me = await webcrypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', d: v.wrap.recipient.d, x: C.b64(pub.slice(1, 33)), y: C.b64(pub.slice(33)) }, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  assert.equal(C.b64(await C.unwrapEpochKey(me, pub, C.unb64(v.wrap.sender.pub), v.wrap.conv, v.wrap.epoch, v.wrap.wrapped)), v.wrap.key);
  assert.deepEqual(await C.decryptFile(v.file.conv, v.file.meta, C.unb64(v.file.cipher)), C.unb64(v.file.plain));
});

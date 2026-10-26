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

/* End-to-end encryption for messages and attachments.
 *
 * The service stores and forwards what this file produces and cannot read,
 * alter or forge it. Only the members of a conversation hold its key.
 *
 * Messages. One random 256-bit conversation key per conversation. A message is
 *
 *     "m1." + base64url( nonce (12) | AES-256-GCM ciphertext | tag (16) )
 *     AAD   = "rtcd-msg" | conv | sender | message id
 *
 * so a message cannot be moved to another conversation, attributed to someone
 * else, or replayed under a different id without failing to decrypt.
 *
 * Attachments. Each file has its own random key. The file is cut into chunks and
 * every chunk is sealed on its own, which lets an upload resume and a download
 * start before it ends:
 *
 *     nonce = salt (4, per file) | chunk index (u64 BE)
 *     AAD   = "rtcd-file" | conv | index | chunk count
 *
 * (the count in the AAD stops the server cutting a file short). The stored file
 * is the chunks one after another; every part but the last is exactly
 * CHUNK + 16 bytes, which is the part size the service is told. The returned
 * `meta` (key, salt, sizes, the SHA-256 of the stored bytes) goes inside an
 * encrypted message; that is how the recipient gets the key.
 *
 * Keys travel wrapped for one member at a time: ECDH over P-256 (the sender's
 * and recipient's long-term keys), HKDF-SHA-256, AES-256-GCM. A safety code over
 * everyone's public keys lets members confirm, over another channel, that the
 * server did not swap one.
 *
 * Epochs. A conversation that uses the service's key directory has numbered
 * key generations ("epochs"). The key of an epoch is wrapped separately for each
 * member DEVICE, with the epoch bound in:
 *
 *     "k2." + base64url( nonce (12) | AES-256-GCM ciphertext | tag (16) )
 *     key   = HKDF-SHA-256( ECDH(P-256), salt = sender pub | recipient pub,
 *                           info = "rtcd-key-wrap" 0x00 conv 0x00 epoch )
 *     AAD   = "rtcd-key" 0x00 conv 0x00 epoch
 *
 * so a wrap cannot be replayed for another conversation or epoch. ChatClient
 * (chat-client.js) runs the directory and rotation protocol on top of this.
 *
 * What is not hidden: who talks to whom, when, and the sizes.
 * Files: encryptFile/decryptFile hold a whole file in memory (fine for a few
 * megabytes); prepareFile/uploadStream/downloadStream work one 1 MiB chunk at a
 * time, for large files and phones, and produce the same bytes.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('node:crypto').webcrypto);
  else root.ChatCrypto = factory(root.crypto);
})(typeof self !== 'undefined' ? self : this, function (crypto) {
  'use strict';
  const subtle = crypto.subtle;
  const te = new TextEncoder(), td = new TextDecoder();
  const TAG = 16;
  const CHUNK = 1048576 - TAG; // plaintext bytes per chunk, so a stored chunk is exactly 1 MiB
  // The service's message body limit is 32 KiB; base64 adds a third.
  const MAX_INLINE = 22000;

  class ChatCryptoError extends Error { constructor(code, msg) { super(msg || code); this.code = code; } }

  const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const unb64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const r = atob(s), u = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i); return u; };
  const cat = (...a) => { const n = a.reduce((x, y) => x + y.length, 0), o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  const rnd = n => crypto.getRandomValues(new Uint8Array(n));
  const aesKey = (raw, use) => subtle.importKey('raw', raw, 'AES-GCM', false, use);
  const hex = u8 => Array.from(u8, x => x.toString(16).padStart(2, '0')).join('');
  const sha256 = async u8 => new Uint8Array(await subtle.digest('SHA-256', u8));

  // ---- messages ----------------------------------------------------------

  const newKey = () => rnd(32);
  const msgAAD = (conv, sender, id) => te.encode(['rtcd-msg', conv, sender, id].join('\0'));

  async function encryptMessage(key, ctx, plaintext) {
    const data = typeof plaintext === 'string' ? te.encode(plaintext) : plaintext;
    if (data.length > MAX_INLINE) throw new ChatCryptoError('too_large', 'send it as an attachment');
    const nonce = rnd(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: msgAAD(ctx.conv, ctx.sender, ctx.id) }, await aesKey(key, ['encrypt']), data));
    return 'm1.' + b64(cat(nonce, ct));
  }

  async function decryptMessage(key, ctx, body, asBytes) {
    if (typeof body !== 'string' || !body.startsWith('m1.')) throw new ChatCryptoError('bad_message');
    const raw = unb64(body.slice(3));
    if (raw.length < 12 + TAG) throw new ChatCryptoError('bad_message');
    try {
      const pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: msgAAD(ctx.conv, ctx.sender, ctx.id) }, await aesKey(key, ['decrypt']), raw.slice(12)));
      return asBytes ? pt : td.decode(pt);
    } catch (e) { throw new ChatCryptoError('forged', 'the message was altered, or is not from this sender in this conversation'); }
  }

  // ---- attachments -------------------------------------------------------

  const fileNonce = (salt, i) => { const n = new Uint8Array(12); n.set(salt, 0); new DataView(n.buffer).setBigUint64(4, BigInt(i)); return n; };
  const fileAAD = (conv, i, count) => te.encode(['rtcd-file', conv, i, count].join('\0'));

  async function encryptFile(conv, bytes) {
    if (!bytes.length) throw new ChatCryptoError('empty');
    const key = rnd(32), salt = rnd(4), k = await aesKey(key, ['encrypt']);
    const count = Math.ceil(bytes.length / CHUNK), parts = [];
    for (let i = 0; i < count; i++) {
      const plain = bytes.subarray(i * CHUNK, Math.min(bytes.length, (i + 1) * CHUNK));
      parts.push(new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: fileNonce(salt, i), additionalData: fileAAD(conv, i, count) }, k, plain)));
    }
    const cipher = cat(...parts);
    return { cipher, chunk: CHUNK + TAG, sha256: hex(await sha256(cipher)), meta: { v: 1, k: b64(key), s: b64(salt), size: bytes.length, count, chunk: CHUNK + TAG, sha256: hex(await sha256(cipher)) } };
  }

  async function decryptFile(conv, meta, cipher) {
    if (!meta || meta.v !== 1) throw new ChatCryptoError('bad_meta');
    if (hex(await sha256(cipher)) !== meta.sha256) throw new ChatCryptoError('corrupt', 'the downloaded bytes are not what was sent');
    const k = await aesKey(unb64(meta.k), ['decrypt']), salt = unb64(meta.s), out = new Uint8Array(meta.size);
    let pos = 0;
    for (let i = 0; i < meta.count; i++) {
      const part = cipher.subarray(i * meta.chunk, Math.min(cipher.length, (i + 1) * meta.chunk));
      let plain;
      try { plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fileNonce(salt, i), additionalData: fileAAD(conv, i, meta.count) }, k, part)); }
      catch (e) { throw new ChatCryptoError('forged', 'a part of the file was altered, moved or cut'); }
      if (pos + plain.length > out.length) throw new ChatCryptoError('forged');
      out.set(plain, pos); pos += plain.length;
    }
    if (pos !== meta.size) throw new ChatCryptoError('forged', 'the file is the wrong length');
    return out;
  }

  /* Upload with the service's HTTP API. `api` is {base, headers()}: headers()
   * returns {Authorization: 'Bearer …'}. Resumes: parts the service already has
   * are skipped. Returns the file id; put it, with enc.meta, in the message. */
  async function uploadFile(api, conv, enc, opts) {
    const f = opts && opts.fetch || fetch, h = () => Object.assign({}, api.headers());
    const call = async (method, path, body, raw) => {
      const r = await f(api.base + path, { method, headers: Object.assign(h(), raw ? {} : { 'Content-Type': 'application/json' }), body: raw ? body : (body === undefined ? undefined : JSON.stringify(body)) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new ChatCryptoError((j.error && j.error.code) || 'http_' + r.status);
      return j;
    };
    let id = opts && opts.resume;
    if (!id) id = (await call('POST', '/v1/files', { conv, size: enc.cipher.length, sha256: enc.sha256, chunk: enc.chunk })).file.id;
    const have = new Set((await call('GET', '/v1/files/' + id)).have || []);
    const count = Math.ceil(enc.cipher.length / enc.chunk);
    for (let n = 0; n < count; n++) {
      if (have.has(n)) continue;
      await call('PUT', '/v1/files/' + id + '/parts/' + n, enc.cipher.subarray(n * enc.chunk, Math.min(enc.cipher.length, (n + 1) * enc.chunk)), true);
      if (opts && opts.onProgress) opts.onProgress((n + 1) / count);
    }
    await call('POST', '/v1/files/' + id + '/complete', {});
    return id;
  }

  async function downloadFile(api, conv, id, meta, opts) {
    const f = opts && opts.fetch || fetch;
    const r = await f(api.base + '/v1/files/' + id + '/blob', { headers: api.headers() });
    if (!r.ok) throw new ChatCryptoError('http_' + r.status);
    return decryptFile(conv, meta, new Uint8Array(await r.arrayBuffer()));
  }

  // ---- keys --------------------------------------------------------------

  async function newIdentity() {
    const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return { privateKey: kp.privateKey, publicRaw: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
  }

  async function wrapKey(myPrivate, myPublicRaw, theirPublicRaw, conv, key) {
    const k = await wrapKeyFor(myPrivate, theirPublicRaw, myPublicRaw, theirPublicRaw, conv, ['encrypt']);
    const nonce = rnd(12);
    return 'k1.' + b64(cat(nonce, new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: te.encode('rtcd-key\0' + conv) }, k, key))));
  }

  async function unwrapKey(myPrivate, myPublicRaw, theirPublicRaw, conv, wrapped) {
    if (typeof wrapped !== 'string' || !wrapped.startsWith('k1.')) throw new ChatCryptoError('bad_key');
    const raw = unb64(wrapped.slice(3));
    const k = await wrapKeyFor(myPrivate, theirPublicRaw, theirPublicRaw, myPublicRaw, conv, ['decrypt']);
    try { return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: te.encode('rtcd-key\0' + conv) }, k, raw.slice(12))); }
    catch (e) { throw new ChatCryptoError('forged', 'the key was not wrapped for you by that member'); }
  }

  // The HKDF salt is sender-public | recipient-public, in that order on both sides.
  async function wrapKeyFor(myPrivate, theirPublicRaw, senderPub, recipientPub, conv, use) {
    const their = await subtle.importKey('raw', theirPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const bits = await subtle.deriveBits({ name: 'ECDH', public: their }, myPrivate, 256);
    const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: cat(senderPub, recipientPub), info: te.encode('rtcd-key-wrap\0' + conv) }, hk, { name: 'AES-GCM', length: 256 }, false, use);
  }

  const epochTag = (conv, epoch) => conv + '\0' + epoch;

  async function wrapEpochKey(myPrivate, myPublicRaw, theirPublicRaw, conv, epoch, key) {
    const k = await wrapKeyFor(myPrivate, theirPublicRaw, myPublicRaw, theirPublicRaw, epochTag(conv, epoch), ['encrypt']);
    const nonce = rnd(12);
    return 'k2.' + b64(cat(nonce, new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: te.encode('rtcd-key\0' + epochTag(conv, epoch)) }, k, key))));
  }

  async function unwrapEpochKey(myPrivate, myPublicRaw, theirPublicRaw, conv, epoch, wrapped) {
    if (typeof wrapped !== 'string' || !wrapped.startsWith('k2.')) throw new ChatCryptoError('bad_wrap');
    const raw = unb64(wrapped.slice(3));
    const k = await wrapKeyFor(myPrivate, theirPublicRaw, theirPublicRaw, myPublicRaw, epochTag(conv, epoch), ['decrypt']);
    try { return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: te.encode('rtcd-key\0' + epochTag(conv, epoch)) }, k, raw.slice(12))); }
    catch (e) { throw new ChatCryptoError('forged', 'the key was not made for this device, conversation and epoch'); }
  }

  // A device identity is a P-256 key pair. These turn it into text to keep in secure storage.
  async function exportIdentity(id) {
    return JSON.stringify({ v: 1, pkcs8: b64(new Uint8Array(await subtle.exportKey('pkcs8', id.privateKey))), pub: b64(id.publicRaw) });
  }
  async function importIdentity(text) {
    const j = JSON.parse(text);
    if (j.v !== 1) throw new ChatCryptoError('bad_identity');
    const privateKey = await subtle.importKey('pkcs8', unb64(j.pkcs8), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return { privateKey, publicRaw: unb64(j.pub) };
  }

  // ---- large files, one chunk at a time ----------------------------------

  /* Incremental SHA-256 (WebCrypto only hashes whole buffers). */
  class Sha256 {
    constructor() { this.h = Sha256.IV.slice(); this.buf = new Uint8Array(64); this.n = 0; this.len = 0; }
    update(u8) {
      this.len += u8.length;
      let i = 0;
      if (this.n) { const t = Math.min(64 - this.n, u8.length); this.buf.set(u8.subarray(0, t), this.n); this.n += t; i = t; if (this.n === 64) { this.block(this.buf, 0); this.n = 0; } }
      for (; i + 64 <= u8.length; i += 64) this.block(u8, i);
      if (i < u8.length) { this.buf.set(u8.subarray(i), 0); this.n = u8.length - i; }
      return this;
    }
    block(b, o) {
      const w = Sha256.W, K = Sha256.K, h = this.h;
      for (let i = 0; i < 16; i++) w[i] = (b[o + 4 * i] << 24 | b[o + 4 * i + 1] << 16 | b[o + 4 * i + 2] << 8 | b[o + 4 * i + 3]) | 0;
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], c = w[i - 2];
        w[i] = (w[i - 16] + ((a >>> 7 | a << 25) ^ (a >>> 18 | a << 14) ^ a >>> 3) + w[i - 7] + ((c >>> 17 | c << 15) ^ (c >>> 19 | c << 13) ^ c >>> 10)) | 0;
      }
      let [a, b1, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const t1 = (hh + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
        const t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + ((a & b1) ^ (a & c) ^ (b1 & c))) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b1; b1 = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b1) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0; h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    digest() {
      const bits = this.len * 8, pad = new Uint8Array(((this.n < 56 ? 56 : 120) - this.n) + 8);
      pad[0] = 0x80;
      const dv = new DataView(pad.buffer);
      dv.setUint32(pad.length - 8, Math.floor(bits / 4294967296)); dv.setUint32(pad.length - 4, bits >>> 0);
      this.update(pad);
      const out = new Uint8Array(32), o = new DataView(out.buffer);
      this.h.forEach((x, i) => o.setUint32(i * 4, x));
      return out;
    }
  }
  Sha256.IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19].map(x => x | 0);
  Sha256.W = new Int32Array(64);
  Sha256.K = new Int32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

  // A source is a Blob/File (anything with size and slice().arrayBuffer()) or a Uint8Array.
  const srcSize = src => src.byteLength !== undefined && src.size === undefined ? src.byteLength : src.size;
  async function srcRead(src, from, to) {
    if (src.slice && src.arrayBuffer === undefined) return src.slice(from, to); // Uint8Array
    if (src.byteLength !== undefined && src.size === undefined) return src.subarray(from, to);
    return new Uint8Array(await src.slice(from, to).arrayBuffer());
  }

  /* prepareFile(conv, source) reads the source twice, one chunk at a time, and
   * returns {meta, size, chunk, sha256, count, part(n)}: size/sha256 are of the
   * stored bytes (what file.init wants) and part(n) is stored part n. Encryption
   * is deterministic for a key and salt, so the second reading reproduces the
   * first. Memory use is about two chunks whatever the file's size. */
  async function prepareFile(conv, source) {
    const size = srcSize(source);
    if (!size) throw new ChatCryptoError('empty');
    const key = rnd(32), salt = rnd(4), k = await aesKey(key, ['encrypt']);
    const count = Math.ceil(size / CHUNK);
    const part = async n => {
      const plain = await srcRead(source, n * CHUNK, Math.min(size, (n + 1) * CHUNK));
      return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: fileNonce(salt, n), additionalData: fileAAD(conv, n, count) }, k, plain));
    };
    const h = new Sha256();
    let total = 0;
    for (let n = 0; n < count; n++) { const p = await part(n); h.update(p); total += p.length; }
    const sha = hex(h.digest());
    return { size: total, chunk: CHUNK + TAG, count, sha256: sha, part, meta: { v: 1, k: b64(key), s: b64(salt), size, count, chunk: CHUNK + TAG, sha256: sha } };
  }

  const httpCall = (api, f) => async (method, path, body, raw, extra) => {
    const r = await f(api.base + path, { method, headers: Object.assign({}, api.headers(), raw ? {} : { 'Content-Type': 'application/json' }, extra || {}), body: raw ? body : (body === undefined ? undefined : JSON.stringify(body)) });
    if (extra && extra.Range && r.ok) return r;
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new ChatCryptoError((j.error && j.error.code) || 'http_' + r.status);
    return j;
  };

  /* Uploads a prepared file part by part (resuming what the service already has)
   * and returns its id. */
  async function uploadStream(api, conv, prep, opts) {
    const call = httpCall(api, opts && opts.fetch || fetch);
    let id = opts && opts.resume;
    if (!id) id = (await call('POST', '/v1/files', { conv, size: prep.size, sha256: prep.sha256, chunk: prep.chunk })).file.id;
    const have = new Set((await call('GET', '/v1/files/' + id)).have || []);
    for (let n = 0; n < prep.count; n++) {
      if (have.has(n)) continue;
      await call('PUT', '/v1/files/' + id + '/parts/' + n, await prep.part(n), true);
      if (opts && opts.onProgress) opts.onProgress((n + 1) / prep.count);
    }
    await call('POST', '/v1/files/' + id + '/complete', {});
    return id;
  }

  /* Downloads a file a chunk at a time (Range requests) and yields the plaintext
   * chunks in order. Each chunk is checked before it is yielded; a file cut short
   * or lengthened is refused at the end. */
  async function* downloadStream(api, conv, id, meta, opts) {
    if (!meta || meta.v !== 1) throw new ChatCryptoError('bad_meta');
    const f = opts && opts.fetch || fetch, k = await aesKey(unb64(meta.k), ['decrypt']), salt = unb64(meta.s);
    let pos = 0;
    for (let i = 0; i < meta.count; i++) {
      const last = i === meta.count - 1;
      const r = await f(api.base + '/v1/files/' + id + '/blob', { headers: Object.assign({}, api.headers(), { Range: 'bytes=' + i * meta.chunk + '-' + ((i + 1) * meta.chunk - 1) }) });
      if (!r.ok) throw new ChatCryptoError('http_' + r.status);
      const part = new Uint8Array(await r.arrayBuffer());
      if (!last && part.length !== meta.chunk) throw new ChatCryptoError('forged', 'a part of the file is the wrong length');
      let plain;
      try { plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fileNonce(salt, i), additionalData: fileAAD(conv, i, meta.count) }, k, part)); }
      catch (e) { throw new ChatCryptoError('forged', 'a part of the file was altered, moved or cut'); }
      pos += plain.length;
      yield plain;
    }
    if (pos !== meta.size) throw new ChatCryptoError('forged', 'the file is the wrong length');
  }

  // Twelve groups of five digits; members compare them out of band.
  async function safetyCode(publicRaws) {
    const sorted = publicRaws.map(hex).sort();
    const d = await sha256(te.encode(sorted.join('\n')));
    const out = [];
    for (let i = 0; i < 12; i++) out.push(String((d[i * 2] << 8 | d[i * 2 + 1]) % 100000).padStart(5, '0'));
    return out.join(' ');
  }

  return { ChatCryptoError, CHUNK, MAX_INLINE, newKey, encryptMessage, decryptMessage, encryptFile, decryptFile, uploadFile, downloadFile, newIdentity, wrapKey, unwrapKey, safetyCode, b64, unb64,
    wrapEpochKey, unwrapEpochKey, exportIdentity, importIdentity, Sha256, prepareFile, uploadStream, downloadStream, hex };
});

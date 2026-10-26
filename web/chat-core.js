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
 * What is not hidden: who talks to whom, when, and the sizes.
 * Files are held in memory (up to the service's max_file_bytes, 256 MiB by default).
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

  // Twelve groups of five digits; members compare them out of band.
  async function safetyCode(publicRaws) {
    const sorted = publicRaws.map(hex).sort();
    const d = await sha256(te.encode(sorted.join('\n')));
    const out = [];
    for (let i = 0; i < 12; i++) out.push(String((d[i * 2] << 8 | d[i * 2 + 1]) % 100000).padStart(5, '0'));
    return out.join(' ');
  }

  return { ChatCryptoError, CHUNK, MAX_INLINE, newKey, encryptMessage, decryptMessage, encryptFile, decryptFile, uploadFile, downloadFile, newIdentity, wrapKey, unwrapKey, safetyCode, b64, unb64 };
});

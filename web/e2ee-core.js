/* End-to-end encryption for calls.
 *
 * What it guarantees: the server (the SFU, the hub, the database, anyone on the
 * network path) relays media and key messages it cannot read, alter or forge.
 * Only the people in the call hold the keys.
 *
 * What it does not hide: who is in a call and when, how much they send, the
 * loudness of their microphone (the SFU uses it to name the speaker), and
 * anything a participant's own device is made to reveal.
 *
 * Media. Each sender encrypts every encoded frame with AES-128-GCM under a key
 * only the call's members have, and leaves a few leading bytes in the clear so
 * the SFU can still tell a keyframe from a delta frame and switch layers:
 *
 *     frame = clear prefix | header (8) | ciphertext | tag (16)
 *     header = 0xE2 | key id | counter (u32 BE) | 0 0
 *     nonce  = per-key salt xor counter
 *     AAD    = clear prefix | header | sender tag
 *
 * The sender tag binds a frame to the person who made it, so the server cannot
 * replay one person's frames as another's. A counter window rejects replays.
 *
 * Keys. Every member makes a random sender key and sends it to each other
 * member wrapped for them alone: ECDH over throwaway P-256 keys, signed by the
 * sender's long-term identity key. The keys change whenever someone joins or
 * leaves, so a person who leaves cannot read what comes after and one who joins
 * cannot read what came before. A safety code (a hash of everyone's identity
 * keys) lets members confirm, over another channel, that the server did not
 * swap keys.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('node:crypto').webcrypto);
  else root.E2EE = factory(root.crypto);
})(typeof self !== 'undefined' ? self : this, function (crypto) {
  'use strict';
  const subtle = crypto.subtle;
  const te = new TextEncoder(), td = new TextDecoder();
  const MAGIC = 0xE2, HEADER = 8, TAG = 16;

  class E2EEError extends Error { constructor(code, msg) { super(msg || code); this.code = code; } }

  // ---- bytes -------------------------------------------------------------------
  const b64 = u8 => { let s = ''; for (const c of u8) s += String.fromCharCode(c); return (typeof btoa === 'function' ? btoa(s) : Buffer.from(u8).toString('base64')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const unb64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; if (typeof atob === 'function') { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; } return new Uint8Array(Buffer.from(s, 'base64')); };
  const cat = (...parts) => { const n = parts.reduce((a, p) => a + p.length, 0); const out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
  const rand = n => crypto.getRandomValues(new Uint8Array(n));
  const sha256 = async data => new Uint8Array(await subtle.digest('SHA-256', typeof data === 'string' ? te.encode(data) : data));
  const eq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; };

  async function hkdf(secret, salt, info, bytes) {
    const k = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) }, k, bytes * 8));
  }

  // ---- media keys ----------------------------------------------------------------
  /** A sender key: 32 secret bytes, expanded to an AES-128 key and a nonce salt. */
  async function expand(secret) {
    const key = await subtle.importKey('raw', await hkdf(secret, new Uint8Array(0), 'rtc-e2ee/v1/media-key', 16), 'AES-GCM', false, ['encrypt', 'decrypt']);
    const salt = await hkdf(secret, new Uint8Array(0), 'rtc-e2ee/v1/media-salt', 12);
    return { key, salt };
  }

  /** How many leading bytes of an encoded frame the SFU must be able to read. */
  function clearPrefix(kind, codec, isKey) {
    if (kind === 'audio') return 1;                          // the Opus TOC byte
    if (/vp8/i.test(codec || '')) return isKey ? 10 : 3;     // the VP8 frame tag (and keyframe size), which the SFU reads to find keyframes
    return 0;                                                // VP9: its descriptor is outside the frame, so nothing needs to stay clear
  }

  const MAX_KEYS_PER_SENDER = 4;
  const WINDOW = 64n, FULL = (1n << 64n) - 1n;

  class KeyRing {
    constructor(selfId) { this.selfId = selfId; this.own = null; this.peers = new Map(); this.tags = new Map(); }
    async tag(id) { let t = this.tags.get(id); if (!t) { t = (await sha256('rtc-e2ee/sender|' + id)).slice(0, 8); this.tags.set(id, t); } return t; }
    /** Install this participant's own sending key. kid is 1..255. */
    async setOwn(kid, secret) { this.own = { kid, ...(await expand(secret)), counter: 0 }; }
    async setPeer(id, kid, secret) {
      let m = this.peers.get(id); if (!m) { m = new Map(); this.peers.set(id, m); }
      m.set(kid, { ...(await expand(secret)), max: -1n, mask: 0n, at: Date.now() });
      while (m.size > MAX_KEYS_PER_SENDER) { const oldest = [...m.entries()].sort((a, b) => a[1].at - b[1].at)[0][0]; m.delete(oldest); }
    }
    dropPeer(id) { this.peers.delete(id); }
    hasPeer(id) { return this.peers.has(id) && this.peers.get(id).size > 0; }
    peerKey(id, kid) { const m = this.peers.get(id); return m && m.get(kid); }
  }

  /** Encrypt one encoded frame. isKey and codec decide the clear prefix. */
  async function encryptFrame(ring, kind, codec, isKey, frame) {
    const own = ring.own;
    if (!own) throw new E2EEError('nokey', 'no sending key yet');
    if (own.counter >= 0x7FFFFFFF) throw new E2EEError('exhausted', 'sending key used up; rotate');
    const ctr = own.counter++;
    const prefix = clearPrefix(kind, codec, isKey);
    if (frame.length < prefix) throw new E2EEError('malformed', 'a frame shorter than its clear prefix');
    const header = new Uint8Array([MAGIC, own.kid, ctr >>> 24 & 255, ctr >>> 16 & 255, ctr >>> 8 & 255, ctr & 255, 0, 0]);
    const iv = own.salt.slice(); iv[8] ^= header[2]; iv[9] ^= header[3]; iv[10] ^= header[4]; iv[11] ^= header[5];
    const aad = cat(frame.subarray(0, prefix), header, await ring.tag(ring.selfId));
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, own.key, frame.subarray(prefix)));
    return cat(frame.subarray(0, prefix), header, ct);
  }

  /** Decrypt one frame from sender. Throws E2EEError: malformed, nokey, replay, tampered. */
  async function decryptFrame(ring, sender, kind, codec, isKey, data) {
    const prefix = clearPrefix(kind, codec, isKey);
    if (data.length < prefix + HEADER + TAG) throw new E2EEError('malformed', 'too short to be an encrypted frame');
    const header = data.subarray(prefix, prefix + HEADER);
    if (header[0] !== MAGIC) throw new E2EEError('malformed', 'not an end-to-end encrypted frame');
    const kid = header[1];
    const ctr = BigInt((header[2] << 24 | header[3] << 16 | header[4] << 8 | header[5]) >>> 0);
    const k = ring.peerKey(sender, kid);
    if (!k) throw new E2EEError('nokey', 'no key ' + kid + ' from ' + sender);
    // Replay: refuse a counter already seen or too far behind, but only record it once the frame authenticates.
    if (k.max >= 0n && ctr <= k.max && (k.max - ctr >= WINDOW || (k.mask >> (k.max - ctr)) & 1n)) throw new E2EEError('replay', 'counter ' + ctr + ' already seen');
    const iv = k.salt.slice(); iv[8] ^= header[2]; iv[9] ^= header[3]; iv[10] ^= header[4]; iv[11] ^= header[5];
    const aad = cat(data.subarray(0, prefix), header, await ring.tag(sender));
    let plain;
    try { plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k.key, data.subarray(prefix + HEADER))); }
    catch { throw new E2EEError('tampered', 'authentication failed'); }
    if (ctr > k.max) { const shift = k.max < 0n ? 64n : ctr - k.max; k.mask = shift >= WINDOW ? 1n : ((k.mask << shift) & FULL) | 1n; k.max = ctr; }
    else k.mask |= 1n << (k.max - ctr);
    return cat(data.subarray(0, prefix), plain);
  }

  // ---- identity -------------------------------------------------------------------
  /** A long-term signing identity. The private key never leaves the device. */
  class Identity {
    constructor(userId, priv, pub, raw) { this.userId = userId; this.priv = priv; this.pub = pub; this.raw = raw; }
    static async create(userId) {
      const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      return new Identity(userId, kp.privateKey, kp.publicKey, new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));
    }
    /** Load this user's identity from a store, making one the first time. store: {get(k), set(k,v)}. */
    static async load(userId, store) {
      const saved = await store.get('identity:' + userId);
      if (saved) return new Identity(userId, saved.priv, saved.pub, new Uint8Array(saved.raw));
      const id = await Identity.create(userId);
      await store.set('identity:' + userId, { priv: id.priv, pub: id.pub, raw: Array.from(id.raw) });
      return id;
    }
    async sign(text) { return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.priv, te.encode(text))); }
    get fingerprint() { return sha256(this.raw).then(h => b64(h.slice(0, 16))); }
  }

  async function verify(pubRaw, text, sig) {
    try {
      const k = await subtle.importKey('raw', pubRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, sig, te.encode(text));
    } catch { return false; }
  }

  /** Six groups of five digits that are the same for everyone only if they hold the same identity keys. */
  async function safetyCode(members) {
    const parts = [...members].sort((a, b) => a.userId < b.userId ? -1 : 1).map(m => m.userId + ':' + b64(m.pub));
    const h = await sha256('rtc-e2ee/safety|' + parts.join('|'));
    const groups = [];
    for (let i = 0; i < 6; i++) groups.push(String(((h[i * 3] << 16 | h[i * 3 + 1] << 8 | h[i * 3 + 2]) >>> 0) % 100000).padStart(5, '0'));
    return groups.join(' ');
  }

  // ---- key exchange -----------------------------------------------------------------
  const MAX_MSG = 12 * 1024;

  /**
   * One member's side of a call's key exchange.
   *   opts.callId, opts.identity, opts.pins {get(user), set(user, fp)},
   *   opts.send(to, text) -> Promise   carries a message through the (untrusted) server,
   *   opts.onKey(user|null, kid, secret)  a key to install (null = our own),
   *   opts.onWarning({type, user}).
   */
  class Session {
    constructor(opts) {
      this.o = opts; this.callId = opts.callId; this.id = opts.identity.userId; this.identity = opts.identity;
      this.peers = new Map();   // user -> {idRaw, eph (raw), trusted}
      this.kid = 0; this.secret = null; this.eph = null; this.ephRaw = null; this.sentHello = new Set(); this.timer = null;
    }
    async start(members) {
      this.eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      this.ephRaw = new Uint8Array(await subtle.exportKey('raw', this.eph.publicKey));
      await this._newKey();
      for (const m of members) if (m !== this.id) await this._hello(m);
    }
    /** Called when the set of members changes (someone joined or left): everybody gets a fresh key. */
    async membersChanged(members) {
      const now = new Set(members);
      for (const u of [...this.peers.keys()]) if (!now.has(u)) { this.peers.delete(u); this.sentHello.delete(u); this.o.onKey && this.o.onKey(u, 0, null); }
      for (const m of members) if (m !== this.id && !this.sentHello.has(m)) await this._hello(m);
      await this._rotate(members);
    }
    async _newKey() {
      this.kid = this.kid % 255 + 1; this.secret = rand(32);
      await this.o.onKey(null, this.kid, this.secret);
    }
    async _rotate(members) {
      await this._newKey();
      for (const m of members) if (m !== this.id && this.peers.get(m)?.trusted) await this._sendKey(m);
    }
    _canon(t, ...f) { return 'rtc-e2ee/' + t + '|' + this.callId + '|' + f.join('|'); }

    async _hello(to) {
      this.sentHello.add(to);
      const n = b64(rand(16)), id = b64(this.identity.raw), e = b64(this.ephRaw);
      const sig = b64(await this.identity.sign(this._canon('hello', this.id, to, id, e, n)));
      await this.o.send(to, JSON.stringify({ v: 1, t: 'hello', c: this.callId, f: this.id, to, id, e, n, sig }));
    }

    async _wrapKey(peer) {
      const theirs = await subtle.importKey('raw', peer.eph, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      const bits = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: theirs }, this.eph.privateKey, 256));
      const ids = [this.id, peer.id].sort().join(',');
      const eph = [b64(this.ephRaw), b64(peer.eph)].sort().join(',');
      const raw = await hkdf(bits, await sha256(this.callId), 'rtc-e2ee/v1/wrap|' + ids + '|' + eph, 32);
      return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
    }

    async _sendKey(to) {
      const peer = this.peers.get(to); if (!peer || !peer.trusted) return;
      const k = await this._wrapKey(peer), iv = rand(12), kid = this.kid;
      const e = b64(this.ephRaw);
      const aad = te.encode(this._canon('key', this.id, to, kid, e));
      const ct = b64(new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, k, this.secret)));
      const sig = b64(await this.identity.sign(this._canon('key', this.id, to, kid, e, b64(iv), ct)));
      await this.o.send(to, JSON.stringify({ v: 1, t: 'key', c: this.callId, f: this.id, to, kid, e, iv: b64(iv), ct, sig }));
    }

    /** Say hello again to one member (they lost our key and are asking for it). */
    async hello(to) { if (to !== this.id) await this._hello(to); }

    /** Handle a message that arrived through the server. Never throws: a bad message is dropped. */
    async receive(from, text) {
      let m;
      try { if (typeof text !== 'string' || text.length > MAX_MSG) return; m = JSON.parse(text); } catch { return; }
      if (!m || m.v !== 1 || m.c !== this.callId || m.f !== from || m.to !== this.id) return; // addressed to us, from the sender the server says
      try {
        if (m.t === 'hello') return await this._onHello(m);
        if (m.t === 'key') return await this._onKey(m);
      } catch { /* a malformed message from a misbehaving peer or server is ignored */ }
    }

    async _onHello(m) {
      const idRaw = unb64(m.id), ephRaw = unb64(m.e);
      if (idRaw.length !== 65 || ephRaw.length !== 65) return;
      if (!await verify(idRaw, this._canon('hello', m.f, m.to, m.id, m.e, m.n), unb64(m.sig))) return;
      // Pin the identity the first time we see it; a different key later is refused.
      const fp = b64((await sha256(idRaw)).slice(0, 16));
      const pinned = await this.o.pins.get(m.f);
      if (pinned && pinned !== fp) { this.peers.set(m.f, { id: m.f, idRaw, eph: ephRaw, trusted: false }); this.o.onWarning && this.o.onWarning({ type: 'identity-changed', user: m.f }); return; }
      if (!pinned) await this.o.pins.set(m.f, fp);
      const prev = this.peers.get(m.f);
      this.peers.set(m.f, { id: m.f, idRaw, eph: ephRaw, trusted: true });
      if (!this.sentHello.has(m.f)) await this._hello(m.f);
      if (!prev || !eq(prev.eph, ephRaw)) await this._sendKey(m.f); // they have just arrived or restarted: give them our key
      else await this._sendKey(m.f);
    }

    async _onKey(m) {
      const peer = this.peers.get(m.f);
      if (!peer || !peer.trusted) return;                       // keys only from people we have authenticated
      if (b64(peer.eph) !== m.e) return;                         // must use the ephemeral key they said hello with
      if (!await verify(peer.idRaw, this._canon('key', m.f, m.to, m.kid, m.e, m.iv, m.ct), unb64(m.sig))) return;
      const k = await this._wrapKey(peer);
      const aad = te.encode(this._canon('key', m.f, m.to, m.kid, m.e));
      let secret;
      try { secret = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(m.iv), additionalData: aad }, k, unb64(m.ct))); } catch { return; }
      if (secret.length !== 32 || !(m.kid >= 1 && m.kid <= 255)) return;
      await this.o.onKey(m.f, m.kid, secret);
    }

    /** Everyone's identity keys, for the safety code. */
    members() {
      const out = [{ userId: this.id, pub: this.identity.raw }];
      for (const [u, p] of this.peers) if (p.trusted) out.push({ userId: u, pub: p.idRaw });
      return out;
    }
    safetyCode() { return safetyCode(this.members()); }
    untrusted() { return [...this.peers.entries()].filter(([, p]) => !p.trusted).map(([u]) => u); }
  }

  // ---- p2p: authenticate the connection itself ---------------------------------------
  // A p2p call is already encrypted end to end by DTLS-SRTP between the two
  // browsers. What the server could still do is swap the certificate fingerprints
  // in the session descriptions it relays and sit in the middle. Each side signs
  // the fingerprints it sends with its identity key, and the other verifies them.
  const fingerprints = sdp => (sdp.match(/^a=fingerprint:.*$/gm) || []).map(s => s.trim()).sort().join('\n');

  async function signSDP(identity, callId, sdp) {
    const fp = fingerprints(sdp);
    if (!fp) throw new E2EEError('nofingerprint', 'the description has no certificate fingerprint');
    return { id: b64(identity.raw), sig: b64(await identity.sign('rtc-e2ee/sdp|' + callId + '|' + identity.userId + '|' + fp)) };
  }

  /** Verify a peer's signed fingerprints; pins their identity the first time. Returns their identity key. */
  async function verifySDP(from, callId, sdp, proof, pins) {
    if (!proof || !proof.id || !proof.sig) throw new E2EEError('unsigned', 'the connection is not authenticated');
    const idRaw = unb64(proof.id), fp = fingerprints(sdp);
    if (!fp || !await verify(idRaw, 'rtc-e2ee/sdp|' + callId + '|' + from + '|' + fp, unb64(proof.sig))) throw new E2EEError('badsignature', 'the connection\'s certificate does not match what ' + from + ' signed');
    const printed = b64((await sha256(idRaw)).slice(0, 16)), pinned = await pins.get(from);
    if (pinned && pinned !== printed) throw new E2EEError('identity-changed', from + '\'s identity key has changed');
    if (!pinned) await pins.set(from, printed);
    return idRaw;
  }

  return { E2EEError, b64, unb64, KeyRing, encryptFrame, decryptFrame, clearPrefix, Identity, Session, safetyCode, signSDP, verifySDP, verify, sha256, HEADER, TAG };
});

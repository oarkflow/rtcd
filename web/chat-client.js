/* ChatClient: end-to-end encrypted conversations over rtcd's key directory.
 *
 * It does the protocol the service's key operations are for, and nothing else.
 * It does not open a connection: you give it `call(op, payload)`, which sends
 * one request over whatever connection you have (a WebSocket, or HTTP with a
 * user's token) and resolves with the answer or rejects with an error that has
 * a `code`. Feed it the service's events with `handleEvent(name, payload)`.
 *
 *   const chat = new ChatClient({
 *     call, user: 'ada', device: 'phone-1', identity,           // identity: ChatCrypto.newIdentity()
 *     cert: signedByMyIdentityKey,                               // published with the key
 *     verifyDevice: async d => myDirectoryAgrees(d),             // REQUIRED, see below
 *     store,                                                     // optional: {get(conv, epoch), set(conv, epoch, key)}
 *   });
 *   await chat.start();
 *   await chat.send(conv, 'hello');
 *   const text = await chat.open(conv, message);               // message: an item of msg.history or a msg.new event
 *
 * verifyDevice({user, device, pub, cert}) is how you stop the service giving
 * you someone else's key: check `cert` against what your own system vouches for
 * (for Aura, the device certificate signed by the person's identity key).
 * A key it rejects is never wrapped for, and a wrap made by a device it rejects
 * is never opened. There is no default; pass `insecureTrustService: true` to
 * accept the service's word, knowing a compromised service could then read
 * what you send.
 *
 * Who makes keys. Whoever notices one is needed makes it: the first message in
 * a conversation, and the first one after someone left (the service refuses
 * messages until a member has made a new epoch, so some online member always
 * does). Whoever has the current key gives it to new members' and new devices'
 * devices (`grant`), usually when told of them by an event. A device that
 * joined later cannot read what was sent before its epoch unless a member
 * passes it the older keys (`grant(conv, {history: true})`).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./chat-core.js'));
  else root.ChatClient = factory(root.ChatCrypto);
})(typeof self !== 'undefined' ? self : this, function (C) {
  'use strict';

  const memoryStore = () => {
    const m = new Map();
    return { get: async (c, e) => m.get(c + '\0' + e) || null, set: async (c, e, k) => { m.set(c + '\0' + e, k); }, all: async c => [...m.keys()].filter(k => k.startsWith(c + '\0')).map(k => +k.slice(c.length + 1)) };
  };
  const rid = () => C.hex(crypto.getRandomValues(new Uint8Array(12)));
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  class ChatClient {
    constructor(o) {
      if (!o || typeof o.call !== 'function' || !o.user || !o.device || !o.identity) throw new Error('ChatClient needs call, user, device and identity');
      if (typeof o.verifyDevice !== 'function' && !o.insecureTrustService) throw new Error('ChatClient needs verifyDevice (or insecureTrustService: true)');
      Object.assign(this, { callOp: o.call, user: o.user, device: o.device, identity: o.identity, cert: o.cert || '', api: o.api });
      this.verify = o.verifyDevice || (async () => true);
      this.store = o.store || memoryStore();
      this.known = new Set();      // conversations this client has used
      this.events = o.onEvent || (() => {});
      this.rotating = new Map();   // conv -> promise, so two triggers make one rotation
      this.jitter = o.jitterMs === undefined ? 400 : o.jitterMs;
    }

    call(op, payload) { return this.callOp(op, payload); }

    /* Publishes this device's key. Safe to call at every start. */
    async start() {
      await this.call('key.publish', { device: this.device, pub: C.b64(this.identity.publicRaw), cert: this.cert });
    }

    pubB64() { return C.b64(this.identity.publicRaw); }

    async trusted(d) {
      try { return !!(await this.verify({ user: d.user, device: d.device, pub: d.pub, cert: d.cert || '' })); } catch (e) { return false; }
    }

    /* Fetches and opens the keys made for this device. Returns the service's
     * view: {epoch, rekey_required}. */
    async sync(conv) {
      this.known.add(conv);
      const r = await this.call('epoch.get', { conv, device: this.device, since: 0 });
      for (const w of r.wraps || []) {
        if (await this.store.get(conv, w.epoch)) continue;
        if (!(await this.trusted({ user: w.by, device: w.by_device, pub: w.by_pub, cert: w.by_cert })) || w.by_revoked) continue;
        try {
          const key = await C.unwrapEpochKey(this.identity.privateKey, this.identity.publicRaw, C.unb64(w.by_pub), conv, w.epoch, w.w);
          await this.store.set(conv, w.epoch, key);
        } catch (e) { /* not for us, or forged: ignore it */ }
      }
      return { epoch: r.epoch, rekey_required: r.rekey_required };
    }

    /* Makes the next epoch: a new key, wrapped for every trusted device of every member. */
    rotate(conv) {
      if (this.rotating.has(conv)) return this.rotating.get(conv);
      const p = this._rotate(conv).finally(() => this.rotating.delete(conv));
      this.rotating.set(conv, p);
      return p;
    }

    async _rotate(conv) {
      this.known.add(conv);
      const st = await this.sync(conv);
      if (st.epoch > 0 && !st.rekey_required && await this.store.get(conv, st.epoch)) return st.epoch; // someone else already did
      const devs = (await this.call('key.list', { conv })).devices || [];
      const ok = [];
      for (const d of devs) if (await this.trusted(d)) ok.push(d);
      const epoch = st.epoch + 1, key = C.newKey();
      const wraps = [];
      for (const d of ok) wraps.push({ user: d.user, device: d.device, w: await C.wrapEpochKey(this.identity.privateKey, this.identity.publicRaw, C.unb64(d.pub), conv, epoch, key) });
      try {
        await this.call('epoch.rotate', { conv, device: this.device, epoch, wraps });
      } catch (e) {
        if (e.code === 'stale_epoch') return (await this.sync(conv)).epoch; // lost the race: use the winner's
        throw e;
      }
      await this.store.set(conv, epoch, key);
      return epoch;
    }

    /* Makes sure a key for the current epoch is held, making a new epoch if one
     * is needed. Rejects with code 'awaiting_key' when the conversation has a key
     * this device has not been given yet (wait for an 'epoch.granted' event). */
    async ensure(conv) {
      let st = await this.sync(conv);
      if (st.epoch === 0 || st.rekey_required) { await this.rotate(conv); st = await this.sync(conv); }
      const key = await this.store.get(conv, st.epoch);
      if (!key) { const e = new Error('this device has no key for epoch ' + st.epoch + ' yet'); e.code = 'awaiting_key'; throw e; }
      return { epoch: st.epoch, key };
    }

    /* Gives the devices that lack the current key (new members, new devices) a
     * wrap of it. With {history: true} also the older keys this device holds. */
    async grant(conv, opts) {
      const m = await this.call('epoch.missing', { conv });
      if (!m.devices || !m.devices.length || !m.epoch) return 0;
      const key = await this.store.get(conv, m.epoch);
      if (!key) return 0;
      const epochs = [m.epoch];
      if (opts && opts.history) for (const e of await (this.store.all ? this.store.all(conv) : [])) if (e < m.epoch) epochs.push(e);
      let added = 0;
      for (const epoch of epochs) {
        const k = await this.store.get(conv, epoch);
        const wraps = [];
        for (const d of m.devices) if (await this.trusted(d)) wraps.push({ user: d.user, device: d.device, w: await C.wrapEpochKey(this.identity.privateKey, this.identity.publicRaw, C.unb64(d.pub), conv, epoch, k) });
        if (wraps.length) added += (await this.call('epoch.grant', { conv, device: this.device, epoch, wraps })).added;
      }
      return added;
    }

    /* Encrypts and sends. Retries with a fresh key when the epoch moved under it. */
    async send(conv, text, opts) {
      const id = (opts && opts.id) || rid();
      for (let attempt = 0; ; attempt++) {
        const { epoch, key } = await this.ensure(conv);
        const body = await C.encryptMessage(key, { conv, sender: this.user, id }, text);
        try {
          const r = await this.call('msg.send', { conv, id, body, epoch, ttl: opts && opts.ttl || 0 });
          return Object.assign({ id, epoch }, r);
        } catch (e) {
          if ((e.code === 'stale_epoch' || e.code === 'rekey_required') && attempt < 3) continue;
          throw e;
        }
      }
    }

    /* Decrypts a message from msg.history or a msg.new event; null for a deleted one. */
    async open(conv, m) {
      if (m.deleted) return null;
      let key = await this.store.get(conv, m.epoch || 0);
      if (!key && m.epoch) { await this.sync(conv); key = await this.store.get(conv, m.epoch); }
      if (!key) { const e = new Error('no key for epoch ' + m.epoch); e.code = 'no_key'; throw e; }
      return C.decryptMessage(key, { conv, sender: m.sender, id: m.id }, m.body);
    }

    /* Encrypts a file in chunks and uploads it. Returns {file, meta}: put that,
     * with whatever else your message format wants, inside an encrypted message. */
    async attach(conv, source, opts) {
      if (!this.api) throw new Error('attachments need the api option: {base, headers()}');
      const prep = await C.prepareFile(conv, source);
      const file = await C.uploadStream(this.api, conv, prep, opts);
      return { file, meta: prep.meta };
    }

    /* Yields a file's plaintext, chunk by chunk. */
    fetchAttachment(conv, d, opts) { return C.downloadStream(this.api, conv, d.file, d.meta, opts); }

    /* Feed it every event from the service. Returns a promise when it acted. */
    async handleEvent(name, p) {
      try {
        switch (name) {
          case 'epoch.new': case 'epoch.granted': if (p && p.conv) return await this.sync(p.conv); break;
          case 'conv.rekey':
            if (this.jitter) await sleep(Math.random() * this.jitter); // let one member's rotation land first
            return await this.rotate(p.conv);
          case 'conv.added': case 'conv.members': case 'group.added': case 'group.members_added': { // group.* : a group a user made
            const conv = p.conv || p.group;
            if (this.jitter) await sleep(Math.random() * this.jitter);
            await this.sync(conv);
            return await this.grant(conv);
          }
          case 'key.added': case 'key.revoked': {
            if (name === 'key.revoked') break; // the service sends conv.rekey for what must change
            if (this.jitter) await sleep(Math.random() * this.jitter);
            let n = 0;
            for (const c of this.known) n += await this.grant(c);
            return n;
          }
        }
      } catch (e) { this.events('error', e); }
    }
  }

  return ChatClient;
});

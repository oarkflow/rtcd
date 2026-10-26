/* chat.js: end-to-end encrypted group chat on top of rtcd.
 *
 * The service stores and forwards messages it cannot read. Everything it sees
 * of the encryption is a message body:
 *
 *   pub1.<json>        "this is my public key" (sent once per person per group)
 *   key1.<json>        a conversation key, wrapped for one member
 *   e<epoch>:m1.<..>   a chat message sealed with that epoch's key
 *
 * Keys are made by the group's owner, handed to each member wrapped for them
 * alone (ECDH P-256), and replaced (a new epoch) when someone is removed, so a
 * removed member cannot read what comes after. The first public key seen for a
 * person is pinned in this browser; a different one later is refused and shown
 * as a warning. The safety code lets members confirm out of band that the server
 * did not swap a key at the very start.
 */
(function () {
  'use strict';
  const { idb, Emitter } = RTC;
  const C = ChatCrypto;
  const te = new TextEncoder(), td = new TextDecoder();
  const jb = o => C.b64(te.encode(JSON.stringify(o)));
  const bj = s => JSON.parse(td.decode(C.unb64(s)));
  const fp = async b64s => C.b64(new Uint8Array(await crypto.subtle.digest('SHA-256', C.unb64(b64s)))).slice(0, 10);
  const rid = () => C.b64(crypto.getRandomValues(new Uint8Array(12)));

  class Chat extends Emitter {
    constructor(rtc) {
      super();
      this.rtc = rtc; this.me = rtc.user; this.convs = new Map(); this.identity = null; this.active = null;
    }

    async init() {
      const saved = await idb.get('id:' + this.me);
      if (saved) this.identity = { privateKey: saved.privateKey, publicRaw: new Uint8Array(saved.publicRaw) };
      else {
        const id = await C.newIdentity();
        this.identity = id;
        await idb.set('id:' + this.me, { privateKey: id.privateKey, publicRaw: Array.from(id.publicRaw) });
      }
      this.pubB64 = C.b64(this.identity.publicRaw);
      this.rtc.on('msg.new', m => this._live(m));
      this.rtc.on('msg.deleted', p => { const c = this.convs.get(p.conv); if (!c) return; const it = c.bySeq.get(p.seq); if (it) { it.deleted = true; it.content = null; this.emit('change', c); } });
      this.rtc.on('msg.read', (p, from) => { const c = this.convs.get(p.conv); if (c) { c.reads.set(from, p.seq); this.emit('change', c); } });
      for (const ev of ['group.added', 'group.removed', 'group.updated', 'group.members_added', 'group.members_removed', 'group.deleted', 'group.role', 'group.owner'])
        this.rtc.on(ev, p => this._groupChanged(ev, p));
    }

    // ---- conversations (groups) ------------------------------------------------
    async refresh() {
      const { groups } = await this.rtc.call('group.list');
      const ids = new Set();
      for (const g of groups) {
        ids.add(g.id);
        let c = this.convs.get(g.id);
        if (!c) this.convs.set(g.id, c = this._new(g.id));
        await this._meta(c, g);
      }
      for (const id of [...this.convs.keys()]) if (!ids.has(id)) { this.convs.delete(id); if (this.active === id) this.active = null; }
      this.emit('list');
      return [...this.convs.values()];
    }

    _new(id) {
      return { id, name: id, owner: '', members: [], keys: new Map(), epoch: 0, pubs: new Map(), keyed: new Set(), items: [], byKey: new Map(), bySeq: new Map(),
        lastSeq: 0, loaded: false, unread: 0, reads: new Map(), warnings: new Set(), pendingPubs: new Map(), inflight: new Set(), loading: null, readSent: 0 };
    }

    async _meta(c, g) {
      if (!g.members || !g.members.length) g = await this.rtc.call('group.get', { group: c.id });
      c.name = g.name; c.owner = g.owner; c.members = g.members.map(m => ({ user: m.user, role: m.role }));
    }

    async _groupChanged(ev, p) {
      const c = this.convs.get(p.group);
      try {
        await this.refresh();
        const now = this.convs.get(p.group);
        if (now && now.loaded) { await this._announce(now); await this._distribute(now); }
        this.emit('group', ev, p);
      } catch (e) { console.warn(ev, e); }
      return c;
    }

    async create(name, members) {
      const g = await this.rtc.call('group.create', { name, members });
      await this.refresh();
      return g.id;
    }
    async remove(conv, user) {
      await this.rtc.call('group.remove', { group: conv.id, users: [user] });
      await this.refresh();
      await this._rotate(this.convs.get(conv.id));
    }
    /** Accept the key a person is now using (after comparing safety codes), and give it the group's key. */
    async trust(c, user) {
      const pub = c.pendingPubs.get(user);
      if (!pub) return;
      await idb.set('pin:' + this.me + ':' + user, pub);
      c.pubs.set(user, pub); c.pendingPubs.delete(user); c.warnings.delete(user);
      await this._distribute(c);
      this.emit('change', c);
    }
    async add(conv, users) { await this.rtc.call('group.add', { group: conv.id, users }); await this.refresh(); }

    // ---- loading a conversation ------------------------------------------------
    open(id) {
      const c = this.convs.get(id);
      if (!c) return Promise.resolve(null);
      this.active = id; c.unread = 0;
      if (!c.loading) c.loading = this._load(c).finally(() => { c.loading = null; });
      return c.loading.then(() => c);
    }

    async _load(c) {
      // Keys and public keys are found in the history, so all of it is read.
      for (const k of await this._storedKeys(c)) c.keys.set(k.epoch, k.key);
      c.epoch = Math.max(0, ...c.keys.keys());
      const got = [];
      let before = Number.MAX_SAFE_INTEGER;
      if (c.lastSeq) { const { messages } = await this.rtc.call('msg.history', { conv: c.id, after: c.lastSeq, limit: 100 }); got.push(...messages.reverse()); }
      else for (;;) {
        const { messages } = await this.rtc.call('msg.history', { conv: c.id, before, limit: 100 });
        got.push(...messages);
        if (messages.length < 100 || got.length >= 5000) break;
        before = messages[messages.length - 1].seq;
      }
      got.reverse();
      c.latestPub = new Map();
      for (const m of got) if (m.body.startsWith('pub1.')) c.latestPub.set(m.sender, m.seq);
      for (const m of got) await this._process(c, m, true);
      c.loaded = true;
      await this._ready(c);
      this.emit('change', c);
    }

    async _ready(c) {
      // The owner makes the first key. An owner who has lost theirs (cleared storage, another
      // device) starts a new one: what was sealed with the old key stays unreadable.
      if (!c.keys.size && c.owner === this.me) await this._newEpoch(c, (c.maxEpoch || 0) + 1);
      await this._announce(c);
      await this._distribute(c);
    }

    async _storedKeys(c) {
      const list = (await idb.get('ckeys:' + this.me + ':' + c.id)) || [];
      return list.map(k => ({ epoch: k.epoch, key: new Uint8Array(k.key) }));
    }
    async _saveKeys(c) {
      await idb.set('ckeys:' + this.me + ':' + c.id, [...c.keys].map(([epoch, key]) => ({ epoch, key: Array.from(key) })));
    }
    async _newEpoch(c, epoch) {
      c.keys.set(epoch, C.newKey()); c.epoch = Math.max(c.epoch, epoch); c.maxEpoch = Math.max(c.maxEpoch || 0, epoch);
      await this._saveKeys(c);
    }
    async _rotate(c) {
      if (!c) return;
      await this._newEpoch(c, Math.max(c.maxEpoch || 0, c.epoch) + 1);
      await this._distribute(c);
      this.emit('change', c);
    }

    // ---- control messages ------------------------------------------------------------
    async _sendRaw(c, id, body) {
      try { await this.rtc.call('msg.send', { conv: c.id, id, body }); } catch (e) { if (e.code !== 'rate_limited') console.warn('control message', e); }
    }
    async _announce(c) {
      if (c.pubs.get(this.me) === this.pubB64) return;
      // The id carries the key's fingerprint: a new device (or cleared storage) makes a
      // new key, and the service must not answer its announcement with the old one.
      await this._sendRaw(c, 'pub:' + this.me + ':' + await fp(this.pubB64), 'pub1.' + jb({ pub: this.pubB64 }));
    }
    async _distribute(c) {
      const epoch = c.maxEpoch || c.epoch;
      const key = c.keys.get(epoch);
      if (!key) return;
      for (const m of c.members) {
        if (m.user === this.me || !c.pubs.has(m.user)) continue;
        const rfp = await fp(c.pubs.get(m.user)), k = m.user + ':' + epoch + ':' + rfp;
        if (c.keyed.has(k) || c.inflight.has(k)) continue;
        c.inflight.add(k);
        try {
          const w = await C.wrapKey(this.identity.privateKey, this.identity.publicRaw, C.unb64(c.pubs.get(m.user)), c.id, key);
          await this._sendRaw(c, 'key:' + m.user + ':' + epoch + ':' + rfp + ':' + this.me, 'key1.' + jb({ to: m.user, epoch, rfp, spub: this.pubB64, w }));
        } finally { c.inflight.delete(k); }
      }
    }

    async _pin(user, pub) {
      const k = 'pin:' + this.me + ':' + user, pinned = await idb.get(k);
      if (!pinned) { await idb.set(k, pub); return true; }
      return pinned === pub;
    }

    // ---- one message ------------------------------------------------------------------
    async _process(c, m, history) {
      const key = m.sender + '\0' + m.id;
      c.lastSeq = Math.max(c.lastSeq, m.seq);
      if (m.deleted) { const it = c.byKey.get(key); if (it) { it.deleted = true; it.content = null; } return; }
      const b = m.body;
      try {
        if (b.startsWith('pub1.')) {
          const { pub } = bj(b.slice(5));
          // Replaying history, only a person's newest announcement counts: older ones are keys they no longer use.
          if (history && c.latestPub && c.latestPub.get(m.sender) !== m.seq) return;
          if (await this._pin(m.sender, pub)) { c.pubs.set(m.sender, pub); c.warnings.delete(m.sender); c.pendingPubs.delete(m.sender); }
          else { c.warnings.add(m.sender); c.pendingPubs.set(m.sender, pub); this.emit('warning', c, m.sender); }
          return;
        }
        if (b.startsWith('key1.')) {
          const k = bj(b.slice(5));
          c.maxEpoch = Math.max(c.maxEpoch || 0, k.epoch); c.keyed.add(k.to + ':' + k.epoch + ':' + k.rfp);
          if (k.to !== this.me || k.rfp !== await fp(this.pubB64)) return; // not for me, or for a key I no longer hold
          if (!(await this._pin(m.sender, k.spub))) { c.warnings.add(m.sender); c.pendingPubs.set(m.sender, k.spub); this.emit('warning', c, m.sender); return; }
          c.pubs.set(m.sender, k.spub);
          if (c.keys.has(k.epoch)) return;
          const secret = await C.unwrapKey(this.identity.privateKey, this.identity.publicRaw, C.unb64(k.spub), c.id, k.w);
          c.keys.set(k.epoch, secret); c.epoch = Math.max(c.epoch, k.epoch);
          await this._saveKeys(c);
          for (const it of c.items) if (it.state === 'locked' && it.epoch === k.epoch) await this._open(c, it);
          return;
        }
      } catch (e) { console.warn('control message ignored', e.code || e); return; }

      const i = b.indexOf(':');
      if (b[0] !== 'e' || i < 2) return;
      const epoch = +b.slice(1, i);
      c.maxEpoch = Math.max(c.maxEpoch || 0, epoch);
      let it = c.byKey.get(key);
      if (!it) {
        it = { key, id: m.id, seq: m.seq, sender: m.sender, at: m.sent_at, body: b.slice(i + 1), epoch, state: 'locked', content: null, deleted: false };
        c.byKey.set(key, it); c.items.push(it);
        c.items.sort((a, z) => (a.seq || 1e15) - (z.seq || 1e15));
      } else { it.seq = m.seq; it.at = m.sent_at; if (it.state === 'sending') it.state = 'locked'; }
      c.bySeq.set(m.seq, it);
      await this._open(c, it);
      if (!history && m.sender !== this.me && this.active !== c.id) c.unread++;
    }

    async _open(c, it) {
      const key = c.keys.get(it.epoch);
      if (!key) { it.state = 'locked'; return; }
      try {
        it.content = JSON.parse(await C.decryptMessage(key, { conv: c.id, sender: it.sender, id: it.id }, it.body));
        it.state = 'ok';
      } catch (e) { it.state = 'forged'; it.content = null; }
    }

    async _live(m) {
      const c = this.convs.get(m.conv);
      if (!c || !c.loaded) return;
      if (m.seq <= c.lastSeq && c.bySeq.has(m.seq)) return;
      await this._process(c, m, false);
      if (m.sender !== this.me && c.pubs.get(this.me) !== undefined) await this._distribute(c);
      if (m.body.startsWith('pub1.')) await this._distribute(c);
      this.emit('change', c);
      this.emit('incoming', c, m);
    }

    // ---- sending ----------------------------------------------------------------------------
    async _seal(c, content, id) {
      const epoch = c.maxEpoch || c.epoch;
      const key = c.keys.get(epoch);
      if (!key) throw new RTC.RtcError('no_key', 'waiting for this group\'s key from another member');
      return 'e' + epoch + ':' + await C.encryptMessage(key, { conv: c.id, sender: this.me, id }, JSON.stringify(content));
    }

    async _post(c, content, extra) {
      const id = rid();
      const it = { key: this.me + '\0' + id, id, seq: 0, sender: this.me, at: new Date().toISOString(), epoch: c.maxEpoch || c.epoch, state: 'sending', content, deleted: false, ...extra };
      c.byKey.set(it.key, it); c.items.push(it);
      this.emit('change', c);
      try {
        const body = await this._seal(c, content, id);
        it.body = body.slice(body.indexOf(':') + 1); // as stored for everyone else: without the epoch prefix
        for (let tries = 0; ; tries++) {
          try { const r = await this.rtc.call('msg.send', { conv: c.id, id, body }); it.seq = r.seq; break; }
          catch (e) { if (e.code === 'rate_limited' && tries < 20) { await RTC.sleep(250 + tries * 100); continue; } throw e; }
        }
        if (it.state === 'sending' || it.state === 'locked') it.state = it.content ? 'ok' : 'locked'; // never mask a message that failed to open
        c.bySeq.set(it.seq, it); c.lastSeq = Math.max(c.lastSeq, it.seq);
      } catch (e) { it.state = 'failed'; it.error = e.message || e.code; }
      c.items.sort((a, z) => (a.seq || 1e15) - (z.seq || 1e15));
      this.emit('change', c);
      return it;
    }

    async sendText(c, text) {
      if (te.encode(text).length > C.MAX_INLINE - 400) return this.sendFile(c, new File([text], 'message.txt', { type: 'text/plain' }));
      return this._post(c, { t: 'text', text });
    }

    async sendFile(c, file) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const content = { t: 'file', name: file.name, type: file.type || 'application/octet-stream', size: file.size };
      const it = { key: this.me + '\0' + rid(), id: '', seq: 0, sender: this.me, at: new Date().toISOString(), epoch: c.epoch, state: 'sending', content, deleted: false, progress: 0, phase: 'encrypting' };
      c.byKey.set(it.key, it); c.items.push(it); this.emit('change', c);
      try {
        const enc = await C.encryptFile(c.id, bytes);
        it.phase = 'uploading';
        const fileId = await C.uploadFile(this.rtc.api(), c.id, enc, { onProgress: p => { it.progress = p; this.emit('progress', c, it); } });
        c.byKey.delete(it.key); c.items.splice(c.items.indexOf(it), 1);
        return await this._post(c, { ...content, file: fileId, meta: enc.meta });
      } catch (e) { it.state = 'failed'; it.error = e.message || e.code; this.emit('change', c); throw e; }
    }

    async download(c, it) {
      return C.downloadFile(this.rtc.api(), c.id, it.content.file, it.content.meta);
    }

    async remove_(c, it) { await this.rtc.call('msg.delete', { conv: c.id, seq: it.seq }); }

    async markRead(c) {
      const top = c.items.reduce((a, i) => Math.max(a, i.seq || 0), 0);
      if (top > c.readSent) { c.readSent = top; try { await this.rtc.call('msg.read', { conv: c.id, seq: top }); } catch {} }
    }

    safetyCode(c) {
      const pubs = [...c.pubs.values()].map(p => C.unb64(p));
      if (!pubs.some(p => C.b64(p) === this.pubB64)) pubs.push(this.identity.publicRaw);
      return C.safetyCode(pubs);
    }
  }

  window.Chat = Chat;
})();

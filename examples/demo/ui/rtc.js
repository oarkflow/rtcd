/* rtc.js: the connection to rtcd, and the small things every page needs.
 *
 * One WebSocket carries requests (answered with the same id) and every event
 * pushed to the user. It signs in with a one-time ticket, not the token, so the
 * credential never sits in a URL that a proxy or the history would keep.
 */
(function () {
  'use strict';

  class RtcError extends Error {
    constructor(code, message) { super(message || code); this.code = code; }
  }

  // ---- a tiny event emitter ---------------------------------------------
  class Emitter {
    constructor() { this._h = new Map(); }
    on(name, fn) { (this._h.get(name) || this._h.set(name, new Set()).get(name)).add(fn); return () => this._h.get(name).delete(fn); }
    emit(name, ...a) { for (const f of [...(this._h.get(name) || []), ...(this._h.get('*') || [])]) { try { f(...(this._h.get('*')?.has(f) ? [name, ...a] : a)); } catch (e) { console.error(e); } } }
  }

  // ---- local storage of keys (IndexedDB), per signed-in user ----------------
  const idb = (() => {
    let db;
    const open = () => db || (db = new Promise((res, rej) => {
      const r = indexedDB.open('rtcd-demo', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    }));
    const tx = async (mode, fn) => { const d = await open(); return new Promise((res, rej) => { const t = d.transaction('kv', mode), s = t.objectStore('kv'); const r = fn(s); t.oncomplete = () => res(r.result); t.onerror = () => rej(t.error); }); };
    return { get: k => tx('readonly', s => s.get(k)), set: (k, v) => tx('readwrite', s => s.put(v, k)), del: k => tx('readwrite', s => s.delete(k)) };
  })();

  // ---- the connection -----------------------------------------------------
  class Rtc extends Emitter {
    constructor(user) {
      super();
      this.user = user; this.token = null; this.expires = 0; this.ws = null; this.seq = 0;
      this.pending = new Map(); this.closed = false; this.state = 'offline'; this.attempt = 0;
      this.stats = { sent: 0, received: 0, events: 0 };
    }

    async login() {
      const r = await fetch('/demo/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: this.user }) });
      const j = await r.json();
      if (!r.ok) throw new RtcError(j.error?.code || 'login', j.error?.message);
      this.token = j.token; this.expires = Date.parse(j.expires_at);
      if (!Number.isFinite(this.expires)) this.expires = Date.now() + 10 * 60000; // never trust an unparseable expiry to schedule work
      return j;
    }

    /** A request to the HTTP API with this user's token. */
    async http(method, path, body, raw) {
      const h = { Authorization: 'Bearer ' + this.token };
      if (body !== undefined && !raw) h['Content-Type'] = 'application/json';
      const r = await fetch(path, { method, headers: h, body: raw ? body : body === undefined ? undefined : JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new RtcError(j.error?.code || 'http_' + r.status, j.error?.message);
      return j;
    }
    api() { return { base: location.origin, headers: () => ({ Authorization: 'Bearer ' + this.token }) }; }

    async connect() {
      this.closed = false;
      if (!this.token || Date.now() > this.expires - 30000) await this.login();
      this._state('connecting');
      const { ticket } = await this.http('POST', '/v1/ws/ticket', {});
      const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/v1/ws?ticket=' + encodeURIComponent(ticket);
      await new Promise((resolve, reject) => {
        const ws = new WebSocket(url);
        let ready = false;
        ws.onmessage = e => {
          let m; try { m = JSON.parse(e.data); } catch { return; }
          this.stats.received++;
          if (m.type === 'ack' || m.type === 'error') {
            const p = this.pending.get(m.replyTo); if (!p) return;
            this.pending.delete(m.replyTo);
            if (m.type === 'ack') p.resolve(m.payload);
            else { const [code, ...rest] = String(m.error || m.code).split(': '); p.reject(new RtcError(code, rest.join(': ') || undefined)); }
          } else if (m.type === 'emit') {
            this.stats.events++;
            if (m.event === 'ready') { ready = true; this.ready = m.payload; this._state('online'); this.attempt = 0; resolve(); }
            this.emit('event', m.event, m.payload, m.from, m.ts);
            this.emit(m.event, m.payload, m.from, m.ts);
          }
        };
        ws.onerror = () => { if (!ready) reject(new RtcError('connect', 'could not open the WebSocket')); };
        ws.onclose = ev => {
          for (const [, p] of this.pending) p.reject(new RtcError('closed', 'the connection closed'));
          this.pending.clear(); clearInterval(this._ping);
          if (!ready) reject(new RtcError('connect', 'the service refused the connection (' + ev.code + ')'));
          if (this.ws === ws) { this.ws = null; this._state('offline'); this.emit('closed', ev); if (!this.closed) this._reconnect(); }
        };
        this.ws = ws;
        this._ping = setInterval(() => ws.readyState === 1 && ws.send('{"type":"ping"}'), 25000);
      });
      clearTimeout(this._refresh);
      this._schedule();
    }

    // Before the token runs out, get another and give it to the open connection.
    async refresh() {
      await this.login();
      await this.call('auth.refresh', { token: this.token });
      this._schedule();
    }

    // Refresh a minute before the token ends, and never more often than every 30 seconds.
    _schedule() {
      clearTimeout(this._refresh);
      this._refresh = setTimeout(() => this.refresh().catch(() => {}), Math.max(30000, this.expires - Date.now() - 60000));
    }

    _reconnect() {
      const delay = Math.min(15000, 500 * 2 ** this.attempt++) * (0.5 + Math.random() / 2);
      this._state('reconnecting');
      this._rt = setTimeout(async () => {
        try { await this.connect(); this.emit('reconnected'); } catch (e) { if (!this.closed) this._reconnect(); }
      }, delay);
    }

    _state(s) { if (this.state !== s) { this.state = s; this.emit('state', s); } }

    call(event, payload, timeout = 20000) {
      return new Promise((resolve, reject) => {
        if (!this.ws || this.ws.readyState !== 1) return reject(new RtcError('offline', 'not connected'));
        const id = String(++this.seq);
        const t = setTimeout(() => { this.pending.delete(id); reject(new RtcError('timeout', event + ' timed out')); }, timeout);
        this.pending.set(id, { resolve: v => { clearTimeout(t); resolve(v); }, reject: e => { clearTimeout(t); reject(e); } });
        this.ws.send(JSON.stringify({ type: 'emit', id, event, payload: payload || {} }));
        this.stats.sent++;
      });
    }

    close() {
      this.closed = true; clearTimeout(this._rt); clearTimeout(this._refresh); clearInterval(this._ping);
      if (this.ws) this.ws.close(1000);
    }
  }

  // ---- helpers ----------------------------------------------------------------
  const el = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'text') e.textContent = v;
      else if (k === 'dataset') Object.assign(e.dataset, v);
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(String(k)));
    return e;
  };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const fmtBytes = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  const fmtTime = d => new Date(d).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const fmtDay = d => { const x = new Date(d), t = new Date(); return x.toDateString() === t.toDateString() ? 'Today' : x.toLocaleDateString([], { weekday: 'long', month: 'short', day: 'numeric' }); };
  const hue = s => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };

  window.RTC = { Rtc, RtcError, Emitter, idb, el, sleep, fmtBytes, fmtTime, fmtDay, hue };
})();

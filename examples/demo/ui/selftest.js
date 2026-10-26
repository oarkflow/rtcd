/* selftest.js: checks rtcd from the browser, end to end, with real sockets,
 * real WebCrypto and real HTTP. Each check makes its own throwaway users and
 * groups, so it never touches your conversations.
 */
(function () {
  'use strict';
  const { Rtc, RtcError, sleep } = RTC;
  const C = ChatCrypto;
  const salt = Math.random().toString(36).slice(2, 7);
  const te = new TextEncoder();

  const hex = u8 => Array.from(u8, x => x.toString(16).padStart(2, '0')).join('');
  const sha = async u8 => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', u8)));
  const code = p => p.then(() => null, e => e.code || String(e));
  const need = (cond, msg) => { if (!cond) throw new Error(msg); };
  const waitFor = (rtc, name, pred = () => true, ms = 6000) => new Promise((res, rej) => {
    const off = rtc.on(name, (p, from) => { if (pred(p, from)) { off(); clearTimeout(t); res(p); } });
    const t = setTimeout(() => { off(); rej(new Error('no ' + name + ' event within ' + ms + ' ms')); }, ms);
  });
  const rawSocket = (ticket) => new Promise(res => {
    const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/v1/ws?ticket=' + encodeURIComponent(ticket));
    let open = false;
    ws.onmessage = () => { open = true; };
    ws.onclose = () => res(open);
    setTimeout(() => { if (open) { ws.close(); } }, 700);
  });

  // The checks. Each gets the shared context and returns a short detail line.
  const checks = [
    { group: 'Browser', name: 'Secure context and required features', run: async () => {
      const f = { 'secure context': window.isSecureContext, WebCrypto: !!crypto.subtle, IndexedDB: !!window.indexedDB, WebSocket: !!window.WebSocket, 'RTCPeerConnection (calls)': !!window.RTCPeerConnection };
      const missing = Object.entries(f).filter(([, v]) => !v).map(([k]) => k);
      need(!missing.length, 'missing: ' + missing.join(', '));
      return 'encrypted calls need RTCRtpScriptTransform: ' + (window.RTCRtpScriptTransform ? 'available' : 'NOT available in this browser (chat still works)');
    } },
    { group: 'Service', name: 'The service is ready', run: async () => {
      const r = await fetch('/readyz'); need(r.ok, 'readyz ' + r.status);
      const i = await (await fetch('/demo/info')).json();
      return 'database ' + i.database + (i.node ? ', node ' + i.node : '') + ', ' + i.connections + ' connections open';
    } },
    { group: 'Sign-in', name: 'Bad credentials are refused', run: async () => {
      const a = await fetch('/v1/ice', { method: 'POST', headers: { Authorization: 'Bearer not-a-token' }, body: '{}' });
      const b = await fetch('/v1/ice', { method: 'POST', body: '{}' });
      // 429 is also a refusal: an address that has failed a lot (an earlier run of these checks) is throttled.
      const refused = s => s === 401 || s === 429;
      need(refused(a.status) && refused(b.status), 'got ' + a.status + ' and ' + b.status);
      return 'a wrong token and no token are both refused (' + a.status + ', ' + b.status + ')';
    } },
    { group: 'Sign-in', name: 'A ticket opens one connection, once', run: async ctx => {
      const r = new Rtc('st-t-' + salt); await r.login();
      const { ticket } = await r.http('POST', '/v1/ws/ticket', {});
      const first = await rawSocket(ticket), second = await rawSocket(ticket);
      need(first === true, 'the first use did not connect');
      need(second === false, 'the ticket worked a second time');
      return 'first use connected, reuse refused (the token never appears in a URL)';
    } },
    { group: 'Sign-in', name: 'Three users connect', run: async ctx => {
      ctx.a = new Rtc('st-a-' + salt); ctx.b = new Rtc('st-b-' + salt); ctx.c = new Rtc('st-c-' + salt);
      await Promise.all([ctx.a, ctx.b, ctx.c].map(r => r.connect()));
      need(ctx.a.ready.scopes.includes('chat'), 'no chat scope');
      return ctx.a.user + ', ' + ctx.b.user + ', ' + ctx.c.user + ' (scopes: ' + ctx.a.ready.scopes.join(', ') + ')';
    } },
    { group: 'Groups', name: 'A group reaches its members', run: async ctx => {
      const got = waitFor(ctx.b, 'group.added');
      const g = await ctx.a.call('group.create', { name: 'selftest ' + salt, members: [ctx.b.user] });
      await got; ctx.g = g.id; ctx.key = C.newKey();
      return 'group ' + g.id.slice(0, 12) + '… created; the other member was told at once';
    } },
    { group: 'Messages', name: 'An encrypted message arrives intact and unreadable to the server', run: async ctx => {
      const id = 'm-' + salt, ctxs = { conv: ctx.g, sender: ctx.a.user, id };
      const body = await C.encryptMessage(ctx.key, ctxs, 'hello ' + salt);
      const got = waitFor(ctx.b, 'msg.new', p => p.id === id);
      const r = await ctx.a.call('msg.send', { conv: ctx.g, id, body });
      const m = await got;
      need(m.body === body && m.sender === ctx.a.user, 'body changed on the way');
      need(await C.decryptMessage(ctx.key, ctxs, m.body) === 'hello ' + salt, 'did not decrypt');
      const h = await ctx.b.call('msg.history', { conv: ctx.g });
      need(!JSON.stringify(h).includes('hello ' + salt), 'plaintext found in stored history');
      ctx.firstSeq = r.seq;
      return 'seq ' + r.seq + '; the stored body is ' + body.length + ' characters of ciphertext';
    } },
    { group: 'Messages', name: 'Sending twice does not duplicate', run: async ctx => {
      const id = 'm-' + salt, body = await C.encryptMessage(ctx.key, { conv: ctx.g, sender: ctx.a.user, id }, 'again');
      const r = await ctx.a.call('msg.send', { conv: ctx.g, id, body });
      need(r.duplicate === true && r.seq === ctx.firstSeq, 'a retry made message ' + JSON.stringify(r));
      return 'the retry returned the stored message (seq ' + r.seq + ', duplicate)';
    } },
    { group: 'Messages', name: 'Strangers are shut out', run: async ctx => {
      const a = await code(ctx.c.call('msg.send', { conv: ctx.g, id: 'x', body: 'x' }));
      const b = await code(ctx.c.call('msg.history', { conv: ctx.g }));
      need(a === 'forbidden' && b === 'forbidden', 'send ' + a + ', read ' + b);
      return 'a non-member can neither send nor read: forbidden';
    } },
    { group: 'Messages', name: 'A forged or moved message fails to decrypt', run: async ctx => {
      const id = 'f-' + salt, body = await C.encryptMessage(ctx.key, { conv: ctx.g, sender: ctx.a.user, id }, 'secret');
      const bad = [['another sender', { conv: ctx.g, sender: ctx.c.user, id }], ['another conversation', { conv: 'other', sender: ctx.a.user, id }], ['another id', { conv: ctx.g, sender: ctx.a.user, id: 'z' }]];
      for (const [what, c] of bad) need((await code(C.decryptMessage(ctx.key, c, body))) === 'forged', what + ' was accepted');
      const flipped = body.slice(0, -3) + (body.endsWith('AAA') ? 'BBB' : 'AAA');
      need((await code(C.decryptMessage(ctx.key, { conv: ctx.g, sender: ctx.a.user, id }, flipped))) === 'forged', 'an altered body was accepted');
      return 'wrong sender, conversation, id and a flipped bit are all refused';
    } },
    { group: 'Messages', name: 'A burst arrives complete and in order', run: async ctx => {
      const N = 40, seen = [];
      const done = new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('only ' + seen.length + ' of ' + N + ' arrived')), 8000); const off = ctx.b.on('msg.new', p => { if (p.id.startsWith('b' + salt)) { seen.push(p.seq); if (seen.length === N) { off(); clearTimeout(t); res(); } } }); });
      await Promise.all(Array.from({ length: N }, async (_, i) => { const id = 'b' + salt + '-' + i; await ctx.a.call('msg.send', { conv: ctx.g, id, body: await C.encryptMessage(ctx.key, { conv: ctx.g, sender: ctx.a.user, id }, 'n' + i) }); }));
      await done;
      need(seen.every((s, i) => i === 0 || s === seen[i - 1] + 1), 'numbers are not consecutive: ' + seen.slice(0, 8).join(','));
      return N + ' messages sent at once, delivered as seq ' + seen[0] + '…' + seen[N - 1] + ' with no gap';
    } },
    { group: 'Messages', name: 'Size limits hold on both sides', run: async ctx => {
      const c1 = await code(C.encryptMessage(ctx.key, { conv: ctx.g, sender: ctx.a.user, id: 'big' }, new Uint8Array(C.MAX_INLINE + 1)));
      const c2 = await code(ctx.a.call('msg.send', { conv: ctx.g, id: 'huge-' + salt, body: 'x'.repeat(40 * 1024) }));
      need(c1 === 'too_large', 'the client let an oversized message through');
      need(c2 === 'invalid', 'the server accepted a 40 KiB body: ' + c2);
      return 'over ' + C.MAX_INLINE + ' bytes must be an attachment; the server refuses a 40 KiB body';
    } },
    { group: 'Attachments', name: 'An interrupted upload resumes, and only members can download', run: async ctx => {
      const plain = new Uint8Array(2.6 * 1048576 | 0); // random bytes, 64 KB at a time (the most getRandomValues gives)
      for (let i = 0; i < plain.length; i += 65536) crypto.getRandomValues(plain.subarray(i, Math.min(plain.length, i + 65536)));
      const enc = await C.encryptFile(ctx.g, plain);
      const api = ctx.a.api();
      const init = await ctx.a.http('POST', '/v1/files', { conv: ctx.g, size: enc.cipher.length, sha256: enc.sha256, chunk: enc.chunk });
      const id = init.file.id;
      await ctx.a.http('PUT', '/v1/files/' + id + '/parts/0', enc.cipher.subarray(0, enc.chunk), true); // …then the connection "drops"
      const st = await ctx.a.http('GET', '/v1/files/' + id);
      need(st.have.length === 1, 'the service should hold exactly part 0, holds ' + st.have);
      const sent = []; await C.uploadFile(api, ctx.g, enc, { resume: id, onProgress: p => sent.push(p) });
      const back = await C.downloadFile(ctx.b.api(), ctx.g, id, enc.meta);
      need(await sha(back) === await sha(plain), 'the downloaded file differs');
      const stranger = await fetch('/v1/files/' + id + '/blob', { headers: { Authorization: 'Bearer ' + ctx.c.token } });
      need(stranger.status === 404, 'a non-member got status ' + stranger.status);
      ctx.file = { id, enc, plain };
      return (plain.length / 1048576).toFixed(1) + ' MB: ' + st.have.length + ' of ' + init.chunks + ' parts were kept, the rest were sent on resume; downloaded and decrypted identically; a stranger got 404';
    } },
    { group: 'Attachments', name: 'Ranges, signed links and tampering', run: async ctx => {
      const { id, enc } = ctx.file;
      const r = await fetch('/v1/files/' + id + '/blob', { headers: { Authorization: 'Bearer ' + ctx.b.token, Range: 'bytes=100-199' } });
      need(r.status === 206 && (await r.arrayBuffer()).byteLength === 100, 'range answered ' + r.status);
      need(r.headers.get('content-type') === 'application/octet-stream' && r.headers.get('x-content-type-options') === 'nosniff', 'missing safe headers');
      const { url } = await ctx.b.call('file.link', { file: id });
      const ok = await fetch(url), other = await fetch(url.replace('u=' + encodeURIComponent(ctx.b.user), 'u=' + encodeURIComponent(ctx.c.user)));
      need(ok.status === 200 && other.status === 401, 'link ' + ok.status + ', tampered link ' + other.status);
      const bad = enc.cipher.slice(); bad[500] ^= 1;
      need((await code(C.decryptFile(ctx.g, enc.meta, bad))) === 'corrupt', 'a flipped bit in the file was not detected');
      return 'HTTP 206 for a range; a signed link works for its user only; a flipped bit is caught on decrypt';
    } },
    { group: 'Attachments', name: 'A file that is not what was announced is discarded', run: async ctx => {
      const init = await ctx.a.http('POST', '/v1/files', { conv: ctx.g, size: 100, sha256: await sha(te.encode('something else')), chunk: 1048576 });
      await ctx.a.http('PUT', '/v1/files/' + init.file.id + '/parts/0', new Uint8Array(100), true);
      const c1 = await code(ctx.a.http('POST', '/v1/files/' + init.file.id + '/complete', {}));
      const c2 = await code(ctx.a.http('GET', '/v1/files/' + init.file.id));
      need(c1 === 'checksum_mismatch' && c2 === 'not_found', 'complete ' + c1 + ', then ' + c2);
      return 'the checksum mismatch was refused and the bytes deleted';
    } },
    { group: 'Limits', name: 'A flooded conversation tells senders to slow down', run: async ctx => {
      let limited = 0, ok = 0;
      await Promise.all(Array.from({ length: 160 }, async (_, i) => { try { await ctx.a.call('msg.send', { conv: ctx.g, id: 'fl' + salt + i, body: 'v1.x' }); ok++; } catch (e) { if (e.code === 'rate_limited') limited++; } }));
      need(limited > 0, 'nothing was limited');
      need(ctx.a.state === 'online' && ctx.b.state === 'online', 'a connection was dropped');
      return ok + ' accepted, ' + limited + ' told "rate_limited"; nobody was disconnected';
    } },
    { group: 'Limits', name: 'Repeated bad sign-ins are throttled, good ones are not', run: async ctx => {
      let last = 0;
      for (let i = 0; i < 40; i++) last = (await fetch('/v1/ice', { method: 'POST', headers: { Authorization: 'Bearer bad-' + i }, body: '{}' })).status;
      const good = await fetch('/v1/ice', { method: 'POST', headers: { Authorization: 'Bearer ' + ctx.a.token, 'Content-Type': 'application/json' }, body: '{}' });
      need(last === 429, 'the 40th bad attempt answered ' + last);
      need(good.status === 200, 'a good token was refused: ' + good.status);
      return 'bad attempts answered 429; a valid token still works';
    } },
    { group: 'Calls', name: 'Calls must be encrypted, and key messages are relayed', run: async ctx => {
      const plain = await code(ctx.a.call('call.start', { to: [ctx.b.user], mode: 'sfu', e2ee: false }));
      need(plain && plain !== 'null', 'a call without end-to-end encryption was accepted');
      const ring = waitFor(ctx.b, 'call.incoming');
      const started = await ctx.a.call('call.start', { to: [ctx.b.user], mode: 'sfu', kind: 'audio' });
      await ring; await ctx.b.call('call.answer', { call: started.call.id });
      const rel = waitFor(ctx.b, 'call.e2ee');
      await ctx.a.call('call.e2ee', { call: started.call.id, to: ctx.b.user, data: 'opaque' });
      const m = await rel; need(m.data === 'opaque' && m.from === ctx.a.user, 'relay changed the message');
      const stranger = await code(ctx.c.call('call.e2ee', { call: started.call.id, to: ctx.b.user, data: 'x' }));
      need(stranger === 'forbidden', 'a non-participant could relay: ' + stranger);
      await ctx.a.call('call.end', { call: started.call.id });
      return 'plaintext refused (' + plain + '); ring, answer, key relay worked; an outsider was refused';
    } },
    { group: 'Revocation', name: 'A revoked user is cut off at once', run: async ctx => {
      const closed = new Promise(res => ctx.c.on('closed', res)); const old = ctx.c.token;
      const r = await fetch('/demo/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: ctx.c.user }) });
      need(r.ok, 'revoke answered ' + r.status);
      await Promise.race([closed, sleep(4000).then(() => { throw new Error('the connection stayed open'); })]);
      const refused = await fetch('/v1/ice', { method: 'POST', headers: { Authorization: 'Bearer ' + old, 'Content-Type': 'application/json' }, body: '{}' });
      need(refused.status === 401 || refused.status === 429, 'the old token answered ' + refused.status);
      ctx.c.close(); await ctx.c.login();
      const fresh = await fetch('/v1/ice', { method: 'POST', headers: { Authorization: 'Bearer ' + ctx.c.token, 'Content-Type': 'application/json' }, body: '{}' });
      need(fresh.status === 200, 'a new token answered ' + fresh.status);
      return 'socket closed, old token refused (' + refused.status + '), a new token → 200';
    } },
    { group: 'Service', name: 'Nothing was dropped or lost', run: async ctx => {
      const i = await (await fetch('/demo/info')).json();
      need(i.slow_clients === 0 && i.audit_refused === 0, 'slow clients ' + i.slow_clients + ', audit refused ' + i.audit_refused);
      return i.events_sent + ' events sent, ' + i.events_dropped + ' dropped, ' + i.audit_written + ' audit entries written, none refused';
    } },
  ];

  async function run(onUpdate, only) {
    const ctx = {}, results = checks.map(c => ({ group: c.group, name: c.name, state: 'pending' }));
    let broken = false;
    onUpdate && onUpdate(results);
    for (let i = 0; i < checks.length; i++) {
      if (only && !only.includes(i)) continue;
      const r = results[i]; r.state = 'running'; onUpdate && onUpdate(results);
      const t0 = performance.now();
      try {
        if (broken && !/Browser|Service|Sign-in/.test(checks[i].group)) throw new Error('skipped: an earlier setup step failed');
        r.detail = await checks[i].run(ctx); r.state = 'pass';
      } catch (e) {
        r.state = String(e.message).startsWith('skipped') ? 'skip' : 'fail'; r.detail = e.message || String(e);
        if (r.state === 'fail' && /Three users|group reaches/.test(r.name)) broken = true;
      }
      r.ms = Math.round(performance.now() - t0); onUpdate && onUpdate(results);
    }
    for (const k of ['a', 'b', 'c']) ctx[k] && ctx[k].close();
    return results;
  }

  window.SelfTest = { run, checks };
})();

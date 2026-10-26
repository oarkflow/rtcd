/* app.js: the interface. Message text is only ever put in the page with
 * textContent, never as HTML, so nothing another user sends can run in your tab. */
(function () {
  'use strict';
  const { el, Rtc, RtcError, fmtBytes, fmtTime, fmtDay, hue, sleep } = RTC;
  const root = document.getElementById('root');
  const NAME = /^[A-Za-z0-9_.-]{1,32}$/;
  const S = { user: null, rtc: null, chat: null, view: 'chat', call: null, tiles: new Map(), info: false, results: null, running: false, log: [], previews: new Map(), ui: {} };

  // ---- small helpers ---------------------------------------------------------
  const ICONS = {
    lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    send: '<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/>',
    clip: '<path d="m21 11-9 9a5 5 0 0 1-7-7l9-9a3.5 3.5 0 0 1 5 5l-9 9a2 2 0 0 1-3-3l8-8"/>',
    phone: '<path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1 1 .4 1.9.7 2.8a2 2 0 0 1-.5 2.1L8 9.9a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.8.7a2 2 0 0 1 1.7 2z"/>',
    video: '<path d="m22 8-6 4 6 4z"/><rect x="2" y="6" width="14" height="12" rx="2"/>',
    videoOff: '<path d="M16 16v1a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2m5.7 0H14a2 2 0 0 1 2 2v3.3l1 1L22 8v8"/><path d="m1 1 22 22"/>',
    mic: '<rect x="9" y="2" width="6" height="12" rx="3"/><path d="M19 10v1a7 7 0 0 1-14 0v-1M12 18v4"/>',
    micOff: '<path d="m1 1 22 22"/><path d="M9 9v2a3 3 0 0 0 5.1 2.1M15 9.3V5a3 3 0 0 0-5.9-.7"/><path d="M19 10v1a7 7 0 0 1-.9 3.4M5 10v1a7 7 0 0 0 11.7 5.2M12 18v4"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    flask: '<path d="M9 2h6M10 2v6L4 19a2 2 0 0 0 1.8 3h12.4A2 2 0 0 0 20 19l-6-11V2"/>',
    chat: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    trash: '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
    back: '<path d="m15 18-6-6 6-6"/>',
    play: '<path d="m6 3 14 9-14 9z"/>',
    copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  };
  const icon = (n, cls) => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('class', 'i ' + (cls || '')); s.setAttribute('aria-hidden', 'true'); s.innerHTML = ICONS[n] || ''; return s; }; // static strings only
  const avatar = (name, cls) => { const a = el('div', { class: 'avatar ' + (cls || ''), title: name, text: name.slice(0, 2) }); a.style.setProperty('--h', hue(name)); return a; };
  const ibtn = (name, label, onclick, cls) => el('button', { class: 'icon-btn ' + (cls || ''), 'aria-label': label, title: label, onclick }, icon(name));
  const store = { get: k => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch {} } };
  const sess = { get: k => { try { return sessionStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch {} } };

  function setTheme(t) { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; }
  setTheme(store.get('theme'));
  const isDark = () => document.documentElement.dataset.theme === 'dark' || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);

  function toast(text, kind, actions, ms) {
    let box = document.querySelector('.toasts');
    if (!box) { box = el('div', { class: 'toasts', role: 'status' }); document.body.append(box); }
    const t = el('div', { class: 'toast ' + (kind || '') }, el('div', { class: 'grow' }, text), ...(actions || []).map(a => el('button', { class: 'btn sm ' + (a.primary ? 'primary' : ''), onclick: () => { t.remove(); a.fn(); } }, a.label)));
    box.append(t);
    if (ms !== 0) setTimeout(() => t.remove(), ms || (actions ? 30000 : 5000));
    return t;
  }
  function modal(title, body, actions) {
    const close = () => scrim.remove();
    const scrim = el('div', { class: 'scrim', onmousedown: e => { if (e.target === scrim) close(); } },
      el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title }, el('h3', { text: title }), body,
        el('div', { class: 'actions' }, ...actions.map(a => el('button', { class: 'btn ' + (a.kind || ''), onclick: async () => { if ((await a.fn?.()) !== false) close(); } }, a.label)))));
    document.addEventListener('keydown', function esc(e) { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); } });
    document.body.append(scrim);
    const f = scrim.querySelector('input,textarea'); if (f) f.focus();
    return close;
  }
  const errText = e => ({ forbidden: 'You are not allowed to do that.', rate_limited: 'Slow down a little.', not_found: 'Not found.', limit_reached: 'A limit was reached.', no_key: 'This group\'s key has not reached you yet.', invalid: 'That was not valid.' })[e.code] || e.message || String(e);

  // ---- sign-in -------------------------------------------------------------------
  function showLogin(msg) {
    teardown();
    const input = el('input', { class: 'input', id: 'name', placeholder: 'e.g. ada', maxlength: '32', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-describedby': 'err' });
    const err = el('div', { class: 'error', id: 'err', text: msg || '' });
    const go = async name => {
      name = (name || input.value).trim();
      if (!NAME.test(name)) { err.textContent = 'Use 1 to 32 letters, digits, dots, dashes or underscores.'; return; }
      err.textContent = ''; btn.disabled = true; btn.textContent = 'Connecting…';
      try { await signIn(name); } catch (e) { err.textContent = errText(e); btn.disabled = false; btn.textContent = 'Continue'; }
    };
    const btn = el('button', { class: 'btn primary', onclick: () => go() }, 'Continue');
    input.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    root.replaceChildren(el('main', { class: 'login' }, el('div', { class: 'login-card' },
      el('div', { class: 'brand' }, el('div', { class: 'logo' }, icon('chat')), 'rtcd'),
      el('div', {}, el('h1', {}, 'Secure calls and chat'), el('p', {}, 'Encrypted groups, files and video, running on your own rtcd service.')),
      el('label', { class: 'field' }, el('span', {}, 'Your name'), input),
      el('div', { class: 'quick' }, ...['ada', 'bob', 'cy', 'dee'].map(n => el('button', { class: 'btn sm', onclick: () => go(n) }, n))),
      err, btn,
      el('div', { class: 'features' },
        ...['End-to-end encrypted messages', 'Encrypted file transfer', 'Group video through an SFU', 'Checks itself in the browser'].map(t => el('div', {}, icon('check'), t))),
      el('div', { class: 'hint' }, 'Open this page in a second window and sign in with another name to talk to yourself. This example signs anyone in; a real backend signs in its own users.'))));
    input.focus();
  }

  async function signIn(name) {
    const rtc = new Rtc(name);
    await rtc.connect();
    S.user = name; S.rtc = rtc; sess.set('user', name);
    S.chat = new Chat(rtc);
    await S.chat.init();
    rtc.on('event', (n, p, from) => { S.log.push({ t: Date.now(), n, p, from }); if (S.log.length > 200) S.log.shift(); if (S.view === 'tests') renderLog(); });
    rtc.on('state', () => renderStatus());
    rtc.on('reconnected', async () => {
      try { await S.chat.refresh(); for (const c of S.chat.convs.values()) if (c.loaded) await S.chat._load(c); toast('Reconnected', 'ok'); } catch (e) { console.warn(e); }
    });
    rtc.on('call.incoming', p => onIncoming(p));
    rtc.on('revoked', () => {});
    rtc.on('closed', ev => { if (ev.reason === 'revoked') { toast('You were signed out by the service.', 'bad', null, 0); showLogin('Signed out: your access was revoked.'); } });
    S.chat.on('list', renderList);
    S.chat.on('change', c => { renderList(); if (S.chat.active === c.id) { renderMessages(c); renderHeader(c); if (S.info) renderInfo(c); S.chat.markRead(c); } });
    S.chat.on('progress', (c, it) => { if (it.bar) it.bar.style.width = Math.round(it.progress * 100) + '%'; });
    S.chat.on('warning', (c, user) => toast(`${user}'s encryption key changed. Messages from the new key are being ignored until you verify them.`, 'bad', null, 12000));
    S.chat.on('incoming', (c, m) => { if (S.chat.active !== c.id || document.hidden) toast(`New message in ${c.name}`, ''); });
    S.chat.on('group', (ev, p) => { if (ev === 'group.added' && p.by !== S.user) toast(`${p.by} added you to ${p.name}`, 'ok'); if (ev === 'group.removed') toast('You were removed from a group', 'bad'); });
    renderApp();
    await S.chat.refresh();
    const last = store.get('conv:' + name);
    if (last && S.chat.convs.has(last)) selectConv(last);
  }

  function teardown() {
    if (S.call) S.call.leave().catch(() => {});
    if (S.rtc) S.rtc.close();
    S.rtc = S.chat = S.call = null; S.user = null; S.tiles.clear(); sess.set('user', null);
  }

  // ---- shell -------------------------------------------------------------------------------------
  function renderApp() {
    const u = S.ui = {};
    u.status = el('small', {});
    u.list = el('div', { class: 'list', role: 'list' });
    u.navChat = el('button', { 'aria-current': 'page', onclick: () => setView('chat') }, icon('chat'), 'Chats');
    u.navTests = el('button', { onclick: () => setView('tests') }, icon('flask'), 'Diagnostics');
    u.foot = el('span', {});
    const side = el('aside', { class: 'side' },
      el('div', { class: 'side-head' }, el('div', { class: 'brand' }, el('div', { class: 'logo' }, icon('chat')), 'rtcd'),
        ibtn(isDark() ? 'sun' : 'moon', 'Toggle theme', e => { const d = !isDark(); setTheme(d ? 'dark' : 'light'); store.set('theme', d ? 'dark' : 'light'); e.currentTarget.replaceChildren(icon(d ? 'sun' : 'moon')); }),
        ibtn('logout', 'Sign out', () => showLogin())),
      el('div', { class: 'whoami' }, avatar(S.user), el('div', { class: 'grow' }, el('b', { text: S.user }), u.status)),
      el('div', {}, el('div', { class: 'nav' }, u.navChat, u.navTests)),
      u.list);
    u.main = el('main', { class: 'main' });
    u.app = el('div', { class: 'app' }, side, u.main);
    root.replaceChildren(u.app);
    for (const ev of ['dragenter', 'dragover']) u.main.addEventListener(ev, e => { if (S.view === 'chat' && S.chat.active && [...(e.dataTransfer?.types || [])].includes('Files')) { e.preventDefault(); u.main.classList.add('dragging'); } });
    u.main.addEventListener('dragleave', e => { if (e.target === u.main || !u.main.contains(e.relatedTarget)) u.main.classList.remove('dragging'); });
    u.main.addEventListener('drop', e => { u.main.classList.remove('dragging'); if (S.view === 'chat' && S.chat.active && e.dataTransfer?.files?.length) { e.preventDefault(); sendFiles([...e.dataTransfer.files]); } });
    renderStatus(); renderList(); setView(S.view);
  }

  function renderStatus() {
    if (!S.ui.status) return;
    const s = S.rtc ? S.rtc.state : 'offline';
    S.ui.status.replaceChildren(el('span', { class: 'dot ' + s }), { online: 'Connected', connecting: 'Connecting…', reconnecting: 'Reconnecting…', offline: 'Offline' }[s]);
  }

  function setView(v) {
    S.view = v;
    S.ui.navChat.setAttribute('aria-current', v === 'chat' ? 'page' : 'false'); S.ui.navTests.setAttribute('aria-current', v === 'tests' ? 'page' : 'false');
    S.ui.app.classList.toggle('in-conv', v === 'tests' || !!S.chat.active);
    if (v === 'tests') renderTests(); else renderChatArea();
    renderList();
  }

  // ---- conversation list ---------------------------------------------------------------------
  function preview(c) {
    const last = [...c.items].reverse().find(i => !i.deleted && i.state !== 'sending');
    if (!last) return c.members.length + ' members';
    const who = last.sender === S.user ? 'You: ' : last.sender + ': ';
    if (last.state === 'ok' && last.content) return who + (last.content.t === 'file' ? '📎 ' + last.content.name : last.content.text);
    return who + 'Encrypted message';
  }
  function renderList() {
    const u = S.ui; if (!u.list || !S.chat) return;
    const convs = [...S.chat.convs.values()].sort((a, b) => (b.items.at(-1)?.at || '').localeCompare(a.items.at(-1)?.at || '') || a.name.localeCompare(b.name));
    u.list.replaceChildren(
      el('div', { class: 'list-title' }, 'Groups', el('button', { class: 'btn sm', onclick: newGroup }, icon('plus'), 'New')),
      ...(convs.length ? convs.map(c => el('button', { class: 'conv', role: 'listitem', 'aria-current': String(S.view === 'chat' && S.chat.active === c.id), onclick: () => selectConv(c.id) },
        avatar(c.name), el('div', { class: 'meta' }, el('div', { class: 'name' }, c.name, S.call && S.call.call.group === c.id ? el('span', { class: 'chip ok' }, 'in call') : null), el('div', { class: 'sub', text: preview(c) })),
        c.unread ? el('span', { class: 'badge', text: String(c.unread) }) : null))
        : [el('div', { class: 'empty' }, icon('users'), el('div', {}, 'No groups yet. Create one and add the name you used in your other window.'), el('button', { class: 'btn primary', onclick: newGroup }, icon('plus'), 'New group'))]));
  }

  function newGroup() {
    const name = el('input', { class: 'input', placeholder: 'Team chat', maxlength: '60' });
    const members = el('input', { class: 'input', placeholder: 'bob, cy', autocapitalize: 'off', spellcheck: 'false' });
    const err = el('div', { class: 'error' });
    modal('New group', el('div', { style: null, class: 'field' },
      el('label', { class: 'field' }, el('span', {}, 'Name'), name),
      el('label', { class: 'field' }, el('span', {}, 'Members (names, separated by commas)'), members),
      el('div', { class: 'hint' }, 'They do not need to exist yet: a name becomes a person when they sign in. The group\'s key is created on your device and given to each member separately.'), err),
      [{ label: 'Cancel' }, { label: 'Create', kind: 'primary', fn: async () => {
        const list = members.value.split(/[,\s]+/).map(s => s.trim()).filter(Boolean).filter(n => n !== S.user);
        if (!name.value.trim()) { err.textContent = 'Give the group a name.'; return false; }
        if (!list.length || list.some(n => !NAME.test(n))) { err.textContent = 'Add at least one other person, using plain names.'; return false; }
        try { const id = await S.chat.create(name.value.trim(), list); selectConv(id); } catch (e) { err.textContent = errText(e); return false; }
      } }]);
  }

  // ---- the chat area ------------------------------------------------------------------------------------
  async function selectConv(id) {
    S.chat.active = id; store.set('conv:' + S.user, id); S.info = false;
    setView('chat');
    const c = S.chat.convs.get(id); if (!c) return;
    renderChatArea();
    try { await S.chat.open(id); } catch (e) { toast('Could not load the group: ' + errText(e), 'bad'); }
    if (S.chat.active === id) { renderChatArea(); S.chat.markRead(c); const m = S.ui.messages; if (m) m.scrollTop = m.scrollHeight; }
    renderList();
  }

  function renderChatArea() {
    const u = S.ui, c = S.chat.active && S.chat.convs.get(S.chat.active);
    u.app.classList.toggle('in-conv', !!c);
    if (!c) {
      u.main.replaceChildren(el('div', { class: 'hero' }, el('div', {}, icon('shield', 'lg'), el('h2', {}, 'Nothing here yet'), el('p', {}, 'Pick a group, or create one. Everything you send is encrypted in this browser before it leaves.'), el('button', { class: 'btn primary', onclick: newGroup }, icon('plus'), 'New group'))));
      return;
    }
    u.head = el('header', { class: 'main-head' });
    u.banner = el('div', {});
    u.messages = el('div', { class: 'messages', role: 'log', 'aria-label': 'Messages' });
    u.text = el('textarea', { rows: '1', placeholder: 'Write a message', 'aria-label': 'Message' });
    u.sendBtn = el('button', { class: 'send', 'aria-label': 'Send', disabled: true, onclick: send }, icon('send'));
    const file = el('input', { type: 'file', multiple: true, class: 'sr', tabindex: '-1', onchange: e => { sendFiles([...e.target.files]); e.target.value = ''; } });
    u.text.addEventListener('input', () => { u.text.style.height = 'auto'; u.text.style.height = Math.min(160, u.text.scrollHeight) + 'px'; u.sendBtn.disabled = !u.text.value.trim(); });
    u.text.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
    u.text.addEventListener('paste', e => { const fs = [...(e.clipboardData?.files || [])]; if (fs.length) { e.preventDefault(); sendFiles(fs); } });
    u.info = el('aside', { class: 'info', 'aria-label': 'Group info' });
    u.callLayer = el('div', { class: 'call', hidden: true });
    u.main.replaceChildren(u.head, el('div', { class: 'body-wrap' }, u.banner, u.messages), el('div', { class: 'composer' }, ibtn('clip', 'Attach files', () => file.click()), file, u.text, u.sendBtn), el('div', { class: 'drop' }, 'Drop files to send them encrypted'), u.info, u.callLayer);
    u.main.style.gridTemplateRows = 'auto 1fr auto';
    renderHeader(c); renderMessages(c); if (S.info) renderInfo(c);
    if (S.call && S.call.visible) showCallLayer();
  }

  function keyState(c) {
    const epoch = c.maxEpoch || c.epoch;
    return c.keys.has(epoch) ? { ok: true, epoch } : { ok: false, epoch };
  }

  function renderHeader(c) {
    const u = S.ui; if (!u.head) return;
    const k = keyState(c);
    u.head.replaceChildren(
      el('button', { class: 'icon-btn back', 'aria-label': 'Back to the list', onclick: () => { S.chat.active = null; renderChatArea(); renderList(); } }, icon('back')),
      avatar(c.name),
      el('div', { class: 'title' }, el('h2', { text: c.name }), el('small', {}, c.members.map(m => m.user).join(', '))),
      k.ok ? el('span', { class: 'chip ok', title: 'Messages are encrypted on your device with a key only members hold' }, icon('lock'), el('span', { class: 'lbl' }, 'End-to-end encrypted')) : el('span', { class: 'chip warn', title: 'Waiting for the group key' }, icon('clock'), el('span', { class: 'lbl' }, 'Waiting for the group key')),
      S.call && S.call.call.group === c.id ? el('button', { class: 'btn primary', onclick: showCallLayer }, icon('video'), 'Open call') : el('button', { class: 'btn', onclick: () => startCall(c), title: GroupCall.supported() ? '' : 'This browser cannot encrypt call media' }, icon('video'), 'Call'),
      ibtn('info', 'Group info', () => { S.info = !S.info; S.ui.info.classList.toggle('open', S.info); if (S.info) renderInfo(c); }, S.info ? 'on' : ''));
    u.banner.replaceChildren(...[...c.warnings].map(w => el('div', { class: 'banner bad' }, icon('alert'), el('div', { class: 'grow' }, `${w} is now using a different encryption key (a new device, or someone in between). Their new key is not trusted until you compare safety codes with ${w}.`),
      el('button', { class: 'btn sm', onclick: () => S.chat.trust(c, w) }, 'Trust new key'))),
      ...(k.ok ? [] : [el('div', { class: 'banner warn' }, icon('clock'), c.owner === S.user ? 'Creating the group key…' : 'The group key is made by the owner and given to you when they are online. Messages stay locked until then.')]));
  }

  const time = it => it.at ? fmtTime(it.at) : '';
  function stateMark(it) {
    if (it.state === 'sending') return el('span', { class: 'stamp', title: 'Sending' }, time(it), icon('clock', 'tiny'));
    if (it.state === 'failed') return el('span', { class: 'stamp', title: it.error }, 'Failed', icon('alert'));
    return el('span', { class: 'stamp' }, time(it), it.sender === S.user ? icon('check') : null);
  }

  function renderMessages(c) {
    const box = S.ui.messages; if (!box) return;
    const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
    const frag = document.createDocumentFragment();
    let day = '', prev = null;
    const admin = c.members.find(m => m.user === S.user && (m.role === 'owner' || m.role === 'admin'));
    for (const it of c.items) {
      const d = it.at ? fmtDay(it.at) : day;
      if (d !== day) { day = d; frag.append(el('div', { class: 'day', text: d })); prev = null; }
      const me = it.sender === S.user, cont = prev && prev.sender === it.sender && Math.abs(new Date(it.at) - new Date(prev.at)) < 5 * 60000;
      prev = it;
      let body;
      if (it.deleted) body = el('div', { class: 'bubble gone' }, 'Message deleted', stateMark(it));
      else if (it.state === 'locked') body = el('div', { class: 'bubble locked' }, icon('lock', 'tiny'), ' Waiting for the key to read this message', stateMark(it));
      else if (it.state === 'forged') body = el('div', { class: 'bubble forged' }, icon('alert', 'tiny'), ' This message could not be verified and was not shown', stateMark(it));
      else if (it.content?.t === 'file') body = el('div', { class: 'bubble' }, fileCard(c, it), stateMark(it));
      else body = el('div', { class: 'bubble' }, it.content?.text || '', stateMark(it));
      const tools = (me || admin) && it.seq && !it.deleted ? el('div', { class: 'tools' }, ibtn('trash', 'Delete message', async () => { try { await S.chat.remove_(c, it); } catch (e) { toast(errText(e), 'bad'); } })) : null;
      frag.append(el('div', { class: 'msg' + (me ? ' me' : '') + (cont ? ' cont' : ''), dataset: { seq: it.seq || '' } },
        me ? null : avatar(it.sender, 'sm'), el('div', {}, !me && !cont ? el('div', { class: 'who', text: it.sender }) : null, body), tools));
    }
    const mine = [...c.items].reverse().find(i => i.sender === S.user && i.seq);
    if (mine) { const seen = [...c.reads].filter(([u, s]) => u !== S.user && s >= mine.seq).map(([u]) => u); if (seen.length) frag.append(el('div', { class: 'seen', text: 'Seen by ' + seen.join(', ') })); }
    box.replaceChildren(frag);
    if (stick) box.scrollTop = box.scrollHeight;
  }

  function fileCard(c, it) {
    const f = it.content, wrap = el('div', {});
    const bar = el('div', { class: 'bar' }, el('i', {}));
    it.bar = bar.firstChild;
    const busy = it.state === 'sending';
    const btn = el('button', { class: 'btn', disabled: busy || !f.file, onclick: async e => {
      const b = e.currentTarget; b.disabled = true; b.textContent = 'Decrypting…';
      try { const bytes = await S.chat.download(c, it); const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' })); const a = el('a', { href: url, download: f.name }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000); }
      catch (err) { toast(err.code === 'corrupt' || err.code === 'forged' ? 'This file failed its integrity check and was not saved.' : errText(err), 'bad'); }
      b.disabled = false; b.replaceChildren(icon('download'), 'Save');
    } }, icon('download'), 'Save');
    const card = el('div', { class: 'file' }, el('div', { class: 'ico' }, icon('file')), el('div', {}, el('b', { text: f.name, title: f.name }), el('small', {}, fmtBytes(f.size) + (busy ? ' · ' + (it.phase === 'encrypting' ? 'encrypting…' : 'uploading ' + Math.round((it.progress || 0) * 100) + '%') : ' · encrypted'))), btn);
    if (busy) { it.bar.style.width = Math.round((it.progress || 0) * 100) + '%'; card.append(bar); }
    if (/^image\/(png|jpe?g|gif|webp)$/.test(f.type) && f.file && !busy && f.size < 6 * 1048576) {
      const key = f.file;
      if (!S.previews.has(key)) S.previews.set(key, S.chat.download(c, it).then(b => URL.createObjectURL(new Blob([b], { type: f.type }))).catch(() => null));
      S.previews.get(key).then(url => { if (url) wrap.prepend(el('img', { class: 'preview', src: url, alt: f.name })); });
    }
    wrap.append(card);
    return wrap;
  }

  async function send() {
    const c = S.chat.convs.get(S.chat.active), t = S.ui.text.value.trim();
    if (!c || !t) return;
    S.ui.text.value = ''; S.ui.text.style.height = 'auto'; S.ui.sendBtn.disabled = true;
    try { await S.chat.sendText(c, t); } catch (e) { toast(errText(e), 'bad'); }
    S.ui.text.focus();
  }
  async function sendFiles(files) {
    const c = S.chat.convs.get(S.chat.active); if (!c) return;
    for (const f of files) {
      if (f.size > 64 * 1048576) { toast(f.name + ' is larger than this demo allows (64 MB).', 'bad'); continue; }
      try { await S.chat.sendFile(c, f); } catch (e) { toast(`${f.name}: ${errText(e)}`, 'bad'); }
    }
  }

  // ---- group info --------------------------------------------------------------------------------------------
  async function renderInfo(c) {
    const box = S.ui.info; if (!box) return;
    box.classList.toggle('open', S.info);
    const code = await S.chat.safetyCode(c), k = keyState(c);
    const isAdmin = c.members.find(m => m.user === S.user && (m.role === 'owner' || m.role === 'admin'));
    const add = el('input', { class: 'input', placeholder: 'Add a person by name', autocapitalize: 'off', spellcheck: 'false' });
    box.replaceChildren(
      el('header', {}, el('h3', {}, 'Group info'), ibtn('x', 'Close', () => { S.info = false; box.classList.remove('open'); })),
      el('div', { class: 'body' },
        el('div', { class: 'card' }, el('h4', {}, 'Encryption'),
          el('div', { class: 'row' }, icon('lock'), el('div', { class: 'grow' }, k.ok ? `Key epoch ${k.epoch} held on this device` : 'No key yet'), k.ok ? el('span', { class: 'chip ok' }, 'active') : el('span', { class: 'chip warn' }, 'waiting')),
          el('small', { class: 'hint' }, 'A new key is made whenever someone is removed, so they cannot read what comes after. Someone added later can read the messages in the key they are given.')),
        el('div', { class: 'card' }, el('h4', {}, 'Safety code'),
          el('div', { class: 'mono', text: code }),
          el('small', { class: 'hint' }, 'Everyone in the group sees the same code. Read it to each other over a call or in person: if it matches, the service did not swap anyone\'s key.'),
          el('button', { class: 'btn sm', onclick: () => navigator.clipboard?.writeText(code).then(() => toast('Copied', 'ok', null, 1500)) }, icon('copy'), 'Copy')),
        el('div', { class: 'card' }, el('h4', {}, `Members · ${c.members.length}`),
          ...c.members.map(m => el('div', { class: 'row' }, avatar(m.user, 'sm'), el('div', { class: 'grow' }, m.user + (m.user === S.user ? ' (you)' : ''),
            el('div', {}, c.pubs.has(m.user) ? el('span', { class: 'chip' }, 'key verified on first use') : el('span', { class: 'chip warn' }, 'not seen yet'))),
            el('span', { class: 'chip ' + (m.role === 'owner' ? 'accent' : '') }, m.role),
            isAdmin && m.role !== 'owner' && m.user !== S.user ? el('button', { class: 'btn sm', onclick: async () => { try { await S.chat.remove(c, m.user); toast(m.user + ' removed and the key changed', 'ok'); } catch (e) { toast(errText(e), 'bad'); } } }, 'Remove') : null)),
          isAdmin ? el('div', { class: 'row' }, add, el('button', { class: 'btn sm primary', onclick: async () => { const n = add.value.trim(); if (!NAME.test(n)) return toast('Use a plain name', 'bad'); try { await S.chat.add(c, [n]); add.value = ''; } catch (e) { toast(errText(e), 'bad'); } } }, 'Add')) : null))
    );
  }

  // ---- calls -------------------------------------------------------------------------------------------------------------
  async function startCall(c) {
    if (S.call) return showCallLayer();
    if (!GroupCall.supported()) return toast('This browser cannot encrypt call media, so it will not join a call. Chat still works.', 'bad');
    try {
      const r = await S.rtc.call('group.call', { group: c.id, kind: 'video' });
      await joinCall(r.call, r.ice, c);
    } catch (e) { toast('Could not start the call: ' + errText(e), 'bad'); }
  }

  function onIncoming(p) {
    const call = p.call;
    if (call.mode !== 'sfu' || S.call) return;
    const c = S.chat.convs.get(call.group), name = c ? c.name : 'a group';
    const t = toast(`${call.initiator} is calling ${name}`, 'ring', [
      { label: 'Decline', fn: () => S.rtc.call('call.decline', { call: call.id }).catch(() => {}) },
      { label: 'Join', primary: true, fn: async () => { try { const r = await S.rtc.call('call.answer', { call: call.id }); await joinCall(r.call, r.ice || p.ice, c); } catch (e) { toast('Could not join: ' + errText(e), 'bad'); } } }], 45000);
    const off = S.rtc.on('call.ended', e => { if (e.call_id === call.id) { t.remove(); off(); } });
  }

  function tileFor(user, local) {
    let t = S.tiles.get(user);
    if (t) return t;
    const video = el('video', { autoplay: true, playsinline: true, muted: local || null });
    video.muted = !!local;
    video.addEventListener('playing', () => video.classList.add('live'));
    const node = el('div', { class: 'tile' + (local ? ' local' : ''), dataset: { user } }, video, avatar(user), el('div', { class: 'lock', title: 'Encrypted frame by frame; the server cannot see this picture' }, icon('lock', 'tiny'), 'E2EE'), el('div', { class: 'label', text: local ? 'You' : user }));
    t = { node, video }; S.tiles.set(user, t);
    S.ui.grid && S.ui.grid.append(node);
    return t;
  }

  async function joinCall(call, ice, c) {
    const gc = new GroupCall(S.rtc, call, ice);
    S.call = gc; S.tiles.clear(); gc.visible = true; gc.startedAt = Date.now();
    buildCallLayer(gc, c);
    gc.on('local', stream => { const t = tileFor(S.user, true); t.video.srcObject = stream; t.video.play().catch(() => {}); });
    gc.on('track', ({ user, stream }) => { const t = tileFor(user, false); if (t.video.srcObject !== stream) { t.video.srcObject = stream; t.video.play().catch(() => {}); } });
    gc.on('gone', u => { const t = S.tiles.get(u); if (t) { t.node.remove(); S.tiles.delete(u); } });
    gc.on('speaker', u => { for (const [n, t] of S.tiles) t.node.classList.toggle('speaking', n === u); });
    gc.on('state', s => { if (S.ui.callState) S.ui.callState.textContent = s; });
    gc.on('stats', st => { if (S.ui.callStats) S.ui.callStats.textContent = `↓ ${Math.round(st.in)} kbps  ↑ ${Math.round(st.out)} kbps  ·  ${Math.round(st.rtt)} ms  ·  ${st.enc} sent, ${st.dec} received, ${st.dropped} dropped (encrypted)`; });
    gc.on('warning', w => toast(w.message || ('Call warning: ' + w.type), 'bad', null, 8000));
    gc.on('left', () => { S.call = null; S.tiles.clear(); if (S.ui.callLayer) { S.ui.callLayer.hidden = true; S.ui.callLayer.replaceChildren(); } clearInterval(gc.timer); renderList(); const cc = S.chat.active && S.chat.convs.get(S.chat.active); if (cc) renderHeader(cc); });
    showCallLayer(); renderList();
    try { await gc.start(); const cc = c || S.chat.convs.get(call.group); if (cc) renderHeader(cc); gc.safetyCode().then(code => { if (S.ui.callCode) S.ui.callCode.textContent = 'Safety code ' + code; }); }
    catch (e) { toast('Could not join the call: ' + errText(e), 'bad', null, 9000); await gc.leave(true); }
  }

  function buildCallLayer(gc, c) {
    if (!S.ui.callLayer) return;
    const u = S.ui;
    u.grid = el('div', { class: 'grid' });
    u.callState = el('span', { class: 'chip' }, 'connecting');
    u.callStats = el('span', { class: 'chip' }, '');
    u.callCode = el('span', { class: 'chip ok', title: 'Compare this with the others in the call' }, 'Safety code …');
    u.timer = el('span', { class: 'chip' }, '00:00');
    clearInterval(gc.timer); gc.timer = setInterval(() => { const s = Math.floor((Date.now() - gc.startedAt) / 1000); u.timer.textContent = String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); }, 1000);
    const mic = el('button', { class: 'ctl', 'aria-label': 'Mute microphone', onclick: () => { gc.setMuted(!gc.muted); mic.classList.toggle('off', gc.muted); mic.replaceChildren(icon(gc.muted ? 'micOff' : 'mic')); } }, icon('mic'));
    const cam = el('button', { class: 'ctl', 'aria-label': 'Turn camera off', onclick: () => { const on = gc.camOn === false; gc.setCamera(on); cam.classList.toggle('off', !on); cam.replaceChildren(icon(on ? 'video' : 'videoOff')); } }, icon('video'));
    const leave = el('button', { class: 'ctl end', 'aria-label': 'Leave the call', onclick: () => gc.leave() }, icon('phone'));
    const group = c || S.chat.convs.get(gc.call.group);
    u.callLayer.replaceChildren(
      el('div', { class: 'call-top' }, el('div', { class: 'grow' }, el('b', { text: group ? group.name : 'Call' }), ' ', u.timer), el('span', { class: 'chip ok' }, icon('lock', 'tiny'), 'End-to-end encrypted'), u.callState, u.callCode,
        el('button', { class: 'btn sm ghost', onclick: hideCallLayer }, 'Back to chat')),
      u.grid,
      el('div', { class: 'controls' }, mic, cam, leave, u.callStats));
  }
  function showCallLayer() { if (!S.call) return; S.call.visible = true; if (S.ui.callLayer) { S.ui.callLayer.hidden = false; if (!S.ui.grid || !S.ui.grid.isConnected) { buildCallLayer(S.call); for (const [, t] of S.tiles) S.ui.grid.append(t.node); } } }
  function hideCallLayer() { if (S.call) S.call.visible = false; if (S.ui.callLayer) S.ui.callLayer.hidden = true; }

  // ---- diagnostics ---------------------------------------------------------------------------------------------------------------
  function renderTests() {
    const u = S.ui;
    u.main.style.gridTemplateRows = '1fr';
    u.run = el('button', { class: 'btn primary', onclick: runTests }, icon('play'), S.results ? 'Run again' : 'Run all checks');
    u.sum = el('div', { class: 'summary' });
    u.suites = el('div', { class: 'tests-suites', style: null });
    u.server = el('div', { class: 'card' });
    u.logbox = el('div', { class: 'log', role: 'log', 'aria-label': 'Event log' });
    u.main.replaceChildren(el('div', { class: 'tests' },
      el('div', { class: 'tests-head' }, el('div', { class: 'grow' }, el('h2', {}, 'Diagnostics'), el('div', { class: 'hint' }, 'Runs real requests, sockets and cryptography from this page against the service. It uses throwaway users and groups, so your conversations are not touched.')), u.run),
      u.sum, u.suites, el('div', { class: 'card' }, el('h4', {}, 'Service'), u.server), el('div', { class: 'card' }, el('h4', {}, 'Live events on your connection'), u.logbox)));
    paintResults(); refreshServer(); renderLog();
    clearInterval(S.serverTimer); S.serverTimer = setInterval(() => { if (S.view !== 'tests') clearInterval(S.serverTimer); else refreshServer(); }, 3000);
  }
  function paintResults() {
    const u = S.ui; if (!u.suites) return;
    const rs = S.results || SelfTest.checks.map(c => ({ group: c.group, name: c.name, state: 'pending' }));
    const groups = new Map();
    for (const r of rs) (groups.get(r.group) || groups.set(r.group, []).get(r.group)).push(r);
    u.suites.replaceChildren(...[...groups].map(([g, list]) => el('section', { class: 'suite', style: null },
      el('h3', {}, g), ...list.map(r => el('div', { class: 'check ' + r.state }, el('div', { class: 'st' }, r.state === 'pass' ? icon('check') : r.state === 'fail' ? icon('x') : r.state === 'skip' ? icon('alert') : null),
        el('div', {}, el('b', { text: r.name }), r.detail ? el('div', { class: 'detail', text: r.detail }) : null), el('span', { class: 'ms' }, r.ms != null ? r.ms + ' ms' : ''))))));
    const n = k => rs.filter(r => r.state === k).length;
    u.sum.replaceChildren(...[['Passed', n('pass')], ['Failed', n('fail')], ['Skipped', n('skip')], ['Total', rs.length]].map(([l, v]) => el('div', { class: 'stat' }, el('b', { text: String(v) }), el('span', {}, l))));
  }
  async function runTests() {
    if (S.running) return; S.running = true; S.ui.run.disabled = true;
    S.results = null;
    try { await SelfTest.run(r => { S.results = r.map(x => ({ ...x })); if (S.view === 'tests') paintResults(); }); } finally { S.running = false; if (S.ui.run) { S.ui.run.disabled = false; S.ui.run.replaceChildren(icon('play'), 'Run again'); } }
    const bad = (S.results || []).filter(r => r.state === 'fail').length;
    toast(bad ? bad + ' check(s) failed' : 'All checks passed', bad ? 'bad' : 'ok');
  }
  async function refreshServer() {
    try {
      const i = await (await fetch('/demo/info')).json();
      S.ui.server && S.ui.server.replaceChildren(el('div', { class: 'summary' }, ...[['Database', i.database + (i.node ? ' · ' + i.node : '')], ['Connections', i.connections], ['Open rooms', i.rooms], ['Events sent', i.events_sent], ['Dropped', i.events_dropped], ['Audit written', i.audit_written]].map(([l, v]) => el('div', { class: 'stat' }, el('b', { text: String(v) }), el('span', {}, l)))));
    } catch {}
  }
  function renderLog() {
    const b = S.ui.logbox; if (!b) return;
    const stick = b.scrollHeight - b.scrollTop - b.clientHeight < 40;
    b.replaceChildren(...S.log.slice(-80).map(e => el('div', {}, el('span', { class: 't', text: new Date(e.t).toLocaleTimeString() + '  ' }), el('span', { class: 'n', text: e.n }), '  ' + (e.from ? 'from ' + e.from + '  ' : '') + JSON.stringify(e.p, (k, v) => (typeof v === 'string' && v.length > 80 ? v.slice(0, 80) + '…' : v)).slice(0, 220))));
    if (stick) b.scrollTop = b.scrollHeight;
  }

  // ---- start ------------------------------------------------------------------------------------------------------------------------------
  window.addEventListener('beforeunload', () => { if (S.call) S.call.leave(true); });
  const saved = sess.get('user');
  if (saved) signIn(saved).catch(e => showLogin(errText(e))); else showLogin();
  window.__rtcd = S; // for the console and the browser tests
})();

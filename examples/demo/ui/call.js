/* call.js: a group video call through rtcd's SFU, end-to-end encrypted.
 *
 * Each frame is encrypted in a worker (RTCRtpScriptTransform, AES-GCM) before it
 * leaves the browser, so the SFU forwards what it cannot read. The people in the
 * call exchange the keys through the service as signed, pairwise-wrapped
 * messages (call.e2ee); e2ee-core.js does that. A browser without
 * RTCRtpScriptTransform cannot join: there is no unencrypted fallback.
 */
(function () {
  'use strict';
  const { idb, Emitter } = RTC;

  const payloadTypes = sdp => {
    const map = {};
    let kind = '';
    for (const line of sdp.split(/\r?\n/)) {
      const m = /^m=(\w+) /.exec(line);
      if (m) { kind = m[1]; continue; }
      const r = /^a=rtpmap:(\d+) ([\w-]+)\//.exec(line);
      if (r && kind) map[r[1]] = kind + '/' + r[2];
    }
    return map;
  };

  class Call extends Emitter {
    constructor(rtc, call, ice, opts) {
      super();
      this.rtc = rtc; this.me = rtc.user; this.call = call; this.id = call.id; this.ice = ice || [];
      this.video = (opts && opts.video) !== false && call.kind !== 'audio';
      this.room = new Set(); this.offers = Promise.resolve(); this.cands = []; this.remoteSet = false; this.joined = false;
      this.stats = { in: 0, out: 0, rtt: 0, enc: 0, dec: 0, dropped: 0 }; this.unsub = [];
      this.local = null; this.ended = false;
    }

    static supported() { return typeof RTCPeerConnection !== 'undefined' && typeof RTCRtpScriptTransform !== 'undefined' && !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia); }

    async start() {
      if (!Call.supported()) throw new RTC.RtcError('unsupported', 'this browser cannot encrypt media (RTCRtpScriptTransform); it will not join an unencrypted call');
      const store = pre => ({ get: k => idb.get(pre + this.me + ':' + k), set: (k, v) => idb.set(pre + this.me + ':' + k, v) });
      const identity = await E2EE.Identity.load(this.me, store('e2eeid:'));
      this.worker = new Worker('/e2ee-worker.js');
      this.worker.postMessage({ type: 'self', id: this.me });
      this.worker.onmessage = e => {
        const m = e.data;
        if (m.type === 'stats') { this.stats.enc = m.encrypted; this.stats.dec = m.decrypted; this.stats.dropped = m.dropped; this.stats.reasons = m.reasons; }
        else if (m.type === 'need') this.session.hello(m.user).catch(() => {});
        else if (m.type === 'error') this.emit('warning', { type: 'worker', message: m.message });
      };
      this.session = new E2EE.Session({
        callId: this.id, identity, pins: store('e2eepin:'),
        send: (to, text) => this.rtc.call('call.e2ee', { call: this.id, to, data: text }).catch(e => { if (e.code !== 'rate_limited') throw e; }),
        onKey: (user, kid, secret) => {
          if (user === null) this.worker.postMessage({ type: 'own', kid, secret });
          else if (!secret) this.worker.postMessage({ type: 'drop', user });
          else this.worker.postMessage({ type: 'peer', user, kid, secret });
        },
        onWarning: w => this.emit('warning', w),
      });

      // Who is in the room already.
      const cur = await this.rtc.call('call.get', { call: this.id });
      for (const p of cur.participants || []) if (p.state === 'joined' && p.user !== this.me) this.room.add(p.user);

      let stream = null;
      try { stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: this.video ? { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } } : false }); }
      catch (e) {
        try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); this.emit('warning', { type: 'camera', message: 'no camera: joined with audio only' }); }
        catch (e2) { this.emit('warning', { type: 'media', message: 'no microphone or camera: joined to watch and listen' }); }
      }
      this.local = stream;

      const pc = this.pc = new RTCPeerConnection({ iceServers: this.ice.map(s => ({ urls: s.urls, username: s.username, credential: s.credential })), bundlePolicy: 'max-bundle' });
      pc.onicecandidate = e => { if (e.candidate) this._cand(e.candidate); };
      pc.ontrack = ev => {
        const stream = ev.streams[0];
        if (!stream) return;
        const user = stream.id;
        ev.receiver.transform = new RTCRtpScriptTransform(this.worker, { op: 'decrypt', kind: ev.track.kind, sender: user });
        this.emit('track', { user, stream, kind: ev.track.kind });
      };
      pc.onconnectionstatechange = () => { this.emit('state', pc.connectionState); if (pc.connectionState === 'failed') this._restart().catch(() => {}); };

      await this.session.start([...this.room]);

      const audio = stream && stream.getAudioTracks()[0], video = stream && stream.getVideoTracks()[0];
      if (audio) { const t = pc.addTransceiver(audio, { direction: 'sendonly', streams: [stream] }); t.sender.transform = new RTCRtpScriptTransform(this.worker, { op: 'encrypt', kind: 'audio' }); }
      else pc.addTransceiver('audio', { direction: 'recvonly' });
      if (video) {
        const t = pc.addTransceiver(video, { direction: 'sendonly', streams: [stream], sendEncodings: [
          { rid: 'q', scaleResolutionDownBy: 4, maxBitrate: 150000 }, { rid: 'h', scaleResolutionDownBy: 2, maxBitrate: 500000 }, { rid: 'f', maxBitrate: 1200000 }] });
        t.sender.transform = new RTCRtpScriptTransform(this.worker, { op: 'encrypt', kind: 'video' });
      }
      if (stream) this.emit('local', stream);

      this.unsub.push(
        this.rtc.on('sfu.offer', p => { if (p.call_id === this.id) this.offers = this.offers.then(() => this._onOffer(p.sdp)).catch(e => this.emit('warning', { type: 'offer', message: e.message })); }),
        this.rtc.on('sfu.candidate', p => { if (p.call_id === this.id) this._remoteCand(p.candidate); }),
        this.rtc.on('call.e2ee', (p, from) => { if (p.call_id === this.id) this.session.receive(p.from || from, p.data); }),
        this.rtc.on('sfu.speaker', p => { if (p.call_id === this.id) this.emit('speaker', p.speaker); }),
        this.rtc.on('sfu.peer', p => { if (p.call_id === this.id) this._peers(p.state === 'joined' ? [p.user] : [], p.state === 'left' ? [p.user] : []); }),
        this.rtc.on('sfu.peers', p => { if (p.call_id === this.id) this._peers(p.joined || [], p.left || []); }),
        this.rtc.on('call.ended', p => { if ((p.call && p.call.id) === this.id || p.call_id === this.id || p.id === this.id) this.leave(true); }),
        this.rtc.on('reconnected', () => { if (this.joined) this.rtc.call('sfu.resync', { call: this.id }).catch(() => {}); }),
      );

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      const ans = await this.rtc.call('sfu.join', { call: this.id, sdp: offer.sdp, e2ee: true });
      this.worker.postMessage({ type: 'pt', map: payloadTypes(ans.sdp) });
      await pc.setRemoteDescription({ type: 'answer', sdp: ans.sdp });
      this.remoteSet = true; this.joined = true;
      await this.rtc.call('sfu.ready', { call: this.id });
      for (const c of this.cands.splice(0)) this._send(c);
      for (const c of this._early || []) pc.addIceCandidate(c).catch(() => {});
      this._early = [];
      this._poll(); this._statsTimer = setInterval(() => this._poll(), 1000);
      this.emit('joined');
    }

    _cand(c) { if (this.joined) this._send(c); else this.cands.push(c); }
    _send(c) { this.rtc.call('sfu.candidate', { call: this.id, candidate: c.toJSON ? c.toJSON() : c }).catch(() => {}); }
    _remoteCand(c) {
      if (!c) return;
      if (!this.remoteSet) (this._early = this._early || []).push(c);
      else this.pc.addIceCandidate(c).catch(() => {});
    }

    async _onOffer(sdp) {
      const pc = this.pc;
      if (!pc || this.ended) return;
      await pc.setRemoteDescription({ type: 'offer', sdp });
      this.worker.postMessage({ type: 'pt', map: payloadTypes(sdp) });
      await pc.setLocalDescription(await pc.createAnswer());
      await this.rtc.call('sfu.answer', { call: this.id, sdp: pc.localDescription.sdp });
    }

    async _restart() {
      if (this.ended || !this.pc) return;
      const offer = await this.pc.createOffer({ iceRestart: true });
      await this.pc.setLocalDescription(offer);
      const a = await this.rtc.call('sfu.restart', { call: this.id, sdp: offer.sdp });
      await this.pc.setRemoteDescription({ type: 'answer', sdp: a.sdp });
    }

    _peers(joined, left) {
      for (const u of joined) if (u !== this.me) this.room.add(u);
      for (const u of left) { this.room.delete(u); this.emit('gone', u); }
      this.session.membersChanged([...this.room]).catch(() => {});
      this.emit('members', [...this.room]);
    }

    async _poll() {
      if (!this.pc) return;
      try {
        const r = await this.pc.getStats();
        let inB = 0, outB = 0, rtt = 0;
        r.forEach(s => {
          if (s.type === 'inbound-rtp') inB += s.bytesReceived || 0;
          if (s.type === 'outbound-rtp') outB += s.bytesSent || 0;
          if (s.type === 'candidate-pair' && s.nominated && s.currentRoundTripTime) rtt = s.currentRoundTripTime * 1000;
        });
        const now = performance.now(), dt = this._t ? (now - this._t) / 1000 : 0;
        if (dt) { this.stats.in = Math.max(0, (inB - this._in) * 8 / dt / 1000); this.stats.out = Math.max(0, (outB - this._out) * 8 / dt / 1000); }
        this._t = now; this._in = inB; this._out = outB; this.stats.rtt = rtt;
        this.emit('stats', this.stats);
      } catch {}
    }

    setMuted(m) { if (this.local) for (const t of this.local.getAudioTracks()) t.enabled = !m; this.muted = m; }
    setCamera(on) { if (this.local) for (const t of this.local.getVideoTracks()) t.enabled = on; this.camOn = on; }
    async safetyCode() { return this.session ? this.session.safetyCode() : ''; }

    async leave(quiet) {
      if (this.ended) return; this.ended = true;
      clearInterval(this._statsTimer);
      for (const u of this.unsub) u();
      if (!quiet) await this.rtc.call('sfu.leave', { call: this.id }).catch(() => {});
      if (this.local) for (const t of this.local.getTracks()) t.stop();
      if (this.pc) this.pc.close();
      if (this.worker) this.worker.terminate();
      this.emit('left');
    }
  }

  window.GroupCall = Call;
})();

// Encrypts the frames this browser sends and decrypts the frames it receives,
// in a worker, so the media never leaves the browser in the clear and the keys
// never leave this worker's memory except into the page that made them.
//
// A frame that cannot be processed (no key yet, tampered, replayed, not
// encrypted at all) is DROPPED. It is never passed on as it came.
importScripts('/e2ee-core.js');

const ring = new E2EE.KeyRing('');
const stats = { encrypted: 0, decrypted: 0, dropped: 0, reasons: {} };
let payloadTypes = {};
let lastNeed = {};

self.onmessage = async e => {
  const m = e.data;
  try {
    if (m.type === 'self') ring.selfId = m.id;
    else if (m.type === 'own') await ring.setOwn(m.kid, m.secret);
    else if (m.type === 'peer') await ring.setPeer(m.user, m.kid, m.secret);
    else if (m.type === 'drop') ring.dropPeer(m.user);
    else if (m.type === 'pt') payloadTypes = m.map;
  } catch (err) { self.postMessage({ type: 'error', message: String(err) }); }
};

self.onrtctransform = event => {
  const t = event.transformer, o = t.options;
  t.readable.pipeThrough(new TransformStream({
    async transform(frame, controller) {
      try {
        const meta = frame.getMetadata ? frame.getMetadata() : {};
        const codec = payloadTypes[meta.payloadType] || (o.kind === 'audio' ? 'audio/opus' : '');
        const isKey = frame.type === 'key';
        const data = new Uint8Array(frame.data);
        let out;
        if (o.op === 'encrypt') { out = await E2EE.encryptFrame(ring, o.kind, codec, isKey, data); stats.encrypted++; }
        else { out = await E2EE.decryptFrame(ring, o.sender, o.kind, codec, isKey, data); stats.decrypted++; }
        frame.data = out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
        controller.enqueue(frame);
      } catch (err) {
        stats.dropped++;
        const why = (err && err.code) || 'error';
        stats.reasons[why] = (stats.reasons[why] || 0) + 1;
        // No key from this sender yet: ask once in a while, not for every frame.
        if (why === 'nokey' && o.op === 'decrypt' && Date.now() - (lastNeed[o.sender] || 0) > 2000) {
          lastNeed[o.sender] = Date.now();
          self.postMessage({ type: 'need', user: o.sender });
        }
      }
    },
  })).pipeTo(t.writable);
};

setInterval(() => self.postMessage({ type: 'stats', ...stats }), 1000);

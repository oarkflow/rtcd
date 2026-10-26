// Regenerates vectors.json: things chat-core.js made, for other implementations
// (clients/dart) to open. Run only when the format changes on purpose:
//   node web/test/make-vectors.js > web/test/vectors.json
const C = require('../chat-core.js');
const { webcrypto } = require('node:crypto');
(async () => {
  const jwkD = async id => (await webcrypto.subtle.exportKey('jwk', id.privateKey)).d;
  const key = C.newKey();
  const msg = { conv: 'grp_vec', sender: 'ada', id: 'm-1', plaintext: 'héllo 👋 from JS' };
  const body = await C.encryptMessage(key, msg, msg.plaintext);

  const sender = await C.newIdentity(), recipient = await C.newIdentity();
  const epochKey = C.newKey();
  const wrapped = await C.wrapEpochKey(sender.privateKey, sender.publicRaw, recipient.publicRaw, 'grp_vec', 7, epochKey);
  const legacy = await C.wrapKey(sender.privateKey, sender.publicRaw, recipient.publicRaw, 'grp_vec', epochKey);

  const plain = new Uint8Array(3000).map((_, i) => (i * 31 + 7) & 255);
  const enc = await C.encryptFile('grp_vec', plain);

  const pubs = [sender.publicRaw, recipient.publicRaw];
  console.log(JSON.stringify({
    note: 'made by web/chat-core.js; see make-vectors.js',
    message: { key: C.b64(key), ...msg, body },
    wrap: { conv: 'grp_vec', epoch: 7, key: C.b64(epochKey), wrapped, legacy,
      sender: { pub: C.b64(sender.publicRaw), d: await jwkD(sender) }, recipient: { pub: C.b64(recipient.publicRaw), d: await jwkD(recipient) } },
    file: { conv: 'grp_vec', meta: enc.meta, cipher: C.b64(enc.cipher), plain: C.b64(plain) },
    safety: { pubs: pubs.map(C.b64), code: await C.safetyCode(pubs) },
  }, null, 1));
})();

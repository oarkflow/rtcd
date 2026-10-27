import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:rtcd_chat/rtcd_chat.dart';
import 'package:test/test.dart';

Map<String, dynamic> vectors() => jsonDecode(File('../../web/test/vectors.json').readAsStringSync()) as Map<String, dynamic>;

DeviceIdentity ident(Map<String, dynamic> side) => DeviceIdentity(unb64(side['d']), unb64(side['pub']));

void main() {
  group('what web/chat-core.js made', () {
    final v = vectors();

    test('a message opens', () async {
      final m = v['message'] as Map<String, dynamic>;
      expect(await decryptMessage(unb64(m['key']), conv: m['conv'], sender: m['sender'], id: m['id'], body: m['body']), m['plaintext']);
      for (final bad in [
        {'conv': 'other', 'sender': m['sender'], 'id': m['id']},
        {'conv': m['conv'], 'sender': 'eve', 'id': m['id']},
        {'conv': m['conv'], 'sender': m['sender'], 'id': 'm-2'},
      ]) {
        await expectLater(decryptMessage(unb64(m['key']), conv: bad['conv']!, sender: bad['sender']!, id: bad['id']!, body: m['body']), throwsA(isA<ChatCryptoException>().having((e) => e.code, 'code', 'forged')));
      }
    });

    test('a wrapped epoch key opens, and only for its conversation, epoch and recipient', () async {
      final w = v['wrap'] as Map<String, dynamic>;
      final me = ident(w['recipient']);
      final sender = unb64(w['sender']['pub']);
      expect(b64(await unwrapEpochKey(me, sender, w['conv'], w['epoch'], w['wrapped'])), w['key']);
      await expectLater(unwrapEpochKey(me, sender, 'other', w['epoch'], w['wrapped']), throwsA(isA<ChatCryptoException>()));
      await expectLater(unwrapEpochKey(me, sender, w['conv'], w['epoch'] + 1, w['wrapped']), throwsA(isA<ChatCryptoException>()));
      await expectLater(unwrapEpochKey(await DeviceIdentity.generate(), sender, w['conv'], w['epoch'], w['wrapped']), throwsA(isA<ChatCryptoException>()));
    });

    test('a small file opens, and the safety code agrees', () async {
      final f = v['file'] as Map<String, dynamic>;
      final meta = FileMeta.fromJson((f['meta'] as Map).cast());
      expect(await openFilePart(f['conv'], meta, 0, unb64(f['cipher'])), unb64(f['plain']));
      final s = v['safety'] as Map<String, dynamic>;
      expect(await safetyCode([for (final p in s['pubs']) unb64(p)]), s['code']);
    });
  });

  test('a public key that is not on the curve is refused', () async {
    final me = await DeviceIdentity.generate();
    final bad = Uint8List.fromList(me.publicRaw)..[64] ^= 1;
    await expectLater(wrapEpochKey(me, bad, 'c', 1, newKey()), throwsA(isA<ChatCryptoException>().having((e) => e.code, 'code', 'bad_wrap')));
    await expectLater(wrapEpochKey(me, Uint8List(65), 'c', 1, newKey()), throwsA(isA<ChatCryptoException>()));
  });

  test('an identity made from a scalar is the same every time, and works like any other', () async {
    final seed = List<int>.generate(48, (i) => (i * 5 + 1) & 255);
    final a = await DeviceIdentity.fromScalar(seed), b = await DeviceIdentity.fromScalar(seed);
    expect(a.publicRaw, b.publicRaw);
    expect(a.publicRaw.length, 65);
    expect(a.publicRaw[0], 4);
    expect((await DeviceIdentity.fromScalar(List.filled(48, 7))).publicRaw, isNot(a.publicRaw));
    final peer = await DeviceIdentity.generate();
    final key = newKey();
    final w = await wrapEpochKey(peer, a.publicRaw, 'c', 1, key);
    expect(await unwrapEpochKey(a, peer.publicRaw, 'c', 1, w), key);
    // the web client can open what it wraps: the public point must be on the curve (agree() checks)
    final w2 = await wrapEpochKey(a, peer.publicRaw, 'c', 2, key);
    expect(await unwrapEpochKey(peer, a.publicRaw, 'c', 2, w2), key);
  });

  group('round trips', () {
    test('a message', () async {
      final k = newKey();
      final body = await encryptMessage(k, conv: 'c', sender: 'ada', id: '1', text: 'héllo 👋');
      expect(body, startsWith('m1.'));
      expect(await decryptMessage(k, conv: 'c', sender: 'ada', id: '1', body: body), 'héllo 👋');
      await expectLater(encryptMessage(k, conv: 'c', sender: 'ada', id: '1', text: 'x' * (maxInline + 1)), throwsA(isA<ChatCryptoException>().having((e) => e.code, 'code', 'too_large')));
    });

    test('an identity through JSON, and a wrap between two devices', () async {
      final ada = await DeviceIdentity.generate(), bob = await DeviceIdentity.generate();
      final back = DeviceIdentity.fromJson(jsonDecode(jsonEncode(bob.toJson())));
      final key = newKey();
      final w = await wrapEpochKey(ada, bob.publicRaw, 'c', 2, key);
      expect(await unwrapEpochKey(back, ada.publicRaw, 'c', 2, w), key);
    });

    test('a file of three chunks, prepared one chunk at a time', () async {
      final data = Uint8List.fromList(List.generate(chunkSize * 2 + 777, (i) => (i * 7 + 3) & 255));
      final prep = await prepareFile('c', BytesSource(data));
      expect(prep.count, 3);
      final out = BytesBuilder();
      var stored = 0;
      for (var i = 0; i < prep.count; i++) {
        final p = await prep.part(i);
        stored += p.length;
        if (i < 2) expect(p.length, prep.chunk);
        out.add(await openFilePart('c', prep.meta, i, p));
      }
      expect(stored, prep.size);
      expect(out.toBytes(), data);
      await expectLater(openFilePart('other', prep.meta, 0, await prep.part(0)), throwsA(isA<ChatCryptoException>()));
      await expectLater(openFilePart('c', prep.meta, 1, await prep.part(0)), throwsA(isA<ChatCryptoException>()), reason: 'a part moved to another place');
    });
  });
}

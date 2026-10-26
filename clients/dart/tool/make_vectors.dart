// Things the Dart client made, for web/test/chat-core.test.js to open:
//   dart run tool/make_vectors.dart > ../../web/test/vectors-dart.json
import 'dart:convert';
import 'dart:typed_data';

import 'package:rtcd_chat/rtcd_chat.dart';

Future<void> main() async {
  final key = newKey();
  const conv = 'grp_vec', sender = 'bob', id = 'd-1', text = 'héllo from Dart 🎯';
  final body = await encryptMessage(key, conv: conv, sender: sender, id: id, text: text);
  final a = await DeviceIdentity.generate(), b = await DeviceIdentity.generate();
  final wrapped = await wrapEpochKey(a, b.publicRaw, conv, 5, key);
  final plain = Uint8List.fromList(List.generate(3000, (i) => (i * 13 + 1) & 255));
  final prep = await prepareFile(conv, BytesSource(plain));
  print(const JsonEncoder.withIndent(' ').convert({
    'note': 'made by clients/dart/tool/make_vectors.dart',
    'message': {'key': b64(key), 'conv': conv, 'sender': sender, 'id': id, 'plaintext': text, 'body': body},
    'wrap': {'conv': conv, 'epoch': 5, 'key': b64(key), 'wrapped': wrapped, 'sender': {'pub': a.publicB64}, 'recipient': {'pub': b.publicB64, 'd': b64(b.d)}},
    'file': {'conv': conv, 'meta': prep.meta.toJson(), 'cipher': b64(await prep.part(0)), 'plain': b64(plain)},
  }));
}

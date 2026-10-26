// Drives the Dart client against a real rtcd process (builds ../../cmd/rtcd),
// including a JavaScript peer. Skipped when RTCD_LIVE=0 or Go/Node are missing.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:rtcd_chat/rtcd_chat.dart';
import 'package:test/test.dart';

const key = 'dart-live-service-key-0123456789', secret = 'dart-live-token-secret-0123456789ab';
late String dir, base;
late Process rtcd;
final h = http.Client();

Future<Map<String, Object?>> svc(String path, Map<String, Object?> body, {String? user}) async {
  final r = await h.post(Uri.parse('$base$path'), headers: {'Authorization': 'Bearer $key', 'Content-Type': 'application/json', if (user != null) 'X-RTC-User': user}, body: jsonEncode(body));
  if (r.statusCode ~/ 100 != 2) throw httpError(r);
  return (jsonDecode(r.body) as Map).cast();
}

Future<String> token(String user) async => (await svc('/v1/tokens', {'user': user, 'ttl_seconds': 600}))['token'] as String;

Future<bool> tool(String name) async => (await Process.run('which', [name])).exitCode == 0;

Future<({RtcdConnection conn, ChatClient chat})> person(String user, String device) async {
  final conn = await RtcdConnection.connect(Uri.parse(base), await token(user));
  final chat = ChatClient.on(conn, user: user, device: device, identity: await DeviceIdentity.generate(), cert: 'vouched', verifyDevice: (d) => d.cert == 'vouched', jitter: Duration.zero);
  chat.listen(conn);
  await chat.start();
  return (conn: conn, chat: chat);
}

/// The next [name] event, optionally only one from [from] (a sender also hears itself).
Future<RtcdEvent> next(RtcdConnection c, String name, {String? from}) => c.events.firstWhere((e) => e.name == name && (from == null || e.data['sender'] == from)).timeout(const Duration(seconds: 8));

void main() {
  final skip = Platform.environment['RTCD_LIVE'] == '0';
  setUpAll(() async {
    if (skip || !await tool('go') || !await tool('node')) return;
    dir = Directory.systemTemp.createTempSync('rtcd-dart-').path;
    final root = Directory('../..').absolute.path;
    final b = await Process.run('go', ['build', '-o', '$dir/rtcd', './cmd/rtcd'], workingDirectory: root);
    if (b.exitCode != 0) fail('go build: ${b.stderr}');
    final s = await ServerSocket.bind('127.0.0.1', 0);
    final port = s.port;
    await s.close();
    File('$dir/rtcd.bcl').writeAsStringSync('''
listen "127.0.0.1:$port"
insecure_http true
database { driver "sqlite"  dsn "file:$dir/r.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" }
key "chat" { key "$key"  tenant "acme" }
token_secret "$secret"
attach_dir "$dir/att"
''');
    rtcd = await Process.start('$dir/rtcd', ['-config', '$dir/rtcd.bcl'], workingDirectory: dir);
    rtcd.stderr.drain<void>();
    rtcd.stdout.drain<void>();
    base = 'http://127.0.0.1:$port';
    for (var i = 0; i < 100; i++) {
      try {
        if ((await h.get(Uri.parse('$base/healthz'))).statusCode == 200) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('rtcd did not start');
  });
  tearDownAll(() {
    if (!skip) rtcd.kill();
  });

  test('keys, rekey on removal, and a large attachment', () async {
    const conv = 'dart-1';
    final ada = await person('ada', 'a1'), bob = await person('bob', 'b1'), cy = await person('cy', 'c1');
    await svc('/v1/conversations/open', {'id': conv, 'members': ['ada', 'bob', 'cy']});

    final bobMsg = next(bob.conn, 'msg.new');
    final sent = await ada.chat.send(conv, 'hello from dart');
    expect(sent['epoch'], 1);
    final ev = WireMessage.fromJson((await bobMsg).data);
    expect(await bob.chat.open(conv, ev), 'hello from dart');
    final forged = WireMessage(seq: ev.seq, id: ev.id, sender: 'cy', body: ev.body, epoch: ev.epoch, deleted: false);
    await expectLater(bob.chat.open(conv, forged), throwsA(isA<ChatCryptoException>().having((e) => e.code, 'code', 'forged')));

    // An attachment of two and a bit chunks, uploaded and downloaded chunk by chunk.
    final data = Uint8List.fromList(List.generate(chunkSize * 2 + 4321, (i) => (i * 11 + 5) & 255));
    final att = await ada.chat.attach(conv, BytesSource(data));
    final out = BytesBuilder();
    await for (final c in bob.chat.fetchAttachment(conv, att.file, att.meta)) {
      out.add(c);
    }
    expect(out.toBytes(), data);

    // cy is removed; the next message is under a new epoch and cy cannot read it.
    final rekey = next(ada.conn, 'conv.rekey');
    await svc('/v1/conversations/remove', {'id': conv, 'members': ['cy']});
    await rekey;
    final bob2 = next(bob.conn, 'msg.new');
    final s2 = await ada.chat.send(conv, 'cy is gone');
    expect(s2['epoch'], 2);
    expect(await bob.chat.open(conv, WireMessage.fromJson((await bob2).data)), 'cy is gone');
    await expectLater(cy.conn.call('msg.history', {'conv': conv}), throwsA(isA<RtcdException>().having((e) => e.code, 'code', 'forbidden')));
    for (final p in [ada, bob, cy]) {
      await p.conn.close();
    }
  }, skip: skip);

  test('a device nobody vouches for is never wrapped for', () async {
    const conv = 'dart-2';
    final conn = await RtcdConnection.connect(Uri.parse(base), await token('zed'));
    final zed = ChatClient.on(conn, user: 'zed', device: 'z1', identity: await DeviceIdentity.generate(), cert: 'forged', verifyDevice: (d) => d.cert == 'vouched', jitter: Duration.zero);
    await zed.start();
    await svc('/v1/conversations/open', {'id': conv, 'members': ['zed']});
    await expectLater(zed.send(conv, 'x'), throwsA(isA<RtcdException>().having((e) => e.code, 'code', 'members_without_keys')));
    await conn.close();
  }, skip: skip);

  test('Dart and JavaScript in one conversation', () async {
    const conv = 'dart-3';
    final root = Directory('../..').absolute.path;
    final peer = await Process.start('node', ['$root/web/test/js_peer.js', base, await token('jo'), 'jo', 'j1', conv]);
    final lines = peer.stdout.transform(utf8.decoder).transform(const LineSplitter()).asBroadcastStream();
    peer.stderr.transform(utf8.decoder).listen((l) => stderr.write('js peer: $l'));
    await lines.firstWhere((l) => l == 'READY').timeout(const Duration(seconds: 10));
    final dee = await person('dee', 'd1');
    await svc('/v1/conversations/open', {'id': conv, 'members': ['dee', 'jo']});
    final got = lines.firstWhere((l) => l.startsWith('GOT ')).timeout(const Duration(seconds: 10));
    final reply = next(dee.conn, 'msg.new', from: 'jo');
    await dee.chat.send(conv, 'ping from dart');
    expect(await got, 'GOT ping from dart');
    expect(await dee.chat.open(conv, WireMessage.fromJson((await reply).data)), 'pong from js');
    await dee.conn.close();
  }, skip: skip);
}

/// End-to-end encrypted conversations over rtcd's key directory: the same
/// protocol as web/chat-client.js. See that file for the model.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'connection.dart';
import 'crypto.dart';

/// A device as the service lists it.
class DirectoryDevice {
  DirectoryDevice(this.user, this.device, this.pub, this.cert);
  final String user, device, pub, cert;

  factory DirectoryDevice.fromJson(Map<String, Object?> j) => DirectoryDevice(
      '${j['user']}', '${j['device']}', '${j['pub']}', '${j['cert'] ?? ''}');
}

/// Decides whether the application vouches for a device's key (check [cert]
/// against your own identity system). A rejected key is never wrapped for, and
/// a wrap made by a rejected device is never opened.
typedef VerifyDevice = FutureOr<bool> Function(DirectoryDevice device);

/// Keeps the keys this device has been given. Back it with secure storage.
abstract class KeyStore {
  Future<Uint8List?> get(String conv, int epoch);
  Future<void> set(String conv, int epoch, Uint8List key);
  Future<List<int>> epochs(String conv);
}

class MemoryKeyStore implements KeyStore {
  final _m = <String, Uint8List>{};
  @override
  Future<Uint8List?> get(String conv, int epoch) async =>
      _m['$conv\u0000$epoch'];
  @override
  Future<void> set(String conv, int epoch, Uint8List key) async =>
      _m['$conv\u0000$epoch'] = key;
  @override
  Future<List<int>> epochs(String conv) async => [
        for (final k in _m.keys)
          if (k.startsWith('$conv\u0000'))
            int.parse(k.substring(conv.length + 1))
      ];
}

/// Thrown by [ChatClient.ensure] when the conversation has a key this device
/// has not been given yet; wait for an `epoch.granted` event and try again.
class AwaitingKey implements Exception {
  AwaitingKey(this.epoch);
  final int epoch;
  @override
  String toString() => 'AwaitingKey(epoch $epoch)';
}

/// A message as `msg.history` and `msg.new` carry it.
class WireMessage {
  WireMessage(
      {required this.seq,
      required this.id,
      required this.sender,
      required this.body,
      required this.epoch,
      required this.deleted,
      this.sentAt = ''});
  final int seq, epoch;
  final String id, sender, body, sentAt;
  final bool deleted;

  factory WireMessage.fromJson(Map<String, Object?> j) => WireMessage(
      seq: (j['seq'] as num).toInt(),
      id: '${j['id']}',
      sender: '${j['sender']}',
      body: '${j['body'] ?? ''}',
      epoch: ((j['epoch'] ?? 0) as num).toInt(),
      deleted: j['deleted'] == true,
      sentAt: '${j['sent_at'] ?? ''}');
}

/// Thrown by [ChatClient.open] when this device has not been given the key a message was sealed under (yet).
/// Wait for an `epoch.granted` event and open it again.
class NoKeyYet implements Exception {
  NoKeyYet(this.epoch);
  final int epoch;
  @override
  String toString() => 'NoKeyYet(epoch $epoch)';
}

class ChatClient {
  ChatClient({
    required this.call,
    required this.user,
    required this.device,
    required this.identity,
    this.cert = '',
    this.verifyDevice,
    this.insecureTrustService = false,
    KeyStore? store,
    this.jitter = const Duration(milliseconds: 400),
    this.http_,
    this.apiBase,
    this.apiHeaders,
  }) : store = store ?? MemoryKeyStore() {
    if (verifyDevice == null && !insecureTrustService) {
      throw ArgumentError(
          'ChatClient needs verifyDevice (or insecureTrustService: true)');
    }
  }

  /// Builds a client on a connection.
  factory ChatClient.on(RtcdConnection c,
          {required String user,
          required String device,
          required DeviceIdentity identity,
          String cert = '',
          VerifyDevice? verifyDevice,
          bool insecureTrustService = false,
          KeyStore? store,
          Duration jitter = const Duration(milliseconds: 400)}) =>
      ChatClient(
          call: c.call,
          user: user,
          device: device,
          identity: identity,
          cert: cert,
          verifyDevice: verifyDevice,
          insecureTrustService: insecureTrustService,
          store: store,
          jitter: jitter,
          http_: c.httpClient,
          apiBase: c.base,
          apiHeaders: () => c.authHeaders);

  final CallFn call;
  final String user, device, cert;
  final DeviceIdentity identity;
  final VerifyDevice? verifyDevice;
  final bool insecureTrustService;
  final KeyStore store;
  final Duration jitter;
  final http.Client? http_;
  final Uri? apiBase;
  final Map<String, String> Function()? apiHeaders;

  final known = <String>{};
  final _rotating = <String, Future<int>>{};
  final _rnd = Random();

  /// Errors from handling events (a failed rotation, say) are reported here.
  void Function(Object error)? onError;

  Future<void> start() => call('key.publish',
      {'device': device, 'pub': identity.publicB64, 'cert': cert});

  Future<bool> _trusted(DirectoryDevice d) async {
    if (verifyDevice == null) return true;
    try {
      return await verifyDevice!(d);
    } catch (_) {
      return false;
    }
  }

  /// Fetches and opens the keys made for this device. Returns the service's
  /// view of the conversation's epoch.
  Future<({int epoch, bool rekeyRequired})> sync(String conv) async {
    known.add(conv);
    final r =
        await call('epoch.get', {'conv': conv, 'device': device, 'since': 0});
    for (final w in (r['wraps'] as List? ?? const [])) {
      final m = (w as Map).cast<String, Object?>();
      final epoch = (m['epoch'] as num).toInt();
      if (await store.get(conv, epoch) != null) continue;
      if (m['by_revoked'] == true) continue;
      final by = DirectoryDevice('${m['by']}', '${m['by_device']}',
          '${m['by_pub'] ?? ''}', '${m['by_cert'] ?? ''}');
      if (by.pub.isEmpty || !await _trusted(by)) continue;
      try {
        await store.set(
            conv,
            epoch,
            await unwrapEpochKey(
                identity, unb64(by.pub), conv, epoch, '${m['w']}'));
      } on ChatCryptoException {
        // not for us, or forged
      }
    }
    return (
      epoch: (r['epoch'] as num).toInt(),
      rekeyRequired: r['rekey_required'] == true
    );
  }

  /// Makes the next epoch: a new key wrapped for every trusted device of every member.
  Future<int> rotate(String conv) =>
      _rotating[conv] ??= _rotate(conv).whenComplete(() {
        _rotating.remove(
            conv); // a block body: returning the future would make it wait for itself
      });

  Future<int> _rotate(String conv) async {
    final st = await sync(conv);
    if (st.epoch > 0 &&
        !st.rekeyRequired &&
        await store.get(conv, st.epoch) != null) return st.epoch;
    final devs =
        ((await call('key.list', {'conv': conv}))['devices'] as List? ??
                const [])
            .map((d) => DirectoryDevice.fromJson((d as Map).cast()))
            .toList();
    final epoch = st.epoch + 1, key = newKey();
    final wraps = <Map<String, Object?>>[];
    for (final d in devs) {
      if (await _trusted(d))
        wraps.add({
          'user': d.user,
          'device': d.device,
          'w': await wrapEpochKey(identity, unb64(d.pub), conv, epoch, key)
        });
    }
    try {
      await call('epoch.rotate',
          {'conv': conv, 'device': device, 'epoch': epoch, 'wraps': wraps});
    } on RtcdException catch (e) {
      if (e.code == 'stale_epoch')
        return (await sync(conv)).epoch; // lost the race: use the winner's
      rethrow;
    }
    await store.set(conv, epoch, key);
    return epoch;
  }

  /// Makes sure a key for the current epoch is held, making a new epoch if one is needed.
  Future<({int epoch, Uint8List key})> ensure(String conv) async {
    var st = await sync(conv);
    if (st.epoch == 0 || st.rekeyRequired) {
      await rotate(conv);
      st = await sync(conv);
    }
    final key = await store.get(conv, st.epoch);
    if (key == null) throw AwaitingKey(st.epoch);
    return (epoch: st.epoch, key: key);
  }

  /// Gives devices that lack the current key (new members, new devices) a wrap of it.
  /// With [history], also the older keys this device holds.
  Future<int> grant(String conv, {bool history = false}) async {
    final m = await call('epoch.missing', {'conv': conv});
    final devs = (m['devices'] as List? ?? const [])
        .map((d) => DirectoryDevice.fromJson((d as Map).cast()))
        .toList();
    final current = (m['epoch'] as num).toInt();
    if (devs.isEmpty || current == 0 || await store.get(conv, current) == null)
      return 0;
    final epochs = [
      current,
      if (history) ...(await store.epochs(conv)).where((e) => e < current)
    ];
    var added = 0;
    for (final epoch in epochs) {
      final k = (await store.get(conv, epoch))!;
      final wraps = <Map<String, Object?>>[];
      for (final d in devs) {
        if (await _trusted(d))
          wraps.add({
            'user': d.user,
            'device': d.device,
            'w': await wrapEpochKey(identity, unb64(d.pub), conv, epoch, k)
          });
      }
      if (wraps.isNotEmpty)
        added += ((await call('epoch.grant', {
          'conv': conv,
          'device': device,
          'epoch': epoch,
          'wraps': wraps
        }))['added'] as num)
            .toInt();
    }
    return added;
  }

  String _id() => hexOf(randomBytes(12));

  /// Encrypts and sends a message; retries with a fresh key if the epoch moved.
  /// Returns the answer (`seq`, `sent_at`, …) plus `id` and `epoch`.
  Future<Map<String, Object?>> send(String conv, String text,
      {int ttlSeconds = 0, String? id}) async {
    final mid = id ?? _id();
    for (var attempt = 0;; attempt++) {
      final k = await ensure(conv);
      final body = await encryptMessage(k.key,
          conv: conv, sender: user, id: mid, text: text);
      try {
        final r = await call('msg.send', {
          'conv': conv,
          'id': mid,
          'body': body,
          'epoch': k.epoch,
          'ttl': ttlSeconds
        });
        return {...r, 'id': mid, 'epoch': k.epoch};
      } on RtcdException catch (e) {
        if ((e.code == 'stale_epoch' || e.code == 'rekey_required') &&
            attempt < 3) continue;
        rethrow;
      }
    }
  }

  /// Decrypts a message; null for a deleted one. Throws [ChatCryptoException]
  /// `forged` for one that was altered or is not from its claimed sender.
  Future<String?> open(String conv, WireMessage m) async {
    if (m.deleted) return null;
    var key = await store.get(conv, m.epoch);
    if (key == null && m.epoch > 0) {
      await sync(conv);
      key = await store.get(conv, m.epoch);
    }
    if (key == null) throw NoKeyYet(m.epoch);
    return decryptMessage(key,
        conv: conv, sender: m.sender, id: m.id, body: m.body);
  }

  /// Encrypts a file a chunk at a time and uploads it. Put the result inside an
  /// encrypted message.
  Future<({String file, FileMeta meta})> attach(String conv, FileSource source,
      {void Function(double)? onProgress}) async {
    final h = http_, base = apiBase, hdr = apiHeaders;
    if (h == null || base == null || hdr == null)
      throw StateError('attachments need an HTTP client and base');
    final prep = await prepareFile(conv, source);
    Future<Map<String, Object?>> json(http.Response r) async {
      if (r.statusCode ~/ 100 != 2) throw httpError(r);
      return r.body.isEmpty ? {} : (jsonDecode(r.body) as Map).cast();
    }

    final init = await json(await h.post(apiUrl(base, '/v1/files'),
        headers: {...hdr(), 'Content-Type': 'application/json'},
        body: jsonEncode({
          'conv': conv,
          'size': prep.size,
          'sha256': prep.sha256,
          'chunk': prep.chunk
        })));
    final id = ((init['file'] as Map)['id']) as String;
    final status =
        await json(await h.get(apiUrl(base, '/v1/files/$id'), headers: hdr()));
    final have = {
      for (final n in (status['have'] as List? ?? const [])) (n as num).toInt()
    };
    for (var n = 0; n < prep.count; n++) {
      if (!have.contains(n)) {
        final r = await h.put(apiUrl(base, '/v1/files/$id/parts/$n'),
            headers: hdr(), body: await prep.part(n));
        if (r.statusCode ~/ 100 != 2) throw httpError(r);
      }
      onProgress?.call((n + 1) / prep.count);
    }
    await json(await h.post(apiUrl(base, '/v1/files/$id/complete'),
        headers: {...hdr(), 'Content-Type': 'application/json'}, body: '{}'));
    return (file: id, meta: prep.meta);
  }

  /// Yields an attachment's plaintext a chunk at a time, each checked before it is yielded.
  Stream<Uint8List> fetchAttachment(
      String conv, String file, FileMeta meta) async* {
    final h = http_, base = apiBase, hdr = apiHeaders;
    if (h == null || base == null || hdr == null)
      throw StateError('attachments need an HTTP client and base');
    var total = 0;
    for (var i = 0; i < meta.count; i++) {
      final r = await h.get(apiUrl(base, '/v1/files/$file/blob'), headers: {
        ...hdr(),
        'Range': 'bytes=${i * meta.chunk}-${(i + 1) * meta.chunk - 1}'
      });
      if (r.statusCode ~/ 100 != 2) throw httpError(r);
      if (i < meta.count - 1 && r.bodyBytes.length != meta.chunk)
        throw ChatCryptoException(
            'forged', 'a part of the file is the wrong length');
      final plain = await openFilePart(conv, meta, i, r.bodyBytes);
      total += plain.length;
      yield plain;
    }
    if (total != meta.size)
      throw ChatCryptoException('forged', 'the file is the wrong length');
  }

  Future<void> _wait() => jitter == Duration.zero
      ? Future.value()
      : Future.delayed(
          Duration(milliseconds: _rnd.nextInt(jitter.inMilliseconds)));

  /// Feed it every event from the service. Completes when it has acted.
  Future<void> handleEvent(RtcdEvent e) async {
    try {
      final conv = (e.data['conv'] ?? e.data['group'])
          as String?; // group.*: a group a user made
      switch (e.name) {
        case 'epoch.new' || 'epoch.granted':
          if (conv != null) await sync(conv);
        case 'conv.rekey':
          await _wait();
          if (conv != null) await rotate(conv);
        case 'conv.added' ||
              'conv.members' ||
              'group.added' ||
              'group.members_added':
          await _wait();
          if (conv != null) {
            await sync(conv);
            await grant(conv);
          }
        case 'key.added':
          await _wait();
          for (final c in known.toList()) {
            await grant(c);
          }
      }
    } catch (err) {
      onError?.call(err);
    }
  }

  /// Subscribes [handleEvent] to a connection's events.
  StreamSubscription<RtcdEvent> listen(RtcdConnection c) =>
      c.events.listen(handleEvent);
}

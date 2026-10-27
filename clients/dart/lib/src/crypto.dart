/// The cryptography of rtcd chat, byte for byte the same as web/chat-core.js.
///
/// See that file's header for the formats. Messages are
/// `m1.` + base64url(nonce | AES-256-GCM | tag) with the conversation, sender
/// and message id as additional data; a conversation's key for an epoch reaches
/// each device wrapped as `k2.…` with ECDH P-256 + HKDF-SHA-256; attachments are
/// sealed a chunk at a time.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart' as pc;

/// Thrown for anything the cryptography refuses. [code] is `forged`,
/// `too_large`, `bad_message`, `bad_wrap`, `bad_meta`, `empty` or `corrupt`.
class ChatCryptoException implements Exception {
  ChatCryptoException(this.code, [this.message = '']);
  final String code;
  final String message;
  @override
  String toString() => 'ChatCryptoException($code${message.isEmpty ? '' : ': $message'})';
}

const _tag = 16;

/// Plaintext bytes per attachment chunk, so a stored chunk is exactly 1 MiB.
const chunkSize = 1048576 - _tag;

/// The largest message sent inline; bigger ones go as attachments.
const maxInline = 22000;

String b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');
Uint8List unb64(String s) => base64Url.decode(base64Url.normalize(s));
String hexOf(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

final _rng = Random.secure();
Uint8List randomBytes(int n) => Uint8List.fromList(List<int>.generate(n, (_) => _rng.nextInt(256)));

Uint8List _cat(List<List<int>> parts) {
  final out = BytesBuilder(copy: false);
  for (final p in parts) {
    out.add(p);
  }
  return out.toBytes();
}

Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));

final _aes = AesGcm.with256bits();
final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

Future<Uint8List> _seal(List<int> key, List<int> nonce, List<int> aad, List<int> plain) async {
  final box = await _aes.encrypt(plain, secretKey: SecretKey(key), nonce: nonce, aad: aad);
  return _cat([box.cipherText, box.mac.bytes]);
}

Future<Uint8List> _open(List<int> key, List<int> nonce, List<int> aad, List<int> sealed) async {
  if (sealed.length < _tag) throw ChatCryptoException('forged');
  final ct = sealed.sublist(0, sealed.length - _tag);
  final mac = sealed.sublist(sealed.length - _tag);
  try {
    return Uint8List.fromList(await _aes.decrypt(SecretBox(ct, nonce: nonce, mac: Mac(mac)), secretKey: SecretKey(key), aad: aad));
  } on SecretBoxAuthenticationError {
    throw ChatCryptoException('forged');
  }
}

// ---- messages ---------------------------------------------------------------

Uint8List newKey() => randomBytes(32);

Uint8List _msgAad(String conv, String sender, String id) => _utf8(['rtcd-msg', conv, sender, id].join('\u0000'));

Future<String> encryptMessage(List<int> key, {required String conv, required String sender, required String id, required String text}) async {
  final data = _utf8(text);
  if (data.length > maxInline) throw ChatCryptoException('too_large', 'send it as an attachment');
  final nonce = randomBytes(12);
  return 'm1.${b64(_cat([nonce, await _seal(key, nonce, _msgAad(conv, sender, id), data)]))}';
}

Future<String> decryptMessage(List<int> key, {required String conv, required String sender, required String id, required String body}) async {
  if (!body.startsWith('m1.')) throw ChatCryptoException('bad_message');
  final raw = unb64(body.substring(3));
  if (raw.length < 12 + _tag) throw ChatCryptoException('bad_message');
  final pt = await _open(key, raw.sublist(0, 12), _msgAad(conv, sender, id), raw.sublist(12));
  return utf8.decode(pt);
}

// ---- device identities and key wraps ---------------------------------------

/// A device's P-256 key pair. Keep [toJson] in secure storage.
class DeviceIdentity {
  DeviceIdentity(this.d, this.publicRaw);

  /// The private scalar (32 bytes).
  final Uint8List d;

  /// The public key in uncompressed form (65 bytes), as published.
  final Uint8List publicRaw;

  String get publicB64 => b64(publicRaw);

  static Future<DeviceIdentity> generate() async {
    final kp = await P256.impl.generate();
    return DeviceIdentity(kp.d, kp.publicRaw);
  }

  /// The identity whose private scalar is [scalar] (1 to 32 bytes, reduced into range), for an app that derives
  /// the key from a secret it already protects instead of storing another.
  static Future<DeviceIdentity> fromScalar(List<int> scalar) async {
    final kp = await P256.impl.fromScalar(Uint8List.fromList(scalar));
    return DeviceIdentity(kp.d, kp.publicRaw);
  }

  Map<String, Object?> toJson() => {'v': 2, 'd': b64(d), 'pub': b64(publicRaw)};

  static DeviceIdentity fromJson(Map<String, Object?> j) {
    if (j['v'] != 2) throw ChatCryptoException('bad_identity');
    return DeviceIdentity(unb64(j['d'] as String), unb64(j['pub'] as String));
  }
}

/// The ECDH over P-256 that key wrapping needs. The default is pure Dart (and
/// so slow on a phone: a few milliseconds a key in release mode). A Flutter app
/// can set [impl] to one backed by the platform's crypto.
abstract class P256 {
  /// A new key pair: the private scalar (32 bytes) and the uncompressed public key (65 bytes).
  Future<({Uint8List d, Uint8List publicRaw})> generate();

  /// The key pair for a given scalar, reduced into [1, n-1].
  Future<({Uint8List d, Uint8List publicRaw})> fromScalar(Uint8List scalar);

  /// The shared secret (the 32-byte x coordinate) of our scalar and their public key.
  /// Throws [ChatCryptoException] `bad_wrap` for a key that is not a point on the curve.
  Future<Uint8List> agree(Uint8List d, Uint8List theirPublicRaw);

  static P256 impl = PointyP256();
}

class PointyP256 implements P256 {
  static final _domain = pc.ECDomainParameters('secp256r1');
  static final _p = BigInt.parse('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', radix: 16);
  static final _b = BigInt.parse('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', radix: 16);

  static BigInt _int(List<int> b) => b.fold(BigInt.zero, (a, x) => (a << 8) | BigInt.from(x));
  static Uint8List _bytes(BigInt v) {
    final out = Uint8List(32);
    for (var i = 31; i >= 0; i--) {
      out[i] = (v & BigInt.from(255)).toInt();
      v >>= 8;
    }
    return out;
  }

  @override
  Future<({Uint8List d, Uint8List publicRaw})> generate() async {
    final rnd = pc.FortunaRandom()..seed(pc.KeyParameter(randomBytes(32)));
    final gen = pc.ECKeyGenerator()..init(pc.ParametersWithRandom(pc.ECKeyGeneratorParameters(_domain), rnd));
    final pair = gen.generateKeyPair();
    final d = (pair.privateKey as pc.ECPrivateKey).d!;
    final q = (pair.publicKey as pc.ECPublicKey).Q!;
    return (d: _bytes(d), publicRaw: Uint8List.fromList(q.getEncoded(false)));
  }

  @override
  Future<({Uint8List d, Uint8List publicRaw})> fromScalar(Uint8List scalar) async {
    final n = _domain.n;
    final d = (_int(scalar) % (n - BigInt.one)) + BigInt.one;
    final q = (_domain.G * d)!;
    return (d: _bytes(d), publicRaw: Uint8List.fromList(q.getEncoded(false)));
  }

  @override
  Future<Uint8List> agree(Uint8List d, Uint8List theirPublicRaw) async {
    if (theirPublicRaw.length != 65 || theirPublicRaw[0] != 4) throw ChatCryptoException('bad_wrap', 'not a P-256 public key');
    final x = _int(theirPublicRaw.sublist(1, 33)), y = _int(theirPublicRaw.sublist(33));
    // y^2 = x^3 - 3x + b (mod p): without this a peer could send a point on a weaker curve.
    if (x >= _p || y >= _p || (y * y) % _p != ((x * x * x) - BigInt.from(3) * x + _b) % _p) throw ChatCryptoException('bad_wrap', 'the public key is not on the curve');
    final agree = pc.ECDHBasicAgreement()..init(pc.ECPrivateKey(_int(d), _domain));
    final secret = agree.calculateAgreement(pc.ECPublicKey(_domain.curve.createPoint(x, y), _domain));
    return _bytes(secret);
  }
}

Future<SecretKey> _wrapKey(DeviceIdentity me, List<int> theirPub, List<int> senderPub, List<int> recipientPub, String tag) async {
  final shared = SecretKey(await P256.impl.agree(me.d, Uint8List.fromList(theirPub)));
  return _hkdf.deriveKey(secretKey: shared, nonce: _cat([senderPub, recipientPub]), info: _utf8('rtcd-key-wrap\u0000$tag'));
}

String _epochTag(String conv, int epoch) => '$conv\u0000$epoch';

/// Wraps a conversation's epoch key for one device.
Future<String> wrapEpochKey(DeviceIdentity me, List<int> theirPublicRaw, String conv, int epoch, List<int> key) async {
  final tag = _epochTag(conv, epoch);
  final k = await _wrapKey(me, theirPublicRaw, me.publicRaw, theirPublicRaw, tag);
  final nonce = randomBytes(12);
  return 'k2.${b64(_cat([nonce, await _seal(await k.extractBytes(), nonce, _utf8('rtcd-key\u0000$tag'), key)]))}';
}

/// Opens an epoch key that [theirPublicRaw] (the wrapping device) made for [me].
Future<Uint8List> unwrapEpochKey(DeviceIdentity me, List<int> theirPublicRaw, String conv, int epoch, String wrapped) async {
  if (!wrapped.startsWith('k2.')) throw ChatCryptoException('bad_wrap');
  final raw = unb64(wrapped.substring(3));
  if (raw.length < 12 + _tag) throw ChatCryptoException('bad_wrap');
  final tag = _epochTag(conv, epoch);
  final k = await _wrapKey(me, theirPublicRaw, theirPublicRaw, me.publicRaw, tag);
  return _open(await k.extractBytes(), raw.sublist(0, 12), _utf8('rtcd-key\u0000$tag'), raw.sublist(12));
}

/// Twelve groups of five digits; members compare them out of band.
Future<String> safetyCode(List<List<int>> publicRaws) async {
  final sorted = publicRaws.map(hexOf).toList()..sort();
  final d = (await Sha256().hash(_utf8(sorted.join('\n')))).bytes;
  return [for (var i = 0; i < 12; i++) ((d[i * 2] << 8 | d[i * 2 + 1]) % 100000).toString().padLeft(5, '0')].join(' ');
}

// ---- attachments -----------------------------------------------------------

/// Where a file's bytes come from; random access, so a part can be read again.
abstract class FileSource {
  int get length;
  Future<Uint8List> read(int start, int end);
}

class BytesSource implements FileSource {
  BytesSource(this.bytes);
  final Uint8List bytes;
  @override
  int get length => bytes.length;
  @override
  Future<Uint8List> read(int start, int end) async => Uint8List.sublistView(bytes, start, end);
}

Uint8List _nonce(List<int> salt, int i) {
  final n = Uint8List(12)..setRange(0, 4, salt);
  ByteData.view(n.buffer).setUint64(4, i, Endian.big);
  return n;
}

Uint8List _fileAad(String conv, int i, int count) => _utf8(['rtcd-file', conv, i, count].join('\u0000'));

/// What goes inside the encrypted message that announces an attachment.
class FileMeta {
  FileMeta({required this.k, required this.s, required this.size, required this.count, required this.chunk, required this.sha256});
  final String k, s, sha256;
  final int size, count, chunk;

  Map<String, Object?> toJson() => {'v': 1, 'k': k, 's': s, 'size': size, 'count': count, 'chunk': chunk, 'sha256': sha256};

  static FileMeta fromJson(Map<String, Object?> j) {
    if (j['v'] != 1) throw ChatCryptoException('bad_meta');
    return FileMeta(k: j['k'] as String, s: j['s'] as String, size: j['size'] as int, count: j['count'] as int, chunk: j['chunk'] as int, sha256: j['sha256'] as String);
  }
}

/// A file ready to upload: [part] makes stored part n on demand, so memory use
/// is a chunk or two whatever the size.
class PreparedFile {
  PreparedFile._(this.meta, this.size, this._source, this._key, this._salt, this._conv);
  final FileMeta meta;

  /// Bytes as stored (encrypted); what `file.init` wants as size.
  final int size;
  final FileSource _source;
  final Uint8List _key, _salt;
  final String _conv;

  int get count => meta.count;
  int get chunk => meta.chunk;
  String get sha256 => meta.sha256;

  Future<Uint8List> part(int n) async {
    final plain = await _source.read(n * chunkSize, min(_source.length, (n + 1) * chunkSize));
    return _seal(_key, _nonce(_salt, n), _fileAad(_conv, n, meta.count), plain);
  }
}

Future<PreparedFile> prepareFile(String conv, FileSource source) async {
  if (source.length == 0) throw ChatCryptoException('empty');
  final key = randomBytes(32), salt = randomBytes(4);
  final count = (source.length + chunkSize - 1) ~/ chunkSize;
  final probe = PreparedFile._(FileMeta(k: b64(key), s: b64(salt), size: source.length, count: count, chunk: chunkSize + _tag, sha256: ''), 0, source, key, salt, conv);
  final sink = Sha256().newHashSink();
  var total = 0;
  for (var n = 0; n < count; n++) {
    final p = await probe.part(n);
    sink.add(p);
    total += p.length;
  }
  sink.close();
  final sha = hexOf((await sink.hash()).bytes);
  final meta = FileMeta(k: b64(key), s: b64(salt), size: source.length, count: count, chunk: chunkSize + _tag, sha256: sha);
  return PreparedFile._(meta, total, source, key, salt, conv);
}

/// Opens stored part [i] of an attachment.
Future<Uint8List> openFilePart(String conv, FileMeta meta, int i, List<int> stored) async {
  try {
    return await _open(unb64(meta.k), _nonce(unb64(meta.s), i), _fileAad(conv, i, meta.count), stored);
  } on ChatCryptoException {
    throw ChatCryptoException('forged', 'a part of the file was altered, moved or cut');
  }
}

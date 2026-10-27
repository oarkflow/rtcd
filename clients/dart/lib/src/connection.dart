/// One WebSocket to rtcd: requests with answers, and the events it pushes.
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';

/// An error the service answered with. [code] is the stable part
/// (`stale_epoch`, `rekey_required`, `forbidden`, …).
class RtcdException implements Exception {
  RtcdException(this.code, [this.message = '']);
  final String code;
  final String message;
  @override
  String toString() =>
      'RtcdException($code${message.isEmpty ? '' : ': $message'})';
}

class RtcdEvent {
  RtcdEvent(this.name, this.data, this.from);
  final String name;
  final Map<String, Object?> data;
  final String from;
}

/// Signature of the function [ChatClient] sends its requests through, so a
/// connection can be this class, an existing socket of yours, or HTTP.
typedef CallFn = Future<Map<String, Object?>> Function(
    String op, Map<String, Object?> payload);

class RtcdConnection {
  RtcdConnection._(this._ch, this._http, this._base, this._token) {
    _sub = _ch.stream.listen(_onFrame,
        onError: _fail,
        onDone: () => _fail(StateError('the connection closed')));
    _ping = Timer.periodic(
        const Duration(seconds: 25), (_) => _send({'type': 'ping'}));
  }

  final WebSocketChannel _ch;
  final http.Client _http;
  final Uri _base;
  final String _token;
  late final StreamSubscription<dynamic> _sub;
  late final Timer _ping;
  final _pending = <String, Completer<Map<String, Object?>>>{};
  final _events = StreamController<RtcdEvent>.broadcast();
  final _closed = Completer<Object>();
  var _n = 0;

  /// Opens a connection for a user token the backend minted. A single-use ticket
  /// is traded for the token first, so the token never appears in a URL.
  static Future<RtcdConnection> connect(Uri base, String token,
      {http.Client? client}) async {
    final h = client ?? http.Client();
    final res = await h.post(apiUrl(base, '/v1/ws/ticket'),
        headers: {
          'Authorization': 'Bearer $token',
          'Content-Type': 'application/json'
        },
        body: '{}');
    if (res.statusCode ~/ 100 != 2) throw _httpError(res);
    final ticket = (jsonDecode(res.body) as Map)['ticket'] as String;
    final ws = apiUrl(base, '/v1/ws').replace(
        scheme: base.scheme == 'https' ? 'wss' : 'ws',
        queryParameters: {'ticket': ticket});
    final ch = WebSocketChannel.connect(ws);
    await ch.ready;
    return RtcdConnection._(ch, h, base, token);
  }

  Stream<RtcdEvent> get events => _events.stream;

  /// Completes when the connection has ended, with the reason.
  Future<Object> get closed => _closed.future;

  void _send(Map<String, Object?> m) {
    if (!_closed.isCompleted) _ch.sink.add(jsonEncode(m));
  }

  void _onFrame(dynamic raw) {
    final m = jsonDecode(raw as String) as Map<String, Object?>;
    switch (m['type']) {
      case 'ack':
        _pending.remove(m['replyTo'])?.complete(
            (m['payload'] as Map?)?.cast<String, Object?>() ??
                <String, Object?>{});
      case 'error':
        final e = '${m['error'] ?? m['code']}';
        final i = e.indexOf(': ');
        _pending.remove(m['replyTo'])?.completeError(RtcdException(
            i < 0 ? e : e.substring(0, i), i < 0 ? '' : e.substring(i + 2)));
      case 'emit':
        _events.add(RtcdEvent(
            '${m['event']}',
            (m['payload'] as Map?)?.cast<String, Object?>() ??
                <String, Object?>{},
            '${m['from'] ?? ''}'));
    }
  }

  void _fail(Object e) {
    if (_closed.isCompleted) return;
    _closed.complete(e);
    _ping.cancel();
    for (final c in _pending.values) {
      c.completeError(RtcdException('closed', '$e'));
    }
    _pending.clear();
    _events.close();
  }

  /// Sends one request and returns its answer; throws [RtcdException] on an error answer.
  Future<Map<String, Object?>> call(String op,
      [Map<String, Object?> payload = const {}]) {
    if (_closed.isCompleted) return Future.error(RtcdException('closed'));
    final id = (++_n).toRadixString(36);
    final c = Completer<Map<String, Object?>>();
    _pending[id] = c;
    _send({'type': 'emit', 'id': id, 'event': op, 'payload': payload});
    return c.future;
  }

  /// For attachments: the HTTP base and the authorization header.
  Uri get base => _base;
  Map<String, String> get authHeaders => {'Authorization': 'Bearer $_token'};
  http.Client get httpClient => _http;

  Future<void> close() async {
    await _sub.cancel();
    await _ch.sink.close();
    _fail(StateError('closed'));
  }
}

RtcdException _httpError(http.Response r) {
  try {
    final e = (jsonDecode(r.body) as Map)['error'] as Map;
    return RtcdException('${e['code']}', '${e['message'] ?? ''}');
  } catch (_) {
    return RtcdException('http_${r.statusCode}');
  }
}

/// [path] under [base], keeping any path [base] already has. A backend that proxies the service under a prefix
/// (`https://api.example.com/rtcd`) hands out that prefix as the base, and `Uri.resolve('/v1/…')` would drop it.
Uri apiUrl(Uri base, String path) => base.replace(
    path: '${base.path.replaceAll(RegExp(r'/+$'), '')}$path',
    query: null,
    fragment: null);

/// Throws the error an HTTP answer carries.
RtcdException httpError(http.Response r) => _httpError(r);

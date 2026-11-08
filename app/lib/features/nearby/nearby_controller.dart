import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../backup/backup_codec.dart';
import 'nearby_codec.dart';
import 'nearby_discovery.dart';
import 'nearby_protocol.dart';
import 'nearby_pairing.dart';
import 'nearby_wifi.dart';

enum NearbyPhase {
  idle,
  starting,
  looking,
  pairing,
  paired,
  offering,
  transferring,
  success,
  failed,
}

abstract interface class NearbyCompanyDisclosure {
  Future<void> requireCurrent();
  void requireLive();
}

class NearbyViewState {
  const NearbyViewState({
    required this.phase,
    required this.deviceName,
    required this.deviceId,
    this.status = 'Open Nearby on the other device. Stay on the same Wi‑Fi.',
    this.error,
    this.verifyCode,
    this.verificationAttemptId,
    this.verificationExpiresAt,
    this.peerName,
    this.peers = const [],
    this.incoming,
    this.progress,
    this.successMessage,
    this.pairedPeer,
  });

  final NearbyPhase phase;
  final String deviceName;
  final String deviceId;
  final String status;
  final String? error;
  final String? verifyCode;

  /// Read-only identity and local deadline for the code currently shown.
  final String? verificationAttemptId;
  final DateTime? verificationExpiresAt;
  final String? peerName;
  final List<NearbyPeer> peers;
  final NearbyOffer? incoming;
  final double? progress;
  final String? successMessage;
  final NearbyPeer? pairedPeer;

  bool get running => phase != NearbyPhase.idle && phase != NearbyPhase.failed;
}

typedef NearbyApplyPayload = Future<void> Function(BackupPayload payload);
typedef NearbyCollectPayload =
    Future<({BackupPayload payload, NearbyOffer offer})> Function();

class NearbyController {
  NearbyController({
    required this.deviceId,
    required this.deviceName,
    required this.discovery,
    NearbyCollectPayload? collectPayload,
    NearbyApplyPayload? applyPayload,
    this.bindAddress,
    this.localIps,
    this.codec,
    this.peerAllowed,
    this.readNetwork = readNearbyWifiNetwork,
    this.now,
    this.companyJoin = false,
    this.onTransportObservation,
    this.transportCapture = NearbyTransportCapture.all,
    this.onJoinReceiveObservation,
  }) : _transportController = onTransportObservation == null
           ? null
           : ++_nextTransportController,
       _collectPayload =
           collectPayload ??
           (() async =>
               throw const NearbyException('Shop copy is unavailable')),
       _applyPayload =
           applyPayload ??
           ((_) async =>
               throw const NearbyException('Shop copy is unavailable'));

  final String deviceId;
  String deviceName;
  final NearbyDiscovery discovery;
  final NearbyCollectPayload _collectPayload;
  final NearbyApplyPayload _applyPayload;
  NearbyCollectPayload get collectPayload => _collectPayload;
  NearbyApplyPayload get applyPayload => _applyPayload;
  Future<Map<String, Object?>> Function(
    NearbyPairedJoinSession pair,
    Map<String, Object?> wire,
  )?
  onJoinMessage;
  NearbyCompanyDisclosure? companySyncDisclosure;
  Future<void> _joinSending = Future<void>.value();

  Future<void> sendJoinMessage(Map<String, Object?> wire) {
    return exchangeCompanyMessage(wire).then((reply) {
      if (reply.length != 1 || reply['ok'] != true) {
        throw const NearbyException('Join message was not admitted');
      }
    });
  }

  Future<Map<String, Object?>> exchangeCompanyMessage(
    Map<String, Object?> wire, {
    NearbyCompanyDisclosure? disclosure,
  }) {
    final result = _joinSending.then((_) async {
      if (wire['kind'] == 'created-jobs' &&
          (disclosure == null ||
              !identical(disclosure, companySyncDisclosure))) {
        throw const NearbyException('Manual Job sync disclosure is required');
      }
      final session = _session;
      final pair = pairedJoinSession;
      if (session == null || pair == null) {
        throw const NearbyException('Pair for company Join first');
      }
      pair.requireCurrent();
      await disclosure?.requireCurrent();
      if (utf8.encode(jsonEncode(wire)).length > 65536) {
        throw const NearbyException('Join message is too large');
      }
      final reply = await _jsonPost(
        session.peer,
        '/v2/join',
        wire,
        session: session,
        disclosure: disclosure,
      );
      pair.requireCurrent();
      disclosure?.requireLive();
      return reply;
    });
    _joinSending = result.then<void>(
      (_) {},
      onError: (Object _, StackTrace _) {},
    );
    return result;
  }

  final InternetAddress? bindAddress;
  final Future<List<String>> Function()? localIps;
  final NearbyCodec? codec;
  final bool Function(String host)? peerAllowed;
  final Future<NearbyWifiNetwork> Function() readNetwork;
  final DateTime Function()? now;
  final bool companyJoin;
  final NearbyTransportObserver? onTransportObservation;
  final NearbyTransportCapture transportCapture;
  final NearbyJoinReceiveObserver? onJoinReceiveObservation;
  static int _nextTransportController = 0;
  final int? _transportController;
  int _transportObservations = 0;
  int _transportRequests = 0;
  int _joinReceiveRequests = 0;

  void _observeTransport(NearbyTransportObservation event) {
    if (transportCapture == NearbyTransportCapture.terminal &&
        event.operation != NearbyTransportOperation.room &&
        event.stage != NearbyTransportStage.responseVerified &&
        event.failure == null &&
        !(event.stage == NearbyTransportStage.httpResponse &&
            event.httpStatus != null &&
            event.httpStatus != HttpStatus.ok)) {
      return;
    }
    _observeTransportEvent(onTransportObservation, event);
  }

  void _observeTransportEvent<T>(
    FutureOr<void> Function(T)? observer,
    T event,
  ) {
    if (observer == null ||
        _transportObservations >= kNearbyTransportObservationLimit) {
      return;
    }
    _transportObservations++;
    try {
      final pending = observer(event);
      if (pending is Future<void>) {
        unawaited(
          pending.then<void>((_) {}, onError: (Object _, StackTrace _) {}),
        );
      }
    } catch (_) {}
  }

  _NearbyTransportTrace? _transportTrace(NearbyPeer peer, String path) {
    final observer = onTransportObservation;
    final operation = switch (path) {
      '/v2/pair/start' => NearbyTransportOperation.pairStart,
      '/v2/pair/reveal' => NearbyTransportOperation.pairReveal,
      '/v2/pair/confirm' => NearbyTransportOperation.pairConfirm,
      '/v2/pair/cancel' => NearbyTransportOperation.pairCancel,
      '/v2/join' => NearbyTransportOperation.join,
      _ => null,
    };
    if (observer == null ||
        operation == null ||
        _transportObservations >= kNearbyTransportObservationLimit) {
      return null;
    }
    return _NearbyTransportTrace(
      request: ++_transportRequests,
      controller: _transportController!,
      generation: _lifecycle,
      operation: operation,
      peer: peer,
      source: _wifi,
      fallbackAddress: bindAddress?.address,
      observer: _observeTransport,
    );
  }

  NearbyPairedJoinSession? get pairedJoinSession =>
      companyJoin ? _session?.joinSession : null;

  NearbyCodec get _codec => codec ?? NearbyCodec();

  final _stateCtrl = StreamController<NearbyViewState>.broadcast();
  Stream<NearbyViewState> get states => _stateCtrl.stream;

  NearbyViewState _state = NearbyViewState(
    phase: NearbyPhase.idle,
    deviceName: '',
    deviceId: '',
  );

  NearbyViewState get state => _state;

  HttpServer? _server;
  int _lifecycle = 0;
  int? _discoveryOwner;
  bool _disposed = false;
  Future<void>? _disposal;
  NearbyWifiNetwork? _wifi;
  _NearbyRoomTrace? _roomTrace;
  StreamSubscription<List<NearbyPeer>>? _peerSub;
  _PairAttempt? _pending;
  int _pairGeneration = 0;
  final _pairStarts = <DateTime>[];
  final _authenticated = Expando<_AuthenticatedRequest>();
  _Session? _session;
  Completer<bool>? _hostMatch;
  _PendingOffer? _pendingOffer;
  _AcceptedOffer? _acceptedOffer;
  Timer? _pairTimer;

  Future<void> start() async {
    if (_disposed) return;
    if (_state.phase != NearbyPhase.idle &&
        _state.phase != NearbyPhase.failed) {
      return;
    }
    final generation = ++_lifecycle;
    final trace = _roomTrace = onTransportObservation == null
        ? null
        : _NearbyRoomTrace(
            _transportController!,
            generation,
            _observeTransport,
          );
    HttpServer? server;
    NearbyWifiNetwork? wifi;
    _emit(
      NearbyViewState(
        phase: NearbyPhase.starting,
        deviceName: deviceName,
        deviceId: deviceId,
        status: 'Opening Nearby on this Wi‑Fi…',
      ),
    );
    try {
      wifi = bindAddress == null ? await readNetwork() : null;
      trace?.source = wifi;
      if (generation != _lifecycle) return;
      server = wifi != null
          ? await wifi.listen(onListenerBound: trace?.bound)
          : await HttpServer.bind(bindAddress!, 0);
      if (wifi == null) {
        trace?.bound(server.address.address, server.port);
      }
      if (generation != _lifecycle) {
        await _closeServer(server, wifi);
        return;
      }
      _server = server;
      _wifi = wifi;
      server.listen(
        _handleHttp,
        onError: (Object e) {
          trace?.failed(NearbyTransportStage.listenerError, e);
          unawaited(
            _transportFailed(
              generation,
              'Nearby connection failed: $e',
              NearbyTransportStopReason.listenerError,
            ),
          );
        },
        onDone: () {
          trace?.emit(NearbyTransportStage.listenerDone);
          unawaited(
            _transportFailed(
              generation,
              'Nearby connection stopped. Open Nearby again.',
              NearbyTransportStopReason.listenerDone,
            ),
          );
        },
      );
      trace?.emit(NearbyTransportStage.httpListening);
      final ips = wifi != null
          ? [wifi.address]
          : await (localIps ?? localIpv4Addresses)();
      if (generation != _lifecycle) {
        await _closeServer(server, wifi);
        return;
      }
      final advertiseIps = ips.isNotEmpty ? ips : [server.address.address];
      _peerSub = discovery.peers.listen(
        (peers) {
          if (generation != _lifecycle ||
              _state.phase == NearbyPhase.starting) {
            return;
          }
          final filtered = peers.where((p) => p.deviceId != deviceId).toList();
          if (_state.phase == NearbyPhase.paired ||
              _state.phase == NearbyPhase.pairing ||
              _state.phase == NearbyPhase.offering ||
              _state.phase == NearbyPhase.transferring) {
            _emit(_state.copyWith(peers: filtered));
            return;
          }
          if (_state.phase == NearbyPhase.success ||
              _state.phase == NearbyPhase.failed) {
            _emit(_state.copyWith(peers: filtered, error: _state.error));
            return;
          }
          final looking = filtered.isEmpty
              ? 'Looking for Wired Parts on this Wi‑Fi. Open More → Nearby on the other device. If Windows or this Mac asks, allow Wired Parts on the network.'
              : 'Tap a device to pair. You will both see a 6-digit code.';
          _emit(
            _state.copyWith(
              phase: NearbyPhase.looking,
              peers: filtered,
              status: looking,
              error: null,
            ),
          );
        },
        onError: (Object error) {
          trace?.failed(NearbyTransportStage.discoveryError, error);
          unawaited(
            _transportFailed(
              generation,
              'Nearby discovery stopped. Check local network access and reopen Nearby. $error',
              NearbyTransportStopReason.discoveryError,
            ),
          );
        },
      );
      _discoveryOwner = generation;
      trace?.emit(NearbyTransportStage.discoveryStarting);
      await discovery.start(
        deviceId: deviceId,
        name: deviceName,
        port: server.port,
        ips: advertiseIps,
      );
      if (generation != _lifecycle) {
        if (_discoveryOwner == generation) await discovery.stop();
        await _closeServer(server, wifi);
        return;
      }
      trace?.emit(NearbyTransportStage.discoveryStarted);
      _emit(
        NearbyViewState(
          phase: NearbyPhase.looking,
          deviceName: deviceName,
          deviceId: deviceId,
          status:
              'Visible on this Wi‑Fi as $deviceName. Looking for other devices… Open Nearby on the other device. Stay on the same Wi‑Fi.',
          peers: const [],
        ),
      );
    } catch (e) {
      if (generation != _lifecycle) {
        await _closeServer(server, wifi);
        return;
      }
      await stop(reason: NearbyTransportStopReason.startupFailure);
      if (!_disposed && _lifecycle == generation + 1) {
        _fail(
          'Could not listen on this Wi-Fi. Allow Wired Parts through the firewall and try again. $e',
        );
      }
    }
  }

  Future<void> _transportFailed(
    int generation,
    String message,
    NearbyTransportStopReason reason,
  ) async {
    if (generation != _lifecycle || _disposed) return;
    await stop(reason: reason);
    if (!_disposed && _lifecycle == generation + 1) {
      _fail(message);
    }
  }

  Future<void> _closeServer(HttpServer? server, NearbyWifiNetwork? wifi) async {
    try {
      await server?.close(force: true);
    } finally {
      await wifi?.close();
    }
  }

  Future<void> stop({
    NearbyTransportStopReason reason = NearbyTransportStopReason.requested,
  }) async {
    final trace = _roomTrace;
    _roomTrace = null;
    trace?.emit(NearbyTransportStage.stopping, stopReason: reason);
    ++_lifecycle;
    _failPending(cancel: true);
    final peerSub = _peerSub;
    final server = _server;
    final wifi = _wifi;
    _peerSub = null;
    _server = null;
    _wifi = null;
    final stopDiscovery = discovery.stop();
    final closeServer = _closeServer(server, wifi);
    if (!_stateCtrl.isClosed) {
      _emit(
        NearbyViewState(
          phase: NearbyPhase.idle,
          deviceName: deviceName,
          deviceId: deviceId,
          status: 'Nearby is off.',
        ),
      );
    }
    await Future.wait<void>([
      if (peerSub != null) peerSub.cancel(),
      stopDiscovery,
      closeServer,
    ]);
    trace?.emit(NearbyTransportStage.stopped, stopReason: reason);
  }

  Future<void> rename(String name) async {
    final trimmed = name.trim();
    deviceName = trimmed.isEmpty ? defaultNearbyName(deviceId) : trimmed;
    final generation = _lifecycle;
    final port = _server?.port;
    if (port != null) {
      final ips = _wifi != null
          ? [_wifi!.address]
          : await (localIps ?? localIpv4Addresses)();
      if (generation != _lifecycle) return;
      await discovery.updateAdvertisement(
        name: deviceName,
        port: port,
        ips: ips.isNotEmpty ? ips : [InternetAddress.loopbackIPv4.address],
      );
    }
    if (generation == _lifecycle && !_disposed) {
      _emit(_state.copyWith(deviceName: deviceName));
    }
  }

  Future<void> pair(NearbyPeer peer) async {
    if (_server == null) {
      _fail('Nearby is not listening. Open this page again.');
      return;
    }
    _failPending(cancel: true);
    final generation = _pairGeneration;
    _emit(
      NearbyViewState(
        phase: NearbyPhase.pairing,
        deviceName: deviceName,
        deviceId: deviceId,
        peerName: peer.label,
        status: 'Connecting to ${peer.label}…',
        peers: _state.peers,
      ),
    );
    try {
      final context = NearbyPairContext(
        id: nearbyRandomId(),
        guestId: deviceId,
        hostId: peer.deviceId,
        guestName: deviceName,
        hostName: peer.name,
        guestPort: _server!.port,
        hostPort: peer.port,
        purpose: companyJoin ? 'company-join@1' : null,
      );
      final agreement = await NearbyPendingPair.create(context, guest: true);
      if (generation != _pairGeneration) return;
      final attempt = _PairAttempt(
        peer,
        agreement,
        expiresAt: (now ?? DateTime.now)().toUtc().add(kNearbyPairingWindow),
      );
      _pending = attempt;
      _armPairExpiry(attempt);
      final start = await _jsonPost(peer, '/v2/pair/start', {
        ...context.toJson(),
        'commitment': agreement.commitment,
      });
      if (!_isCurrentPair(attempt)) return;
      agreement.receiveCommitment(start['commitment']);
      final revealed = await _jsonPost(
        peer,
        '/v2/pair/reveal',
        agreement.reveal(),
      );
      if (!_isCurrentPair(attempt)) return;
      final match = await agreement.receiveReveal(revealed);
      if (!_isCurrentPair(attempt)) return;
      attempt.match = match;
      _showMatch(attempt);
    } catch (e) {
      if (generation == _pairGeneration) {
        _fail(_crewError(e, 'Could not reach ${peer.label}'));
      }
    }
  }

  void _armPairExpiry(_PairAttempt attempt) {
    _pairTimer?.cancel();
    _pairTimer = Timer(kNearbyPairingWindow, () {
      if (identical(_pending, attempt)) _fail('Pair expired. Try again.');
    });
  }

  bool _isCurrentPair(_PairAttempt attempt) {
    if (!identical(_pending, attempt)) return false;
    if (!(now ?? DateTime.now)().toUtc().isBefore(attempt.expiresAt)) {
      _fail('Pair expired. Try again.');
      return false;
    }
    return true;
  }

  Duration _pairingRemaining(DateTime deadline) {
    final remaining = deadline.difference((now ?? DateTime.now)().toUtc());
    if (remaining <= Duration.zero) {
      throw const NearbyException('Pair expired. Try again.');
    }
    return remaining;
  }

  void _showMatch(_PairAttempt attempt) {
    _emit(
      NearbyViewState(
        phase: NearbyPhase.pairing,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        peerName: attempt.peer.label,
        verifyCode: attempt.match!.code,
        verificationAttemptId: attempt.agreement.context.id,
        verificationExpiresAt: attempt.expiresAt,
        status:
            'Check that ${attempt.peer.label} shows this same code, then tap Match.',
      ),
    );
  }

  void _paired(_PairAttempt attempt, NearbySessionKeys keys) {
    if (!_isCurrentPair(attempt)) return;
    _pairTimer?.cancel();
    _pairTimer = null;
    _pending = null;
    _hostMatch = null;
    attempt.ended.complete();
    _session = _Session(attempt.peer, keys);
    if (companyJoin) {
      _session!.joinSession = NearbyPairedJoinSession._(this, _session!);
    }
    _emit(
      NearbyViewState(
        phase: NearbyPhase.paired,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        peerName: attempt.peer.label,
        pairedPeer: attempt.peer,
        status:
            'Paired with ${attempt.peer.label}. Send this shop to replace the shop on that device.',
      ),
    );
  }

  Future<void> confirmCode() async {
    final attempt = _pending;
    if (attempt == null || !_isCurrentPair(attempt)) return;
    final match = attempt.match;
    if (match == null || attempt.localConfirmed) return;
    attempt.localConfirmed = true;
    final proof = match.confirmLocal();
    _emit(
      _state.copyWith(
        status: 'Waiting for ${attempt.peer.label} to tap Match…',
      ),
    );
    if (!attempt.agreement.guest) {
      _hostMatch?.complete(true);
      return;
    }
    try {
      final reply = await _jsonPost(
        attempt.peer,
        '/v2/pair/confirm',
        {'id': match.transactionId, 'proof': proof},
        pairingDeadline: attempt.expiresAt,
        pairingEnded: attempt.ended.future,
      );
      if (!_isCurrentPair(attempt)) return;
      match.confirmRemote(reply['proof']);
      _paired(attempt, match.finish());
    } catch (e) {
      if (_isCurrentPair(attempt)) _fail(_crewError(e, 'Pair failed'));
    }
  }

  Future<void> rejectCode() async {
    final attempt = _pending;
    final session = _session;
    _failPending(cancel: true);
    _emit(
      NearbyViewState(
        phase: NearbyPhase.looking,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        error: 'Pair cancelled. Codes must match on both screens.',
        status: 'Tap a device to pair. You will both see a 6-digit code.',
      ),
    );
    try {
      if (session != null) {
        await _jsonPost(session.peer, '/v2/pair/cancel', {}, session: session);
      } else if (attempt != null) {
        await _jsonPost(attempt.peer, '/v2/pair/cancel', {
          'id': attempt.agreement.context.id,
        });
      }
    } catch (_) {}
  }

  bool isCurrentOffer(NearbyOffer offer) {
    final pending = _pendingOffer;
    return !_disposed &&
        pending != null &&
        identical(pending.offer, offer) &&
        identical(pending.session, _session) &&
        !pending.decision.isCompleted &&
        (now ?? DateTime.now)().toUtc().isBefore(pending.expiresAt);
  }

  Future<void> acceptOffer(NearbyOffer offer) async {
    final pending = _pendingOffer;
    if (!isCurrentOffer(offer)) return;
    pending!.decision.complete(true);
    _emit(
      _state.copyWith(
        phase: NearbyPhase.transferring,
        status: 'Accepted. Receiving shop…',
        progress: 0,
      ),
    );
  }

  Future<void> declineOffer(NearbyOffer offer) async {
    final pending = _pendingOffer;
    if (!isCurrentOffer(offer)) return;
    pending!.decision.complete(false);
    _emit(
      NearbyViewState(
        phase: NearbyPhase.looking,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        error:
            'You declined the incoming shop. Nothing on this device changed.',
        status: 'Looking for Wired Parts on this Wi‑Fi.',
      ),
    );
  }

  Future<void> sendTo(NearbyPeer peer) async {
    if (companyJoin) {
      throw const NearbyException(
        'Shop copy is unavailable during company Join',
      );
    }
    final session = _session;
    if (session == null || peer != session.peer) {
      _fail('Pair first, then send.');
      return;
    }
    _emit(
      _state.copyWith(
        phase: NearbyPhase.transferring,
        pairedPeer: peer,
        peerName: peer.label,
        status: 'Preparing this shop to send…',
        progress: 0,
      ),
    );
    try {
      final packed = await collectPayload();
      if (!identical(_session, session)) return;
      final transferId = nearbyRandomId();
      final bytes = await _codec.encrypt(
        payload: packed.payload,
        key: session.keys.sendKey,
        sessionId: session.keys.id,
        direction: session.keys.sendDirection,
        transferId: transferId,
        offer: packed.offer,
      );
      if (!identical(_session, session)) return;
      _emit(
        _state.copyWith(
          status: 'Waiting for ${peer.label} to accept…',
          progress: 0,
        ),
      );
      await _jsonPost(
        peer,
        '/v2/offer',
        {
          'sourceDeviceId': packed.offer.sourceDeviceId,
          'sourceName': packed.offer.sourceName,
          'jobs': packed.offer.jobs,
          'parts': packed.offer.parts,
          'photos': packed.offer.photos,
          'bytes': bytes.length,
          'transferId': transferId,
          'digest': nearbyDigest(bytes),
        },
        session: session,
        timeout: const Duration(minutes: 2),
      );
      if (!identical(_session, session)) return;
      _emit(
        _state.copyWith(status: 'Sending shop to ${peer.label}…', progress: 0),
      );
      await _putBytes(
        peer,
        '/v2/transfer',
        bytes,
        session: session,
        onProgress: (p) {
          if (!identical(_session, session)) return;
          _emit(
            _state.copyWith(
              progress: p,
              status: 'Sending shop to ${peer.label}… ${(p * 100).round()}%',
            ),
          );
        },
      );
      if (!identical(_session, session)) return;
      _emit(
        NearbyViewState(
          phase: NearbyPhase.success,
          deviceName: deviceName,
          deviceId: deviceId,
          peers: _state.peers,
          pairedPeer: peer,
          peerName: peer.label,
          successMessage:
              'Sent this shop to ${peer.label} (${packed.offer.summary}).',
          status: 'Sent this shop to ${peer.label}.',
          progress: 1,
        ),
      );
    } catch (e) {
      if (identical(_session, session)) {
        _fail(_crewError(e, 'Send did not finish. Check the other device.'));
      }
    }
  }

  Future<void> _handleHttp(HttpRequest request) async {
    _NearbyJoinReceiveTrace? receiveTrace;
    try {
      if (!_allowsPeer(request.connectionInfo?.remoteAddress.address ?? '')) {
        request.response.statusCode = HttpStatus.forbidden;
        await _writeJson(request, {'error': 'Use the same Wi-Fi network'});
        return;
      }
      final path = request.uri.path;
      if (request.method == 'POST' && path == '/v2/join') {
        final pair = pairedJoinSession;
        if (!companyJoin ||
            pair == null ||
            onJoinMessage == null ||
            !_authed(request)) {
          request.response.statusCode = HttpStatus.forbidden;
          await _writeJson(request, {'error': 'Join unavailable'});
          return;
        }
        if (onJoinReceiveObservation != null &&
            _transportObservations < kNearbyTransportObservationLimit) {
          receiveTrace = _NearbyJoinReceiveTrace(++_joinReceiveRequests);
        }
        pair.requireCurrent();
        receiveTrace?.lastBoundary = NearbyJoinReceiveBoundary.bodyRead;
        final wire = await _readJson(request);
        receiveTrace?.lastBoundary = NearbyJoinReceiveBoundary.pairAfterBody;
        pair.requireCurrent();
        receiveTrace?.lastBoundary = NearbyJoinReceiveBoundary.disclosureGate;
        final disclosure = wire['kind'] == 'created-jobs'
            ? companySyncDisclosure
            : null;
        if (wire['kind'] == 'created-jobs' && disclosure == null) {
          throw const NearbyException('Manual Job sync is unavailable');
        }
        // Only the company layer opens ciphertext or decides membership.
        receiveTrace?.lastBoundary = NearbyJoinReceiveBoundary.callbackLookup;
        final callback = onJoinMessage!;
        receiveTrace?.lastBoundary = NearbyJoinReceiveBoundary.callback;
        final reply = await callback(pair, wire);
        receiveTrace?.lastBoundary =
            NearbyJoinReceiveBoundary.callbackReturnedDisclosureCurrent;
        await disclosure?.requireCurrent();
        receiveTrace?.lastBoundary =
            NearbyJoinReceiveBoundary.pairAfterCallback;
        pair.requireCurrent();
        receiveTrace?.lastBoundary = NearbyJoinReceiveBoundary.disclosureLive;
        disclosure?.requireLive();
        receiveTrace?.lastBoundary = NearbyJoinReceiveBoundary.responseWrite;
        await _writeJson(request, reply);
        if (receiveTrace != null) {
          receiveTrace.lastBoundary = NearbyJoinReceiveBoundary.completed;
          _observeTransportEvent(
            onJoinReceiveObservation,
            receiveTrace.finish(NearbyJoinReceiveOutcome.completed),
          );
        }
        return;
      }
      if (request.method == 'GET' && path == '/v2/hello') {
        await _writeJson(request, {
          'proto': kNearbyProto,
          'v': kNearbyProtoVersion,
          'deviceId': deviceId,
          'name': deviceName,
          if (companyJoin) 'purpose': 'company-join@1',
        });
        return;
      }
      if (request.method == 'POST' && path == '/v2/pair/start') {
        await _onPairStart(request);
        return;
      }
      if (request.method == 'POST' && path == '/v2/pair/reveal') {
        await _onPairReveal(request);
        return;
      }
      if (request.method == 'POST' && path == '/v2/pair/confirm') {
        await _onPairConfirm(request);
        return;
      }
      if (request.method == 'POST' && path == '/v2/pair/cancel') {
        await _onPairCancel(request);
        return;
      }
      if (request.method == 'POST' && path == '/v2/offer') {
        if (companyJoin) {
          throw const NearbyException(
            'Shop copy is unavailable during company Join',
          );
        }
        await _onOffer(request);
        return;
      }
      if (request.method == 'PUT' && path == '/v2/transfer') {
        if (companyJoin) {
          throw const NearbyException(
            'Shop copy is unavailable during company Join',
          );
        }
        await _onTransfer(request);
        return;
      }
      request.response.statusCode = HttpStatus.notFound;
      await _writeJson(request, {'error': 'Unknown nearby request'});
    } catch (e) {
      if (receiveTrace != null) {
        _observeTransportEvent(
          onJoinReceiveObservation,
          receiveTrace.finish(NearbyJoinReceiveOutcome.caughtFailure),
        );
      }
      try {
        request.response.statusCode = HttpStatus.internalServerError;
        await _writeJson(request, {
          'error': companyJoin ? 'Join refused' : '$e',
        });
      } catch (_) {}
    }
  }

  Future<void> _onPairStart(HttpRequest request) async {
    final body = await _readJson(request);
    final context = NearbyPairContext.parse(body);
    if (context.purpose != (companyJoin ? 'company-join@1' : null)) {
      throw const NearbyException('Pair purposes differ. Update both devices.');
    }
    if (context.hostId != deviceId ||
        context.guestId == deviceId ||
        context.hostPort != _server?.port ||
        context.hostName != deviceName) {
      throw const NearbyException('Pair does not match this device');
    }
    final rateLimitNow = DateTime.now();
    _pairStarts.removeWhere(
      (time) => rateLimitNow.difference(time) > const Duration(minutes: 1),
    );
    if (_pairStarts.length >= 5) {
      request.response.statusCode = HttpStatus.tooManyRequests;
      await _writeJson(request, {
        'error': 'Too many pair attempts. Wait a minute.',
      });
      return;
    }
    _pairStarts.add(rateLimitNow);
    _failPending(cancel: true);
    final generation = _pairGeneration;
    final agreement = await NearbyPendingPair.create(context, guest: false);
    if (generation != _pairGeneration) {
      throw const NearbyException('Pair cancelled');
    }
    agreement.receiveCommitment(body['commitment']);
    final attempt = _PairAttempt(
      NearbyPeer(
        deviceId: context.guestId,
        name: context.guestName,
        host: request.connectionInfo?.remoteAddress.address ?? '',
        port: context.guestPort,
      ),
      agreement,
      expiresAt: (now ?? DateTime.now)().toUtc().add(kNearbyPairingWindow),
    );
    _pending = attempt;
    _hostMatch = Completer<bool>();
    _armPairExpiry(attempt);
    _emit(
      NearbyViewState(
        phase: NearbyPhase.pairing,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        peerName: attempt.peer.label,
        status: 'Connecting to ${attempt.peer.label}…',
      ),
    );
    await _writeJson(request, {'commitment': agreement.commitment});
  }

  _PairAttempt _hostAttempt(Map<String, Object?> body) {
    final attempt = _pending;
    if (attempt == null ||
        attempt.agreement.guest ||
        attempt.agreement.context.id != body['id']) {
      throw const NearbyException('Pair expired or was cancelled');
    }
    if (!_isCurrentPair(attempt)) {
      throw const NearbyException('Pair expired or was cancelled');
    }
    return attempt;
  }

  Future<void> _onPairReveal(HttpRequest request) async {
    final body = await _readJson(request);
    final attempt = _hostAttempt(body);
    final reveal = attempt.agreement.reveal();
    final match = await attempt.agreement.receiveReveal(body);
    if (!_isCurrentPair(attempt)) {
      throw const NearbyException('Pair expired or was cancelled');
    }
    attempt.match = match;
    _showMatch(attempt);
    await _writeJson(request, reveal);
  }

  Future<void> _onPairConfirm(HttpRequest request) async {
    final body = await _readJson(request);
    final attempt = _hostAttempt(body);
    final match = attempt.match;
    if (match == null) throw const NearbyException('Pair reveal required');
    match.confirmRemote(body['proof']);
    final hostMatch = _hostMatch!;
    final accepted = await hostMatch.future.timeout(
      _pairingRemaining(attempt.expiresAt),
      onTimeout: () {
        if (identical(_pending, attempt)) _fail('Pair expired. Try again.');
        return false;
      },
    );
    if (!_isCurrentPair(attempt) || !accepted) {
      throw const NearbyException('Pair cancelled');
    }
    final proof = match.confirmLocal();
    _paired(attempt, match.finish());
    await _writeJson(request, {'proof': proof});
  }

  Future<void> _onPairCancel(HttpRequest request) async {
    final session = _session;
    if (session != null) {
      if (!_authed(request)) {
        request.response.statusCode = HttpStatus.unauthorized;
        await _writeJson(request, {'error': 'Pair again'});
        return;
      }
      await _readJson(request);
      if (!identical(_session, session)) {
        throw const NearbyException('Pair expired');
      }
    } else {
      final body = await _readJson(request);
      if (_pending == null || body['id'] != _pending!.agreement.context.id) {
        throw const NearbyException('Pair expired');
      }
    }
    _failPending(cancel: true);
    _emit(
      NearbyViewState(
        phase: NearbyPhase.looking,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        error: 'The other device cancelled pair.',
        status: 'Looking for Wired Parts on this Wi-Fi.',
      ),
    );
    await _writeJson(request, {'ok': true});
  }

  Future<void> _onOffer(HttpRequest request) async {
    if (!_authed(request)) {
      request.response.statusCode = HttpStatus.unauthorized;
      await _writeJson(request, {'error': 'Pair again, then send'});
      return;
    }
    final session = _session!;
    final body = await _readJson(request);
    if (!identical(_session, session)) {
      request.response.statusCode = HttpStatus.unauthorized;
      await _writeJson(request, {'error': 'Pair again, then send'});
      return;
    }
    if (_pendingOffer != null || _state.phase == NearbyPhase.transferring) {
      request.response.statusCode = HttpStatus.conflict;
      await _writeJson(request, {
        'error': 'Finish the current shop copy first',
      });
      return;
    }
    final transferId = body['transferId'];
    final digest = body['digest'];
    if (transferId is! String ||
        transferId.length > 128 ||
        transferId.isEmpty ||
        digest is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(digest)) {
      throw const NearbyException('Invalid transfer identity');
    }
    final offer = NearbyOffer(
      sourceDeviceId: body['sourceDeviceId'] as String? ?? '',
      sourceName: body['sourceName'] as String? ?? 'Other device',
      jobs: body['jobs'] as int? ?? 0,
      parts: body['parts'] as int? ?? 0,
      photos: body['photos'] as int? ?? 0,
      bytes: body['bytes'] as int? ?? 0,
    );
    if (offer.sourceDeviceId != session.peer.deviceId ||
        offer.bytes <= 0 ||
        offer.bytes > kMaxNearbyTransferBytes) {
      request.response.statusCode = HttpStatus.badRequest;
      await _writeJson(request, {'error': 'Damaged shop offer'});
      return;
    }
    final pending = _PendingOffer(
      offer: offer,
      session: session,
      expiresAt: (now ?? DateTime.now)().toUtc().add(
        const Duration(minutes: 2),
      ),
    );
    _pendingOffer = pending;
    _emit(
      NearbyViewState(
        phase: NearbyPhase.offering,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        incoming: offer,
        peerName: offer.sourceName,
        status:
            '${offer.sourceName} wants to send their shop (${offer.summary}). Accept replaces catalog, jobs, warehouse locations, inventory and its history, and photos on this device.',
      ),
    );
    final accepted = await pending.decision.future.timeout(
      const Duration(minutes: 2),
      onTimeout: () => false,
    );
    final current = identical(_pendingOffer, pending);
    if (current) _pendingOffer = null;
    if (!accepted || !current || !identical(_session, session)) {
      if (current &&
          identical(_session, session) &&
          !pending.decision.isCompleted) {
        _emit(
          NearbyViewState(
            phase: NearbyPhase.looking,
            deviceName: deviceName,
            deviceId: deviceId,
            peers: _state.peers,
            status: 'Incoming shop offer expired. Pair again, then send.',
          ),
        );
      }
      request.response.statusCode = HttpStatus.forbidden;
      await _writeJson(request, {
        'error': 'They declined, or accept timed out. Nothing was copied.',
      });
      return;
    }
    _acceptedOffer = _AcceptedOffer(
      offer: offer,
      session: session,
      transferId: transferId,
      digest: digest,
      expiresAt: DateTime.now().add(const Duration(minutes: 2)),
    );
    await _writeJson(request, {'ok': true});
  }

  Future<void> _onTransfer(HttpRequest request) async {
    if (!_authed(request)) {
      request.response.statusCode = HttpStatus.unauthorized;
      await _writeJson(request, {'error': 'Pair again, then send'});
      return;
    }
    final accepted = _acceptedOffer;
    if (accepted == null ||
        accepted.claimed ||
        !identical(accepted.session, _session) ||
        !DateTime.now().isBefore(accepted.expiresAt)) {
      request.response.statusCode = HttpStatus.forbidden;
      await _writeJson(request, {
        'error': 'Accept this shop before receiving it',
      });
      return;
    }
    accepted.claimed = true;
    final length = request.contentLength;
    if (length != accepted.offer.bytes) {
      request.response.statusCode = HttpStatus.badRequest;
      await _writeJson(request, {
        'error': 'Transfer does not match the accepted shop',
      });
      return;
    }
    if (length > kMaxNearbyTransferBytes) {
      request.response.statusCode = HttpStatus.requestEntityTooLarge;
      await _writeJson(request, {
        'error': 'Shop is too large to send this way',
      });
      return;
    }
    _emit(
      _state.copyWith(
        phase: NearbyPhase.transferring,
        status: 'Receiving shop…',
        progress: 0,
      ),
    );
    final builder = BytesBuilder(copy: false);
    var got = 0;
    await for (final chunk in request) {
      if (!identical(_acceptedOffer, accepted) ||
          !identical(_session, accepted.session)) {
        request.response.statusCode = HttpStatus.forbidden;
        await _writeJson(request, {'error': 'Shop acceptance was cancelled'});
        return;
      }
      got += chunk.length;
      if (got > kMaxNearbyTransferBytes) {
        request.response.statusCode = HttpStatus.requestEntityTooLarge;
        await _writeJson(request, {
          'error': 'Shop is too large to send this way',
        });
        return;
      }
      builder.add(chunk);
      final total = length > 0 ? length : got;
      _emit(
        _state.copyWith(
          progress: total == 0 ? 0 : got / total,
          status:
              'Receiving shop… ${((total == 0 ? 0 : got / total) * 100).round()}%',
        ),
      );
    }
    final bytes = builder.takeBytes();
    final authentication = _authenticated[request]!;
    try {
      authentication.session.keys.verifyBody(authentication.proof, bytes);
      if (nearbyDigest(bytes) != accepted.digest) {
        throw const NearbyException(
          'Transfer does not match the accepted shop',
        );
      }
      final decrypted = await _codec.decrypt(
        Uint8List.fromList(bytes),
        accepted.session.keys.receiveKey,
        sessionId: accepted.session.keys.id,
        direction: accepted.session.keys.receiveDirection,
        transferId: accepted.transferId,
      );
      final offer = decrypted.offer;
      if (offer.sourceDeviceId != accepted.offer.sourceDeviceId ||
          offer.sourceName != accepted.offer.sourceName ||
          offer.jobs != accepted.offer.jobs ||
          offer.parts != accepted.offer.parts ||
          offer.photos != accepted.offer.photos ||
          got != accepted.offer.bytes) {
        throw const NearbyException(
          'Transfer does not match the accepted shop',
        );
      }
      if (!identical(_acceptedOffer, accepted) ||
          !identical(_session, accepted.session) ||
          !DateTime.now().isBefore(accepted.expiresAt)) {
        request.response.statusCode = HttpStatus.forbidden;
        await _writeJson(request, {'error': 'Shop acceptance was cancelled'});
        return;
      }
      _acceptedOffer = null;
      await applyPayload(decrypted.payload);
      _emit(
        NearbyViewState(
          phase: NearbyPhase.success,
          deviceName: deviceName,
          deviceId: deviceId,
          peers: _state.peers,
          peerName: decrypted.offer.sourceName,
          successMessage:
              'Received shop from ${decrypted.offer.sourceName} (${decrypted.offer.summary}). This device kept its own id.',
          status: 'Shop received.',
          progress: 1,
        ),
      );
      await _writeJson(request, {'ok': true});
    } catch (e) {
      if (identical(_session, accepted.session)) {
        _fail(_crewError(e, 'Receive failed. This shop was not replaced.'));
      }
      request.response.statusCode = HttpStatus.badRequest;
      await _writeJson(request, {'error': '$e'});
    }
  }

  bool _authed(HttpRequest request) {
    final session = _session;
    if (session == null ||
        request.headers.value('x-nearby-session') != session.keys.id) {
      return false;
    }
    try {
      final sequence = int.tryParse(
        request.headers.value('x-nearby-sequence') ?? '',
      );
      final digest = request.headers.value('x-nearby-digest');
      final mac = request.headers.value('x-nearby-mac');
      if (sequence == null || digest == null || mac == null) return false;
      final proof = NearbyRequestProof(sequence, digest, mac);
      session.keys.acceptRequest(request.method, request.uri.path, proof);
      _authenticated[request] = _AuthenticatedRequest(session, proof);
      return true;
    } catch (_) {
      return false;
    }
  }

  void _setProof(
    HttpClientRequest request,
    _Session session,
    NearbyRequestProof proof,
  ) {
    request.headers.set('x-nearby-session', session.keys.id);
    request.headers.set('x-nearby-sequence', proof.sequence);
    request.headers.set('x-nearby-digest', proof.digest);
    request.headers.set('x-nearby-mac', proof.mac);
  }

  Future<Map<String, Object?>> _jsonPost(
    NearbyPeer peer,
    String path,
    Map<String, Object?> body, {
    _Session? session,
    Duration timeout = const Duration(seconds: 20),
    DateTime? pairingDeadline,
    Future<void>? pairingEnded,
    NearbyCompanyDisclosure? disclosure,
  }) => _request(
    peer,
    'POST',
    path,
    Uint8List.fromList(utf8.encode(jsonEncode(body))),
    session: session,
    timeout: timeout,
    pairingDeadline: pairingDeadline,
    pairingEnded: pairingEnded,
    disclosure: disclosure,
  );

  Future<void> _putBytes(
    NearbyPeer peer,
    String path,
    Uint8List bytes, {
    required _Session session,
    required void Function(double progress) onProgress,
  }) async {
    await _request(
      peer,
      'PUT',
      path,
      bytes,
      session: session,
      timeout: const Duration(minutes: 10),
      onProgress: onProgress,
    );
  }

  Future<Map<String, Object?>> _request(
    NearbyPeer peer,
    String method,
    String path,
    Uint8List bytes, {
    _Session? session,
    Duration timeout = const Duration(seconds: 20),
    DateTime? pairingDeadline,
    Future<void>? pairingEnded,
    NearbyCompanyDisclosure? disclosure,
    void Function(double progress)? onProgress,
  }) async {
    final trace = _transportTrace(peer, path);
    trace?.emit(NearbyTransportStage.selected);
    if (!_allowsPeer(peer.host)) {
      trace?.fail(const NearbyException('Use the same Wi-Fi network'));
      throw const NearbyException('Use the same Wi-Fi network');
    }
    final client = HttpClient()..findProxy = (_) => 'DIRECT';
    HttpClient? activeClient = client;
    pairingEnded?.then((_) => activeClient?.close(force: true));
    Duration phaseTimeout({bool humanWait = false}) {
      if (pairingDeadline == null) return timeout;
      final remaining = _pairingRemaining(pairingDeadline);
      return humanWait || remaining < timeout ? remaining : timeout;
    }

    final wifi = _wifi;
    if (wifi != null) {
      client.connectionFactory = (uri, proxyHost, proxyPort) {
        trace?.factoryTarget(uri);
        return wifi.connect(uri, onStage: trace?.emit);
      };
    }
    try {
      final connectTimeout = phaseTimeout();
      final req = await client
          .open(method, peer.host, peer.port, path)
          .timeout(connectTimeout);
      trace?.emit(NearbyTransportStage.httpOpened);
      await disclosure?.requireCurrent();
      disclosure?.requireLive();
      req.followRedirects = false;
      req.headers.contentLength = bytes.length;
      req.headers.contentType = method == 'PUT'
          ? ContentType.binary
          : ContentType.json;
      final proof = session?.keys.signRequest(method, path, bytes);
      if (session != null && proof != null) _setProof(req, session, proof);
      const chunk = 64 * 1024;
      for (var i = 0; i < bytes.length; i += chunk) {
        final end = i + chunk > bytes.length ? bytes.length : i + chunk;
        req.add(bytes.sublist(i, end));
        onProgress?.call(end / bytes.length);
      }
      final responseTimeout = phaseTimeout(humanWait: true);
      final response = await req.close().timeout(responseTimeout);
      trace?.emit(
        NearbyTransportStage.httpResponse,
        httpStatus: response.statusCode,
      );
      final bodyTimeout = phaseTimeout();
      final responseBytes = await _readBounded(
        response,
        64 * 1024,
      ).timeout(bodyTimeout);
      if (pairingDeadline != null) _pairingRemaining(pairingDeadline);
      if (session != null && proof != null) {
        trace?.emit(NearbyTransportStage.responseAuthentication);
        session.keys.verifyResponse(
          proof,
          method,
          path,
          response.statusCode,
          responseBytes,
          response.headers.value('x-nearby-mac'),
        );
        trace?.emit(NearbyTransportStage.responseVerified);
      }
      final map = _decodeJson(responseBytes);
      if (response.statusCode != HttpStatus.ok) {
        throw NearbyException(
          map['error'] is String
              ? map['error']! as String
              : 'Nearby request failed',
        );
      }
      return map;
    } on TimeoutException catch (error) {
      trace?.fail(error);
      throw const NearbyException(
        'The other device did not answer. Keep Nearby open on both, same Wi-Fi.',
      );
    } catch (error) {
      trace?.fail(error);
      rethrow;
    } finally {
      activeClient = null;
      client.close(force: true);
    }
  }

  bool _allowsPeer(String host) =>
      (peerAllowed?.call(host) ?? true) && (_wifi?.allowsPeer(host) ?? true);

  Future<Uint8List> _readBounded(Stream<List<int>> stream, int limit) async {
    final builder = BytesBuilder(copy: false);
    await for (final chunk in stream) {
      if (builder.length + chunk.length > limit) {
        throw const NearbyException('Nearby message is too large');
      }
      builder.add(chunk);
    }
    return builder.takeBytes();
  }

  Map<String, Object?> _decodeJson(List<int> bytes) {
    final Object? decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map<String, dynamic>) {
      throw const NearbyException('Damaged nearby message');
    }
    return Map<String, Object?>.from(decoded);
  }

  Future<Map<String, Object?>> _readJson(HttpRequest request) async {
    final bytes = await _readBounded(
      request,
      64 * 1024,
    ).timeout(const Duration(seconds: 20));
    final authentication = _authenticated[request];
    authentication?.session.keys.verifyBody(authentication.proof, bytes);
    return _decodeJson(bytes);
  }

  Future<void> _writeJson(
    HttpRequest request,
    Map<String, Object?> body,
  ) async {
    final bytes = utf8.encode(jsonEncode(body));
    request.response.headers.contentType = ContentType.json;
    final authentication = _authenticated[request];
    if (authentication != null) {
      request.response.headers.set(
        'x-nearby-mac',
        authentication.session.keys.signResponse(
          authentication.proof,
          request.method,
          request.uri.path,
          request.response.statusCode,
          bytes,
        ),
      );
    }
    request.response.add(bytes);
    await request.response.close();
  }

  void _failPending({required bool cancel}) {
    _acceptedOffer = null;
    _pairTimer?.cancel();
    _pairTimer = null;
    _pairGeneration++;
    _pending?.ended.complete();
    _pending = null;
    _session = null;
    if (_hostMatch != null && !_hostMatch!.isCompleted) {
      _hostMatch!.complete(false);
    }
    _hostMatch = null;
    final pendingOffer = _pendingOffer;
    if (pendingOffer != null && !pendingOffer.decision.isCompleted) {
      pendingOffer.decision.complete(false);
    }
    _pendingOffer = null;
  }

  void _fail(String message) {
    _failPending(cancel: true);
    _emit(
      NearbyViewState(
        phase: NearbyPhase.failed,
        deviceName: deviceName,
        deviceId: deviceId,
        peers: _state.peers,
        error: message,
        status: message,
      ),
    );
  }

  String _crewError(Object e, String fallback) {
    if (e is NearbyException) return e.message;
    final s = '$e';
    if (s.isEmpty) return fallback;
    return '$fallback: $s';
  }

  void _emit(NearbyViewState next) {
    _state = next;
    if (!_stateCtrl.isClosed) _stateCtrl.add(next);
  }

  Future<void> dispose() {
    _disposed = true;
    return _disposal ??= _dispose();
  }

  Future<void> _dispose() async {
    await stop(reason: NearbyTransportStopReason.disposed);
    await _stateCtrl.close();
  }
}

final class _NearbyJoinReceiveTrace {
  _NearbyJoinReceiveTrace(this.request);

  final int request;
  final Stopwatch _clock = Stopwatch()..start();
  NearbyJoinReceiveBoundary lastBoundary =
      NearbyJoinReceiveBoundary.pairBeforeBody;

  NearbyJoinReceiveObservation finish(NearbyJoinReceiveOutcome outcome) =>
      NearbyJoinReceiveObservation(
        request: request,
        lastBoundary: lastBoundary,
        outcome: outcome,
        eventUtc: DateTime.now().toUtc(),
        elapsedMicros: _clock.elapsedMicroseconds,
      );
}

final class _NearbyRoomTrace {
  _NearbyRoomTrace(this.controller, this.generation, this.observer);
  final int controller;
  final int generation;
  final NearbyTransportObserver observer;
  final Stopwatch _clock = Stopwatch()..start();
  NearbyWifiNetwork? source;
  String? _address;
  int? _port;

  void bound(String address, int port) {
    _address = address;
    _port = port;
    emit(NearbyTransportStage.listenerBound);
  }

  void emit(
    NearbyTransportStage stage, {
    NearbyTransportStopReason? stopReason,
    NearbyTransportFailure? failure,
    int? osError,
  }) {
    observer(
      NearbyTransportObservation(
        request: 0,
        operation: NearbyTransportOperation.room,
        stage: stage,
        elapsedMicros: _clock.elapsedMicroseconds,
        peerAddress: '',
        peerPort: 0,
        generation: generation,
        controller: controller,
        listenerAddress: _address,
        listenerPort: _port,
        sourceInterfaceIndex: source?.index,
        sourceAddress: source?.address,
        sourcePrefixLength: source?.prefixLength,
        stopReason: stopReason,
        failure: failure,
        osError: osError,
      ),
    );
  }

  void failed(NearbyTransportStage stage, Object error) => emit(
    stage,
    failure: switch (error) {
      SocketException() => NearbyTransportFailure.socket,
      OSError() => NearbyTransportFailure.operatingSystem,
      _ => NearbyTransportFailure.other,
    },
    osError: switch (error) {
      SocketException(:final osError) => osError?.errorCode,
      OSError(:final errorCode) => errorCode,
      _ => null,
    },
  );
}

final class _NearbyTransportTrace {
  _NearbyTransportTrace({
    required this.request,
    required this.controller,
    required this.generation,
    required this.operation,
    required this.peer,
    required this.source,
    required this.fallbackAddress,
    required this.observer,
  });
  final int request;
  final int controller;
  final int generation;
  final NearbyTransportOperation operation;
  final NearbyPeer peer;
  final NearbyWifiNetwork? source;
  final String? fallbackAddress;
  final NearbyTransportObserver observer;
  final Stopwatch _clock = Stopwatch()..start();
  NearbyTransportStage _stage = NearbyTransportStage.selected;
  int _count = 0;
  String? _factoryAddress;
  int? _factoryPort;

  void factoryTarget(Uri uri) {
    _factoryAddress = uri.host;
    _factoryPort = uri.port;
    emit(NearbyTransportStage.factoryTarget);
  }

  void emit(
    NearbyTransportStage stage, {
    int? httpStatus,
    NearbyTransportFailure? failure,
    int? osError,
  }) {
    if (_count++ >= 16) return;
    _stage = stage;
    observer(
      NearbyTransportObservation(
        request: request,
        controller: controller,
        generation: generation,
        operation: operation,
        stage: stage,
        elapsedMicros: _clock.elapsedMicroseconds,
        peerAddress: peer.host,
        peerPort: peer.port,
        sourceInterfaceIndex: source?.index,
        sourceAddress: source?.address ?? fallbackAddress,
        sourcePrefixLength: source?.prefixLength,
        httpStatus: httpStatus,
        failure: failure,
        osError: osError,
        factoryAddress: _factoryAddress,
        factoryPort: _factoryPort,
      ),
    );
  }

  void fail(Object error) => emit(
    _stage,
    failure: switch (error) {
      SocketException() => NearbyTransportFailure.socket,
      OSError() => NearbyTransportFailure.operatingSystem,
      TimeoutException() => NearbyTransportFailure.timeout,
      NearbyException() => NearbyTransportFailure.refused,
      _ => NearbyTransportFailure.other,
    },
    osError: switch (error) {
      SocketException(:final osError) => osError?.errorCode,
      OSError(:final errorCode) => errorCode,
      _ => null,
    },
  );
}

final class NearbyPairedJoinSession {
  NearbyPairedJoinSession._(this._owner, this._session);
  final NearbyController _owner;
  final _Session _session;
  final Stopwatch _clock = Stopwatch()..start();
  final Set<String> _nonces = {};
  bool _revoked = false;
  Duration get timeUntilExpiry => const Duration(minutes: 5) - _clock.elapsed;
  int get remainingReceivedNonces => 128 - _nonces.length;
  void revoke() => _revoked = true;
  void requireCurrent() {
    if (!_owner.companyJoin ||
        !identical(_owner._session, _session) ||
        _owner._disposed ||
        _revoked ||
        timeUntilExpiry <= Duration.zero ||
        _session.keys.purpose != 'company-join@1') {
      throw const NearbyException('The approved pairing is no longer current');
    }
  }

  void reserveReceivedNonce(String nonce) {
    requireCurrent();
    if (_nonces.length >= 128 || !_nonces.add(nonce)) {
      throw const NearbyException('Join replay or channel capacity reached');
    }
  }

  NearbySessionKeys get keys {
    requireCurrent();
    return _session.keys;
  }
}

class _PairAttempt {
  _PairAttempt(this.peer, this.agreement, {required this.expiresAt});
  final NearbyPeer peer;
  final NearbyPendingPair agreement;
  NearbyAwaitingMatch? match;
  final DateTime expiresAt;
  final ended = Completer<void>();
  bool localConfirmed = false;
}

class _Session {
  NearbyPairedJoinSession? joinSession;
  _Session(this.peer, this.keys);
  final NearbyPeer peer;
  final NearbySessionKeys keys;
}

class _AuthenticatedRequest {
  _AuthenticatedRequest(this.session, this.proof);
  final _Session session;
  final NearbyRequestProof proof;
}

extension on NearbyViewState {
  NearbyViewState copyWith({
    NearbyPhase? phase,
    String? deviceName,
    String? deviceId,
    String? status,
    String? error,
    String? verifyCode,
    String? verificationAttemptId,
    DateTime? verificationExpiresAt,
    String? peerName,
    List<NearbyPeer>? peers,
    NearbyOffer? incoming,
    double? progress,
    String? successMessage,
    NearbyPeer? pairedPeer,
  }) {
    return NearbyViewState(
      phase: phase ?? this.phase,
      deviceName: deviceName ?? this.deviceName,
      deviceId: deviceId ?? this.deviceId,
      status: status ?? this.status,
      error: error,
      verifyCode: verifyCode ?? this.verifyCode,
      verificationAttemptId:
          verificationAttemptId ?? this.verificationAttemptId,
      verificationExpiresAt:
          verificationExpiresAt ?? this.verificationExpiresAt,
      peerName: peerName ?? this.peerName,
      peers: peers ?? this.peers,
      incoming: incoming ?? this.incoming,
      progress: progress ?? this.progress,
      successMessage: successMessage ?? this.successMessage,
      pairedPeer: pairedPeer ?? this.pairedPeer,
    );
  }
}

class _PendingOffer {
  _PendingOffer({
    required this.offer,
    required this.session,
    required this.expiresAt,
  });

  final NearbyOffer offer;
  final _Session session;
  final DateTime expiresAt;
  final decision = Completer<bool>();
}

class _AcceptedOffer {
  _AcceptedOffer({
    required this.offer,
    required this.session,
    required this.transferId,
    required this.digest,
    required this.expiresAt,
  });

  final NearbyOffer offer;
  final _Session session;
  final String transferId;
  final String digest;
  final DateTime expiresAt;
  bool claimed = false;
}

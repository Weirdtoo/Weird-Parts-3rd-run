import 'dart:convert';
import 'dart:async';

const kNearbyServiceType = '_wiredpart._tcp';

/// Shared Mac/Windows UDP beacon port. Not 45454: Windows (Hyper-V/WinNAT-style)
/// reserves ~44700–48799 on Impure even when `netsh excludedportrange` is empty.
const kNearbyUdpPort = 41000;
const kNearbyMulticastGroup = '239.55.12.42';
const kNearbyProto = 'wiredpart-link';
const kNearbyProtoVersion = 2;
const kNearbyPairingWindow = Duration(minutes: 5);
const kNearbyTransferMagic = [0x57, 0x50, 0x4c, 0x32]; // WPL2
const kMaxNearbyTransferBytes = 512 * 1024 * 1024;
const kLastNearbyAtKey = 'last_nearby_at';
const kLastNearbyPeerKey = 'last_nearby_peer';

enum NearbyTransportOperation {
  pairStart,
  pairReveal,
  pairConfirm,
  pairCancel,
  join,
  room,
}

enum NearbyTransportStage {
  selected,
  factoryTarget,
  interfaceCheck,
  interfaceValidated,
  tcpStart,
  tcpConnected,
  bindingCheck,
  bindingValidated,
  httpOpened,
  httpResponse,
  responseAuthentication,
  responseVerified,
  listenerBound,
  httpListening,
  discoveryStarting,
  discoveryStarted,
  listenerDone,
  listenerError,
  discoveryError,
  stopping,
  stopped,
}

enum NearbyTransportStopReason {
  requested,
  inactive,
  hidden,
  paused,
  detached,
  disposed,
  startupFailure,
  listenerDone,
  listenerError,
  discoveryError,
}

enum NearbyTransportFailure { socket, operatingSystem, timeout, refused, other }

typedef NearbyTransportObserver = FutureOr<void> Function(
  NearbyTransportObservation event,
);
const kNearbyTransportObservationLimit = 128;

enum NearbyJoinReceiveBoundary {
  pairBeforeBody,
  bodyRead,
  pairAfterBody,
  disclosureGate,
  callbackLookup,
  callback,
  callbackReturnedDisclosureCurrent,
  pairAfterCallback,
  disclosureLive,
  responseWrite,
  completed,
}

enum NearbyJoinReceiveOutcome { completed, caughtFailure }

typedef NearbyJoinReceiveObserver = FutureOr<void> Function(
  NearbyJoinReceiveObservation event,
);

/// A terminal observation for one authenticated request, local to its receiver.
final class NearbyJoinReceiveObservation {
  const NearbyJoinReceiveObservation({
    required this.request,
    required this.lastBoundary,
    required this.outcome,
    required this.eventUtc,
    required this.elapsedMicros,
  });

  final int request;

  /// The operation being attempted on failure, or completed after the write.
  final NearbyJoinReceiveBoundary lastBoundary;
  final NearbyJoinReceiveOutcome outcome;
  final DateTime eventUtc;
  final int elapsedMicros;

  Map<String, Object?> toJson() => {
    'operation': 'join',
    'outcome': outcome.name,
    'lastBoundary': lastBoundary.name,
    'request': request,
    'eventUtc': eventUtc.toUtc().toIso8601String(),
    'elapsedMicros': elapsedMicros,
  };
}

/// Local measurements contain no protocol bytes or error strings.
final class NearbyTransportObservation {
  const NearbyTransportObservation({
    required this.request,
    required this.operation,
    required this.stage,
    required this.elapsedMicros,
    required this.peerAddress,
    required this.peerPort,
    this.sourceInterfaceIndex,
    this.sourceAddress,
    this.sourcePrefixLength,
    this.httpStatus,
    this.failure,
    this.osError,
    this.factoryAddress,
    this.factoryPort,
    this.generation,
    this.controller,
    this.listenerAddress,
    this.listenerPort,
    this.stopReason,
  });
  final int request;
  final NearbyTransportOperation operation;
  final NearbyTransportStage stage;
  final int elapsedMicros;
  final String peerAddress;
  final int peerPort;
  final int? sourceInterfaceIndex;
  final String? sourceAddress;
  final int? sourcePrefixLength;
  final int? httpStatus;
  final NearbyTransportFailure? failure;
  final int? osError;
  final String? factoryAddress;
  final int? factoryPort;
  final int? generation;
  final int? controller;
  final String? listenerAddress;
  final int? listenerPort;
  final NearbyTransportStopReason? stopReason;

  static String? _ipv4(String? value) {
    if (value == null || value.length > 15) return null;
    final parts = value.split('.');
    if (parts.length != 4 ||
        parts.any(
          (part) =>
              !RegExp(r'^(0|[1-9][0-9]{0,2})$').hasMatch(part) ||
              int.parse(part) > 255,
        )) {
      return null;
    }
    return value;
  }

  Map<String, Object?> toJson() => {
    'request': request,
    'operation': operation.name,
    'stage': stage.name,
    'elapsedMicros': elapsedMicros,
    'peerAddress': _ipv4(peerAddress),
    'peerPort': peerPort > 0 && peerPort <= 65535 ? peerPort : null,
    'sourceInterfaceIndex':
        sourceInterfaceIndex != null &&
            sourceInterfaceIndex! > 0 &&
            sourceInterfaceIndex! <= 2147483647
        ? sourceInterfaceIndex
        : null,
    'sourceAddress': _ipv4(sourceAddress),
    'sourcePrefixLength':
        sourcePrefixLength != null &&
            sourcePrefixLength! >= 1 &&
            sourcePrefixLength! <= 30
        ? sourcePrefixLength
        : null,
    'httpStatus': httpStatus != null && httpStatus! >= 100 && httpStatus! <= 599
        ? httpStatus
        : null,
    'failure': failure?.name,
    'osError':
        osError != null && osError! >= -2147483648 && osError! <= 2147483647
        ? osError
        : null,
    'factoryAddress': _ipv4(factoryAddress),
    'factoryPort':
        factoryPort != null && factoryPort! > 0 && factoryPort! <= 65535
        ? factoryPort
        : null,
    'generation': generation,
    'controller': controller,
    'listenerAddress': _ipv4(listenerAddress),
    'listenerPort':
        listenerPort != null && listenerPort! > 0 && listenerPort! <= 65535
        ? listenerPort
        : null,
    'stopReason': stopReason?.name,
  };
}

class NearbyException implements Exception {
  const NearbyException(this.message);
  final String message;
  @override
  String toString() => message;
}

class NearbyPeer {
  const NearbyPeer({
    required this.deviceId,
    required this.name,
    required this.host,
    required this.port,
  });

  final String deviceId;
  final String name;
  final String host;
  final int port;

  String get label =>
      name.trim().isEmpty ? 'WiredPart ${shortId(deviceId)}' : name;

  NearbyPeer copyWith({String? host, int? port, String? name}) => NearbyPeer(
    deviceId: deviceId,
    name: name ?? this.name,
    host: host ?? this.host,
    port: port ?? this.port,
  );

  @override
  bool operator ==(Object other) =>
      other is NearbyPeer &&
      other.deviceId == deviceId &&
      other.host == host &&
      other.port == port;

  @override
  int get hashCode => Object.hash(deviceId, host, port);
}

class NearbyOffer {
  const NearbyOffer({
    required this.sourceDeviceId,
    required this.sourceName,
    required this.jobs,
    required this.parts,
    required this.photos,
    required this.bytes,
  });

  final String sourceDeviceId;
  final String sourceName;
  final int jobs;
  final int parts;
  final int photos;
  final int bytes;

  String get summary {
    final size = bytes < 1024 * 1024
        ? '${(bytes / 1024).ceil()} KB'
        : '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '$jobs jobs, $parts parts, $photos photos ($size)';
  }
}

String shortId(String deviceId) {
  final compact = deviceId.replaceAll('-', '');
  if (compact.length < 4) return compact;
  return compact.substring(compact.length - 4);
}

String defaultNearbyName(String deviceId) => 'WiredPart ${shortId(deviceId)}';

Map<String, Object?> decodeBeacon(List<int> bytes) {
  final Object? decoded = jsonDecode(utf8.decode(bytes));
  if (decoded is! Map) {
    throw const NearbyException('Damaged nearby beacon');
  }
  return Map<String, Object?>.from(decoded);
}

List<int> encodeBeacon({
  required String deviceId,
  required String name,
  required int port,
  required List<String> ips,
}) {
  return utf8.encode(
    jsonEncode({
      'v': kNearbyProtoVersion,
      'kind': 'wiredpart',
      'proto': kNearbyProto,
      'id': deviceId,
      'name': name,
      'port': port,
      'ips': ips,
    }),
  );
}

List<int> encodeWhoQuery() {
  return utf8.encode(
    jsonEncode({'v': kNearbyProtoVersion, 'kind': 'wiredpart-who'}),
  );
}

NearbyPeer? peerFromBeacon(Map<String, Object?> map, {String? fromHost}) {
  if (map['kind'] != 'wiredpart') return null;
  if (map['proto'] != kNearbyProto) return null;
  if (map['v'] != kNearbyProtoVersion) return null;
  final id = map['id'] as String?;
  final name = map['name'] as String? ?? '';
  final port = map['port'];
  if (id == null || id.isEmpty || port is! int || port <= 0 || port > 65535) {
    return null;
  }
  final ips = <String>[];
  final rawIps = map['ips'];
  if (rawIps is List) {
    for (final ip in rawIps) {
      if (ip is String && ip.isNotEmpty) ips.add(ip);
    }
  }
  final host = ips.isNotEmpty ? ips.first : fromHost;
  if (host == null || host.isEmpty) return null;
  return NearbyPeer(deviceId: id, name: name, host: host, port: port);
}

bool isWhoQuery(Map<String, Object?> map) => map['kind'] == 'wiredpart-who';

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'company_peer_native_driver_control.dart';
import 'native_nearby_test_commands.dart';
import 'native_nearby_test_crypto.dart';
import 'native_nearby_test_output.dart';
import 'native_nearby_test_rpc.dart';

const nativeTestSupportedRuns = {
  'nearby-lifecycle-20261007a',
  'nearby-resident-probe-20261009a',
  companyPeerDriverRun,
};
const _maxHostBytes = 65536;
const _maxDiscoveryVmBytes = 1048576;
const _extensions = {
  'ext.wired_parts.nearbyTest.info',
  'ext.wired_parts.nearbyTest.configure',
  'ext.wired_parts.nearbyTest.command',
};

enum NativeTestHostError {
  invalidInput,
  invalidOutput,
  notReady,
  notConfigured,
  alreadyConfigured,
  busy,
  identityMismatch,
  rpcFailed,
  rpcTimeout,
  disconnected,
  launcherFailed,
  unsupportedHost,
}

enum NativeTestVmFailureReason {
  socketClosed,
  frameTooLarge,
  invalidEnvelope,
  rpcError,
}

enum NativeTestVmMethod {
  getVM,
  getIsolate,
  info,
  configure,
  command;

  bool get isDiscovery => this == getVM || this == getIsolate;

  String get wireName => switch (this) {
    getVM => 'getVM',
    getIsolate => 'getIsolate',
    info => 'ext.wired_parts.nearbyTest.info',
    configure => 'ext.wired_parts.nearbyTest.configure',
    command => 'ext.wired_parts.nearbyTest.command',
  };
}

final class NativeTestVmDiagnostic {
  const NativeTestVmDiagnostic(this.reason, this.method, this.byteCount);
  final NativeTestVmFailureReason reason;
  final NativeTestVmMethod? method;
  final int? byteCount;

  Map<String, Object?> toJson() => {
    'reason': reason.name,
    'method': method?.wireName ?? 'none',
    'byteCount': byteCount,
  };
}

final class NativeTestHostFailure implements Exception {
  const NativeTestHostFailure(this.category, {this.diagnostic});
  final NativeTestHostError category;
  final NativeTestVmDiagnostic? diagnostic;
  Map<String, Object> toJson() => {
    'outcome': 'failed',
    'category': category.name,
    if (diagnostic != null) 'diagnostic': diagnostic!.toJson(),
  };
  @override
  String toString() => 'NativeTestHostFailure';
}

final class NativeTestVmResult {
  const NativeTestVmResult(this.value, this.byteCount);
  final Object? value;
  final int byteCount;
}

NativeTestVmResult nativeTestVmResult(
  Object? message, {
  required NativeTestVmMethod? method,
  required int? expectedId,
}) {
  final limit = method?.isDiscovery == true
      ? _maxDiscoveryVmBytes
      : _maxHostBytes;
  int? bytes;
  Never fail(NativeTestVmFailureReason reason) => throw NativeTestHostFailure(
    NativeTestHostError.disconnected,
    diagnostic: NativeTestVmDiagnostic(reason, method, bytes),
  );
  if (message is String) {
    if (message.length > limit) {
      fail(NativeTestVmFailureReason.frameTooLarge);
    }
    bytes = utf8.encode(message).length;
  } else if (message is List<int>) {
    bytes = message.length;
  }
  if (bytes != null && bytes > limit) {
    fail(NativeTestVmFailureReason.frameTooLarge);
  }
  try {
    if (message is! String) fail(NativeTestVmFailureReason.invalidEnvelope);
    final m = jsonDecode(message);
    if (m is! Map ||
        expectedId == null ||
        m['jsonrpc'] != '2.0' ||
        m['id'] is! int ||
        m['id'] != expectedId ||
        m.containsKey('error') == m.containsKey('result')) {
      fail(NativeTestVmFailureReason.invalidEnvelope);
    }
    if (m.containsKey('error')) fail(NativeTestVmFailureReason.rpcError);
    return NativeTestVmResult(m['result'], bytes!);
  } on NativeTestHostFailure {
    rethrow;
  } catch (_) {
    fail(NativeTestVmFailureReason.invalidEnvelope);
  }
}

Never _reject([
  NativeTestHostError category = NativeTestHostError.invalidOutput,
]) => throw NativeTestHostFailure(category);

String _isolateId(Object? value) {
  if (value is! String || !RegExp(r'^isolates/[0-9]{1,32}$').hasMatch(value)) {
    _reject();
  }
  return value;
}

Map<String, dynamic> _map(
  Object? value,
  Set<String> required, [
  Set<String> optional = const {},
]) {
  if (value is! Map<String, dynamic> ||
      !required.every(value.containsKey) ||
      !value.keys.every(
        (key) => required.contains(key) || optional.contains(key),
      )) {
    _reject();
  }
  return value;
}

int _integer(Object? value, {bool zero = false}) {
  if (value is! int || value < (zero ? 0 : 1) || value > 9007199254740991) {
    _reject();
  }
  return value;
}

bool _boolean(Object? value) {
  if (value is! bool) {
    _reject();
  }
  return value;
}

T _enumValue<T extends Enum>(Object? value, List<T> values) {
  for (final item in values) {
    if (item.name == value) return item;
  }
  _reject();
}

abstract interface class NativeTestHostTransport {
  Future<Object?> getVm();
  Future<Object?> getIsolate(String isolateId);
  Future<Object?> info(String isolateId, {Duration? timeout});
  Future<Object?> configure(String isolateId, String data);
  Future<Object?> command(String isolateId, String data, {Duration? timeout});
}

final class NativeTestHost {
  NativeTestHost({
    required this.transport,
    required this.run,
    required this.platform,
    this.observeContextBudget = const Duration(seconds: 3),
    this.observeContextElapsed,
  }) {
    if (observeContextBudget <= Duration.zero ||
        observeContextBudget > const Duration(seconds: 3)) {
      _reject(NativeTestHostError.invalidInput);
    }
    if (!nativeTestSupportedRuns.contains(run) ||
        (platform != 'windows' && platform != 'macos') ||
        (run == companyPeerDriverRun && platform != 'windows')) {
      _reject(NativeTestHostError.invalidInput);
    }
  }

  final NativeTestHostTransport transport;
  final String run, platform;
  final Duration observeContextBudget;

  /// Test-only monotonic elapsed time since the current observation began.
  /// When omitted, each observation uses a fresh real Stopwatch.
  final Duration Function()? observeContextElapsed;
  String? _isolate;
  TestSession? _session;
  bool _configureAttempted = false;
  bool _handling = false;
  int? _pid;

  TestRole get role =>
      platform == 'windows' ? TestRole.receiver : TestRole.sender;
  String get deviceId => 'lan-$run-${role.name}';
  String get peerId => run == companyPeerDriverRun
      ? companyPeerDriverOperator
      : 'lan-$run-${role == TestRole.sender ? 'receiver' : 'sender'}';

  Future<bool> discover() async {
    final vm = await transport.getVm();
    if (vm is! Map || vm['isolates'] is! List) {
      _reject();
    }
    final isolates = vm['isolates'] as List;
    if (isolates.length > 8) {
      _reject();
    }
    final matches = <String>[];
    for (final ref in isolates) {
      if (ref is! Map) {
        _reject();
      }
      final id = _isolateId(ref['id']);
      final isolate = await transport.getIsolate(id);
      if (isolate is Map &&
          isolate['type'] == 'Sentinel' &&
          isolate['kind'] == 'Collected') {
        continue;
      }
      if (isolate is! Map || isolate['id'] != id) {
        _reject();
      }
      final extensions = isolate['extensionRPCs'];
      if (extensions == null) continue;
      if (extensions is! List) _reject();
      if (extensions.length > 256 || !extensions.every((e) => e is String)) {
        _reject();
      }
      if (_extensions.every(extensions.contains)) matches.add(id);
    }
    if (matches.isEmpty) {
      return false;
    }
    if (matches.length != 1 ||
        (_isolate != null && _isolate != matches.single)) {
      _reject(NativeTestHostError.identityMismatch);
    }
    _isolate = matches.single;
    return true;
  }

  Future<Map<String, Object>> handleLine(String source) async {
    if (_handling) {
      return {'outcome': 'failed', 'category': NativeTestHostError.busy.name};
    }
    _handling = true;
    try {
      if (source.length > _maxHostBytes ||
          utf8.encode(source).length > _maxHostBytes) {
        _reject(NativeTestHostError.invalidInput);
      }
      final decoded = jsonDecode(source);
      if (decoded is! Map<String, dynamic>) {
        _reject(NativeTestHostError.invalidInput);
      }
      final operation = decoded['operation'];
      if (operation != 'info' &&
          operation != 'configure' &&
          operation != 'command') {
        _reject(NativeTestHostError.invalidInput);
      }
      if (_isolate == null) {
        _reject(NativeTestHostError.notReady);
      }
      if (operation == 'info') {
        _map(decoded, {'operation'});
        return {
          'outcome': 'info',
          'isolateId': _isolate!,
          'value': await _info(),
        };
      }
      if (operation == 'configure') {
        _map(decoded, {'operation', 'session'});
        if (_configureAttempted) {
          _reject(NativeTestHostError.alreadyConfigured);
        }
        final session = TestSession.fromJson(decoded['session']);
        if (session.run != run ||
            session.role != role ||
            session.deviceId != deviceId ||
            session.peerId != peerId) {
          _reject(NativeTestHostError.identityMismatch);
        }
        final info = await _info();
        if (info['outcome'] != 'ready') {
          _reject(NativeTestHostError.notReady);
        }
        if (info['configured'] == true) {
          _reject(NativeTestHostError.alreadyConfigured);
        }
        // A lost configure reply does not authorize a second configuration.
        _configureAttempted = true;
        final output = _map(
          await transport.configure(_isolate!, jsonEncode(session.toJson())),
          {'version', 'outcome'},
        );
        if (output['version'] != 1 ||
            (output['outcome'] != 'configured' &&
                output['outcome'] != 'rejected')) {
          _reject();
        }
        if (output['outcome'] == 'configured') _session = session;
        return {
          'outcome': 'configure',
          'value': {'version': 1, 'outcome': output['outcome'] as String},
        };
      }
      _map(decoded, {'operation', 'command'});
      final session = _session;
      if (session == null) {
        _reject(NativeTestHostError.notConfigured);
      }
      final data = jsonEncode(decoded['command']);
      final command = NativeTestCommand.parseRequest(data, session);
      final currentInfo = await _info();
      if (currentInfo['outcome'] != 'ready' ||
          currentInfo['configured'] != true) {
        _reject(NativeTestHostError.notConfigured);
      }
      return {
        'outcome': 'command',
        'value': _commandReply(
          await transport.command(_isolate!, data),
          command,
          session,
        ),
      };
    } on NativeTestHostFailure catch (failure) {
      return failure.toJson();
    } catch (_) {
      return {
        'outcome': 'failed',
        'category': NativeTestHostError.invalidInput.name,
      };
    } finally {
      _handling = false;
    }
  }

  /// The opt-in operation emits a bound context immediately before a completed
  /// observation. Ordinary operations retain their single-record behavior.
  Future<List<Map<String, Object>>> handleRecords(String source) async {
    try {
      if (source.length <= _maxHostBytes &&
          utf8.encode(source).length <= _maxHostBytes) {
        final decoded = jsonDecode(source);
        if (decoded is Map<String, dynamic> &&
            decoded['operation'] == 'observeAndContext') {
          return await _observeAndContext(decoded);
        }
      }
    } catch (_) {
      // The existing parser owns ordinary malformed-input responses.
    }
    return [await handleLine(source)];
  }

  Future<List<Map<String, Object>>> _observeAndContext(
    Map<String, dynamic> decoded,
  ) async {
    if (_handling) {
      return [const NativeTestHostFailure(NativeTestHostError.busy).toJson()];
    }
    _handling = true;
    final clock = Stopwatch()..start();
    Map<String, Object>? last;
    int? nativeRemainingAtStart;
    Duration remaining() {
      final elapsed =
          observeContextElapsed?.call().inMicroseconds ??
          clock.elapsedMicroseconds;
      var micros = observeContextBudget.inMicroseconds - elapsed;
      final native = nativeRemainingAtStart;
      if (native != null) {
        final nativeMicros = native * 1000 - elapsed;
        if (nativeMicros < micros) micros = nativeMicros;
      }
      if (micros <= 0) _reject(NativeTestHostError.rpcTimeout);
      return Duration(microseconds: micros);
    }

    try {
      _map(decoded, {'operation', 'command'});
      if (_isolate == null) _reject(NativeTestHostError.notReady);
      final session = _session;
      if (session == null) _reject(NativeTestHostError.notConfigured);
      final data = jsonEncode(decoded['command']);
      late final NativeTestCommand command;
      try {
        command = NativeTestCommand.parseRequest(data, session);
      } catch (_) {
        _reject(NativeTestHostError.invalidInput);
      }
      if (command.action != NativeTestAction.observe) {
        _reject(NativeTestHostError.invalidInput);
      }
      final currentInfo = await _info(timeout: remaining());
      if (currentInfo['outcome'] != 'ready' ||
          currentInfo['configured'] != true) {
        _reject(NativeTestHostError.notConfigured);
      }
      // Counting the initial info RPC again is conservative: it cannot extend
      // the resident's original deadline or the host's monotonic wait budget.
      nativeRemainingAtStart =
          command.deadlineMillis - (currentInfo['elapsedMillis'] as int);
      while (true) {
        final reply = _commandReply(
          await transport.command(_isolate!, data, timeout: remaining()),
          command,
          session,
        );
        last = {'outcome': 'command', 'value': reply};
        final state = reply['state'];
        if (state == 'completed') {
          final info = await _info(timeout: remaining());
          remaining();
          if (info['outcome'] != 'ready' || info['configured'] != true) {
            _reject(NativeTestHostError.notConfigured);
          }
          if ((info['elapsedMillis'] as int) <
              (currentInfo['elapsedMillis'] as int)) {
            _reject(NativeTestHostError.identityMismatch);
          }
          return [
            {
              'outcome': 'info',
              'isolateId': _isolate!,
              'value': info,
              'commandIdentity': {
                'epoch': command.epoch,
                'commandId': command.commandId,
                'sequence': command.sequence,
                'action': command.action.name,
                'contentHash': command.contentHash,
              },
            },
            last,
          ];
        }
        if (state != 'accepted' && state != 'running') return [last];
        final budget = remaining();
        final delay = budget < const Duration(milliseconds: 50)
            ? budget
            : const Duration(milliseconds: 50);
        await Future<void>.delayed(delay);
      }
    } on NativeTestHostFailure catch (failure) {
      return [?last, failure.toJson()];
    } catch (_) {
      return [
        ?last,
        const NativeTestHostFailure(NativeTestHostError.rpcFailed).toJson(),
      ];
    } finally {
      _handling = false;
    }
  }

  Future<Map<String, Object>> _info({Duration? timeout}) async {
    final raw = await transport.info(_isolate!, timeout: timeout);
    if (raw is Map && raw['outcome'] == 'not-ready') {
      final m = _map(raw, {'version', 'outcome'});
      if (m['version'] != 1) {
        _reject();
      }
      return {'version': 1, 'outcome': 'not-ready'};
    }
    final m = _map(raw, {
      'version',
      'outcome',
      'appPid',
      'run',
      'role',
      'deviceId',
      'peerId',
      'configured',
      'elapsedMillis',
      'phase',
      'sameNearbyState',
      'discovered',
      'codePresent',
      if (run == companyPeerDriverRun) ...{'candidateInputKey', 'candidateUi'},
    });
    if (m['version'] != 1 ||
        m['outcome'] != 'ready' ||
        m['run'] != run ||
        m['role'] != role.name ||
        m['deviceId'] != deviceId ||
        m['peerId'] != peerId) {
      _reject(NativeTestHostError.identityMismatch);
    }
    final pid = _integer(m['appPid']);
    if (_pid != null && _pid != pid) {
      _reject(NativeTestHostError.identityMismatch);
    }
    _pid = pid;
    return {
      'version': 1,
      'outcome': 'ready',
      'appPid': pid,
      'run': run,
      'role': role.name,
      'deviceId': deviceId,
      'peerId': peerId,
      'configured': _boolean(m['configured']),
      'elapsedMillis': _integer(m['elapsedMillis'], zero: true),
      'phase': _enumValue(m['phase'], NativeTestPhase.values).name,
      'sameNearbyState': _boolean(m['sameNearbyState']),
      'discovered': _boolean(m['discovered']),
      'codePresent': _boolean(m['codePresent']),
      if (run == companyPeerDriverRun) ...{
        'candidateInputKey': base64Url.encode(
          nativeTestBytes(m['candidateInputKey'], 32),
        ),
        'candidateUi': companyPeerDriverUi(m['candidateUi']),
      },
    };
  }

  Map<String, Object> _commandReply(
    Object? raw,
    NativeTestCommand command,
    TestSession session,
  ) {
    if (raw is Map && raw['outcome'] == 'not-configured') {
      final m = _map(raw, {'version', 'outcome'});
      if (m['version'] != 1) {
        _reject();
      }
      return {'version': 1, 'outcome': 'not-configured'};
    }
    final m = _map(
      raw,
      {'version', 'state', 'outcome', 'inflight', 'effect'},
      {'sequence', 'result'},
    );
    if (m['version'] != 1) {
      _reject();
    }
    final effect = _enumValue(m['effect'], NativeTestEffect.values);
    final inflight = _boolean(m['inflight']);
    final state = m['state'];
    if (state == 'rejected') {
      if (m.containsKey('sequence') ||
          m.containsKey('result') ||
          inflight ||
          effect != NativeTestEffect.none) {
        _reject();
      }
      return {
        'version': 1,
        'state': 'rejected',
        'outcome': _enumValue(m['outcome'], NativeTestCommandError.values).name,
        'inflight': false,
        'effect': 'none',
      };
    }
    final status = _enumValue(state, NativeTestCommandState.values);
    if (_integer(m['sequence']) != command.sequence ||
        inflight !=
            (status == NativeTestCommandState.running ||
                status == NativeTestCommandState.unknown)) {
      _reject();
    }
    final expectedOutcome = switch (status) {
      NativeTestCommandState.accepted ||
      NativeTestCommandState.running => 'pending',
      NativeTestCommandState.unknown => 'UNKNOWN',
      NativeTestCommandState.completed => 'success',
      NativeTestCommandState.failed => _enumValue(
        m['outcome'],
        NativeTestCommandError.values,
      ).name,
    };
    if (m['outcome'] != expectedOutcome ||
        m.containsKey('result') !=
            (status == NativeTestCommandState.completed) ||
        ((status == NativeTestCommandState.accepted ||
                status == NativeTestCommandState.running) &&
            effect != NativeTestEffect.none) ||
        (status == NativeTestCommandState.unknown &&
            effect != NativeTestEffect.possible)) {
      _reject();
    }
    return {
      'version': 1,
      'sequence': command.sequence,
      'state': status.name,
      'outcome': expectedOutcome,
      'inflight': inflight,
      'effect': effect.name,
      if (status == NativeTestCommandState.completed)
        'result': _result(m['result'], command, session, effect),
    };
  }

  Map<String, Object> _result(
    Object? raw,
    NativeTestCommand command,
    TestSession session,
    NativeTestEffect effect,
  ) {
    final m = _map(raw, {'outcome', 'effect'}, {'observation', 'snapshot'});
    if (m['outcome'] != 'success' ||
        m['effect'] != effect.name ||
        effect == NativeTestEffect.possible ||
        m.containsKey('observation') !=
            (command.action == NativeTestAction.observe) ||
        m.containsKey('snapshot') !=
            (command.action == NativeTestAction.snapshot)) {
      _reject();
    }
    if (command.action == NativeTestAction.observe) {
      final o = _map(
        m['observation'],
        {
          'epoch',
          'run',
          'role',
          'deviceId',
          'peerId',
          'phase',
          'sameNearbyState',
          'discovered',
          'codePresent',
        },
        {'sealedObservation'},
      );
      if (o['epoch'] != session.epoch ||
          o['run'] != run ||
          o['role'] != role.name ||
          o['deviceId'] != deviceId ||
          o['peerId'] != peerId ||
          effect != NativeTestEffect.none) {
        _reject();
      }
      final sealed = o.containsKey('sealedObservation')
          ? SealedObservation.fromJson(o['sealedObservation'])
          : null;
      if (sealed != null &&
          (command.comparison == null ||
              jsonEncode(sealed.challenge.toJson()) !=
                  jsonEncode(command.comparison!.toJson()))) {
        _reject();
      }
      return NativeTestCommandResult.observation(
        NativeTestObservationResult(
          session: session,
          phase: _enumValue(o['phase'], NativeTestPhase.values),
          sameNearbyState: _boolean(o['sameNearbyState']),
          discovered: _boolean(o['discovered']),
          codePresent: _boolean(o['codePresent']),
          sealedObservation: sealed,
        ),
      ).toJson();
    }
    if (command.action == NativeTestAction.snapshot) {
      final s = _map(
        m['snapshot'],
        {
          'digest',
          'assetsDigest',
          'sharedSettingsDigest',
          'profileDigest',
          'schemaVersion',
          'tableCount',
          'rowCount',
          'assetCount',
          'integrityValid',
          'referencesValid',
          'profileEqual',
          'assetsEqual',
          'settingsEqual',
          'ownershipEqual',
          'sealedProof',
        },
        {'lastNearbySourceId', 'lastNearbyAtMillis'},
      );
      if (effect != NativeTestEffect.none ||
          (s.containsKey('lastNearbySourceId') &&
              s['lastNearbySourceId'] != peerId)) {
        _reject();
      }
      final proof = SealedPrivateSnapshot.fromJson(s['sealedProof']);
      if (proof.epoch != session.epoch ||
          proof.run != run ||
          proof.role != role ||
          proof.stage != command.snapshotStage) {
        _reject();
      }
      return NativeTestCommandResult.snapshot(
        NativeTestSnapshotResult(
          digest: nativeTestText(s['digest']),
          assetsDigest: nativeTestText(s['assetsDigest']),
          sharedSettingsDigest: nativeTestText(s['sharedSettingsDigest']),
          profileDigest: nativeTestText(s['profileDigest']),
          schemaVersion: _integer(s['schemaVersion']),
          tableCount: _integer(s['tableCount'], zero: true),
          rowCount: _integer(s['rowCount'], zero: true),
          assetCount: _integer(s['assetCount'], zero: true),
          integrityValid: _boolean(s['integrityValid']),
          referencesValid: _boolean(s['referencesValid']),
          profileEqual: _boolean(s['profileEqual']),
          assetsEqual: _boolean(s['assetsEqual']),
          settingsEqual: _boolean(s['settingsEqual']),
          ownershipEqual: _boolean(s['ownershipEqual']),
          sealedProof: proof,
          lastNearbySourceId: s.containsKey('lastNearbySourceId')
              ? peerId
              : null,
          lastNearbyAtMillis: s.containsKey('lastNearbyAtMillis')
              ? _integer(s['lastNearbyAtMillis'], zero: true)
              : null,
        ),
      ).toJson();
    }
    return NativeTestCommandResult.effect(effect: effect).toJson();
  }
}

final class NativeTestLauncherDiagnostics {
  NativeTestLauncherDiagnostics({this.onConfigureDiagnostic});
  final void Function(NativeTestConfigureDiagnostic)? onConfigureDiagnostic;
  final _clock = Stopwatch()..start();
  final _buffers = ['', ''];
  final _discard = [false, false];
  bool _timeout = false;
  bool _outOfBand = false;
  bool _cleanup = false;
  bool _nativeFailure = false;
  NativeTestConfigureDiagnostic? _lastConfigureDiagnostic;
  int _configureDiagnosticCount = 0;

  int get bufferedCharacters => _buffers[0].length + _buffers[1].length;
  void addStdout(List<int> bytes) => _add(bytes, 0);
  void addStderr(List<int> bytes) => _add(bytes, 1);
  void finishStdout() => _finish(0);
  void finishStderr() => _finish(1);

  void _finish(int channel) {
    if (!_discard[channel]) _line(_buffers[channel]);
    _buffers[channel] = '';
    _discard[channel] = false;
  }

  void _add(List<int> bytes, int channel) {
    for (final byte in bytes) {
      if (byte == 10 || byte == 13) {
        if (!_discard[channel]) _line(_buffers[channel]);
        _buffers[channel] = '';
        _discard[channel] = false;
      } else if (!_discard[channel]) {
        if (_buffers[channel].length >= 4096) {
          _buffers[channel] = '';
          _discard[channel] = true;
        } else {
          // Preserve bytes privately; malformed payload bytes must not be
          // stripped into a valid diagnostic. The full line remains bounded.
          _buffers[channel] += String.fromCharCode(byte);
        }
      }
    }
  }

  void _line(String line) {
    _timeout |= line.contains('Test timed out after ');
    _outOfBand |= line.contains('finished with out-of-band failure');
    _cleanup |= line.contains('ensuring test device is terminated');
    _nativeFailure |= line.contains('NativeTestFailure');
    if (!line.startsWith(nativeTestConfigureDiagnosticPrefix) ||
        _configureDiagnosticCount >= 8) {
      return;
    }
    try {
      final record = NativeTestConfigureDiagnostic.fromJson(
        jsonDecode(line.substring(nativeTestConfigureDiagnosticPrefix.length)),
      );
      _lastConfigureDiagnostic = record;
      _configureDiagnosticCount++;
      onConfigureDiagnostic?.call(record);
    } catch (_) {
      // Neither malformed log text nor a failed diagnostic sink is forwarded.
    }
  }

  Map<String, Object> toJson() => {
    'launcherElapsedMillis': _clock.elapsedMilliseconds,
    'testTimeoutMarkerSeen': _timeout,
    'outOfBandFailureMarkerSeen': _outOfBand,
    'cleanupMarkerSeen': _cleanup,
    'nativeTestFailureMarkerSeen': _nativeFailure,
    if (_lastConfigureDiagnostic != null)
      'configureDiagnostic': _lastConfigureDiagnostic!.toJson(),
  };
}

final class NativeTestVmBannerScanner {
  String _buffer = '';
  bool _discardLine = false;
  Uri? _uri;
  Uri? get privateUri => _uri;
  int get bufferedCharacters => _buffer.length;

  void add(List<int> bytes) {
    for (final byte in bytes) {
      if (byte == 10 || byte == 13) {
        if (!_discardLine) _line(_buffer);
        _buffer = '';
        _discardLine = false;
      } else if (!_discardLine) {
        if (_buffer.length >= 4096) {
          _buffer = '';
          _discardLine = true;
        } else if (byte >= 32 && byte <= 126) {
          _buffer += String.fromCharCode(byte);
        }
      }
    }
  }

  void _line(String line) {
    if (_uri != null ||
        (!line.contains('Dart VM service is listening on ') &&
            !line.contains('Dart VM Service on ') &&
            !line.contains('VM Service URL on device: ') &&
            !line.contains('Dart Development Service started at '))) {
      return;
    }
    final match = RegExp(
      r'http://127\.0\.0\.1:([0-9]{1,5})/[A-Za-z0-9_=.-]{1,128}/',
    ).firstMatch(line);
    if (match == null) return;
    final uri = Uri.tryParse(match.group(0)!);
    if (uri == null || uri.port < 1 || uri.port > 65535) return;
    _uri = uri;
  }
}

final class _VmTransport implements NativeTestHostTransport {
  _VmTransport(this._socket) {
    _socket.listen(
      _receive,
      onError: (_) => _disconnect(),
      onDone: _disconnect,
    );
  }
  final WebSocket _socket;
  final _pending = <int, Completer<Object?>>{};
  int _nextId = 0;
  bool _closed = false;
  NativeTestVmMethod? _activeMethod;
  NativeTestHostFailure? _failure;
  int _discoveryMaxFrameBytes = 0;
  int get discoveryMaxFrameBytes => _discoveryMaxFrameBytes;

  static Future<_VmTransport> connect(Uri uri) async {
    if (uri.scheme != 'http' ||
        uri.host != '127.0.0.1' ||
        uri.port < 1 ||
        uri.port > 65535 ||
        uri.userInfo.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment) {
      _reject(NativeTestHostError.invalidInput);
    }
    try {
      final socket = await WebSocket.connect(
        uri.replace(scheme: 'ws', path: '${uri.path}ws').toString(),
      ).timeout(const Duration(seconds: 5));
      return _VmTransport(socket);
    } catch (_) {
      _reject(NativeTestHostError.rpcFailed);
    }
  }

  Future<Object?> _call(
    NativeTestVmMethod method, [
    Map<String, String> params = const {},
    Duration? timeout,
  ]) async {
    if (_closed) {
      throw _failure ??
          const NativeTestHostFailure(NativeTestHostError.disconnected);
    }
    if (_pending.isNotEmpty) {
      _reject(NativeTestHostError.rpcFailed);
    }
    if (timeout != null && timeout <= Duration.zero) {
      _reject(NativeTestHostError.rpcTimeout);
    }
    final id = ++_nextId;
    final completer = Completer<Object?>();
    _pending[id] = completer;
    _activeMethod = method;
    try {
      _socket.add(
        jsonEncode({
          'jsonrpc': '2.0',
          'id': id,
          'method': method.wireName,
          'params': params,
        }),
      );
      return await completer.future.timeout(
        timeout ?? const Duration(seconds: 5),
        onTimeout: () {
          if (timeout != null) {
            // A bounded request is never left pending for a later command.
            _disconnect(
              const NativeTestHostFailure(NativeTestHostError.rpcTimeout),
            );
            unawaited(
              _socket.close().then<void>((_) {}, onError: (Object _) {}),
            );
          }
          _reject(NativeTestHostError.rpcTimeout);
        },
      );
    } on NativeTestHostFailure {
      rethrow;
    } catch (_) {
      _reject(NativeTestHostError.rpcFailed);
    } finally {
      _pending.remove(id);
      _activeMethod = null;
    }
  }

  void _receive(Object? message) {
    try {
      final pending = _pending.length == 1 ? _pending.values.single : null;
      final result = nativeTestVmResult(
        message,
        method: _activeMethod,
        expectedId: pending == null || pending.isCompleted
            ? null
            : _pending.keys.single,
      );
      if (_activeMethod?.isDiscovery == true &&
          result.byteCount > _discoveryMaxFrameBytes) {
        _discoveryMaxFrameBytes = result.byteCount;
      }
      pending!.complete(result.value);
    } on NativeTestHostFailure catch (failure) {
      _disconnect(failure);
    } catch (_) {
      _disconnect();
    }
  }

  void _disconnect([NativeTestHostFailure? failure]) {
    if (_closed) return;
    _closed = true;
    _failure =
        failure ??
        NativeTestHostFailure(
          NativeTestHostError.disconnected,
          diagnostic: NativeTestVmDiagnostic(
            NativeTestVmFailureReason.socketClosed,
            _activeMethod,
            0,
          ),
        );
    for (final pending in _pending.values) {
      if (!pending.isCompleted) {
        pending.completeError(_failure!);
      }
    }
  }

  @override
  Future<Object?> getVm() => _call(NativeTestVmMethod.getVM);
  @override
  Future<Object?> getIsolate(String id) =>
      _call(NativeTestVmMethod.getIsolate, {'isolateId': _isolateId(id)});
  @override
  Future<Object?> info(String id, {Duration? timeout}) =>
      _call(NativeTestVmMethod.info, {'isolateId': _isolateId(id)}, timeout);
  @override
  Future<Object?> configure(String id, String data) => _call(
    NativeTestVmMethod.configure,
    {'isolateId': _isolateId(id), 'data': data},
  );
  @override
  Future<Object?> command(String id, String data, {Duration? timeout}) => _call(
    NativeTestVmMethod.command,
    {'isolateId': _isolateId(id), 'data': data},
    timeout,
  );
  Future<void> close() async {
    _disconnect();
    await _socket.close();
  }
}

Stream<String?> nativeTestHostInputLines(Stream<List<int>> source) async* {
  final bytes = <int>[];
  var oversized = false;
  await for (final chunk in source) {
    for (final byte in chunk) {
      if (byte == 10) {
        yield oversized ? null : utf8.decode(bytes, allowMalformed: true);
        bytes.clear();
        oversized = false;
      } else if (!oversized) {
        if (bytes.length >= _maxHostBytes) {
          bytes.clear();
          oversized = true;
        } else {
          bytes.add(byte);
        }
      }
    }
  }
  if (oversized || bytes.isNotEmpty) yield null;
}

final _outputEncoder = NativeTestOutputEncoder(framed: Platform.isWindows);

void _emit(Map<String, Object> record) {
  try {
    final encoded = _outputEncoder.encode(record);
    if (encoded.invalidOutput) exitCode = 1;
    stdout.write(encoded.text);
  } catch (_) {
    exitCode = 1;
  }
}

Future<void> nativeTestHostOutputDone(Future<void> outputDone) =>
    outputDone.then<void>(
      (_) {},
      onError: (Object _) {
        exitCode = 1;
      },
    );

Future<void> main(List<String> arguments) async {
  unawaited(nativeTestHostOutputDone(stdout.done));
  try {
    await nativeTestGuardInputEcho(
      () => _runHost(arguments),
      windows: Platform.isWindows,
      terminal: stdin.hasTerminal,
      readEcho: () => stdin.echoMode,
      writeEcho: (value) => stdin.echoMode = value,
    );
  } catch (_) {
    _emit({'outcome': 'failed', 'category': 'launcherFailed'});
    exitCode = 1;
  }
}

Future<void> _runHost(List<String> arguments) async {
  _VmTransport? transport;
  try {
    if (arguments.length != 1 || !arguments.single.startsWith('--run=')) {
      _reject(NativeTestHostError.invalidInput);
    }
    final run = arguments.single.substring(6);
    if (!nativeTestSupportedRuns.contains(run)) {
      _reject(NativeTestHostError.invalidInput);
    }
    final platform = Platform.isWindows
        ? 'windows'
        : Platform.isMacOS
        ? 'macos'
        : null;
    final candidate = run == companyPeerDriverRun;
    if (platform == null || (candidate && platform != 'windows')) {
      _reject(NativeTestHostError.unsupportedHost);
    }
    final role = platform == 'windows' ? 'receiver' : 'sender';
    final cache = File(Platform.resolvedExecutable).parent.parent.parent;
    final snapshot = File(
      '${cache.path}${Platform.pathSeparator}flutter_tools.snapshot',
    );
    final app = File(Platform.script.toFilePath()).parent.parent;
    final target = candidate
        ? 'integration_test/company_peer_native_driver_test.dart'
        : 'integration_test/nearby_resident_test.dart';
    if (!snapshot.existsSync() || !File('${app.path}/$target').existsSync()) {
      _reject(NativeTestHostError.launcherFailed);
    }
    Future<String> sourceRef(String ref) async {
      final result = await Process.run('git', [
        'rev-parse',
        ref,
      ], workingDirectory: app.path);
      final value = (result.stdout as String).trim();
      if (result.exitCode != 0 || !RegExp(r'^[a-f0-9]{40}$').hasMatch(value)) {
        _reject(NativeTestHostError.launcherFailed);
      }
      return value;
    }

    if (candidate) {
      final diff = await Process.run('git', [
        'diff',
        '--quiet',
        'HEAD',
        '--',
      ], workingDirectory: app.path);
      final extras = await Process.run('git', [
        'ls-files',
        '--others',
        '--exclude-standard',
      ], workingDirectory: app.path);
      if (diff.exitCode != 0 ||
          extras.exitCode != 0 ||
          (extras.stdout as String).trim().isNotEmpty) {
        _reject(NativeTestHostError.launcherFailed);
      }
    }
    final launcherDiagnostics = NativeTestLauncherDiagnostics(
      onConfigureDiagnostic: (record) =>
          _emit({'outcome': 'diagnostic', 'diagnostic': record.toJson()}),
    );
    final child = await Process.start(
      Platform.resolvedExecutable,
      [
        snapshot.path,
        'test',
        '--no-pub',
        '--no-dds',
        '--verbose',
        '--reporter',
        'expanded',
        target,
        '-d',
        platform,
        if (candidate) ...[
          '--dart-define=NATIVE_COMPANY_PEER_DRIVER=true',
          '--dart-define=COMPANY_USER_SOURCE_REVISION=${await sourceRef('HEAD')}',
          '--dart-define=COMPANY_USER_SOURCE_TREE=${await sourceRef('HEAD^{tree}')}',
        ] else
          '--dart-define=NATIVE_NEARBY_TEST_MODE=true',
        '--dart-define=LAN_VALIDATION_RUN=$run',
        '--dart-define=LAN_VALIDATION_ROLE=$role',
      ],
      workingDirectory: app.path,
      runInShell: false,
    );
    final stdoutScanner = NativeTestVmBannerScanner();
    final stderrScanner = NativeTestVmBannerScanner();
    final stdoutDone = Completer<void>();
    final stderrDone = Completer<void>();
    var launcherOutputComplete = true;
    void finishStdout() {
      if (!stdoutDone.isCompleted) {
        launcherDiagnostics.finishStdout();
        stdoutDone.complete();
      }
    }

    void finishStderr() {
      if (!stderrDone.isCompleted) {
        launcherDiagnostics.finishStderr();
        stderrDone.complete();
      }
    }

    child.stdout.listen(
      (bytes) {
        stdoutScanner.add(bytes);
        launcherDiagnostics.addStdout(bytes);
      },
      onError: (_) {
        launcherOutputComplete = false;
        finishStdout();
      },
      onDone: finishStdout,
    );
    child.stderr.listen(
      (bytes) {
        stderrScanner.add(bytes);
        launcherDiagnostics.addStderr(bytes);
      },
      onError: (_) {
        launcherOutputComplete = false;
        finishStderr();
      },
      onDone: finishStderr,
    );
    Uri? privateUri() => stdoutScanner.privateUri ?? stderrScanner.privateUri;
    int? childExit;
    unawaited(
      child.exitCode.then<void>(
        (code) async {
          childExit = code;
          try {
            await Future.wait([stdoutDone.future, stderrDone.future])
                .timeout(const Duration(seconds: 2));
          } catch (_) {
            launcherOutputComplete = false;
          }
          _emit({
            'outcome': 'launcherExit',
            'exitCode': code,
            'launcherOutputComplete': launcherOutputComplete,
            ...launcherDiagnostics.toJson(),
          });
        },
        onError: (Object _) {
          childExit = 1;
        },
      ),
    );
    final startup = Stopwatch()..start();
    while (privateUri() == null &&
        childExit == null &&
        startup.elapsed < const Duration(minutes: 5)) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    if (privateUri() == null) {
      _reject(NativeTestHostError.launcherFailed);
    }
    transport = await _VmTransport.connect(privateUri()!);
    final host = NativeTestHost(
      transport: transport,
      run: run,
      platform: platform,
    );
    final discovery = Stopwatch()..start();
    while (!await host.discover()) {
      if (childExit != null ||
          discovery.elapsed > const Duration(seconds: 30)) {
        _reject(NativeTestHostError.notReady);
      }
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }
    _emit({
      'outcome': 'connected',
      'discoveryMaxFrameBytes': transport.discoveryMaxFrameBytes,
    });
    await for (final line in nativeTestHostInputLines(stdin)) {
      final records = line == null
          ? <Map<String, Object>>[
              {'outcome': 'failed', 'category': 'invalidInput'},
            ]
          : await host.handleRecords(line);
      for (final record in records) {
        _emit(record);
      }
    }
    _emit({'outcome': 'hostInputClosed'});
  } on NativeTestHostFailure catch (failure) {
    _emit(failure.toJson());
    exitCode = 1;
  } catch (_) {
    _emit({'outcome': 'failed', 'category': 'launcherFailed'});
    exitCode = 1;
  } finally {
    try {
      await transport?.close();
    } catch (_) {}
  }
}

import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'company_peer_native_driver_control.dart';
import 'native_nearby_test_crypto.dart';

const nativeTestMaxCommandBytes = 16384;
const nativeTestMaxCommandMillis = 20000;
const _maxSequence = 9007199254740991;

enum NativeTestAction {
  observe,
  pair,
  matchWithGrant,
  send,
  accept,
  snapshot,
  markReceivedDatabase,
  finish,
  normalExit,
  jobNameUi,
  jobDetailsUi,
  jobLifecycleUi,
  companyPeerUi,
}

enum NativeJobLifecycleUiStep {
  inspect,
  prepareDeleteOffline,
  deleteOffline,
  prepareEditNotesOffline,
  editNotesOffline,
  inspectConflict,
  checkpointConflict,
  prepareKeepEdited,
  keepEdited,
  inspectResolved,
  checkpointResolved,
}

enum NativeJobDetailsUiStep {
  inspect,
  editMixedOffline,
  inspectMixed,
  checkpointMixed,
  editNotesOffline,
  inspectConflict,
  checkpointConflict,
  resolveNotes,
  inspectResolved,
  checkpointResolved,
}

enum NativeJobNameUiStep {
  inspect,
  renameSequential,
  renameConcurrent,
  inspectConflict,
  checkpointConflict,
  resolveFirst,
  inspectResolved,
}

enum NativeTestCommandState { accepted, running, completed, failed, unknown }

enum NativeTestEffect { none, completed, possible }

enum NativeTestCommandError {
  invalidRequest,
  wrongSession,
  identityConflict,
  hashMismatch,
  deadlineExpired,
  busy,
  outcomeUnavailable,
  wrongPhase,
  stateChanged,
  grantRejected,
  invalidResult,
  harnessFailed,
  exitUnverified,
}

enum NativeTestPhase {
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

final class NativeTestCommand {
  NativeTestCommand._({
    required this.epoch,
    required this.commandId,
    required this.sequence,
    required this.action,
    required this.contentHash,
    required this.deadlineMillis,
    this.comparison,
    this.grant,
    this.leg,
    this.snapshotStage,
    this.jobNameStep,
    this.jobDetailsStep,
    this.jobLifecycleStep,
    this.companyPeerArgument,
  });

  final String epoch, commandId, contentHash;
  final int sequence, deadlineMillis;
  final NativeTestAction action;
  final ComparisonChallenge? comparison;
  final MatchGrant? grant;
  final int? leg;
  final PrivateSnapshotStage? snapshotStage;
  final NativeJobNameUiStep? jobNameStep;
  final NativeJobDetailsUiStep? jobDetailsStep;
  final NativeJobLifecycleUiStep? jobLifecycleStep;
  final CompanyPeerDriverArgument? companyPeerArgument;

  static NativeTestCommand parseRequest(String source, TestSession session) {
    try {
      return _parseCommand(source, session);
    } on _CommandFailure {
      rethrow;
    } catch (_) {
      _reject(NativeTestCommandError.invalidRequest);
    }
  }

  static String idFor(String epoch, int sequence) {
    nativeTestId(epoch);
    nativeTestInt(sequence);
    return '$epoch.$sequence';
  }

  static String encodeRequest({
    required TestSession session,
    required int sequence,
    required NativeTestAction action,
    required int deadlineMillis,
    ComparisonChallenge? comparison,
    MatchGrant? grant,
    int? leg,
    PrivateSnapshotStage? snapshotStage,
    NativeJobNameUiStep? jobNameStep,
    NativeJobDetailsUiStep? jobDetailsStep,
    NativeJobLifecycleUiStep? jobLifecycleStep,
    CompanyPeerDriverArgument? companyPeerArgument,
  }) {
    if ((jobNameStep != null && action != NativeTestAction.jobNameUi) ||
        (jobDetailsStep != null && action != NativeTestAction.jobDetailsUi) ||
        (jobLifecycleStep != null &&
            action != NativeTestAction.jobLifecycleUi) ||
        (companyPeerArgument != null &&
            action != NativeTestAction.companyPeerUi)) {
      _reject(NativeTestCommandError.invalidRequest);
    }
    final arguments = <String, Object>{
      if (comparison != null) 'comparison': comparison.toJson(),
      if (grant != null) 'grant': grant.toJson(),
      'leg': ?leg,
      if (snapshotStage != null) 'stage': snapshotStage.wireName,
      if (jobNameStep != null) 'step': jobNameStep.name,
      if (jobDetailsStep != null) 'step': jobDetailsStep.name,
      if (jobLifecycleStep != null) 'step': jobLifecycleStep.name,
      if (companyPeerArgument != null)
        'candidate': companyPeerArgument.toJson(),
    };
    final request = <String, Object>{
      'epoch': session.epoch,
      'commandId': idFor(session.epoch, sequence),
      'sequence': sequence,
      'action': action.name,
      'deadlineMillis': deadlineMillis,
      'arguments': arguments,
    };
    request['contentHash'] = _requestHash(request);
    final encoded = jsonEncode(request);
    _parseCommand(encoded, session);
    return encoded;
  }
}

final class NativeTestObservationResult {
  NativeTestObservationResult({
    required this.session,
    required this.phase,
    required this.sameNearbyState,
    required this.discovered,
    required this.codePresent,
    this.sealedObservation,
  }) {
    final sealed = sealedObservation;
    if (sealed != null &&
        (!codePresent ||
            sealed.epoch != session.epoch ||
            sealed.run != session.run ||
            sealed.role != session.role)) {
      _reject(NativeTestCommandError.invalidResult);
    }
  }

  final TestSession session;
  final NativeTestPhase phase;
  final bool sameNearbyState, discovered, codePresent;
  final SealedObservation? sealedObservation;

  Map<String, Object> toJson() => {
    'epoch': session.epoch,
    'run': session.run,
    'role': session.role.name,
    'deviceId': session.deviceId,
    'peerId': session.peerId,
    'phase': phase.name,
    'sameNearbyState': sameNearbyState,
    'discovered': discovered,
    'codePresent': codePresent,
    if (sealedObservation != null)
      'sealedObservation': sealedObservation!.toJson(),
  };
}

final class NativeTestSnapshotResult {
  NativeTestSnapshotResult({
    required String digest,
    required String assetsDigest,
    required String sharedSettingsDigest,
    required String profileDigest,
    required int schemaVersion,
    required int tableCount,
    required int rowCount,
    required int assetCount,
    required this.integrityValid,
    required this.referencesValid,
    required this.profileEqual,
    required this.assetsEqual,
    required this.settingsEqual,
    required this.ownershipEqual,
    this.sealedProof,
    String? lastNearbySourceId,
    int? lastNearbyAtMillis,
  }) : digest = _digest(digest),
       assetsDigest = _digest(assetsDigest),
       sharedSettingsDigest = _digest(sharedSettingsDigest),
       profileDigest = _digest(profileDigest),
       schemaVersion = _boundedCount(schemaVersion),
       tableCount = _boundedCount(tableCount),
       rowCount = _boundedCount(rowCount),
       assetCount = _boundedCount(assetCount),
       lastNearbySourceId = lastNearbySourceId == null
           ? null
           : nativeTestId(lastNearbySourceId),
       lastNearbyAtMillis = lastNearbyAtMillis == null
           ? null
           : _boundedCount(lastNearbyAtMillis);

  final String digest, assetsDigest, sharedSettingsDigest, profileDigest;
  final String? lastNearbySourceId;
  final int? lastNearbyAtMillis;
  final SealedPrivateSnapshot? sealedProof;
  final int schemaVersion, tableCount, rowCount, assetCount;
  final bool integrityValid, referencesValid, profileEqual, assetsEqual;
  final bool settingsEqual, ownershipEqual;

  Map<String, Object> toJson() => {
    'digest': digest,
    'assetsDigest': assetsDigest,
    'sharedSettingsDigest': sharedSettingsDigest,
    'profileDigest': profileDigest,
    'schemaVersion': schemaVersion,
    'tableCount': tableCount,
    'rowCount': rowCount,
    'assetCount': assetCount,
    'integrityValid': integrityValid,
    'referencesValid': referencesValid,
    'profileEqual': profileEqual,
    'assetsEqual': assetsEqual,
    'settingsEqual': settingsEqual,
    'ownershipEqual': ownershipEqual,
    'lastNearbySourceId': ?lastNearbySourceId,
    'lastNearbyAtMillis': ?lastNearbyAtMillis,
    if (sealedProof != null) 'sealedProof': sealedProof!.toJson(),
  };
}

final class NativeTestCommandResult {
  const NativeTestCommandResult.effect({
    this.effect = NativeTestEffect.completed,
  }) : observation = null,
       snapshot = null;

  const NativeTestCommandResult.observation(NativeTestObservationResult value)
    : observation = value,
      effect = NativeTestEffect.none,
      snapshot = null;

  const NativeTestCommandResult.snapshot(NativeTestSnapshotResult value)
    : snapshot = value,
      effect = NativeTestEffect.none,
      observation = null;

  final NativeTestEffect effect;
  final NativeTestObservationResult? observation;
  final NativeTestSnapshotResult? snapshot;

  Map<String, Object> toJson() => {
    'outcome': 'success',
    'effect': effect.name,
    if (observation != null) 'observation': observation!.toJson(),
    if (snapshot != null) 'snapshot': snapshot!.toJson(),
  };
}

final class NativeTestCommandReply {
  const NativeTestCommandReply._({
    this.sequence,
    this.state,
    this.error,
    this.effect = NativeTestEffect.none,
    this.result,
  });

  final int? sequence;
  final NativeTestCommandState? state;
  final NativeTestCommandError? error;
  final NativeTestEffect effect;
  final NativeTestCommandResult? result;

  Map<String, Object> toJson() => {
    'version': 1,
    'sequence': ?sequence,
    'state': state?.name ?? 'rejected',
    'outcome': state == NativeTestCommandState.unknown
        ? 'UNKNOWN'
        : error?.name ?? (result == null ? 'pending' : 'success'),
    'inflight':
        state == NativeTestCommandState.running ||
        state == NativeTestCommandState.unknown,
    'effect': effect.name,
    if (result != null) 'result': result!.toJson(),
  };
}

final class NativeTestCommandCache {
  NativeTestCommandCache({
    required this.session,
    this.maxEntries = 64,
    int Function()? clockMillis,
  }) {
    if (maxEntries < 1 || maxEntries > 64) {
      _reject(NativeTestCommandError.invalidRequest);
    }
    final stopwatch = Stopwatch()..start();
    _clockMillis = clockMillis ?? () => stopwatch.elapsedMilliseconds;
  }

  final TestSession session;
  final int maxEntries;
  late final int Function() _clockMillis;
  final _entries = <int, _CommandEntry>{};
  _CommandEntry? _active;
  int _highWater = 0;

  int get elapsedMillis => _clockMillis();
  int get highWater => _highWater;
  int get cachedCount => _entries.length;
  bool get hasInflight => _active != null;

  NativeTestCommandReply submitJson(
    String json, {
    Set<NativeTestAction>? allowedActions,
  }) {
    tick();
    try {
      final command = _parseCommand(json, session);
      final previous = _entries[command.sequence];
      if (previous != null) {
        if (previous.command.contentHash != command.contentHash) {
          return _rejected(NativeTestCommandError.identityConflict);
        }
        return previous.reply;
      }
      if (command.sequence <= _highWater) {
        return _rejected(NativeTestCommandError.outcomeUnavailable);
      }
      final now = elapsedMillis;
      if (command.deadlineMillis > now + nativeTestMaxCommandMillis) {
        return _rejected(NativeTestCommandError.invalidRequest);
      }
      if (_active != null) return _rejected(NativeTestCommandError.busy);
      final entry = _CommandEntry(command);
      _highWater = command.sequence;
      _entries[command.sequence] = entry;
      _evict();
      if (command.deadlineMillis <= now) {
        entry.fail(NativeTestCommandError.deadlineExpired);
      } else if (allowedActions != null &&
          !allowedActions.contains(command.action)) {
        entry.fail(NativeTestCommandError.wrongPhase);
      } else {
        _active = entry;
      }
      return entry.reply;
    } on _CommandFailure catch (failure) {
      return _rejected(failure.error);
    } catch (_) {
      return _rejected(NativeTestCommandError.invalidRequest);
    }
  }

  NativeTestCommand? takeNext({Set<NativeTestAction>? allowedActions}) {
    tick();
    final entry = _active;
    if (entry == null || entry.state != NativeTestCommandState.accepted) {
      return null;
    }
    if (allowedActions != null &&
        !allowedActions.contains(entry.command.action)) {
      entry.fail(NativeTestCommandError.wrongPhase);
      _active = null;
      return null;
    }
    entry.state = NativeTestCommandState.running;
    return entry.command;
  }

  NativeTestCommandReply complete(
    NativeTestCommand command,
    NativeTestCommandResult result,
  ) {
    final entry = _ownedRunning(command);
    if (entry == null) return _rejected(NativeTestCommandError.invalidResult);
    final observation = result.observation;
    if ((command.action == NativeTestAction.observe) != (observation != null) ||
        (command.action == NativeTestAction.snapshot) !=
            (result.snapshot != null) ||
        (observation != null &&
            jsonEncode(observation.session.toJson()) !=
                jsonEncode(session.toJson())) ||
        (observation?.sealedObservation != null &&
            (command.comparison == null ||
                jsonEncode(
                      observation!.sealedObservation!.challenge.toJson(),
                    ) !=
                    jsonEncode(command.comparison!.toJson()))) ||
        (result.snapshot?.sealedProof != null &&
            (result.snapshot!.sealedProof!.epoch != session.epoch ||
                result.snapshot!.sealedProof!.run != session.run ||
                result.snapshot!.sealedProof!.role != session.role ||
                result.snapshot!.sealedProof!.stage !=
                    command.snapshotStage)) ||
        result.effect == NativeTestEffect.possible) {
      return fail(command, NativeTestCommandError.invalidResult);
    }
    entry.state = NativeTestCommandState.completed;
    entry.result = result;
    entry.effect = result.effect;
    _active = null;
    return entry.reply;
  }

  NativeTestCommandReply fail(
    NativeTestCommand command,
    NativeTestCommandError error, {
    NativeTestEffect effect = NativeTestEffect.possible,
  }) {
    final entry = _ownedRunning(command);
    if (entry == null) return _rejected(NativeTestCommandError.invalidResult);
    entry.fail(error, effect: effect);
    _active = null;
    return entry.reply;
  }

  void tick() {
    final entry = _active;
    if (entry == null || elapsedMillis < entry.command.deadlineMillis) return;
    if (entry.state == NativeTestCommandState.accepted) {
      entry.fail(NativeTestCommandError.deadlineExpired);
      _active = null;
    } else if (entry.state == NativeTestCommandState.running) {
      // A timeout cannot undo a tap or cancel its future.
      entry.state = NativeTestCommandState.unknown;
      entry.effect = NativeTestEffect.possible;
    }
  }

  _CommandEntry? _ownedRunning(NativeTestCommand command) {
    final entry = _active;
    if (entry == null ||
        !identical(entry.command, command) ||
        (entry.state != NativeTestCommandState.running &&
            entry.state != NativeTestCommandState.unknown)) {
      return null;
    }
    return entry;
  }

  void _evict() {
    while (_entries.length > maxEntries) {
      _entries.remove(_entries.keys.first);
    }
  }
}

final class _CommandEntry {
  _CommandEntry(this.command);
  final NativeTestCommand command;
  NativeTestCommandState state = NativeTestCommandState.accepted;
  NativeTestEffect effect = NativeTestEffect.none;
  NativeTestCommandError? error;
  NativeTestCommandResult? result;

  NativeTestCommandReply get reply => NativeTestCommandReply._(
    sequence: command.sequence,
    state: state,
    error: error,
    effect: effect,
    result: result,
  );

  void fail(
    NativeTestCommandError failure, {
    NativeTestEffect effect = NativeTestEffect.none,
  }) {
    state = NativeTestCommandState.failed;
    error = failure;
    this.effect = effect;
  }
}

final class _CommandFailure implements Exception {
  const _CommandFailure(this.error);
  final NativeTestCommandError error;
  @override
  String toString() => 'NativeTestCommandFailure';
}

Never _reject(NativeTestCommandError error) => throw _CommandFailure(error);
NativeTestCommandReply _rejected(NativeTestCommandError error) =>
    NativeTestCommandReply._(error: error);

String _digest(Object? value) {
  if (value is! String || !RegExp(r'^[a-f0-9]{64}$').hasMatch(value)) {
    _reject(NativeTestCommandError.invalidRequest);
  }
  return value;
}

int _boundedCount(int value) {
  if (value < 0 || value > _maxSequence) {
    _reject(NativeTestCommandError.invalidResult);
  }
  return value;
}

Object? _canonicalValue(Object? value) {
  if (value is Map<String, dynamic>) {
    final keys = value.keys.toList()..sort();
    return {for (final key in keys) key: _canonicalValue(value[key])};
  }
  if (value is List) return value.map(_canonicalValue).toList();
  return value;
}

String _requestHash(Map<String, dynamic> request) => sha256
    .convert(
      utf8.encode(
        jsonEncode([
          'wired-parts/native-nearby-test/v1',
          'command',
          request['epoch'],
          request['commandId'],
          request['sequence'],
          request['action'],
          request['deadlineMillis'],
          _canonicalValue(request['arguments']),
        ]),
      ),
    )
    .toString();

NativeTestCommand _parseCommand(String source, TestSession session) {
  if (source.length > nativeTestMaxCommandBytes ||
      utf8.encode(source).length > nativeTestMaxCommandBytes) {
    _reject(NativeTestCommandError.invalidRequest);
  }
  final m = nativeTestMap(jsonDecode(source), {
    'epoch',
    'commandId',
    'sequence',
    'action',
    'contentHash',
    'deadlineMillis',
    'arguments',
  });
  if (m['epoch'] != session.epoch) {
    _reject(NativeTestCommandError.wrongSession);
  }
  final sequence = nativeTestInt(m['sequence']);
  if (m['commandId'] != NativeTestCommand.idFor(session.epoch, sequence)) {
    _reject(NativeTestCommandError.identityConflict);
  }
  final action = NativeTestAction.values.where((a) => a.name == m['action']);
  if (action.length != 1) _reject(NativeTestCommandError.invalidRequest);
  final deadline = nativeTestInt(m['deadlineMillis']);
  final contentHash = _digest(m['contentHash']);
  if (contentHash != _requestHash(m)) {
    _reject(NativeTestCommandError.hashMismatch);
  }
  final kind = action.single;
  ComparisonChallenge? comparison;
  MatchGrant? grant;
  int? leg;
  PrivateSnapshotStage? snapshotStage;
  NativeJobNameUiStep? jobNameStep;
  NativeJobDetailsUiStep? jobDetailsStep;
  NativeJobLifecycleUiStep? jobLifecycleStep;
  CompanyPeerDriverArgument? companyPeerArgument;
  final arguments = m['arguments'];
  if (kind == NativeTestAction.observe &&
      arguments is Map<String, dynamic> &&
      arguments.isNotEmpty) {
    final a = nativeTestMap(arguments, {'comparison'});
    comparison = ComparisonChallenge.fromJson(a['comparison']);
    if (comparison.epoch != session.epoch) {
      _reject(NativeTestCommandError.wrongSession);
    }
  } else if (kind == NativeTestAction.matchWithGrant) {
    final a = nativeTestMap(arguments, {'grant'});
    grant = MatchGrant.fromJson(a['grant'], session);
    if (grant.comparison.epoch != session.epoch) {
      _reject(NativeTestCommandError.wrongSession);
    }
  } else if (kind == NativeTestAction.markReceivedDatabase) {
    final a = nativeTestMap(arguments, {'leg'});
    leg = nativeTestInt(a['leg'], max: 2);
  } else if (kind == NativeTestAction.snapshot) {
    final a = nativeTestMap(arguments, {'stage'});
    snapshotStage = PrivateSnapshotStage.parse(a['stage']);
  } else if (kind == NativeTestAction.jobNameUi) {
    final a = nativeTestMap(arguments, {'step'});
    final steps = NativeJobNameUiStep.values.where((v) => v.name == a['step']);
    if (steps.length != 1) _reject(NativeTestCommandError.invalidRequest);
    jobNameStep = steps.single;
  } else if (kind == NativeTestAction.jobDetailsUi) {
    final a = nativeTestMap(arguments, {'step'});
    final steps = NativeJobDetailsUiStep.values.where(
      (v) => v.name == a['step'],
    );
    if (steps.length != 1) _reject(NativeTestCommandError.invalidRequest);
    jobDetailsStep = steps.single;
  } else if (kind == NativeTestAction.jobLifecycleUi) {
    final a = nativeTestMap(arguments, {'step'});
    final steps = NativeJobLifecycleUiStep.values.where(
      (s) => s.name == a['step'],
    );
    if (steps.length != 1) _reject(NativeTestCommandError.invalidRequest);
    jobLifecycleStep = steps.single;
  } else if (kind == NativeTestAction.companyPeerUi) {
    final a = nativeTestMap(arguments, {'candidate'});
    companyPeerArgument = CompanyPeerDriverArgument.parse(
      a['candidate'],
      session,
    );
  } else {
    nativeTestMap(arguments, {});
  }
  return NativeTestCommand._(
    epoch: session.epoch,
    commandId: m['commandId'] as String,
    sequence: sequence,
    action: kind,
    contentHash: contentHash,
    deadlineMillis: deadline,
    comparison: comparison,
    grant: grant,
    leg: leg,
    snapshotStage: snapshotStage,
    jobNameStep: jobNameStep,
    jobDetailsStep: jobDetailsStep,
    jobLifecycleStep: jobLifecycleStep,
    companyPeerArgument: companyPeerArgument,
  );
}

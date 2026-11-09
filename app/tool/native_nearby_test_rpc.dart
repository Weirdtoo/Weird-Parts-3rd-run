import 'dart:async';
import 'dart:convert';

import 'native_nearby_test_commands.dart';
import 'native_nearby_test_crypto.dart';

const nativeTestConfigureDiagnosticPrefix =
    'WIRED_PARTS_CONFIGURE_DIAGNOSTIC_V1 ';
const _maxProgress = 9007199254740991;

enum NativeTestConfigureRejection {
  closed,
  alreadyAttempted,
  oversize,
  invalidSession,
  identityMismatch,
  timerExpired,
  expiredInLoop,
  installerRejected,
}

final class NativeTestConfigureDiagnostic {
  const NativeTestConfigureDiagnostic({
    required this.reason,
    required this.pumpPending,
    required this.loopIterations,
    required this.pumpStarts,
    required this.pumpCompletions,
    required this.publicationAgeMillis,
  });
  final NativeTestConfigureRejection reason;
  final bool pumpPending;
  final int loopIterations, pumpStarts, pumpCompletions;
  final int? publicationAgeMillis;

  factory NativeTestConfigureDiagnostic.fromJson(Object? value) {
    final m = nativeTestMap(value, {
      'version',
      'reason',
      'pumpPending',
      'loopIterations',
      'pumpStarts',
      'pumpCompletions',
      'publicationAgeMillis',
    });
    final reasons = NativeTestConfigureRejection.values.where(
      (reason) => reason.name == m['reason'],
    );
    if (m['version'] is! int ||
        m['version'] != 1 ||
        m['pumpPending'] is! bool ||
        reasons.length != 1) {
      rejectNativeTest();
    }
    int progress(Object? value) {
      if (value is! int || value < 0 || value > _maxProgress) {
        rejectNativeTest();
      }
      return value;
    }

    final loops = progress(m['loopIterations']);
    final starts = progress(m['pumpStarts']);
    final completions = progress(m['pumpCompletions']);
    if (loops < starts ||
        completions > starts ||
        starts - completions > 1 ||
        m['pumpPending'] != (starts != completions)) {
      rejectNativeTest();
    }
    return NativeTestConfigureDiagnostic(
      reason: reasons.single,
      pumpPending: m['pumpPending'] as bool,
      loopIterations: loops,
      pumpStarts: starts,
      pumpCompletions: completions,
      publicationAgeMillis: m['publicationAgeMillis'] == null
          ? null
          : progress(m['publicationAgeMillis']),
    );
  }

  Map<String, Object?> toJson() => {
    'version': 1,
    'reason': reason.name,
    'pumpPending': pumpPending,
    'loopIterations': loopIterations,
    'pumpStarts': pumpStarts,
    'pumpCompletions': pumpCompletions,
    'publicationAgeMillis': publicationAgeMillis,
  };
}

final class NativeTestResidentViewInfo {
  const NativeTestResidentViewInfo({
    required this.phase,
    required this.sameNearbyState,
    required this.discovered,
    required this.codePresent,
    this.allowedActions = const {},
    this.candidateUi,
  });
  final NativeTestPhase phase;
  final bool sameNearbyState, discovered, codePresent;
  final Set<NativeTestAction> allowedActions;
  final Map<String, Object?>? candidateUi;
}

final class NativeTestResidentRpc {
  NativeTestResidentRpc({
    required this.appPid,
    required this.run,
    required this.role,
    required this.deviceId,
    required this.peerId,
    required this.clockMillis,
    required this.readInfoInLoop,
    this.onDiagnostic,
    this.candidateInputKey,
  });

  final int appPid;
  final String run, deviceId, peerId;
  final TestRole role;
  final int Function() clockMillis;
  final NativeTestResidentViewInfo Function() readInfoInLoop;
  final void Function(NativeTestConfigureDiagnostic)? onDiagnostic;
  final String? candidateInputKey;
  NativeTestResidentViewInfo? _published;
  Set<NativeTestAction> _publishedAllowedActions = const {};
  Set<NativeTestAction> get allowedActions => _publishedAllowedActions;
  _PendingConfiguration? _pending;
  bool _configureAttempted = false;
  bool _configured = false;
  bool _closed = false;
  bool _pumpPending = false;
  int _loopIterations = 0;
  int _pumpStarts = 0;
  int _pumpCompletions = 0;
  int? _publishedAtMillis;

  // These count the resident owner-loop pump only. A completion is a settled
  // await (including errors), never evidence that a frame rendered correctly.
  void markLoopStarted() => _loopIterations = _increment(_loopIterations);
  void markPumpStarted() {
    _pumpPending = true;
    _pumpStarts = _increment(_pumpStarts);
  }

  void markPumpSettled() {
    _pumpPending = false;
    _pumpCompletions = _increment(_pumpCompletions);
  }

  // Only the resident loop may read widget state. Extension callbacks consume
  // an immutable summary, including while an awaited pump owns a guard scope.
  void refreshInfoInLoop() {
    if (!_closed) {
      final next = readInfoInLoop();
      final allowedActions = Set<NativeTestAction>.unmodifiable(
        next.allowedActions,
      );
      _published = next;
      _publishedAllowedActions = allowedActions;
      _publishedAtMillis = clockMillis();
    }
  }

  Map<String, Object> info() {
    final current = _published;
    if (_closed || current == null) {
      return {'version': 1, 'outcome': 'not-ready'};
    }
    return {
      'version': 1,
      'outcome': 'ready',
      'appPid': appPid,
      'run': run,
      'role': role.name,
      'deviceId': deviceId,
      'peerId': peerId,
      'configured': _configured,
      'elapsedMillis': clockMillis(),
      'phase': current.phase.name,
      'sameNearbyState': current.sameNearbyState,
      'discovered': current.discovered,
      'codePresent': current.codePresent,
      'candidateInputKey': ?candidateInputKey,
      'candidateUi': ?current.candidateUi,
    };
  }

  Future<Map<String, Object>> configure(String data) {
    if (_closed) {
      return _rejectConfiguration(NativeTestConfigureRejection.closed);
    }
    if (_configureAttempted) {
      return _rejectConfiguration(
        NativeTestConfigureRejection.alreadyAttempted,
      );
    }
    if (data.length > nativeTestMaxEnvelopeBytes ||
        utf8.encode(data).length > nativeTestMaxEnvelopeBytes) {
      return _rejectConfiguration(NativeTestConfigureRejection.oversize);
    }
    late final TestSession next;
    try {
      next = TestSession.fromJson(jsonDecode(data));
    } catch (_) {
      return _rejectConfiguration(NativeTestConfigureRejection.invalidSession);
    }
    if (next.run != run ||
        next.role != role ||
        next.deviceId != deviceId ||
        next.peerId != peerId) {
      return _rejectConfiguration(
        NativeTestConfigureRejection.identityMismatch,
      );
    }
    try {
      // Once accepted, a lost reply or an expired request cannot authorize a
      // second configuration, even when the original was never installed.
      _configureAttempted = true;
      final pending = _PendingConfiguration(next, clockMillis() + 3000);
      _pending = pending;
      pending.timer = Timer(const Duration(seconds: 3), () {
        if (identical(_pending, pending)) {
          _pending = null;
          _diagnose(NativeTestConfigureRejection.timerExpired);
          pending.complete(false);
        }
      });
      return pending.reply.future;
    } catch (_) {
      return _rejectConfiguration(
        NativeTestConfigureRejection.installerRejected,
      );
    }
  }

  // The installer performs fresh widget/device checks and commits all resident
  // fields without awaiting. No extension callback invokes this method.
  void processConfigurationInLoop(void Function(TestSession) install) {
    final pending = _pending;
    if (pending == null) return;
    _pending = null;
    pending.timer?.cancel();
    if (_closed) {
      _diagnose(NativeTestConfigureRejection.closed);
      pending.complete(false);
      return;
    }
    if (clockMillis() >= pending.expiresAtMillis) {
      _diagnose(NativeTestConfigureRejection.expiredInLoop);
      pending.complete(false);
      return;
    }
    try {
      install(pending.session);
      _configured = true;
      pending.complete(true);
    } catch (_) {
      _diagnose(NativeTestConfigureRejection.installerRejected);
      pending.complete(false);
    }
  }

  void close() {
    _closed = true;
    _published = null;
    _publishedAllowedActions = const {};
    final pending = _pending;
    _pending = null;
    if (pending != null) {
      _diagnose(NativeTestConfigureRejection.closed);
      pending.complete(false);
    }
  }

  Future<Map<String, Object>> _rejectConfiguration(
    NativeTestConfigureRejection reason,
  ) {
    _diagnose(reason);
    return Future.value(_configurationReply(false));
  }

  void _diagnose(NativeTestConfigureRejection reason) {
    // Diagnostics are best-effort and cannot affect parsing, installation,
    // the accepted-attempt latch, or completion of a rejected request.
    try {
      final published = _publishedAtMillis;
      onDiagnostic?.call(
        NativeTestConfigureDiagnostic(
          reason: reason,
          pumpPending: _pumpPending,
          loopIterations: _loopIterations,
          pumpStarts: _pumpStarts,
          pumpCompletions: _pumpCompletions,
          publicationAgeMillis: published == null
              ? null
              : (clockMillis() - published).clamp(0, _maxProgress),
        ),
      );
    } catch (_) {}
  }
}

int _increment(int value) => value < _maxProgress ? value + 1 : value;

Map<String, Object> _configurationReply(bool installed) => {
  'version': 1,
  'outcome': installed ? 'configured' : 'rejected',
};

final class _PendingConfiguration {
  _PendingConfiguration(this.session, this.expiresAtMillis);
  final TestSession session;
  final int expiresAtMillis;
  final reply = Completer<Map<String, Object>>();
  Timer? timer;

  void complete(bool installed) {
    timer?.cancel();
    if (!reply.isCompleted) reply.complete(_configurationReply(installed));
  }
}

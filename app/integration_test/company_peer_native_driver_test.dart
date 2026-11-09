import 'dart:async';
import 'dart:convert';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:crypto/crypto.dart' show sha256;
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:wired_parts/features/company/company_join_page.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';

import '../tool/company_peer_native_driver_control.dart';
import '../tool/company_peer_native_driver_ui.dart';
import '../tool/company_users_native_validation.dart';
import '../tool/native_nearby_test_commands.dart';
import '../tool/native_nearby_test_crypto.dart';
import '../tool/native_nearby_test_exit.dart';
import '../tool/native_nearby_test_rpc.dart';
import '../tool/native_nearby_test_tap.dart';
import '../tool/nearby_lan_validation.dart';
import '../tool/nearby_lan_workspace.dart';

const _enabled = bool.fromEnvironment('NATIVE_COMPANY_PEER_DRIVER');
const _run = String.fromEnvironment('LAN_VALIDATION_RUN');
const _role = String.fromEnvironment('LAN_VALIDATION_ROLE');
const _revision = String.fromEnvironment('COMPANY_USER_SOURCE_REVISION');
const _tree = String.fromEnvironment('COMPANY_USER_SOURCE_TREE');

void main() {
  if (!kDebugMode ||
      !_enabled ||
      !Platform.isWindows ||
      _run != companyPeerDriverRun ||
      _role != 'receiver' ||
      !RegExp(r'^[a-f0-9]{40}$').hasMatch(_revision) ||
      !RegExp(r'^[a-f0-9]{40}$').hasMatch(_tree)) {
    rejectNativeTest('candidate-startup-refused');
  }
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('isolated Windows company peer candidate', (tester) async {
    ValidationWorkspace? openedWorkspace;
    CompanyUserTransportReceipts? openedReceipts;
    Future<void> Function()? closeDatabase;
    final driver = _CandidateUi(tester, binding);
    binding.addObserver(driver);
    try {
      await tester.pumpWidget(const SizedBox.shrink());
      await driver.run(
        'lan-$_run-$_role',
        initialize: (current) async {
          if (!current()) rejectNativeTest('candidate-startup-refused');
          final workspace = ValidationWorkspace.open(
            run: _run,
            role: ValidationRole.receiver,
          );
          openedWorkspace = workspace;
          final receipts = CompanyUserTransportReceipts(
            directory: workspace.receipts,
            run: _run,
            role: _role,
            sourceRevision: _revision,
            sourceTree: _tree,
            processId: pid,
          );
          openedReceipts = receipts;
          final app = await validationApplication(
            workspace,
            createCompanyJoinController: (alias) {
              final controller = receipts.createController(alias);
              driver.attach(controller);
              return controller;
            },
          );
          closeDatabase = app.db.close;
          if (!current()) rejectNativeTest('candidate-startup-refused');
          final installation = app.installation!;
          final identity = installation.identity!;
          final trust = await installation.readCompanyTrust(app.db);
          if (!current() || (!workspace.initialized && trust != null)) {
            rejectNativeTest('candidate-startup-refused');
          }
          if (!workspace.initialized) workspace.markInitialized();
          workspace.requireOwnedReceipts();
          final receipt = File(
            '${workspace.receipts.path}${Platform.pathSeparator}'
            'company-peer-driver-startup-$pid-${DateTime.now().microsecondsSinceEpoch}.json',
          );
          receipt.createSync(exclusive: true);
          receipt.writeAsStringSync(
            jsonEncode({
              'kind': 'company-peer-driver-startup@1',
              'sourceRevision': _revision,
              'sourceTree': _tree,
              'run': _run,
              'appPid': pid,
              'installation': identity.id.value,
              'generation': identity.generation.value,
              'keySha256': sha256.convert(identity.publicKey).toString(),
              'storeGeneration': installation.receivingStoreGeneration?.value,
              'company': trust?.companyId.value,
            }),
            flush: true,
          );
          await tester.pumpWidget(app);
        },
      );
    } catch (_) {
      rejectNativeTest('candidate-driver-failed');
    } finally {
      binding.removeObserver(driver);
      await driver.close();
      await openedReceipts?.close();
      await closeDatabase?.call();
      openedWorkspace?.close();
    }
  }, timeout: const Timeout(Duration(minutes: 20)));
}

final class _CandidateUi with WidgetsBindingObserver {
  _CandidateUi(this.tester, this.binding);

  final WidgetTester tester;
  final WidgetsBinding binding;
  final _clock = Stopwatch()..start();
  final _startup = CompanyPeerDriverStartup();
  NearbyController? _controller;
  StreamSubscription<NearbyViewState>? _states;
  CompanyPeerDriverPair? _pair;
  ({CompanyPeerDriverPair pair, String proof})? _sealed;
  TestSession? _session;
  NativeTestCommandCache? _cache;
  late final SimpleKeyPair _inputKey;
  late final String _inputPublicKey;
  bool _exiting = false;
  int _lifecycleEpoch = 0;

  bool get _resumed => binding.lifecycleState == AppLifecycleState.resumed;
  int get _millis => _clock.elapsedMilliseconds;
  int get _wallMillis => DateTime.now().millisecondsSinceEpoch;

  Element? get _page {
    final pages = find.byType(CompanyJoinPage).evaluate();
    return pages.length == 1 ? pages.single : null;
  }

  Finder _key(String value) => find.byKey(ValueKey(value));

  String? get _renderedCode {
    final elements = _key('company-join-code').hitTestable().evaluate();
    if (elements.length != 1) return null;
    final widget = elements.single.widget;
    return widget is Text ? widget.data : null;
  }

  void attach(NearbyController controller) {
    _invalidatePair();
    unawaited(_states?.cancel());
    _controller = controller;
    _states = controller.states.listen((state) {
      if (identical(_controller, controller)) _pair?.observe(state);
    });
  }

  void _invalidatePair() {
    _pair?.invalidate();
    _pair = null;
    _sealed = null;
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) {
      _lifecycleEpoch++;
      _invalidatePair();
    }
  }

  Future<void> close() async {
    _invalidatePair();
    await _states?.cancel();
  }

  Future<void> run(
    String deviceId, {
    required Future<void> Function(bool Function()) initialize,
  }) async {
    _inputKey = await X25519().newKeyPair();
    _inputPublicKey = base64Url.encode(
      (await _inputKey.extractPublicKey()).bytes,
    );
    const actions = {
      NativeTestAction.observe,
      NativeTestAction.companyPeerUi,
      NativeTestAction.normalExit,
    };
    final rpc = NativeTestResidentRpc(
      appPid: pid,
      run: _run,
      role: TestRole.receiver,
      deviceId: deviceId,
      peerId: companyPeerDriverOperator,
      clockMillis: () => _millis,
      readInfoInLoop: () => NativeTestResidentViewInfo(
        phase: _phase,
        sameNearbyState: _page != null,
        discovered: _controller?.state.peers.isNotEmpty ?? false,
        codePresent: _renderedCode != null,
        candidateUi: _candidateUi(),
        allowedActions: _startup.started && _resumed && !_exiting
            ? actions
            : const {},
      ),
      candidateInputKey: _inputPublicKey,
    );
    bool params(Map<String, String> values, String? key) {
      final keys = values.keys.where((key) => key != 'isolateId').toList();
      return key == null
          ? keys.isEmpty
          : keys.length == 1 && keys.single == key;
    }

    developer.ServiceExtensionResponse response(Map<String, Object> body) =>
        developer.ServiceExtensionResponse.result(jsonEncode(body));
    const rejected = {'version': 1, 'outcome': 'rejected'};
    developer.registerExtension(
      'ext.wired_parts.nearbyTest.info',
      (_, values) async =>
          response(params(values, null) ? rpc.info() : rejected),
    );
    developer.registerExtension(
      'ext.wired_parts.nearbyTest.configure',
      (_, values) async => response(
        params(values, 'data')
            ? await rpc.configure(values['data']!)
            : rejected,
      ),
    );
    developer.registerExtension(
      'ext.wired_parts.nearbyTest.command',
      (_, values) async => response(
        !params(values, 'data')
            ? rejected
            : _cache
                      ?.submitJson(
                        values['data']!,
                        allowedActions: rpc.allowedActions,
                      )
                      .toJson() ??
                  {'version': 1, 'outcome': 'not-configured'},
      ),
    );

    try {
      while (true) {
        rpc.markLoopStarted();
        rpc.processConfigurationInLoop((session) {
          if (!_resumed || _session != null) {
            rejectNativeTest('context-mismatch');
          }
          _session = session;
          _cache = NativeTestCommandCache(
            session: session,
            clockMillis: () => _millis,
          );
        });
        if (_session != null && !_startup.started) {
          final epoch = _lifecycleEpoch;
          bool current() => _resumed && _lifecycleEpoch == epoch;
          await _startup.start(
            session: _session,
            isCurrent: current,
            initialize: () => initialize(current),
          );
        }
        rpc.markPumpStarted();
        try {
          await tester.pump();
        } finally {
          rpc.markPumpSettled();
        }
        rpc.refreshInfoInLoop();
        final cache = _cache;
        final command = cache?.takeNext(allowedActions: rpc.allowedActions);
        if (command != null) {
          try {
            final result = await _execute(command);
            cache!.complete(command, result);
          } catch (_) {
            cache!.fail(command, NativeTestCommandError.stateChanged);
          }
        }
        await Future<void>.delayed(const Duration(milliseconds: 40));
      }
    } finally {
      rpc.close();
    }
  }

  Map<String, Object?> _candidateUi() {
    final peers = _controller?.state.peers ?? const [];
    final statuses = _key('company-join-status').evaluate();
    final text = statuses.length == 1 ? statuses.single.widget : null;
    final status = text is Text ? text.data : null;
    return {
      'initialized': _startup.started,
      'discovered': [
        if (_resumed && _page != null)
          for (final peer in peers.take(8))
            if (_enabledButton(
              _key('company-join-pair-${peer.deviceId}').hitTestable(),
            ))
              peer.deviceId,
      ],
      'selectedUser': _resumed ? companyPeerDriverSelectedUser() : null,
      'canVerify':
          _resumed && _enabledButton(_key('company-peer-verify').hitTestable()),
      'canMakeAvailable':
          _resumed &&
          _enabledButton(_key('company-jobs-enable-sync').hitTestable()),
      'canSync':
          _resumed &&
          _enabledButton(_key('company-jobs-sync-now').hitTestable()),
      'sync': status?.startsWith('Job snapshot synced.') == true
          ? 'complete'
          : status?.startsWith('Job sync incomplete.') == true
          ? 'incomplete'
          : 'none',
    };
  }

  NativeTestPhase get _phase {
    if (!_startup.started) return NativeTestPhase.starting;
    if (_page == null) {
      return _key('company-peer-open').evaluate().length == 1
          ? NativeTestPhase.success
          : NativeTestPhase.idle;
    }
    if (_renderedCode != null) return NativeTestPhase.pairing;
    if (_controller?.pairedJoinSession != null) return NativeTestPhase.paired;
    return NativeTestPhase.looking;
  }

  bool _live(NativeTestCommand command) =>
      _resumed && !_exiting && _millis < command.deadlineMillis;

  bool _enabledButton(Finder finder) {
    final matches = finder.evaluate();
    if (matches.length != 1) return false;
    final widget = matches.single.widget;
    return widget is ButtonStyleButton && widget.onPressed != null;
  }

  Future<void> _tap(
    NativeTestCommand command,
    String key, {
    bool Function()? check,
  }) async {
    final visible = _key(key).hitTestable();
    bool current() =>
        _live(command) && _enabledButton(visible) && (check?.call() ?? true);
    await guardedNativeTap(tester, visible, isStillCurrent: current);
  }

  bool _currentPair(CompanyPeerDriverPair attempt, String peerId) {
    final page = _page;
    final controller = _controller;
    return identical(attempt, _pair) &&
        page != null &&
        controller != null &&
        attempt.current(
          page: page,
          peerId: peerId,
          state: controller.state,
          renderedCode: _renderedCode,
          resumed: _resumed,
          nowMillis: _wallMillis,
        );
  }

  Future<NativeTestCommandResult> _execute(NativeTestCommand command) async {
    if (!_live(command)) rejectNativeTest('state-changed');
    if (command.action == NativeTestAction.observe) return _observe(command);
    if (command.action == NativeTestAction.normalExit) {
      if (_page != null || (_controller?.state.running ?? false)) {
        rejectNativeTest('state-changed');
      }
      _exiting = true;
      await requestNativeTestExit();
      return const NativeTestCommandResult.effect();
    }
    final arg = command.companyPeerArgument;
    if (command.action != NativeTestAction.companyPeerUi || arg == null) {
      rejectNativeTest('context-mismatch');
    }
    switch (arg.step) {
      case CompanyPeerDriverStep.openJoin:
        await _tap(command, 'company-join-open');
      case CompanyPeerDriverStep.openRetained:
        await _tap(command, 'company-peer-open');
      case CompanyPeerDriverStep.pair:
        await _beginPair(command, arg.target!);
      case CompanyPeerDriverStep.match:
        await _match(command, arg);
      case CompanyPeerDriverStep.requestJoin:
        await _tap(command, 'company-join-request');
      case CompanyPeerDriverStep.acceptJoin:
        await _tap(
          command,
          'company-join-consent',
          check: () =>
              find
                  .textContaining('Company: ${arg.target}\nUser: ')
                  .evaluate()
                  .length ==
              1,
        );
      case CompanyPeerDriverStep.closeJoin:
        _invalidatePair();
        await _tap(command, 'company-join-close');
      case CompanyPeerDriverStep.signIn:
        await _signIn(command, arg);
      case CompanyPeerDriverStep.selectRetained:
        final tile = _key('company-peer-${arg.target}').hitTestable();
        final page = _page;
        bool current() {
          final elements = tile.evaluate();
          if (!_live(command) ||
              page == null ||
              !identical(_page, page) ||
              elements.length != 1) {
            return false;
          }
          final widget = elements.single.widget;
          return widget is ListTile && widget.onTap != null;
        }
        await guardedNativeTap(tester, tile, isStillCurrent: current);
      case CompanyPeerDriverStep.verifyRetained:
        await _tap(command, 'company-peer-verify');
      case CompanyPeerDriverStep.makeAvailable:
        await _tap(command, 'company-jobs-enable-sync');
      case CompanyPeerDriverStep.syncNow:
        await _tap(command, 'company-jobs-sync-now');
    }
    return const NativeTestCommandResult.effect();
  }

  Future<void> _beginPair(NativeTestCommand command, String peerId) async {
    final page = _page;
    final controller = _controller;
    if (page == null || controller == null) rejectNativeTest('state-changed');
    final peers = controller.state.peers.where(
      (peer) => peer.deviceId == peerId,
    );
    if (peers.length != 1) rejectNativeTest('state-changed');
    final peer = peers.single;
    _invalidatePair();
    final pair = _pair = CompanyPeerDriverPair(page, peer);
    try {
      await _tap(
        command,
        'company-join-pair-$peerId',
        check: () =>
            identical(_page, page) &&
            identical(_controller, controller) &&
            identical(_pair, pair) &&
            controller.state.phase != NearbyPhase.pairing &&
            controller.state.pairedPeer == null &&
            controller.state.peers.contains(peer),
      );
    } catch (_) {
      _invalidatePair();
      rethrow;
    }
  }

  Future<NativeTestCommandResult> _observe(NativeTestCommand command) async {
    final session = _session!;
    final pair = _pair;
    final challenge = command.comparison;
    SealedObservation? sealed;
    if (challenge != null) {
      if (pair == null || !_currentPair(pair, pair.peer.deviceId)) {
        rejectNativeTest('state-changed');
      }
      final state = _controller!.state;
      final expires = state.verificationExpiresAt!.millisecondsSinceEpoch;
      final observation = RenderedObservation(
        renderedCode: _renderedCode!,
        attemptId: state.verificationAttemptId!,
        localExpiresAtMillis: expires,
        remainingMillis: expires - _wallMillis,
        deviceId: session.deviceId,
        peerId: session.peerId,
      );
      sealed = await sealRenderedObservation(
        session: session,
        challenge: challenge,
        observation: observation,
      );
      final proof = await sealed.identityHash();
      if (!_live(command) || !_currentPair(pair, pair.peer.deviceId)) {
        rejectNativeTest('state-changed');
      }
      _sealed = (pair: pair, proof: proof);
    }
    return NativeTestCommandResult.observation(
      NativeTestObservationResult(
        session: session,
        phase: _phase,
        sameNearbyState: _page != null,
        discovered: _controller?.state.peers.isNotEmpty ?? false,
        codePresent: _renderedCode != null,
        sealedObservation: sealed,
      ),
    );
  }

  List<int> _context(
    NativeTestCommand command,
    CompanyPeerDriverArgument arg,
  ) => CompanyPeerDriverPermit.context(
    session: _session!,
    appPid: pid,
    sequence: command.sequence,
    step: arg.step,
    target: arg.target!,
    expires: arg.permit!.expires,
    proof: arg.permit!.proof,
  );

  Future<void> _match(
    NativeTestCommand command,
    CompanyPeerDriverArgument arg,
  ) async {
    final saved = _sealed;
    final permit = arg.permit!;
    if (saved == null || saved.proof != permit.proof) {
      rejectNativeTest('grant-rejected');
    }
    final peerId = arg.target!;
    final attemptId = _controller?.state.verificationAttemptId;
    bool current() =>
        attemptId != null &&
        _controller?.state.verificationAttemptId == attemptId &&
        _millis < permit.expires &&
        _currentPair(saved.pair, peerId);
    await saved.pair.authorizeMatch(
      permit: permit,
      observedProof: saved.proof,
      session: _session!,
      context: _context(command, arg),
      nowMillis: _millis,
      isStillCurrent: () => _live(command) && current(),
    );
    _sealed = null;
    await _tap(command, 'company-join-match', check: current);
  }

  Future<void> _signIn(
    NativeTestCommand command,
    CompanyPeerDriverArgument arg,
  ) async {
    final permit = arg.permit!;
    if (permit.proof != _inputPublicKey) rejectNativeTest('grant-rejected');
    final context = _context(command, arg);
    await companyPeerDriverSignIn(
      tester,
      targetUser: arg.target!,
      isStillCurrent: () =>
          _live(command) && _millis < permit.expires && _page == null,
      authorizePin: () async {
        await permit.verify(
          session: _session!,
          context: context,
          nowMillis: _millis,
        );
        return permit.openPin(_inputKey, context);
      },
    );
  }
}

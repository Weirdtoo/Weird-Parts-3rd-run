import 'dart:convert';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:wired_parts/app.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';
import 'package:wired_parts/features/nearby/nearby_page.dart';
import 'package:wired_parts/main.dart' as production;

import '../tool/nearby_lan_workspace.dart';
import '../tool/native_nearby_test_commands.dart';
import '../tool/native_nearby_test_crypto.dart';
import '../tool/native_nearby_test_exit.dart';
import '../tool/native_nearby_test_fixture.dart';
import '../tool/native_nearby_test_rpc.dart';
import '../tool/native_nearby_test_tap.dart';

const _run = String.fromEnvironment('LAN_VALIDATION_RUN');
const _roleName = String.fromEnvironment('LAN_VALIDATION_ROLE');
const _enabled = bool.fromEnvironment('NATIVE_NEARBY_TEST_MODE');

void _guard() {
  if (!_enabled ||
      (!Platform.isWindows && !Platform.isMacOS) ||
      (_run != 'nearby-lifecycle-20261007a' &&
          _run != 'nearby-resident-probe-20261009a') ||
      _roleName != (Platform.isWindows ? 'receiver' : 'sender')) {
    rejectNativeTest('entrypoint-rejected');
  }
}

void main() {
  _guard();
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('resident native Nearby acceptance', (tester) async {
    final originalErrorHandler = FlutterError.onError;
    FlutterError.onError = (_) => originalErrorHandler?.call(
      FlutterErrorDetails(
        exception: const NativeTestFailure('framework-failed'),
      ),
    );
    try {
      final workspace = openExistingNativeFixture(
        run: _run,
        role: ValidationRole.values.singleWhere(
          (role) => role.name == _roleName,
        ),
      );
      PathProviderPlatform.instance = workspace;
      await production.main();
      await _settle(tester);
      final more = find.text('More');
      if (more.evaluate().length != 1) rejectNativeTest('bootstrap-failed');
      await tester.tap(more);
      await _settle(tester);
      final nearby = find.widgetWithText(ListTile, 'Nearby');
      if (nearby.evaluate().length != 1) rejectNativeTest('bootstrap-failed');
      await tester.tap(nearby);
      await tester.pump(const Duration(milliseconds: 100));
      final resident = _Resident(tester, workspace);
      await resident.initialize();
      resident.register();
      await resident.run();
    } catch (_) {
      // No finder/widget dump, framework exception or verification value is
      // sent to the test runner, including a failed code comparison.
      throw const NativeTestFailure('resident-failed');
    } finally {
      FlutterError.onError = originalErrorHandler;
    }
  }, timeout: const Timeout(Duration(minutes: 25)));
}

Future<void> _settle(WidgetTester tester) => tester.pumpAndSettle(
  const Duration(milliseconds: 100),
  EnginePhase.sendSemanticsUpdate,
  const Duration(seconds: 20),
);

final class _SavedPair {
  _SavedPair(this.sealed, this.plaintext, this.captured);
  final SealedObservation sealed;
  final RenderedObservation plaintext;
  final int captured;
}

final class _Resident {
  _Resident(this.tester, this.workspace);
  final WidgetTester tester;
  final ValidationWorkspace workspace;
  final clock = Stopwatch()..start();
  late final State nearbyState;
  late final NativeFixtureSnapshot baseline;
  TestSession? session;
  NativeTestCommandCache? cache;
  MatchGrantVerifier? verifier;
  _SavedPair? savedPair;
  var finished = false;
  var snapshotOrdinal = 0;
  var markedLeg = 0;
  var exitRequested = false;
  late final rpc = NativeTestResidentRpc(
    appPid: pid,
    run: _run,
    role: role,
    deviceId: workspace.deviceId,
    peerId: peerId,
    clockMillis: () => clock.elapsedMilliseconds,
    onDiagnostic: (record) {
      // The stock integration runner forwards test-zone print records.
      // ignore: avoid_print
      print(
        '$nativeTestConfigureDiagnosticPrefix${jsonEncode(record.toJson())}',
      );
    },
    readInfoInLoop: () {
      final current = view;
      return NativeTestResidentViewInfo(
        phase: NativeTestPhase.values.byName(current.phase.name),
        sameNearbyState: sameNearbyState,
        discovered: current.peers.any((peer) => peer.deviceId == peerId),
        codePresent: current.verifyCode != null,
      );
    },
  );

  TestRole get role =>
      TestRole.values.singleWhere((role) => role.name == _roleName);
  String get peerId =>
      'lan-$_run-${role == TestRole.sender ? 'receiver' : 'sender'}';
  bool get sameNearbyState =>
      find.byType(NearbyPage).evaluate().length == 1 &&
      identical(nearbyState, tester.state(find.byType(NearbyPage)));
  NearbyViewState get view {
    if (!sameNearbyState || find.byType(NearbyView).evaluate().length != 1) {
      rejectNativeTest('state-changed');
    }
    return tester.widget<NearbyView>(find.byType(NearbyView)).state;
  }

  AppScope get scope => AppScope.of(tester.element(find.byType(NearbyPage)));

  Future<void> initialize() async {
    if (find.byType(NearbyPage).evaluate().length != 1) rejectNativeTest();
    nearbyState = tester.state(find.byType(NearbyPage));
    baseline = await NativeFixtureSnapshot.capture(scope.db, workspace);
    if (!baseline.integrityValid ||
        !baseline.referencesValid ||
        baseline.schemaVersion != 2 ||
        scope.deviceId != workspace.deviceId) {
      rejectNativeTest('fixture-rejected');
    }
    rpc.refreshInfoInLoop();
  }

  void register() {
    developer.registerExtension('ext.wired_parts.nearbyTest.info', (
      _,
      params,
    ) async {
      if (!_keys(params, {})) {
        return _response({'version': 1, 'outcome': 'rejected'});
      }
      return _response(rpc.info());
    });
    developer.registerExtension('ext.wired_parts.nearbyTest.configure', (
      _,
      params,
    ) async {
      if (!_keys(params, {'data'})) {
        return _response({'version': 1, 'outcome': 'rejected'});
      }
      return _response(await rpc.configure(params['data']!));
    });
    developer.registerExtension('ext.wired_parts.nearbyTest.command', (
      _,
      params,
    ) async {
      if (!_keys(params, {'data'})) {
        return _response({'version': 1, 'outcome': 'rejected'});
      }
      final commands = cache;
      if (commands == null) {
        return _response({'version': 1, 'outcome': 'not-configured'});
      }
      return _response(commands.submitJson(params['data']!).toJson());
    });
  }

  static bool _keys(Map<String, String> params, Set<String> expected) {
    final keys = params.keys.where((key) => key != 'isolateId').toSet();
    return keys.length == expected.length && keys.containsAll(expected);
  }

  static developer.ServiceExtensionResponse _response(
    Map<String, Object> result,
  ) => developer.ServiceExtensionResponse.result(jsonEncode(result));

  Future<void> run() async {
    try {
      while (!finished) {
        rpc.markLoopStarted();
        rpc.processConfigurationInLoop((next) {
          if (session != null ||
              exitRequested ||
              scope.deviceId != workspace.deviceId ||
              !sameNearbyState) {
            rejectNativeTest();
          }
          final nextCache = NativeTestCommandCache(
            session: next,
            clockMillis: () => clock.elapsedMilliseconds,
          );
          final nextVerifier = MatchGrantVerifier(next);
          session = next;
          cache = nextCache;
          verifier = nextVerifier;
        });
        cache?.tick();
        final command = cache?.takeNext();
        NativeTestCommandResult? result;
        NativeTestCommandError? failure;
        if (command != null) {
          try {
            result = await perform(command);
          } on NativeTestFailure {
            failure = NativeTestCommandError.stateChanged;
          } catch (_) {
            failure = NativeTestCommandError.harnessFailed;
          }
        }
        rpc.markPumpStarted();
        try {
          await tester.pump(const Duration(milliseconds: 100));
        } finally {
          rpc.markPumpSettled();
        }
        rpc.refreshInfoInLoop();
        // A terminal reply is visible only after the rendered view has been
        // pumped and published. The host reads info immediately on completion.
        if (command != null) {
          if (result != null) {
            cache!.complete(command, result);
          } else {
            cache!.fail(command, failure!, effect: NativeTestEffect.possible);
          }
        }
        // Real native timers/HTTP need event-loop time even if no frame changed.
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
    } finally {
      rpc.close();
    }
  }

  Future<NativeTestCommandResult> perform(NativeTestCommand command) async {
    final active = session!;
    if (!sameNearbyState || exitRequested) rejectNativeTest('state-changed');
    switch (command.action) {
      case NativeTestAction.observe:
        final current = view;
        SealedObservation? sealed;
        final comparison = command.comparison;
        if (comparison != null) {
          final code = _renderedCode();
          final attempt = current.verificationAttemptId;
          final expiry = current.verificationExpiresAt?.millisecondsSinceEpoch;
          if (current.phase != NearbyPhase.pairing ||
              attempt == null ||
              expiry == null ||
              expiry <= DateTime.now().millisecondsSinceEpoch) {
            rejectNativeTest();
          }
          final prior = savedPair;
          if (prior != null &&
              prior.plaintext.attemptId == attempt &&
              jsonEncode(prior.sealed.challenge.toJson()) ==
                  jsonEncode(comparison.toJson())) {
            sealed = prior.sealed;
          } else {
            final captured = clock.elapsedMilliseconds;
            final remaining = expiry - DateTime.now().millisecondsSinceEpoch;
            final plaintext = RenderedObservation(
              renderedCode: code,
              attemptId: attempt,
              localExpiresAtMillis: expiry,
              remainingMillis: remaining,
              deviceId: active.deviceId,
              peerId: active.peerId,
            );
            sealed = await sealRenderedObservation(
              session: active,
              challenge: comparison,
              observation: plaintext,
            );
            savedPair = _SavedPair(sealed, plaintext, captured);
          }
        }
        return NativeTestCommandResult.observation(
          NativeTestObservationResult(
            session: active,
            phase: NativeTestPhase.values.byName(current.phase.name),
            sameNearbyState: sameNearbyState,
            discovered: current.peers.any((peer) => peer.deviceId == peerId),
            codePresent: current.verifyCode != null,
            sealedObservation: sealed,
          ),
        );
      case NativeTestAction.pair:
        final current = view;
        if (!{
          NearbyPhase.looking,
          NearbyPhase.paired,
          NearbyPhase.success,
        }.contains(current.phase)) {
          rejectNativeTest('wrong-phase');
        }
        final peer = current.peers
            .where((peer) => peer.deviceId == peerId)
            .singleOrNull;
        if (peer == null) rejectNativeTest('wrong-phase');
        final tile = find.widgetWithText(ListTile, peer.label);
        await _tap(
          find.descendant(
            of: tile,
            matching: find.widgetWithText(TextButton, 'Pair'),
          ),
        );
        return const NativeTestCommandResult.effect();
      case NativeTestAction.matchWithGrant:
        final saved = savedPair;
        final grant = command.grant!;
        if (saved == null) rejectNativeTest('grant-rejected');
        bool stillCurrent() {
          final current = view;
          final age = clock.elapsedMilliseconds - saved.captured;
          return current.phase == NearbyPhase.pairing &&
              current.deviceId == active.deviceId &&
              current.verificationAttemptId == saved.plaintext.attemptId &&
              current.verificationExpiresAt?.millisecondsSinceEpoch ==
                  saved.plaintext.localExpiresAtMillis &&
              _renderedCode() == saved.plaintext.renderedCode &&
              age >= 0 &&
              age < grant.ttlMillis &&
              age < saved.plaintext.remainingMillis &&
              clock.elapsedMilliseconds < command.deadlineMillis &&
              DateTime.now().millisecondsSinceEpoch <
                  saved.plaintext.localExpiresAtMillis;
        }
        await verifier!.consume(
          grant: grant,
          savedObservation: saved.sealed,
          challenge: saved.sealed.challenge,
          savedPlaintext: saved.plaintext,
          activeAttemptId: view.verificationAttemptId!,
          currentRenderedCode: _renderedCode(),
          localExpiresAtMillis:
              view.verificationExpiresAt!.millisecondsSinceEpoch,
          observationCapturedElapsedMillis: saved.captured,
          nowElapsedMillis: clock.elapsedMilliseconds,
          nowMillis: DateTime.now().millisecondsSinceEpoch,
          isStillCurrent: stillCurrent,
        );
        if (!stillCurrent()) rejectNativeTest('state-changed');
        await guardedNativeTap(
          tester,
          find.widgetWithText(FilledButton, 'Match'),
          isStillCurrent: stillCurrent,
        );
        await tester.pump(const Duration(milliseconds: 100));
        return const NativeTestCommandResult.effect();
      case NativeTestAction.send:
        if (!{NearbyPhase.paired, NearbyPhase.success}.contains(view.phase) ||
            view.pairedPeer?.deviceId != peerId) {
          rejectNativeTest('wrong-phase');
        }
        await _tap(find.widgetWithText(FilledButton, 'Send this shop'));
        await _pinAndConfirm('Send this shop');
        return const NativeTestCommandResult.effect();
      case NativeTestAction.accept:
        if (view.phase != NearbyPhase.offering ||
            view.incoming?.sourceDeviceId != peerId) {
          rejectNativeTest('wrong-phase');
        }
        await _tap(find.widgetWithText(FilledButton, 'Accept shop'));
        await _pinAndConfirm('Accept shop');
        return const NativeTestCommandResult.effect();
      case NativeTestAction.snapshot:
        if ({
          NearbyPhase.starting,
          NearbyPhase.offering,
          NearbyPhase.transferring,
        }.contains(view.phase)) {
          rejectNativeTest('wrong-phase');
        }
        final next = await NativeFixtureSnapshot.capture(scope.db, workspace);
        final proof = PrivateSnapshotProof(
          domainDigest: next.digest,
          assetsDigest: next.assetsDigest,
          completeSettingsDigest: next.completeSettingsDigest,
          sharedSettingsDigestIncludingPin: next.privateSharedSettingsDigest,
          profileDigest: next.profileDigest,
          pinDigest: next.privatePinDigest,
          schemaVersion: next.schemaVersion,
          tableCount: next.domain.length,
          rowCount: next.rowCount,
          assetCount: next.assets.length,
          referenceCount: next.referenceCount,
          integrityValid: next.integrityValid,
          referencesValid: next.referencesValid,
        );
        final sealed = await sealPrivateSnapshot(
          session: active,
          stage: command.snapshotStage!,
          ordinal: ++snapshotOrdinal,
          proof: proof,
        );
        final nearbyAt = next.setting('last_nearby_at');
        return NativeTestCommandResult.snapshot(
          NativeTestSnapshotResult(
            digest: next.digest,
            assetsDigest: next.assetsDigest,
            sharedSettingsDigest: next.sharedSettingsDigest,
            profileDigest: next.profileDigest,
            schemaVersion: next.schemaVersion,
            tableCount: next.domain.length,
            rowCount: next.rowCount,
            assetCount: next.assets.length,
            integrityValid: next.integrityValid,
            referencesValid: next.referencesValid,
            profileEqual: next.profileDigest == baseline.profileDigest,
            assetsEqual: next.assetsDigest == baseline.assetsDigest,
            settingsEqual:
                next.completeSettingsDigest == baseline.completeSettingsDigest,
            ownershipEqual: next.ownerDigest == baseline.ownerDigest,
            lastNearbySourceId: next.setting('last_nearby_peer') as String?,
            lastNearbyAtMillis: nearbyAt is String
                ? DateTime.tryParse(nearbyAt)?.millisecondsSinceEpoch
                : null,
            sealedProof: sealed,
          ),
        );
      case NativeTestAction.markReceivedDatabase:
        final leg = command.leg!;
        if (view.phase != NearbyPhase.success ||
            markedLeg != 0 ||
            (leg == 1 && role != TestRole.receiver) ||
            (leg == 2 && role != TestRole.sender)) {
          rejectNativeTest('wrong-phase');
        }
        final db = scope.db;
        await db.transaction(() async {
          final jobs = await db.jobsDao.listActiveJobs();
          if (jobs.length != 1 || jobs.single.id != '$_run-sender-job') {
            rejectNativeTest('fixture-rejected');
          }
          await db.customStatement(
            'UPDATE jobs SET notes=notes||?, revision=revision+1 WHERE id=?',
            [' [native-nearby-test:leg$leg]', '$_run-sender-job'],
          );
        });
        markedLeg = leg;
        return const NativeTestCommandResult.effect();
      case NativeTestAction.finish:
        if (view.phase != NearbyPhase.success) rejectNativeTest('wrong-phase');
        _writeWitness('finished');
        // Keep the test resident for normalExit; returning invokes stock
        // runner cleanup, which is not normal application quit evidence.
        return const NativeTestCommandResult.effect(
          effect: NativeTestEffect.none,
        );
      case NativeTestAction.normalExit:
        if (view.phase != NearbyPhase.success) rejectNativeTest('wrong-phase');
        _writeWitness('normal-exit-requested');
        exitRequested = true;
        await requestNativeTestExit();
        // Windows replies before its asynchronous request-app-exit callback.
        // Remaining alive after this grace is unverified, never an exit pass.
        await Future<void>.delayed(const Duration(seconds: 2));
        rejectNativeTest('exit-unverified');
      case NativeTestAction.jobNameUi:
      case NativeTestAction.jobDetailsUi:
      case NativeTestAction.companyPeerUi:
        rejectNativeTest('context-mismatch');
      case NativeTestAction.jobLifecycleUi:
        rejectNativeTest('wrong-phase');
    }
  }

  String _renderedCode() {
    final current = view;
    final code = current.verifyCode;
    if (code == null ||
        !RegExp(r'^[0-9]{6}$').hasMatch(code) ||
        find.text(code).evaluate().length != 1) {
      rejectNativeTest('code-not-rendered');
    }
    return code;
  }

  Future<void> _tap(Finder finder) async {
    if (finder.evaluate().length != 1) rejectNativeTest('control-not-rendered');
    await tester.tap(finder);
    await tester.pump(const Duration(milliseconds: 100));
  }

  Future<void> _pinAndConfirm(String label) async {
    final deadline = clock.elapsedMilliseconds + 10000;
    while (clock.elapsedMilliseconds < deadline) {
      final pin = find.widgetWithText(AlertDialog, 'Editor PIN');
      if (pin.evaluate().length == 1) {
        final field = find.descendant(
          of: pin,
          matching: find.byType(TextField),
        );
        if (field.evaluate().length != 1) {
          rejectNativeTest('pin-control-failed');
        }
        await tester.enterText(field, '1234');
        await _tap(
          find.descendant(
            of: pin,
            matching: find.widgetWithText(FilledButton, 'Unlock'),
          ),
        );
      }
      final dialogs = find.byType(AlertDialog);
      final confirm = find.descendant(of: dialogs, matching: find.text(label));
      if (confirm.evaluate().length == 1) {
        await _tap(confirm);
        return;
      }
      await tester.pump(const Duration(milliseconds: 100));
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    rejectNativeTest('pin-or-confirm-timeout');
  }

  void _writeWitness(String outcome) {
    File(
      p.join(
        workspace.receipts.path,
        'native-resident-${session!.epoch}-$outcome.json',
      ),
    ).writeAsStringSync(
      jsonEncode({
        'format': 1,
        'outcome': outcome,
        'run': _run,
        'role': _roleName,
        'deviceId': workspace.deviceId,
        'appPid': pid,
        'sameNearbyState': sameNearbyState,
        'phase': view.phase.name,
        'observedAt': DateTime.now().toUtc().toIso8601String(),
      }),
      flush: true,
    );
  }
}

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';

import '../../tool/native_nearby_test_commands.dart';
import '../../tool/native_nearby_test_crypto.dart';

TestSession session([String epoch = 'epoch-a']) => TestSession(
  epoch: epoch,
  run: 'run-a',
  role: TestRole.sender,
  deviceId: 'device-a',
  peerId: 'device-b',
  encryptionPublicKey: base64Url.encode(List.filled(32, 1)),
  signingPublicKey: base64Url.encode(List.filled(32, 2)),
);

final class Fixture {
  Fixture({int maxEntries = 64}) {
    cache = NativeTestCommandCache(
      session: localSession,
      maxEntries: maxEntries,
      clockMillis: () => now,
    );
  }
  int now = 0;
  final localSession = session();
  late final NativeTestCommandCache cache;

  String request(
    int sequence, {
    NativeTestAction action = NativeTestAction.pair,
    int deadline = 1000,
    ComparisonChallenge? comparison,
    MatchGrant? grant,
    int? leg,
    PrivateSnapshotStage? snapshotStage,
    NativeJobNameUiStep? jobNameStep,
  }) => NativeTestCommand.encodeRequest(
    session: localSession,
    sequence: sequence,
    action: action,
    deadlineMillis: deadline,
    comparison: comparison,
    grant: grant,
    leg: leg,
    snapshotStage: action == NativeTestAction.snapshot
        ? snapshotStage ?? PrivateSnapshotStage.baseline
        : snapshotStage,
    jobNameStep: action == NativeTestAction.jobNameUi
        ? jobNameStep ?? NativeJobNameUiStep.inspect
        : jobNameStep,
    jobDetailsStep: action == NativeTestAction.jobDetailsUi
        ? NativeJobDetailsUiStep.inspect
        : null,
    jobLifecycleStep: action == NativeTestAction.jobLifecycleUi
        ? NativeJobLifecycleUiStep.inspect
        : null,
  );

  NativeTestCommand finish(int sequence) {
    expect(
      cache.submitJson(request(sequence)).state,
      NativeTestCommandState.accepted,
    );
    final command = cache.takeNext()!;
    expect(
      cache.complete(command, const NativeTestCommandResult.effect()).state,
      NativeTestCommandState.completed,
    );
    return command;
  }
}

Object? sortedJson(Object? value) {
  if (value is Map<String, dynamic>) {
    final keys = value.keys.toList()..sort();
    return {for (final key in keys) key: sortedJson(value[key])};
  }
  if (value is List) return value.map(sortedJson).toList();
  return value;
}

String change(String source, void Function(Map<String, dynamic>) mutation) {
  final map = jsonDecode(source) as Map<String, dynamic>;
  mutation(map);
  map['contentHash'] = sha256
      .convert(
        utf8.encode(
          jsonEncode([
            'wired-parts/native-nearby-test/v1',
            'command',
            map['epoch'],
            map['commandId'],
            map['sequence'],
            map['action'],
            map['deadlineMillis'],
            sortedJson(map['arguments']),
          ]),
        ),
      )
      .toString();
  return jsonEncode(map);
}

ComparisonChallenge challenge(TestSession local) => ComparisonChallenge(
  epoch: local.epoch,
  leg: 1,
  comparisonId: 1,
  challenge: base64Url.encode(List.filled(32, 3)),
);

MatchGrant grant(TestSession local) => MatchGrant(
  session: local,
  comparison: challenge(local),
  attemptId: 'attempt-a',
  sealedCiphertextHash: base64Url.encode(List.filled(32, 4)),
  localExpiresAtMillis: 10000,
  ttlMillis: 1000,
  signature: base64Url.encode(List.filled(64, 5)),
);

NativeTestSnapshotResult snapshot({String? sourceId, int? at}) =>
    NativeTestSnapshotResult(
      digest: 'a' * 64,
      assetsDigest: 'b' * 64,
      sharedSettingsDigest: 'c' * 64,
      profileDigest: 'd' * 64,
      schemaVersion: 15,
      tableCount: 20,
      rowCount: 30,
      assetCount: 0,
      integrityValid: true,
      referencesValid: true,
      profileEqual: true,
      assetsEqual: true,
      settingsEqual: false,
      ownershipEqual: true,
      lastNearbySourceId: sourceId,
      lastNearbyAtMillis: at,
    );

void main() {
  test('identical retries expose accepted/running/completed without another effect', () {
    final f = Fixture();
    final request = f.request(1);
    expect(f.cache.submitJson(request).toJson(), {
      'version': 1,
      'sequence': 1,
      'state': 'accepted',
      'outcome': 'pending',
      'inflight': false,
      'effect': 'none',
    });
    expect(f.cache.submitJson(request).state, NativeTestCommandState.accepted);
    final command = f.cache.takeNext()!;
    var effects = 1;
    expect(f.cache.submitJson(request).state, NativeTestCommandState.running);
    expect(f.cache.takeNext(), isNull);
    final reply = f.cache.complete(
      command,
      const NativeTestCommandResult.effect(),
    );
    expect(reply.toJson(), {
      'version': 1,
      'sequence': 1,
      'state': 'completed',
      'outcome': 'success',
      'inflight': false,
      'effect': 'completed',
      'result': {'outcome': 'success', 'effect': 'completed'},
    });
    for (var i = 0; i < 5; i++) {
      expect(f.cache.submitJson(request).toJson(), reply.toJson());
      if (f.cache.takeNext() != null) effects++;
    }
    expect(effects, 1);
  });

  test(
    'changed action or deadline under one identity rejects before execution',
    () {
      final f = Fixture();
      f.finish(1);
      for (final request in [
        f.request(1, action: NativeTestAction.send),
        f.request(1, deadline: 1001),
      ]) {
        expect(
          f.cache.submitJson(request).error,
          NativeTestCommandError.identityConflict,
        );
        expect(f.cache.takeNext(), isNull);
      }
    },
  );

  test('canonical content ignores JSON map order but binds all content', () {
    final f = Fixture();
    final request = f.request(
      1,
      action: NativeTestAction.observe,
      comparison: challenge(f.localSession),
    );
    expect(f.cache.submitJson(request).state, NativeTestCommandState.accepted);
    final map = jsonDecode(request) as Map<String, dynamic>;
    final args = map['arguments'] as Map<String, dynamic>;
    final comparison = args['comparison'] as Map<String, dynamic>;
    args['comparison'] = Map.fromEntries(comparison.entries.toList().reversed);
    final reordered = jsonEncode(
      Map.fromEntries(map.entries.toList().reversed),
    );
    expect(
      f.cache.submitJson(reordered).state,
      NativeTestCommandState.accepted,
    );
    final altered = jsonDecode(request) as Map<String, dynamic>;
    altered['deadlineMillis'] = 999;
    expect(
      f.cache.submitJson(jsonEncode(altered)).error,
      NativeTestCommandError.hashMismatch,
    );
  });

  test(
    'only one command is queued or running including observation and snapshot',
    () {
      final f = Fixture();
      f.cache.submitJson(f.request(1));
      expect(
        f.cache
            .submitJson(f.request(2, action: NativeTestAction.observe))
            .error,
        NativeTestCommandError.busy,
      );
      final command = f.cache.takeNext()!;
      expect(
        f.cache
            .submitJson(f.request(2, action: NativeTestAction.snapshot))
            .error,
        NativeTestCommandError.busy,
      );
      expect(f.cache.highWater, 1);
      f.cache.complete(command, const NativeTestCommandResult.effect());
      expect(
        f.cache.submitJson(f.request(2)).state,
        NativeTestCommandState.accepted,
      );
    },
  );

  test(
    '64 entry eviction retains sequence high water and prohibits ID reuse',
    () {
      final f = Fixture();
      for (var sequence = 1; sequence <= 65; sequence++) {
        f.finish(sequence);
      }
      expect(f.cache.cachedCount, 64);
      expect(f.cache.highWater, 65);
      expect(
        f.cache.submitJson(f.request(1)).error,
        NativeTestCommandError.outcomeUnavailable,
      );
      expect(
        f.cache.submitJson(f.request(1, action: NativeTestAction.send)).error,
        NativeTestCommandError.outcomeUnavailable,
      );
      final reusedId = change(
        f.request(66),
        (m) => m['commandId'] = 'epoch-a.1',
      );
      expect(
        f.cache.submitJson(reusedId).error,
        NativeTestCommandError.identityConflict,
      );
      expect(f.cache.takeNext(), isNull);
      expect(f.cache.highWater, 65);
      expect(
        f.cache.submitJson(f.request(65)).state,
        NativeTestCommandState.completed,
      );
    },
  );

  test('skipped old sequences cannot execute even if never cached', () {
    final f = Fixture(maxEntries: 1);
    f.finish(5);
    expect(
      f.cache.submitJson(f.request(4)).error,
      NativeTestCommandError.outcomeUnavailable,
    );
    f.finish(6);
    expect(f.cache.cachedCount, 1);
    expect(f.cache.highWater, 6);
    expect(
      f.cache.submitJson(f.request(5)).error,
      NativeTestCommandError.outcomeUnavailable,
    );
  });

  test(
    'queued deadline removes command before activation and stores failure',
    () {
      final f = Fixture();
      final request = f.request(1, deadline: 5);
      f.cache.submitJson(request);
      f.now = 5;
      expect(f.cache.takeNext(), isNull);
      expect(f.cache.hasInflight, isFalse);
      final failed = f.cache.submitJson(request);
      expect(failed.state, NativeTestCommandState.failed);
      expect(failed.error, NativeTestCommandError.deadlineExpired);
      expect(failed.effect, NativeTestEffect.none);
      expect(
        f.cache.submitJson(f.request(2)).state,
        NativeTestCommandState.accepted,
      );
    },
  );

  test(
    'running deadline is UNKNOWN/inflight and never makes command rerunnable',
    () {
      final f = Fixture();
      final request = f.request(1, deadline: 5);
      f.cache.submitJson(request);
      final command = f.cache.takeNext()!;
      f.now = 5;
      expect(f.cache.submitJson(request).toJson(), {
        'version': 1,
        'sequence': 1,
        'state': 'unknown',
        'outcome': 'UNKNOWN',
        'inflight': true,
        'effect': 'possible',
      });
      expect(f.cache.hasInflight, isTrue);
      expect(f.cache.takeNext(), isNull);
      expect(
        f.cache.submitJson(f.request(2)).error,
        NativeTestCommandError.busy,
      );
      f.now = 30000;
      expect(f.cache.submitJson(request).state, NativeTestCommandState.unknown);
      expect(
        f.cache.complete(command, const NativeTestCommandResult.effect()).state,
        NativeTestCommandState.completed,
      );
      expect(
        f.cache.submitJson(request).state,
        NativeTestCommandState.completed,
      );
      expect(
        f.cache.submitJson(f.request(2, deadline: 30005)).state,
        NativeTestCommandState.accepted,
      );
    },
  );

  test(
    'new already-expired requests and unbounded deadlines never activate',
    () {
      final f = Fixture()..now = 50;
      expect(
        f.cache.submitJson(f.request(1, deadline: 50)).error,
        NativeTestCommandError.deadlineExpired,
      );
      expect(f.cache.takeNext(), isNull);
      expect(
        f.cache.submitJson(f.request(2, deadline: 20051)).error,
        NativeTestCommandError.invalidRequest,
      );
      expect(f.cache.highWater, 1);
      expect(
        f.cache.submitJson(f.request(2, deadline: 20050)).state,
        NativeTestCommandState.accepted,
      );
    },
  );

  test('phase guards run at submission and actual activation', () {
    final f = Fixture();
    expect(
      f.cache.submitJson(f.request(1), allowedActions: {}).error,
      NativeTestCommandError.wrongPhase,
    );
    expect(f.cache.takeNext(), isNull);
    final request = f.request(2);
    f.cache.submitJson(request, allowedActions: {NativeTestAction.pair});
    expect(
      f.cache.takeNext(allowedActions: {NativeTestAction.observe}),
      isNull,
    );
    expect(
      f.cache.submitJson(request).error,
      NativeTestCommandError.wrongPhase,
    );
    expect(f.cache.hasInflight, isFalse);
  });

  test(
    'finite action arguments become typed and all unexpected fields reject',
    () {
      for (final action in NativeTestAction.values) {
        final f = Fixture();
        if (action == NativeTestAction.companyPeerUi) {
          expect(
            () => f.request(1, action: action),
            throwsA(isA<NativeTestFailure>()),
          );
          continue;
        }
        final request = f.request(
          1,
          action: action,
          comparison: action == NativeTestAction.observe
              ? challenge(f.localSession)
              : null,
          grant: action == NativeTestAction.matchWithGrant
              ? grant(f.localSession)
              : null,
          leg: action == NativeTestAction.markReceivedDatabase ? 2 : null,
        );
        expect(
          f.cache.submitJson(request).state,
          NativeTestCommandState.accepted,
        );
        final command = f.cache.takeNext()!;
        expect(command.action, action);
        if (action == NativeTestAction.observe) {
          expect(command.comparison!.comparisonId, 1);
        }
        if (action == NativeTestAction.matchWithGrant) {
          expect(command.grant!.attemptId, 'attempt-a');
        }
        if (action == NativeTestAction.markReceivedDatabase) {
          expect(command.leg, 2);
        }
        if (action == NativeTestAction.snapshot) {
          expect(command.snapshotStage, PrivateSnapshotStage.baseline);
        }
        if (action == NativeTestAction.jobNameUi) {
          expect(command.jobNameStep, NativeJobNameUiStep.inspect);
        }
        final invalid = change(request, (m) {
          (m['arguments'] as Map<String, dynamic>)['path'] = 'forbidden';
        });
        expect(
          f.cache.submitJson(invalid).error,
          NativeTestCommandError.invalidRequest,
        );
      }
    },
  );

  test(
    'wrong epoch in envelope, comparison or grant cannot enter the queue',
    () {
      final f = Fixture();
      final wrong = NativeTestCommand.encodeRequest(
        session: session('epoch-b'),
        sequence: 1,
        action: NativeTestAction.pair,
        deadlineMillis: 1000,
      );
      expect(
        f.cache.submitJson(wrong).error,
        NativeTestCommandError.wrongSession,
      );
      final observed = f.request(
        1,
        action: NativeTestAction.observe,
        comparison: challenge(f.localSession),
      );
      expect(
        f.cache
            .submitJson(
              change(observed, (m) {
                (m['arguments']['comparison']
                        as Map<String, dynamic>)['epoch'] =
                    'epoch-b';
              }),
            )
            .error,
        NativeTestCommandError.wrongSession,
      );
      final matched = f.request(
        1,
        action: NativeTestAction.matchWithGrant,
        grant: grant(f.localSession),
      );
      expect(
        f.cache
            .submitJson(
              change(matched, (m) {
                (m['arguments']['grant']['session']
                        as Map<String, dynamic>)['peerId'] =
                    'device-other';
              }),
            )
            .error,
        NativeTestCommandError.invalidRequest,
      );
      expect(f.cache.highWater, 0);
      expect(f.cache.takeNext(), isNull);
    },
  );

  test('snapshot accepts only known wire stages with no raw proof fields', () {
    for (final stage in PrivateSnapshotStage.values) {
      final f = Fixture();
      final request = f.request(
        1,
        action: NativeTestAction.snapshot,
        snapshotStage: stage,
      );
      expect(
        f.cache.submitJson(request).state,
        NativeTestCommandState.accepted,
      );
      expect(f.cache.takeNext()!.snapshotStage, stage);
    }
    for (final arguments in [
      <String, Object>{},
      {'stage': 'finalState'},
      {'stage': 'PRIVATE_CANARY'},
      {'stage': 'baseline', 'pinDigest': 'PRIVATE_CANARY'},
      {'stage': false},
    ]) {
      final f = Fixture();
      final request = change(
        f.request(1, action: NativeTestAction.snapshot),
        (m) => m['arguments'] = arguments,
      );
      final reply = f.cache.submitJson(request);
      expect(reply.error, NativeTestCommandError.invalidRequest);
      expect(jsonEncode(reply.toJson()).contains('PRIVATE_CANARY'), isFalse);
      expect(f.cache.takeNext(), isNull);
    }
  });

  test('malformed and oversized requests never echo canaries', () {
    const canaries = [
      '739281',
      '1234',
      'http://127.0.0.1:9999/PRIVATE_AUTH_CANARY=/',
      '192.168.1.222:41001',
      'PRIVATE_KEY_CANARY',
    ];
    for (final canary in canaries) {
      final f = Fixture();
      final valid = f.request(1);
      final malformed = [
        canary,
        jsonEncode(canary),
        change(valid, (m) => m['action'] = canary),
        change(valid, (m) => m['sequence'] = canary),
        change(valid, (m) => m['commandId'] = canary),
        change(valid, (m) => m['deadlineMillis'] = canary),
        change(valid, (m) => m['arguments'] = {'path': canary}),
        change(valid, (m) => m['extra'] = canary),
        jsonEncode({
          ...jsonDecode(valid) as Map<String, dynamic>,
          'contentHash': canary,
        }),
        ' ' * nativeTestMaxCommandBytes + canary,
      ];
      for (final source in malformed) {
        final response = jsonEncode(f.cache.submitJson(source).toJson());
        expect(response.contains(canary), isFalse);
        expect(f.cache.takeNext(), isNull);
      }
    }
  });

  test(
    'strict scalar boundaries reject booleans doubles zeros and excess ints',
    () {
      for (final key in ['sequence', 'deadlineMillis']) {
        for (final value in [null, false, 1.0, 0, -1, 9007199254740992]) {
          final f = Fixture();
          expect(
            f.cache
                .submitJson(change(f.request(1), (m) => m[key] = value))
                .state,
            isNull,
          );
          expect(f.cache.takeNext(), isNull);
        }
      }
    },
  );

  test('terminal failures retry with exact known outcome and no effect', () {
    final f = Fixture();
    final request = f.request(1);
    f.cache.submitJson(request);
    final command = f.cache.takeNext()!;
    final failed = f.cache.fail(
      command,
      NativeTestCommandError.stateChanged,
      effect: NativeTestEffect.none,
    );
    expect(failed.error, NativeTestCommandError.stateChanged);
    expect(f.cache.submitJson(request).toJson(), failed.toJson());
    expect(f.cache.takeNext(), isNull);
    expect(
      f.cache.complete(command, const NativeTestCommandResult.effect()).error,
      NativeTestCommandError.invalidResult,
    );
  });

  test('only exact owned running command can resolve outcomes', () {
    final f = Fixture();
    final other = Fixture();
    f.cache.submitJson(f.request(1));
    other.cache.submitJson(other.request(1));
    final foreign = other.cache.takeNext()!;
    expect(
      f.cache.complete(foreign, const NativeTestCommandResult.effect()).error,
      NativeTestCommandError.invalidResult,
    );
    final own = f.cache.takeNext()!;
    expect(
      f.cache.fail(foreign, NativeTestCommandError.harnessFailed).error,
      NativeTestCommandError.invalidResult,
    );
    expect(f.cache.hasInflight, isTrue);
    expect(
      f.cache.complete(own, const NativeTestCommandResult.effect()).state,
      NativeTestCommandState.completed,
    );
  });

  test(
    'observation and snapshot outputs are fixed schemas and retained on retry',
    () {
      final f = Fixture();
      final request = f.request(1, action: NativeTestAction.observe);
      f.cache.submitJson(request);
      final observation = NativeTestObservationResult(
        session: f.localSession,
        phase: NativeTestPhase.looking,
        sameNearbyState: true,
        discovered: true,
        codePresent: false,
      );
      final reply = f.cache.complete(
        f.cache.takeNext()!,
        NativeTestCommandResult.observation(observation),
      );
      expect(reply.result!.toJson(), {
        'outcome': 'success',
        'effect': 'none',
        'observation': {
          'epoch': 'epoch-a',
          'run': 'run-a',
          'role': 'sender',
          'deviceId': 'device-a',
          'peerId': 'device-b',
          'phase': 'looking',
          'sameNearbyState': true,
          'discovered': true,
          'codePresent': false,
        },
      });
      expect(f.cache.submitJson(request).toJson(), reply.toJson());
      f.cache.submitJson(f.request(2, action: NativeTestAction.snapshot));
      final snapshotReply = f.cache.complete(
        f.cache.takeNext()!,
        NativeTestCommandResult.snapshot(
          snapshot(sourceId: 'device-b', at: 500),
        ),
      );
      expect(snapshotReply.result!.toJson()['snapshot'], {
        'digest': 'a' * 64,
        'assetsDigest': 'b' * 64,
        'sharedSettingsDigest': 'c' * 64,
        'profileDigest': 'd' * 64,
        'schemaVersion': 15,
        'tableCount': 20,
        'rowCount': 30,
        'assetCount': 0,
        'integrityValid': true,
        'referencesValid': true,
        'profileEqual': true,
        'assetsEqual': true,
        'settingsEqual': false,
        'ownershipEqual': true,
        'lastNearbySourceId': 'device-b',
        'lastNearbyAtMillis': 500,
      });
    },
  );

  test('wrong result kind and foreign observation context fail closed', () {
    final f = Fixture();
    f.cache.submitJson(f.request(1));
    expect(
      f.cache
          .complete(
            f.cache.takeNext()!,
            NativeTestCommandResult.snapshot(snapshot()),
          )
          .error,
      NativeTestCommandError.invalidResult,
    );
    f.cache.submitJson(f.request(2, action: NativeTestAction.observe));
    expect(
      f.cache
          .complete(
            f.cache.takeNext()!,
            NativeTestCommandResult.observation(
              NativeTestObservationResult(
                session: session('epoch-b'),
                phase: NativeTestPhase.looking,
                sameNearbyState: true,
                discovered: false,
                codePresent: false,
              ),
            ),
          )
          .error,
      NativeTestCommandError.invalidResult,
    );
  });

  test(
    'raw failure messages have no input slot in public result serialization',
    () {
      final f = Fixture();
      f.cache.submitJson(f.request(1));
      final command = f.cache.takeNext()!;
      const canary = '739281/1234/PRIVATE_AUTH_CANARY/192.168.1.222';
      try {
        throw StateError(canary);
      } catch (_) {
        final reply = f.cache.fail(
          command,
          NativeTestCommandError.harnessFailed,
        );
        expect(jsonEncode(reply.toJson()).contains(canary), isFalse);
        expect(reply.effect, NativeTestEffect.possible);
      }
    },
  );

  test('cache size cannot exceed the admitted bound', () {
    for (final size in [0, 65, -1]) {
      expect(
        () => NativeTestCommandCache(session: session(), maxEntries: size),
        throwsA(isA<Exception>()),
      );
    }
  });
}

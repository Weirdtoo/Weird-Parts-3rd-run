import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import '../../tool/company_peer_native_driver_control.dart';
import '../../tool/native_nearby_test_commands.dart';
import '../../tool/native_nearby_test_crypto.dart';
import '../../tool/native_nearby_test_host.dart';
import '../../tool/native_nearby_test_rpc.dart';

const run = 'nearby-lifecycle-20261007a';
const canary =
    'SAS739281/PIN1234/http://127.0.0.1:9999/AUTH_CANARY=/PRIVATE_KEY';

final class FakeTransport implements NativeTestHostTransport {
  final calls = <String>[];
  bool configured = false;
  bool failConfigure = false;
  bool failInfo = false;
  Object? infoOverride;
  Object? reply;
  final commandData = <String>[];
  final timeouts = <Duration?>[];
  Future<Object?> Function(Duration?)? onInfo;
  Future<Object?> Function(Duration?)? onCommand;
  final isolates = ['isolates/123'];
  final isolateReplies = <String, Object?>{};

  Map<String, Object> get infoValue => {
    'version': 1,
    'outcome': 'ready',
    'appPid': 100,
    'run': run,
    'role': 'receiver',
    'deviceId': 'lan-$run-receiver',
    'peerId': 'lan-$run-sender',
    'configured': configured,
    'elapsedMillis': 10,
    'phase': 'looking',
    'sameNearbyState': true,
    'discovered': true,
    'codePresent': false,
  };
  @override
  Future<Object?> getVm() async {
    calls.add('getVM');
    return {
      'isolates': [
        for (final id in isolates) {'id': id},
      ],
    };
  }

  @override
  Future<Object?> getIsolate(String id) async {
    calls.add('getIsolate');
    if (isolateReplies.containsKey(id)) return isolateReplies[id];
    return {
      'id': id,
      'extensionRPCs': [
        'ext.wired_parts.nearbyTest.info',
        'ext.wired_parts.nearbyTest.configure',
        'ext.wired_parts.nearbyTest.command',
      ],
    };
  }

  @override
  Future<Object?> info(String id, {Duration? timeout}) async {
    calls.add('info');
    timeouts.add(timeout);
    if (onInfo != null) return onInfo!(timeout);
    if (failInfo) throw StateError(canary);
    return infoOverride ?? infoValue;
  }

  @override
  Future<Object?> configure(String id, String data) async {
    calls.add('configure');
    if (failConfigure) throw StateError(canary);
    configured = true;
    return {'version': 1, 'outcome': 'configured'};
  }

  @override
  Future<Object?> command(String id, String data, {Duration? timeout}) async {
    calls.add('command');
    commandData.add(data);
    timeouts.add(timeout);
    if (onCommand != null) return onCommand!(timeout);
    return reply;
  }
}

final class Fixture {
  Fixture({this.budget = const Duration(seconds: 3), this.elapsed});
  final Duration budget;
  final Duration Function()? elapsed;
  final transport = FakeTransport();
  late final host = NativeTestHost(
    transport: transport,
    run: run,
    platform: 'windows',
    observeContextBudget: budget,
    observeContextElapsed: elapsed,
  );
  final session = TestSession(
    epoch: 'epoch-a',
    run: run,
    role: TestRole.receiver,
    deviceId: 'lan-$run-receiver',
    peerId: 'lan-$run-sender',
    encryptionPublicKey: base64Url.encode(List.filled(32, 1)),
    signingPublicKey: base64Url.encode(List.filled(32, 2)),
  );

  Future<void> ready() async {
    expect(await host.discover(), isTrue);
    expect(
      await host.handleLine(
        jsonEncode({'operation': 'configure', 'session': session.toJson()}),
      ),
      {
        'outcome': 'configure',
        'value': {'version': 1, 'outcome': 'configured'},
      },
    );
    transport.calls.clear();
    transport.timeouts.clear();
  }

  String request({
    NativeTestAction action = NativeTestAction.pair,
    ComparisonChallenge? comparison,
  }) => jsonEncode({
    'operation': 'command',
    'command': jsonDecode(
      NativeTestCommand.encodeRequest(
        session: session,
        sequence: 1,
        action: action,
        deadlineMillis: 1000,
        comparison: comparison,
        leg: action == NativeTestAction.markReceivedDatabase ? 1 : null,
        snapshotStage: action == NativeTestAction.snapshot
            ? PrivateSnapshotStage.baseline
            : null,
        jobNameStep: action == NativeTestAction.jobNameUi
            ? NativeJobNameUiStep.inspect
            : null,
        jobDetailsStep: action == NativeTestAction.jobDetailsUi
            ? NativeJobDetailsUiStep.inspect
            : null,
        jobLifecycleStep: action == NativeTestAction.jobLifecycleUi
            ? NativeJobLifecycleUiStep.inspect
            : null,
      ),
    ),
  });
  Map<String, Object> result(Object value, {String effect = 'none'}) => {
    'version': 1,
    'sequence': 1,
    'state': 'completed',
    'outcome': 'success',
    'inflight': false,
    'effect': effect,
    'result': value,
  };
}

Map<String, Object> sealedObservation(
  Fixture f,
  ComparisonChallenge comparison,
) => {
  'version': 1,
  'epoch': f.session.epoch,
  'run': run,
  'role': 'receiver',
  'comparison': comparison.toJson(),
  'ephemeralPublicKey': base64Url.encode(List.filled(32, 3)),
  'nonce': base64Url.encode(List.filled(12, 4)),
  'ciphertext': base64Url.encode(utf8.encode(canary)),
  'tag': base64Url.encode(List.filled(16, 5)),
};

Map<String, Object> sealedSnapshot(Fixture f) => {
  'version': 1,
  'epoch': f.session.epoch,
  'run': run,
  'role': 'receiver',
  'stage': 'baseline',
  'ordinal': 1,
  'ephemeralPublicKey': base64Url.encode(List.filled(32, 3)),
  'nonce': base64Url.encode(List.filled(12, 4)),
  'ciphertext': base64Url.encode(utf8.encode(canary)),
  'tag': base64Url.encode(List.filled(16, 5)),
};

Map<String, Object> pendingObservation(String state) => {
  'version': 1,
  'sequence': 1,
  'state': state,
  'outcome': state == 'unknown' ? 'UNKNOWN' : 'pending',
  'inflight': state != 'accepted',
  'effect': state == 'unknown' ? 'possible' : 'none',
};

String contextRequest(Fixture f) => f
    .request(action: NativeTestAction.observe)
    .replaceFirst('"operation":"command"', '"operation":"observeAndContext"');

Map<String, Object> completedObservation(Fixture f) => f.result({
  'outcome': 'success',
  'effect': 'none',
  'observation': {
    'epoch': f.session.epoch,
    'run': run,
    'role': 'receiver',
    'deviceId': f.host.deviceId,
    'peerId': f.host.peerId,
    'phase': 'pairing',
    'sameNearbyState': true,
    'discovered': true,
    'codePresent': true,
  },
});

void main() {
  test(
    'observeAndContext serially polls one exact envelope then binds context',
    () async {
      final f = Fixture();
      await f.ready();
      final replies = [
        pendingObservation('accepted'),
        pendingObservation('running'),
        completedObservation(f),
      ];
      var active = 0, maxActive = 0, index = 0;
      f.transport.onCommand = (_) async {
        active++;
        if (active > maxActive) maxActive = active;
        await Future<void>.delayed(Duration.zero);
        active--;
        return replies[index++];
      };
      final source = contextRequest(f);
      final output = await f.host.handleRecords(source);
      expect(maxActive, 1);
      expect(f.transport.commandData.length, 3);
      expect(f.transport.commandData.toSet().length, 1);
      expect(
        jsonDecode(f.transport.commandData.first),
        jsonDecode(source)['command'],
      );
      expect(f.transport.calls, [
        'info',
        'command',
        'command',
        'command',
        'info',
      ]);
      expect(output.map((r) => r['outcome']), ['info', 'command']);
      final command = jsonDecode(source)['command'];
      expect(output.first, {
        'outcome': 'info',
        'isolateId': 'isolates/123',
        'value': f.transport.infoValue,
        'commandIdentity': {
          for (final key in [
            'epoch',
            'commandId',
            'sequence',
            'action',
            'contentHash',
          ])
            key: command[key],
        },
      });
      expect((output.last['value'] as Map)['state'], 'completed');
      final budgets = f.transport.timeouts.cast<Duration>();
      expect(
        budgets.every(
          (d) => d > Duration.zero && d <= const Duration(seconds: 3),
        ),
        isTrue,
      );
      for (var i = 1; i < budgets.length; i++) {
        expect(budgets[i] < budgets[i - 1], isTrue);
      }
    },
  );

  test(
    'ordinary command stays single reply with unbounded legacy transport',
    () async {
      final f = Fixture();
      await f.ready();
      f.transport.reply = pendingObservation('accepted');
      final output = await f.host.handleRecords(
        f.request(action: NativeTestAction.observe),
      );
      expect(output, [
        {'outcome': 'command', 'value': f.transport.reply},
      ]);
      expect(f.transport.calls, ['info', 'command']);
      expect(f.transport.timeouts, [null, null]);
    },
  );

  test(
    'already completed observation needs one submission and postterminal info',
    () async {
      final f = Fixture();
      await f.ready();
      f.transport.reply = completedObservation(f);
      final output = await f.host.handleRecords(contextRequest(f));
      expect(output.map((r) => r['outcome']), ['info', 'command']);
      expect(f.transport.calls, ['info', 'command', 'info']);
    },
  );

  for (final state in ['unknown', 'failed', 'rejected']) {
    test(
      'observeAndContext stops $state without context or further poll',
      () async {
        final f = Fixture();
        await f.ready();
        f.transport.reply = state == 'unknown'
            ? pendingObservation(state)
            : {
                'version': 1,
                if (state != 'rejected') 'sequence': 1,
                'state': state,
                'outcome': state == 'failed' ? 'stateChanged' : 'busy',
                'inflight': false,
                'effect': 'none',
              };
        final output = await f.host.handleRecords(contextRequest(f));
        expect(output, [
          {'outcome': 'command', 'value': f.transport.reply},
        ]);
        expect(f.transport.calls, ['info', 'command']);
      },
    );
  }

  for (final action in NativeTestAction.values.where(
    (a) =>
        a != NativeTestAction.observe &&
        a != NativeTestAction.matchWithGrant &&
        a != NativeTestAction.companyPeerUi,
  )) {
    test('observeAndContext rejects ${action.name} before transport', () async {
      final f = Fixture();
      await f.ready();
      final source = f
          .request(action: action)
          .replaceFirst(
            '"operation":"command"',
            '"operation":"observeAndContext"',
          );
      expect(await f.host.handleRecords(source), [
        {'outcome': 'failed', 'category': 'invalidInput'},
      ]);
      expect(f.transport.calls, isEmpty);
    });
  }

  test(
    'candidate controls stay in command RPC and validate safe info',
    () async {
      final transport = FakeTransport();
      final host = NativeTestHost(
        transport: transport,
        run: companyPeerDriverRun,
        platform: 'windows',
      );
      final key = base64Url.encode(List.filled(32, 4));
      final ui = {
        'initialized': true,
        'discovered': ['actual-peer'],
        'selectedUser': null,
        'canVerify': false,
        'canMakeAvailable': false,
        'canSync': false,
        'sync': 'none',
      };
      transport.onInfo = (_) async => {
        ...transport.infoValue,
        'run': companyPeerDriverRun,
        'deviceId': 'lan-$companyPeerDriverRun-receiver',
        'peerId': companyPeerDriverOperator,
        'candidateInputKey': key,
        'candidateUi': ui,
      };
      final session = TestSession(
        epoch: 'control-session',
        run: companyPeerDriverRun,
        role: TestRole.receiver,
        deviceId: 'lan-$companyPeerDriverRun-receiver',
        peerId: companyPeerDriverOperator,
        encryptionPublicKey: key,
        signingPublicKey: key,
      );
      expect(await host.discover(), isTrue);
      final info = await host.handleLine(jsonEncode({'operation': 'info'}));
      expect((info['value'] as Map)['candidateUi'], ui);
      expect(
        await host.handleLine(
          jsonEncode({'operation': 'configure', 'session': session.toJson()}),
        ),
        {
          'outcome': 'configure',
          'value': {'version': 1, 'outcome': 'configured'},
        },
      );
      transport.calls.clear();
      final command = NativeTestCommand.encodeRequest(
        session: session,
        sequence: 1,
        action: NativeTestAction.companyPeerUi,
        deadlineMillis: 1000,
        companyPeerArgument: CompanyPeerDriverArgument.parse({
          'step': 'pair',
          'target': 'actual-peer',
        }, session),
      );
      expect(
        await host.handleRecords(
          jsonEncode({
            'operation': 'observeAndContext',
            'command': jsonDecode(command),
          }),
        ),
        [
          {'outcome': 'failed', 'category': 'invalidInput'},
        ],
      );
      expect(transport.calls, isEmpty);
      ui['unexpected'] = 'not allowed';
      final malformed = await host.handleLine(
        jsonEncode({'operation': 'info'}),
      );
      expect(malformed['outcome'], 'failed');
      expect(jsonEncode(malformed), isNot(contains('not allowed')));
    },
  );

  test(
    'observeAndContext rejects valid match grant before any transport',
    () async {
      final f = Fixture();
      await f.ready();
      final comparison = ComparisonChallenge(
        epoch: f.session.epoch,
        leg: 1,
        comparisonId: 1,
        challenge: base64Url.encode(List.filled(32, 3)),
      );
      final grant = MatchGrant(
        session: f.session,
        comparison: comparison,
        attemptId: 'attempt-a',
        sealedCiphertextHash: base64Url.encode(List.filled(32, 4)),
        localExpiresAtMillis: 10000,
        ttlMillis: 20000,
        signature: base64Url.encode(List.filled(64, 5)),
      );
      final source = jsonEncode({
        'operation': 'observeAndContext',
        'command': jsonDecode(
          NativeTestCommand.encodeRequest(
            session: f.session,
            sequence: 1,
            action: NativeTestAction.matchWithGrant,
            deadlineMillis: 1000,
            grant: grant,
          ),
        ),
      });
      expect(await f.host.handleRecords(source), [
        {'outcome': 'failed', 'category': 'invalidInput'},
      ]);
      expect(f.transport.calls, isEmpty);
    },
  );

  test(
    'context timeout preserves completed and does not publish context',
    () async {
      final f = Fixture(budget: const Duration(milliseconds: 80));
      await f.ready();
      f.transport.reply = completedObservation(f);
      var count = 0;
      f.transport.onInfo = (timeout) async {
        if (count++ == 0) return f.transport.infoValue;
        await Future<void>.delayed(timeout!);
        throw const NativeTestHostFailure(NativeTestHostError.rpcTimeout);
      };
      final output = await f.host.handleRecords(contextRequest(f));
      expect(output, [
        {'outcome': 'command', 'value': completedObservation(f)},
        {'outcome': 'failed', 'category': 'rpcTimeout'},
      ]);
      expect(f.transport.calls, ['info', 'command', 'info']);
    },
  );

  test('initial info consumes overall budget before any command', () async {
    final f = Fixture(budget: const Duration(milliseconds: 40));
    await f.ready();
    f.transport.onInfo = (timeout) async {
      await Future<void>.delayed(timeout!);
      throw const NativeTestHostFailure(NativeTestHostError.rpcTimeout);
    };
    expect(await f.host.handleRecords(contextRequest(f)), [
      {'outcome': 'failed', 'category': 'rpcTimeout'},
    ]);
    expect(f.transport.calls, ['info']);
  });

  test(
    'observeAndContext malformed envelope never reaches transport',
    () async {
      final f = Fixture();
      await f.ready();
      for (final source in [
        '{"operation":"observeAndContext","command":{}}',
        '{"operation":"observeAndContext","command":{},"extra":1}',
      ]) {
        expect(
          (await f.host.handleRecords(source)).single['outcome'],
          'failed',
        );
        expect(f.transport.calls, isEmpty);
      }
    },
  );

  for (final failure in [
    'transport error',
    'invalid reply',
    'expired before second poll',
  ]) {
    test('poll $failure retains last accepted and bounded failure', () async {
      final exhausted = failure == 'expired before second poll';
      final malformed = failure != 'transport error';
      var elapsed = Duration.zero;
      final f = Fixture(elapsed: () => elapsed);
      await f.ready();
      var count = 0;
      f.transport.onCommand = (_) async {
        if (count++ == 0) return pendingObservation('accepted');
        if (malformed) return {'raw': canary};
        throw StateError(canary);
      };
      final pollDelays = <Duration>[];
      final output = await runZoned(
        () => f.host.handleRecords(contextRequest(f)),
        zoneSpecification: ZoneSpecification(
          createTimer: (self, parent, zone, delay, callback) {
            pollDelays.add(delay);
            return parent.createTimer(zone, delay, () {
              elapsed = Duration(milliseconds: exhausted ? 990 : 50);
              callback();
            });
          },
        ),
      );
      expect(output, [
        {'outcome': 'command', 'value': pendingObservation('accepted')},
        {
          'outcome': 'failed',
          'category': exhausted
              ? 'rpcTimeout'
              : malformed
              ? 'invalidOutput'
              : 'rpcFailed',
        },
      ]);
      expect(pollDelays, [const Duration(milliseconds: 50)]);
      expect(jsonEncode(output).contains(canary), isFalse);
      expect(f.transport.calls, ['info', 'command', if (!exhausted) 'command']);
      expect(f.transport.timeouts, [
        const Duration(seconds: 3),
        const Duration(milliseconds: 990),
        if (!exhausted) const Duration(milliseconds: 940),
      ]);
      expect(count, exhausted ? 1 : 2);
    });
  }

  for (final failure in ['transport', 'pid', 'not-ready', 'clock-rollback']) {
    test('postterminal $failure cannot erase completed observation', () async {
      final f = Fixture();
      await f.ready();
      f.transport.reply = completedObservation(f);
      var infos = 0;
      f.transport.onInfo = (_) async {
        if (infos++ == 0) return f.transport.infoValue;
        if (failure == 'transport') throw StateError(canary);
        if (failure == 'pid') return {...f.transport.infoValue, 'appPid': 101};
        if (failure == 'clock-rollback') {
          return {...f.transport.infoValue, 'elapsedMillis': 9};
        }
        return {'version': 1, 'outcome': 'not-ready'};
      };
      final output = await f.host.handleRecords(contextRequest(f));
      expect(output.first, {
        'outcome': 'command',
        'value': completedObservation(f),
      });
      expect(output.last['outcome'], 'failed');
      expect(output.any((r) => r['outcome'] == 'info'), isFalse);
      expect(jsonEncode(output).contains(canary), isFalse);
    });
  }

  test(
    'overall budget bounds one pending RPC and no later request escapes',
    () async {
      final f = Fixture(budget: const Duration(milliseconds: 120));
      await f.ready();
      var active = false, count = 0;
      f.transport.onCommand = (timeout) async {
        if (count++ == 0) return pendingObservation('accepted');
        active = true;
        try {
          await Future<void>.delayed(timeout!);
          throw const NativeTestHostFailure(NativeTestHostError.rpcTimeout);
        } finally {
          active = false;
        }
      };
      final output = await f.host.handleRecords(contextRequest(f));
      expect(active, isFalse);
      expect(count, 2);
      expect(output, [
        {'outcome': 'command', 'value': pendingObservation('accepted')},
        {'outcome': 'failed', 'category': 'rpcTimeout'},
      ]);
      expect(
        f.transport.timeouts.last! < const Duration(milliseconds: 80),
        isTrue,
      );
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(count, 2);
      f.transport.onCommand = null;
      f.transport.reply = pendingObservation('accepted');
      expect((await f.host.handleLine(f.request()))['outcome'], 'command');
    },
  );

  test('native deadline already expired blocks the first command', () async {
    final f = Fixture();
    await f.ready();
    f.transport.infoOverride = {
      ...f.transport.infoValue,
      'elapsedMillis': 1000,
    };
    expect(await f.host.handleRecords(contextRequest(f)), [
      {'outcome': 'failed', 'category': 'rpcTimeout'},
    ]);
    expect(f.transport.calls, ['info']);
  });

  test('host remains busy across local wait and context collection', () async {
    final f = Fixture();
    await f.ready();
    final pending = Completer<Object?>();
    f.transport.onCommand = (_) => pending.future;
    final first = f.host.handleRecords(contextRequest(f));
    await Future<void>.delayed(Duration.zero);
    expect(await f.host.handleRecords(contextRequest(f)), [
      {'outcome': 'failed', 'category': 'busy'},
    ]);
    expect(await f.host.handleLine('{"operation":"info"}'), {
      'outcome': 'failed',
      'category': 'busy',
    });
    pending.complete(completedObservation(f));
    expect((await first).map((r) => r['outcome']), ['info', 'command']);
  });

  test('observe context wait budget cannot widen production limit', () {
    for (final budget in [Duration.zero, const Duration(seconds: 4)]) {
      expect(
        () => NativeTestHost(
          transport: FakeTransport(),
          run: run,
          platform: 'windows',
          observeContextBudget: budget,
        ),
        throwsA(isA<NativeTestHostFailure>()),
      );
    }
  });

  test('host emits strict fixed diagnostic from split marker', () {
    final records = <NativeTestConfigureDiagnostic>[];
    final scanner = NativeTestLauncherDiagnostics(
      onConfigureDiagnostic: records.add,
    );
    final record = const NativeTestConfigureDiagnostic(
      reason: NativeTestConfigureRejection.timerExpired,
      pumpPending: true,
      loopIterations: 1,
      pumpStarts: 1,
      pumpCompletions: 0,
      publicationAgeMillis: 3000,
    ).toJson();
    final marker = '$nativeTestConfigureDiagnosticPrefix${jsonEncode(record)}';
    scanner.addStdout(utf8.encode(marker.substring(0, 25)));
    scanner.addStdout(utf8.encode('${marker.substring(25)}\r'));
    scanner.addStdout(utf8.encode('\n'));
    expect(records, hasLength(1));
    expect(records.single.toJson(), record);
  });

  test('diagnostic marker survives every chunk split and final EOF without raw prefix', () {
    final record = const NativeTestConfigureDiagnostic(
      reason: NativeTestConfigureRejection.expiredInLoop,
      pumpPending: true,
      loopIterations: 2,
      pumpStarts: 2,
      pumpCompletions: 1,
      publicationAgeMillis: 3000,
    ).toJson();
    final line = utf8.encode(
      '$nativeTestConfigureDiagnosticPrefix${jsonEncode(record)}',
    );
    for (var split = 0; split <= line.length; split++) {
      final records = <NativeTestConfigureDiagnostic>[];
      final scanner = NativeTestLauncherDiagnostics(
        onConfigureDiagnostic: records.add,
      );
      scanner.addStdout(utf8.encode('$canary\n'));
      scanner.addStdout(line.sublist(0, split));
      scanner.addStdout(line.sublist(split));
      scanner.finishStdout();
      expect(records, hasLength(1));
      expect(records.single.toJson(), record);
      expect(scanner.bufferedCharacters, 0);
      expect(jsonEncode(scanner.toJson()).contains(canary), isFalse);
    }
  });

  test('diagnostic scanner rejects malformed fields, trailing text and nonascii laundering', () {
    final valid = const NativeTestConfigureDiagnostic(
      reason: NativeTestConfigureRejection.closed,
      pumpPending: false,
      loopIterations: 0,
      pumpStarts: 0,
      pumpCompletions: 0,
      publicationAgeMillis: null,
    ).toJson();
    final malformed = [
      '{}',
      '[1]',
      '{',
      jsonEncode({...valid, 'reason': canary}),
      jsonEncode({...valid, 'code': canary}),
      jsonEncode({...valid, 'pumpPending': 'false'}),
      jsonEncode({...valid, 'loopIterations': -1}),
      jsonEncode({...valid, 'pumpStarts': 9007199254740992}),
      jsonEncode({...valid, 'publicationAgeMillis': 1.0}),
      '${jsonEncode(valid)} $canary',
      jsonEncode(valid).replaceFirst('reason', 'reas\u00e9on'),
    ];
    final records = <NativeTestConfigureDiagnostic>[];
    final scanner = NativeTestLauncherDiagnostics(
      onConfigureDiagnostic: records.add,
    );
    for (final text in malformed) {
      scanner.addStderr(
        utf8.encode('$nativeTestConfigureDiagnosticPrefix$text\n'),
      );
    }
    scanner.addStderr(
      utf8.encode(
        '$canary $nativeTestConfigureDiagnosticPrefix${jsonEncode(valid)}\n',
      ),
    );
    scanner.addStdout(
      utf8.encode(
        '[+ 1 ms] flutter: $nativeTestConfigureDiagnosticPrefix${jsonEncode(valid)}\n',
      ),
    );
    expect(records, isEmpty);
    expect(jsonEncode(scanner.toJson()).contains(canary), isFalse);
    expect(scanner.toJson().containsKey('configureDiagnostic'), isFalse);
  });

  test(
    'diagnostic scanner bounds lines and never combines separate streams',
    () {
      final record = const NativeTestConfigureDiagnostic(
        reason: NativeTestConfigureRejection.oversize,
        pumpPending: false,
        loopIterations: 0,
        pumpStarts: 0,
        pumpCompletions: 0,
        publicationAgeMillis: null,
      ).toJson();
      final line = '$nativeTestConfigureDiagnosticPrefix${jsonEncode(record)}';
      final records = <NativeTestConfigureDiagnostic>[];
      final scanner = NativeTestLauncherDiagnostics(
        onConfigureDiagnostic: records.add,
      );
      scanner.addStdout(utf8.encode(line.substring(0, 20)));
      scanner.addStderr(utf8.encode('${line.substring(20)}\n'));
      scanner.addStdout(utf8.encode('\n'));
      scanner.addStdout(utf8.encode('${'x' * 100000}$line'));
      expect(scanner.bufferedCharacters, lessThanOrEqualTo(8192));
      scanner.finishStdout();
      scanner.addStderr(utf8.encode('$nativeTestConfigureDiagnosticPrefix{'));
      scanner.finishStderr();
      expect(records, isEmpty);
      scanner.addStdout(utf8.encode('$line\r'));
      scanner.addStdout(utf8.encode('\n'));
      expect(records, hasLength(1));
    },
  );

  test(
    'diagnostic emission is capped and sink errors never escape scanner',
    () {
      final record = const NativeTestConfigureDiagnostic(
        reason: NativeTestConfigureRejection.installerRejected,
        pumpPending: false,
        loopIterations: 1,
        pumpStarts: 1,
        pumpCompletions: 1,
        publicationAgeMillis: 0,
      ).toJson();
      var calls = 0;
      final scanner = NativeTestLauncherDiagnostics(
        onConfigureDiagnostic: (_) {
          calls++;
          throw StateError(canary);
        },
      );
      for (var i = 0; i < 20; i++) {
        scanner.addStdout(
          utf8.encode(
            '$nativeTestConfigureDiagnosticPrefix${jsonEncode(record)}\n',
          ),
        );
      }
      expect(calls, 8);
      expect(scanner.toJson()['configureDiagnostic'], record);
      expect(jsonEncode(scanner.toJson()).contains(canary), isFalse);
    },
  );

  test(
    'launcher diagnostics classify split SDK markers without raw values',
    () {
      final diagnostics = NativeTestLauncherDiagnostics();
      diagnostics.addStdout(utf8.encode('$canary Test timed '));
      diagnostics.addStdout(utf8.encode('out after 25 minutes.\n'));
      diagnostics.addStderr(utf8.encode('test 0: finished with out-of-'));
      diagnostics.addStderr(utf8.encode('band failure $canary\n'));
      diagnostics.addStdout(
        utf8.encode('test 0: ensuring test device is terminated.\n'),
      );
      diagnostics.addStderr(
        utf8.encode('Exception: NativeTestFailure $canary\r'),
      );
      diagnostics.addStderr(utf8.encode('\n'));
      final receipt = diagnostics.toJson();
      expect(receipt.keys.toSet(), {
        'launcherElapsedMillis',
        'testTimeoutMarkerSeen',
        'outOfBandFailureMarkerSeen',
        'cleanupMarkerSeen',
        'nativeTestFailureMarkerSeen',
      });
      expect(receipt['launcherElapsedMillis'], isNonNegative);
      expect(receipt['testTimeoutMarkerSeen'], isTrue);
      expect(receipt['outOfBandFailureMarkerSeen'], isTrue);
      expect(receipt['cleanupMarkerSeen'], isTrue);
      expect(receipt['nativeTestFailureMarkerSeen'], isTrue);
      expect(jsonEncode(receipt).contains(canary), isFalse);
      expect(diagnostics.bufferedCharacters, 0);
    },
  );

  test(
    'launcher diagnostics bound lines and keep stdout and stderr separate',
    () {
      final diagnostics = NativeTestLauncherDiagnostics();
      diagnostics.addStdout(utf8.encode('Test timed '));
      diagnostics.addStderr(utf8.encode('out after 25 minutes.\n'));
      diagnostics.addStdout(utf8.encode('\n'));
      diagnostics.addStdout(
        utf8.encode('Test timed out after ${'x' * 100000}$canary'),
      );
      diagnostics.addStderr(
        utf8.encode('ensuring test device is terminated${'x' * 100000}$canary'),
      );
      expect(diagnostics.bufferedCharacters, lessThanOrEqualTo(8192));
      diagnostics.addStdout(utf8.encode('\n'));
      diagnostics.addStderr(utf8.encode('\r\n'));
      diagnostics.addStdout(utf8.encode('Connection closed $canary\n'));
      final receipt = diagnostics.toJson();
      expect(receipt.remove('launcherElapsedMillis'), isNonNegative);
      expect(receipt, {
        'testTimeoutMarkerSeen': false,
        'outOfBandFailureMarkerSeen': false,
        'cleanupMarkerSeen': false,
        'nativeTestFailureMarkerSeen': false,
      });
      expect(diagnostics.bufferedCharacters, 0);
      expect(jsonEncode(diagnostics.toJson()).contains(canary), isFalse);
      diagnostics.addStderr(utf8.encode('Test timed out after 25 minutes.\n'));
      expect(diagnostics.toJson()['testTimeoutMarkerSeen'], isTrue);
    },
  );

  test('launcher diagnostics classify bounded unterminated lines at EOF', () {
    final diagnostics = NativeTestLauncherDiagnostics();
    diagnostics.addStdout(
      utf8.encode('${'x' * 5000}NativeTestFailure $canary'),
    );
    diagnostics.addStderr(
      utf8.encode('Test timed out after 25 minutes. $canary'),
    );
    diagnostics.finishStdout();
    diagnostics.finishStderr();
    final receipt = diagnostics.toJson();
    expect(receipt['testTimeoutMarkerSeen'], isTrue);
    expect(receipt['nativeTestFailureMarkerSeen'], isFalse);
    expect(receipt['cleanupMarkerSeen'], isFalse);
    expect(receipt['outOfBandFailureMarkerSeen'], isFalse);
    expect(diagnostics.bufferedCharacters, 0);
    expect(jsonEncode(receipt).contains(canary), isFalse);
  });

  test(
    'asynchronous output failures become fixed exit status without raw errors',
    () async {
      final savedExit = exitCode;
      try {
        await nativeTestHostOutputDone(Future<void>.error(StateError(canary)));
        expect(exitCode, 1);
      } finally {
        exitCode = savedExit;
      }
    },
  );
  test('unsupported runs and platforms never construct launcher state', () {
    for (final candidate in ['arbitrary', canary]) {
      expect(
        () => NativeTestHost(
          transport: FakeTransport(),
          run: candidate,
          platform: 'windows',
        ),
        throwsA(isA<NativeTestHostFailure>()),
      );
    }
    expect(
      () => NativeTestHost(
        transport: FakeTransport(),
        run: run,
        platform: 'linux',
      ),
      throwsA(isA<NativeTestHostFailure>()),
    );
  });

  test('discovery requires exactly one matching actual VM isolate', () async {
    final f = Fixture();
    expect(await f.host.discover(), isTrue);
    expect(f.transport.calls, ['getVM', 'getIsolate']);
    final output = await f.host.handleLine('{"operation":"info"}');
    expect(output, {
      'outcome': 'info',
      'isolateId': 'isolates/123',
      'value': f.transport.infoValue,
    });
    f.transport.isolates.add('isolates/124');
    await expectLater(f.host.discover(), throwsA(isA<NativeTestHostFailure>()));
  });

  test('discovery skips workers without registered extensions', () async {
    for (final includeNull in [false, true]) {
      final f = Fixture();
      f.transport.isolates.insert(0, 'isolates/125');
      f.transport.isolateReplies['isolates/125'] = {
        'id': 'isolates/125',
        if (includeNull) 'extensionRPCs': null,
      };
      expect(await f.host.discover(), isTrue);
      expect(
        (await f.host.handleLine('{"operation":"info"}'))['isolateId'],
        'isolates/123',
      );
    }
  });

  test('collected isolate permits main match and later rediscovery', () async {
    final f = Fixture();
    f.transport.isolateReplies['isolates/123'] = {
      'type': 'Sentinel',
      'kind': 'Collected',
    };
    expect(await f.host.discover(), isFalse);
    f.transport.isolates.add('isolates/126');
    expect(await f.host.discover(), isTrue);
    expect(
      (await f.host.handleLine('{"operation":"info"}'))['isolateId'],
      'isolates/126',
    );
  });

  test('worker extension types and isolate identity remain strict', () async {
    for (final reply in <Object>[
      {'id': 'isolates/125', 'extensionRPCs': canary},
      {
        'id': 'isolates/125',
        'extensionRPCs': [1],
      },
      {'id': 'isolates/999'},
      {'type': 'Sentinel', 'kind': 'Expired'},
    ]) {
      final f = Fixture();
      f.transport.isolates.insert(0, 'isolates/125');
      f.transport.isolateReplies['isolates/125'] = reply;
      await expectLater(
        f.host.discover(),
        throwsA(isA<NativeTestHostFailure>()),
      );
    }
  });

  test('missing isolate is notReady and identity changes reject', () async {
    final f = Fixture();
    f.transport.isolates.clear();
    expect(await f.host.discover(), isFalse);
    expect(await f.host.handleLine('{"operation":"info"}'), {
      'outcome': 'failed',
      'category': 'notReady',
    });
    f.transport.isolates.add('isolates/123');
    expect(await f.host.discover(), isTrue);
    f.transport.isolates[0] = 'isolates/124';
    await expectLater(f.host.discover(), throwsA(isA<NativeTestHostFailure>()));
  });

  test(
    'only exact info configure command operations can call transport',
    () async {
      final f = Fixture();
      await f.ready();
      for (final input in [
        '{"operation":"evaluate","expression":"$canary"}',
        '{"operation":"info","vmMethod":"getObject"}',
        '{"operation":"command","shell":"$canary"}',
        jsonEncode(canary),
        'x' * 65537,
      ]) {
        final output = await f.host.handleLine(input);
        expect(output['outcome'], 'failed');
        expect(jsonEncode(output).contains(canary), isFalse);
        expect(f.transport.calls, isEmpty);
      }
    },
  );

  test('configure checks fixed native identity and occurs only once', () async {
    final f = Fixture();
    await f.ready();
    final output = await f.host.handleLine(
      jsonEncode({'operation': 'configure', 'session': f.session.toJson()}),
    );
    expect(output, {'outcome': 'failed', 'category': 'alreadyConfigured'});
    expect(f.transport.calls, isEmpty);
    final other = Fixture();
    await other.host.discover();
    expect(
      await other.host.handleLine(
        jsonEncode({
          'operation': 'configure',
          'session': {...other.session.toJson(), 'peerId': 'other-device'},
        }),
      ),
      {'outcome': 'failed', 'category': 'identityMismatch'},
    );
    expect(other.transport.calls.contains('configure'), isFalse);
  });

  test(
    'concurrent host requests cannot duplicate a configure or RPC',
    () async {
      final f = Fixture();
      await f.host.discover();
      final source = jsonEncode({
        'operation': 'configure',
        'session': f.session.toJson(),
      });
      final first = f.host.handleLine(source);
      expect(await f.host.handleLine(source), {
        'outcome': 'failed',
        'category': 'busy',
      });
      expect((await first)['outcome'], 'configure');
      expect(
        f.transport.calls.where((method) => method == 'configure').length,
        1,
      );
    },
  );

  test('lost configure response cannot cause second configuration', () async {
    final f = Fixture();
    await f.host.discover();
    f.transport.failConfigure = true;
    final source = jsonEncode({
      'operation': 'configure',
      'session': f.session.toJson(),
    });
    final output = await f.host.handleLine(source);
    expect(output['outcome'], 'failed');
    expect(jsonEncode(output).contains(canary), isFalse);
    expect(await f.host.handleLine(source), {
      'outcome': 'failed',
      'category': 'alreadyConfigured',
    });
    expect(
      f.transport.calls.where((method) => method == 'configure').length,
      1,
    );
  });

  test(
    'command cannot run before configuration or after PID changes',
    () async {
      final f = Fixture();
      await f.host.discover();
      expect(await f.host.handleLine(f.request()), {
        'outcome': 'failed',
        'category': 'notConfigured',
      });
      await f.ready();
      f.transport.infoOverride = {...f.transport.infoValue, 'appPid': 101};
      expect(await f.host.handleLine(f.request()), {
        'outcome': 'failed',
        'category': 'identityMismatch',
      });
      expect(f.transport.calls, ['info']);
    },
  );

  test('valid command UNKNOWN retains inflight and possible effect', () async {
    final f = Fixture();
    await f.ready();
    f.transport.reply = {
      'version': 1,
      'sequence': 1,
      'state': 'unknown',
      'outcome': 'UNKNOWN',
      'inflight': true,
      'effect': 'possible',
    };
    expect(await f.host.handleLine(f.request()), {
      'outcome': 'command',
      'value': f.transport.reply,
    });
    expect(f.transport.calls, ['info', 'command']);
  });

  test(
    'malformed reply schemas and supplied errors cannot leave host',
    () async {
      final f = Fixture();
      await f.ready();
      final accepted = <String, Object>{
        'version': 1,
        'sequence': 1,
        'state': 'accepted',
        'outcome': 'pending',
        'inflight': false,
        'effect': 'none',
      };
      for (final malformed in [
        canary,
        {'error': canary},
        {...accepted, 'rawError': canary},
        {...accepted, 'outcome': canary},
        {...accepted, 'state': canary},
        {...accepted, 'sequence': 2},
        {...accepted, 'inflight': true},
        {...accepted, 'result': canary},
        {...accepted, 'effect': canary},
      ]) {
        f.transport.reply = malformed;
        final output = await f.host.handleLine(f.request());
        expect(output['outcome'], 'failed');
        expect(jsonEncode(output).contains(canary), isFalse);
      }
    },
  );

  test(
    'info canaries unknown fields and raw transport errors never emerge',
    () async {
      final f = Fixture();
      await f.host.discover();
      for (final field in [
        'phase',
        'deviceId',
        'peerId',
        'appPid',
        'elapsedMillis',
        'configured',
        'sameNearbyState',
        'codePresent',
        'rawDump',
      ]) {
        f.transport.infoOverride = {...f.transport.infoValue, field: canary};
        final output = await f.host.handleLine('{"operation":"info"}');
        expect(output['outcome'], 'failed');
        expect(jsonEncode(output).contains(canary), isFalse);
      }
      f.transport.failInfo = true;
      expect(
        jsonEncode(await f.host.handleLine('{"operation":"info"}'))
            .contains(canary),
        isFalse,
      );
    },
  );

  test(
    'typed encrypted observation remains ciphertext with exact challenge',
    () async {
      final f = Fixture();
      await f.ready();
      final comparison = ComparisonChallenge(
        epoch: f.session.epoch,
        leg: 1,
        comparisonId: 1,
        challenge: base64Url.encode(List.filled(32, 3)),
      );
      final observation = {
        'epoch': f.session.epoch,
        'run': run,
        'role': 'receiver',
        'deviceId': f.host.deviceId,
        'peerId': f.host.peerId,
        'phase': 'pairing',
        'sameNearbyState': true,
        'discovered': true,
        'codePresent': true,
        'sealedObservation': sealedObservation(f, comparison),
      };
      f.transport.reply = f.result({
        'outcome': 'success',
        'effect': 'none',
        'observation': observation,
      });
      final output = await f.host.handleLine(
        f.request(action: NativeTestAction.observe, comparison: comparison),
      );
      expect(output['outcome'], 'command');
      expect(jsonEncode(output).contains(canary), isFalse);
      final wrong = ComparisonChallenge(
        epoch: f.session.epoch,
        leg: 1,
        comparisonId: 2,
        challenge: comparison.challenge,
      );
      expect(
        (await f.host.handleLine(
          f.request(action: NativeTestAction.observe, comparison: wrong),
        ))['outcome'],
        'failed',
      );
    },
  );

  test(
    'actual snapshot reply requires encrypted proof and strict summary',
    () async {
      final f = Fixture();
      await f.ready();
      final snapshot = <String, Object>{
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
        'sealedProof': sealedSnapshot(f),
        'lastNearbySourceId': f.host.peerId,
        'lastNearbyAtMillis': 500,
      };
      f.transport.reply = f.result({
        'outcome': 'success',
        'effect': 'none',
        'snapshot': snapshot,
      });
      final output = await f.host.handleLine(
        f.request(action: NativeTestAction.snapshot),
      );
      expect(output['outcome'], 'command');
      expect(jsonEncode(output).contains(canary), isFalse);
      snapshot['pinDigest'] = canary;
      expect(
        (await f.host.handleLine(
          f.request(action: NativeTestAction.snapshot),
        ))['outcome'],
        'failed',
      );
      snapshot.remove('pinDigest');
      snapshot.remove('sealedProof');
      expect(
        (await f.host.handleLine(
          f.request(action: NativeTestAction.snapshot),
        ))['outcome'],
        'failed',
      );
    },
  );

  test('banner scanner bounds private raw memory and accepts only loopback banners', () {
    final scanner = NativeTestVmBannerScanner();
    scanner.add(utf8.encode('ordinary failure $canary\n'));
    expect(scanner.privateUri, isNull);
    scanner.add(
      utf8.encode(
        'The Dart VM service is listening on http://192.168.1.1:9999/AUTH=/\n',
      ),
    );
    expect(scanner.privateUri, isNull);
    scanner.add(utf8.encode('x' * 100000));
    expect(scanner.bufferedCharacters, lessThanOrEqualTo(4096));
    scanner.add(
      utf8.encode(
        '\nThe Dart VM service is listening on http://127.0.0.1:9999/',
      ),
    );
    scanner.add(utf8.encode('AUTH_CANARY=/\n'));
    expect(scanner.privateUri?.host, '127.0.0.1');
    expect(scanner.privateUri?.port, 9999);
    expect(scanner.bufferedCharacters, 0);
    expect(scanner.toString().contains('AUTH_CANARY'), isFalse);
  });

  test(
    'stdin scanner bounds oversized and unterminated input without exposing it',
    () async {
      final source = Stream<List<int>>.fromIterable([
        utf8.encode('x' * 100000),
        utf8.encode('\n{"operation":"info"}\n'),
        utf8.encode(canary),
      ]);
      expect(await nativeTestHostInputLines(source).toList(), [
        null,
        '{"operation":"info"}',
        null,
      ]);
    },
  );

  test('desktop VM trace stays bounded and accepts a split trusted banner', () {
    const token = 'SYNTHETIC_AUTH_TOKEN=';
    final scanner = NativeTestVmBannerScanner();
    for (final line in [
      'unrelated http://127.0.0.1:12345/$token/',
      'VM Service URL on device: http://192.0.2.1:12345/$token/',
      'VM Service URL on device: http://127.0.0.1:0/$token/',
      'VM Service URL on device: http://127.0.0.1:65536/$token/',
      'VM Service URL on device: http://127.0.0.1:12345/',
    ]) {
      scanner.add(utf8.encode('$line\n'));
      expect(scanner.privateUri, isNull);
    }
    scanner.add(utf8.encode('VM Service URL on device: ${'x' * 5000}'));
    expect(scanner.bufferedCharacters, lessThanOrEqualTo(4096));
    scanner.add(utf8.encode('\n'));
    expect(scanner.privateUri, isNull);
    for (final chunk in [
      '[ +27 ms] VM Serv',
      'ice URL on dev',
      'ice: http://127.0.',
      '0.1:12345/SYNTHETIC_',
      'AUTH_TOKEN=/\r',
      '\n',
    ]) {
      scanner.add(utf8.encode(chunk));
    }
    expect(scanner.privateUri?.host, '127.0.0.1');
    expect(scanner.privateUri?.port, 12345);
    expect(scanner.privateUri?.path, '/$token/');
    expect(scanner.bufferedCharacters, 0);
    expect(scanner.toString().contains(token), isFalse);
  });

  test('VM response boundary accepts only the matching response', () {
    final response = jsonEncode({
      'jsonrpc': '2.0',
      'id': 1,
      'result': {'type': 'VM'},
    });
    expect(
      nativeTestVmResult(
        response,
        method: NativeTestVmMethod.getVM,
        expectedId: 1,
      ).value,
      {'type': 'VM'},
    );
    expect(
      () => nativeTestVmResult(
        response,
        method: NativeTestVmMethod.getVM,
        expectedId: 2,
      ),
      throwsA(
        isA<NativeTestHostFailure>().having(
          (failure) => failure.diagnostic?.reason,
          'reason',
          NativeTestVmFailureReason.invalidEnvelope,
        ),
      ),
    );
  });

  test('VM failure diagnostics expose only fixed metadata', () {
    final cases = <(Object, NativeTestVmFailureReason)>[
      (canary, NativeTestVmFailureReason.invalidEnvelope),
      (
        jsonEncode({
          'jsonrpc': '2.0',
          'id': 1,
          'error': {'message': canary, 'data': canary},
        }),
        NativeTestVmFailureReason.rpcError,
      ),
      (
        jsonEncode({
          'jsonrpc': '2.0',
          'method': 'streamNotify',
          'params': {'event': canary},
        }),
        NativeTestVmFailureReason.invalidEnvelope,
      ),
    ];
    for (final (message, reason) in cases) {
      NativeTestHostFailure? failure;
      try {
        nativeTestVmResult(
          message,
          method: NativeTestVmMethod.getIsolate,
          expectedId: 1,
        );
      } on NativeTestHostFailure catch (caught) {
        failure = caught;
      }
      expect(failure, isNotNull);
      expect(failure!.toJson(), {
        'outcome': 'failed',
        'category': 'disconnected',
        'diagnostic': {
          'reason': reason.name,
          'method': 'getIsolate',
          'byteCount': utf8.encode(message as String).length,
        },
      });
      expect(jsonEncode(failure.toJson()).contains(canary), isFalse);
      expect(failure.toString(), 'NativeTestHostFailure');
    }
  });

  test('oversized VM text reports only boundedly measured byte counts', () {
    final cases = <(String, int?)>[
      ('$canary${'x' * 65536}', null),
      ('é' * 65537, null),
      ('é' * 32769, 65538),
    ];
    for (final (message, expectedBytes) in cases) {
      NativeTestHostFailure? failure;
      try {
        nativeTestVmResult(
          message,
          method: NativeTestVmMethod.info,
          expectedId: 1,
        );
      } on NativeTestHostFailure catch (caught) {
        failure = caught;
      }
      expect(failure, isNotNull);
      expect(failure!.toJson(), {
        'outcome': 'failed',
        'category': 'disconnected',
        'diagnostic': {
          'reason': 'frameTooLarge',
          'method': 'ext.wired_parts.nearbyTest.info',
          'byteCount': expectedBytes,
        },
      });
      expect(jsonEncode(failure.toJson()).contains(canary), isFalse);
    }
  });

  test('large discovery metadata has a separate measured frame limit', () {
    final payload = {'type': 'Isolate', 'padding': 'x' * 70000};
    final response = jsonEncode({'jsonrpc': '2.0', 'id': 1, 'result': payload});
    final expectedBytes = utf8.encode(response).length;
    expect(expectedBytes, greaterThan(65536));
    expect(expectedBytes, lessThan(1048576));
    for (final method in [
      NativeTestVmMethod.getVM,
      NativeTestVmMethod.getIsolate,
    ]) {
      final result = nativeTestVmResult(
        response,
        method: method,
        expectedId: 1,
      );
      expect(result.value, payload);
      expect(result.byteCount, expectedBytes);
    }
    for (final method in [
      NativeTestVmMethod.info,
      NativeTestVmMethod.configure,
      NativeTestVmMethod.command,
    ]) {
      expect(
        () => nativeTestVmResult(response, method: method, expectedId: 1),
        throwsA(
          isA<NativeTestHostFailure>()
              .having(
                (failure) => failure.diagnostic?.reason,
                'reason',
                NativeTestVmFailureReason.frameTooLarge,
              )
              .having(
                (failure) => failure.diagnostic?.byteCount,
                'byteCount',
                isNull,
              ),
        ),
      );
    }
  });

  test('discovery metadata retains early and UTF8 byte bounds', () {
    final cases = <(String, int?)>[
      ('x' * 1048577, null),
      ('é' * 1048577, null),
      ('é' * 524289, 1048578),
    ];
    for (final method in [
      NativeTestVmMethod.getVM,
      NativeTestVmMethod.getIsolate,
    ]) {
      for (final (message, expectedBytes) in cases) {
        expect(
          () => nativeTestVmResult(message, method: method, expectedId: 1),
          throwsA(
            isA<NativeTestHostFailure>()
                .having(
                  (failure) => failure.diagnostic?.reason,
                  'reason',
                  NativeTestVmFailureReason.frameTooLarge,
                )
                .having(
                  (failure) => failure.diagnostic?.byteCount,
                  'byteCount',
                  expectedBytes,
                ),
          ),
        );
      }
    }
  });
}

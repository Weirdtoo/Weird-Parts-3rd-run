import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';
import 'package:wired_parts/features/nearby/nearby_protocol.dart';

import 'company_join_test.dart'
    show
        JoinFixture,
        activateFixtureB,
        joinChannels,
        sqlSnapshot,
        expectJoinProtectedUnchanged,
        canonicalJoinTest,
        advanceJoinFloor;

Future<CompanyJobSyncAvailability> receiverAvailability(
  JoinFixture f,
  OwnerSession owner,
) async {
  final (bc, ac) = await joinChannels();
  final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
  final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
  final first = await aa.beginPeerChallenge(
    ac,
    (await aa.retainedPeers(session: f.owner)).single,
    session: f.owner,
  );
  final response = await ba.receivePeerChallenge(bc, first, session: owner);
  final complete = await aa.receivePeerResponse(ac, response);
  final result = await ba.receivePeerCompletion(bc, complete);
  await aa.receivePeerAcknowledgment(ac, result.acknowledgment);
  return CompanyJobSyncAvailability.open(
    enrollment: f.bEnrollment,
    owner: owner,
    peer: result.membership,
  );
}

Future<
  ({CompanyCreatedJobSync a, CompanyCreatedJobSync b, OwnerSession ownerB})
>
openSyncPair(
  JoinFixture f, {
  CompanyEnrollment? peerEnrollment,
  int chunkBytes = kCreatedJobSyncChunkBytes,
  void Function(String)? onAStatus,
  void Function(String)? onBStatus,
  void Function(CreatedJobSyncDiagnostic)? onADiagnostic,
  void Function(CreatedJobSyncDiagnostic)? onBDiagnostic,
}) async {
  final peer = peerEnrollment ?? f.bEnrollment;
  final bo = peer.currentSession ?? await peer.signIn('1234');
  late NearbyController ac, bc;
  final (bChannel, aChannel) = await joinChannels(
    onPaired: (b, a) {
      bc = b;
      ac = a;
    },
  );
  final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
  final ba = CompanyPeerAuthentication(enrollment: peer);
  final first = await aa.beginPeerChallenge(
    aChannel,
    (await aa.retainedPeers(session: f.owner))
        .firstWhere((p) => p.deviceId == bo.identity.deviceId),
    session: f.owner,
  );
  final response = await ba.receivePeerChallenge(bChannel, first, session: bo);
  final complete = await aa.receivePeerResponse(aChannel, response);
  final done = await ba.receivePeerCompletion(bChannel, complete);
  final aPeer = await aa.receivePeerAcknowledgment(
    aChannel,
    done.acknowledgment,
  );
  final a = CompanyCreatedJobSync(
    availability: await CompanyJobSyncAvailability.open(
      enrollment: f.aEnrollment,
      owner: f.owner,
      peer: aPeer,
    ),
    controller: ac,
    onStatus: onAStatus,
    onDiagnostic: onADiagnostic,
    chunkBytes: chunkBytes,
  );
  final b = CompanyCreatedJobSync(
    availability: await CompanyJobSyncAvailability.open(
      enrollment: peer,
      owner: bo,
      peer: done.membership,
    ),
    controller: bc,
    onStatus: onBStatus,
    onDiagnostic: onBDiagnostic,
    chunkBytes: chunkBytes,
  );
  ac.onJoinMessage = (_, wire) => a.receive(wire);
  bc.onJoinMessage = (_, wire) => b.receive(wire);
  return (a: a, b: b, ownerB: bo);
}

Future<Map<String, Object?>> syncAttackWire(
  NearbyPairedJoinSession pair,
  String recipient,
  String run,
  String action,
  Object? data, [
  String protocol = 'company.job.sync@7',
]) async {
  final keys = pair.keys;
  final kdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final join = await kdf.deriveKey(
    secretKey: keys.sendKey,
    nonce: utf8.encode(keys.id),
    info: utf8.encode('wiredpart-v2/company-join@1/${keys.sendDirection}'),
  );
  final sync = await kdf.deriveKey(
    secretKey: join,
    nonce: utf8.encode(keys.id),
    info: utf8.encode(
      'wiredpart-v2/company-job-create-sync@1/${keys.sendDirection}',
    ),
  );
  final recipientTag = await Hmac.sha256().calculateMac(
    utf8.encode('wiredpart.company.join.recipient@1:${keys.id}:$recipient'),
    secretKey: sync,
  );
  final header = <String, Object?>{
    'v': 1,
    'kind': 'created-jobs',
    'request': const Uuid().v4(),
    'recipient': base64Encode(recipientTag.bytes),
    'session': keys.id,
    'direction': keys.sendDirection,
  };
  final body = {
    'v': 1,
    'protocol': protocol,
    'remaining': pair.remainingReceivedNonces,
    'action': action,
    'run': run,
    'data': data,
  };
  final box = await AesGcm.with256bits().encrypt(
    utf8.encode(canonicalJoinTest(body)),
    secretKey: sync,
    aad: utf8.encode(canonicalJoinTest(header)),
  );
  return {
    ...header,
    'nonce': base64Encode(box.nonce),
    'ciphertext': base64Encode(box.cipherText),
    'tag': base64Encode(box.mac.bytes),
  };
}

Future<void> admitAttackRun(
  ({CompanyCreatedJobSync a, CompanyCreatedJobSync b, OwnerSession ownerB})
  pair,
  String run,
) async {
  final source = pair.a.availability;
  final recipient = base64Encode(
    pair.b.availability.enrollment.installation.identity!.publicKey,
  );
  final users =
      (await source.enrollment.listCompanyUsers())
          .skip(1)
          .map((user) => user.userId)
          .toList()
        ..sort();
  for (final step in <(String, Map<String, Object?>)>[
    (
      'profile',
      {
        'profile': '$kCompanyUserProfile/job.create.authorization@4',
        'capacity': kCompanyUserCapacity,
        'users': users,
      },
    ),
    for (final userId in users) ...[
      (
        'policyOffer',
        {
          'offer': await source.enrollment.createUserLifecycleOffer(
            source.peer,
            userId: userId,
          ),
        },
      ),
      ('policy', {'policy': null}),
      ('policyAck', {'receipt': null}),
    ],
  ]) {
    await pair.b.receive(
      await syncAttackWire(
        pair.a.controller.pairedJoinSession!,
        recipient,
        run,
        step.$1,
        step.$2,
      ),
    );
  }
}

void main() {
  test('collection capability and complete per-user policy gate inventory without mutation', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final first = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'First',
      pin: '0123',
    );
    final second = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Second',
      pin: '4567',
    );
    final pair = await openSyncPair(f);
    final users = [first.userId, second.userId]..sort();
    final before = Map.of(f.bStore.states);
    final sql = await sqlSnapshot(f.bDb);
    final recipient = base64Encode(f.b.identity!.publicKey);
    for (final bad in [
      {'profile': 'company.user.state@1/job.create.authorization@4'},
      {
        'profile': '$kCompanyUserProfile/job.create.authorization@4',
        'capacity': 1,
        'users': users,
      },
      {
        'profile': '$kCompanyUserProfile/job.create.authorization@4',
        'capacity': 2.0,
        'users': users,
      },
      {
        'profile': '$kCompanyUserProfile/job.create.authorization@4',
        'capacity': kCompanyUserCapacity,
        'users': [first.userId, first.userId],
      },
      {
        'profile': '$kCompanyUserProfile/job.create.authorization@4',
        'capacity': kCompanyUserCapacity,
        'users': users.reversed.toList(),
      },
    ]) {
      await expectLater(
        pair.b.receive(
          await syncAttackWire(
            pair.a.controller.pairedJoinSession!,
            recipient,
            const Uuid().v4(),
            'profile',
            bad,
          ),
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.bStore, before);
      expect(await sqlSnapshot(f.bDb), sql);
    }
    final run = const Uuid().v4();
    for (final step in <(String, Map<String, Object?>)>[
      (
        'profile',
        {
          'profile': '$kCompanyUserProfile/job.create.authorization@4',
          'capacity': kCompanyUserCapacity,
          'users': users,
        },
      ),
      (
        'policyOffer',
        {
          'offer': await f.aEnrollment.createUserLifecycleOffer(
            pair.a.availability.peer,
            userId: first.userId,
          ),
        },
      ),
      ('policy', {'policy': null}),
      ('policyAck', {'receipt': null}),
    ]) {
      await pair.b.receive(
        await syncAttackWire(
          pair.a.controller.pairedJoinSession!,
          recipient,
          run,
          step.$1,
          step.$2,
        ),
      );
    }
    await expectLater(
      pair.b.receive(
        await syncAttackWire(
          pair.a.controller.pairedJoinSession!,
          recipient,
          run,
          'start',
          {},
        ),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.bStore, before);
    expect(await sqlSnapshot(f.bDb), sql);
    // A peer's advertised absence cannot omit either locally known account.
    final omittedRun = const Uuid().v4();
    final source = pair.b.controller.pairedJoinSession!;
    final aRecipient = base64Encode(f.a.identity!.publicKey);
    final aBefore = Map.of(f.aStore.states);
    await pair.a.receive(
      await syncAttackWire(source, aRecipient, omittedRun, 'profile', {
        'profile': '$kCompanyUserProfile/job.create.authorization@4',
        'capacity': kCompanyUserCapacity,
        'users': <String>[],
      }),
    );
    await expectLater(
      pair.a.receive(
        await syncAttackWire(source, aRecipient, omittedRun, 'start', {}),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.aStore, aBefore);
  });

  test('creation confirmation survives a pending owner edit while whole-Job confirmation waits', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final pair = await openSyncPair(f);
    expect((await pair.a.syncNow()).complete, isTrue);
    final commands = CompanyJobCommands(enrollment: f.aEnrollment);
    final view = (await commands.listJobViews(ownerSession: f.owner)).single;
    await commands.renameJob(
      RenameJob(
        companyId: f.owner.identity.companyId,
        shopId: f.owner.identity.shopId,
        jobId: view.baseJob.id,
        requestId: const Uuid().v4(),
        creationDigest: view.creationDigest,
        observedHeads: view.nameHeads,
        observedLifecycleHeads: view.lifecycle.lifecycleHeads,
        name: 'Pending owner edit',
      ),
      ownerSession: f.owner,
    );
    expect(
      (await CompanyCreatedJobSync.confirmedPeerCounts(
        f.aEnrollment,
        f.owner,
      ))[view.baseJob.id],
      0,
    );
    expect(
      (await CompanyCreatedJobSync.confirmedPeerCounts(
        f.aEnrollment,
        f.owner,
        creationOnly: true,
      ))[view.baseJob.id],
      1,
    );
  }, timeout: const Timeout(Duration(minutes: 2)));
  for (final foreign in [false, true]) {
    final label = foreign ? 'foreign' : 'owned';
    test(
      'malformed data for $label run preserves only the rightful owner',
      () async {
        final f = await JoinFixture.create(allowOwnerAdditions: true);
        await activateFixtureB(f);
        final statuses = <String>[];
        final diagnostics = <CreatedJobSyncDiagnostic>[];
        final pair = await openSyncPair(
          f,
          onBStatus: statuses.add,
          onBDiagnostic: diagnostics.add,
        );
        final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
        final inventory = CreatedJobHoldingsInventory.local([source]);
        final bytes = utf8.encode(source.operationBytes);
        final descriptor = inventory.descriptors.single;
        final run = const Uuid().v4();
        Future<Map<String, Object?>> send(
          String id,
          String action,
          Object? data,
        ) async => pair.b.receive(
          await syncAttackWire(
            pair.a.controller.pairedJoinSession!,
            base64Encode(f.b.identity!.publicKey),
            id,
            action,
            data,
          ),
        );
        await admitAttackRun(pair, run);
        await send(run, 'start', {
          'inventory': inventory.meta,
          'store': f.a.receivingStoreGeneration!.value,
        });
        await send(run, 'holdings', {
          'ordinal': 0,
          'digest': inventory.digest,
          'items': inventory.page(0),
          'confirmedStores': [null],
        });
        await send(run, 'put', {
          'descriptor': descriptor,
          'offset': 0,
          'bytes': base64Encode(bytes.sublist(0, 1)),
        });
        final before = await sqlSnapshot(f.bDb);
        final protected = Map.of(f.bStore.states);
        final status = statuses.last;
        final eventCount = diagnostics.length;
        await expectLater(
          send(foreign ? const Uuid().v4() : run, 'put', []),
          throwsA(anything),
        );
        expect(await sqlSnapshot(f.bDb), before);
        expectJoinProtectedUnchanged(f.bStore, protected);
        final remaining = {
          'descriptor': descriptor,
          'offset': 1,
          'bytes': base64Encode(bytes.sublist(1)),
        };
        if (foreign) {
          expect(statuses.last, status);
          expect(diagnostics, hasLength(eventCount));
          await send(run, 'put', remaining);
          expect(
            (await f.bDb.select(f.bDb.companyJobs).get()).single.operationBytes,
            source.operationBytes,
          );
          await send(run, 'finish', {'complete': false, 'unsupported': 0});
        } else {
          await expectLater(send(run, 'put', remaining), throwsA(anything));
          expect(await sqlSnapshot(f.bDb), before);
          expectJoinProtectedUnchanged(f.bStore, protected);
        }
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }

  test('inbound start owns the run throughout inventory freeze', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final entered = Completer<void>();
    final release = Completer<void>();
    final pair = await openSyncPair(
      f,
      onBDiagnostic: (event) {
        if (event.kind == CreatedJobSyncDiagnosticKind.started) {
          f.bStore.beforeRead = (namespace) {
            if (namespace == f.b.namespace && !entered.isCompleted) {
              entered.complete();
              return release.future;
            }
            return null;
          };
        }
      },
    );
    final inventory = CreatedJobHoldingsInventory.local(
      await f.aDb.select(f.aDb.companyJobs).get(),
    );
    final run = const Uuid().v4();
    await admitAttackRun(pair, run);
    final wire = await syncAttackWire(
      pair.a.controller.pairedJoinSession!,
      base64Encode(f.b.identity!.publicKey),
      run,
      'start',
      {
        'inventory': inventory.meta,
        'store': f.a.receivingStoreGeneration!.value,
      },
    );
    Future<CreatedJobSyncResult>? competing;
    final receiving = pair.a.controller.exchangeCompanyMessage(
      wire,
      disclosure: pair.a.availability,
    );
    try {
      await entered.future;
      expect(() {
        competing = pair.b.syncNow();
      }, throwsA(isA<CompanyBootstrapRefusal>()));
      release.complete();
      await receiving;
      expect(pair.b.syncNow, throwsA(isA<CompanyBootstrapRefusal>()));
    } finally {
      f.bStore.beforeRead = null;
      final drains = Future.wait([
        pair.a.closeAndDrain(),
        pair.b.closeAndDrain(),
      ]);
      if (!release.isCompleted) release.complete();
      await receiving.catchError((Object _) => <String, Object?>{});
      await competing;
      await drains;
    }
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('second inbound start preserves the accepted run and status', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final statuses = <String>[];
    final pair = await openSyncPair(f, onBStatus: statuses.add);
    final inventory = CreatedJobHoldingsInventory.local(
      await f.aDb.select(f.aDb.companyJobs).get(),
    );
    final run = const Uuid().v4();
    Future<Map<String, Object?>> send(
      String id,
      String action,
      Map<String, Object?> data,
    ) async => pair.a.controller.exchangeCompanyMessage(
      await syncAttackWire(
        pair.a.controller.pairedJoinSession!,
        base64Encode(f.b.identity!.publicKey),
        id,
        action,
        data,
      ),
      disclosure: pair.a.availability,
    );
    final start = {
      'inventory': inventory.meta,
      'store': f.a.receivingStoreGeneration!.value,
    };
    await admitAttackRun(pair, run);
    await send(run, 'start', start);
    final before = await sqlSnapshot(f.bDb);
    final protected = Map.of(f.bStore.states);
    final status = statuses.last;
    await expectLater(
      send(const Uuid().v4(), 'start', start),
      throwsA(anything),
    );
    expect(statuses.last, status);
    await send(run, 'holdings', {
      'ordinal': 0,
      'digest': inventory.digest,
      'items': inventory.page(0),
      'confirmedStores': [null],
    });
    expect(await sqlSnapshot(f.bDb), before);
    expectJoinProtectedUnchanged(f.bStore, protected);
  }, timeout: const Timeout(Duration(minutes: 2)));

  for (final terminal in ['incomplete', 'unconfirmed', 'chunk failure']) {
    test(
      '$terminal retires partial transfer and rejects fresh late run frames',
      () async {
        final f = await JoinFixture.create(allowOwnerAdditions: true);
        await activateFixtureB(f);
        final statuses = <String>[];
        final diagnostics = <CreatedJobSyncDiagnostic>[];
        final pair = await openSyncPair(
          f,
          onBStatus: statuses.add,
          onBDiagnostic: diagnostics.add,
        );
        final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
        final bytes = utf8.encode(source.operationBytes);
        final inventory = CreatedJobHoldingsInventory.local([source]);
        final descriptor = inventory.descriptors.single;
        final run = const Uuid().v4();
        Future<Map<String, Object?>> send(
          String action,
          Map<String, Object?> data,
        ) async => pair.b.receive(
          await syncAttackWire(
            pair.a.controller.pairedJoinSession!,
            base64Encode(f.b.identity!.publicKey),
            run,
            action,
            data,
          ),
        );
        final start = {
          'inventory': inventory.meta,
          'store': f.a.receivingStoreGeneration!.value,
        };
        final holdings = {
          'ordinal': 0,
          'digest': inventory.digest,
          'items': inventory.page(0),
          'confirmedStores': [null],
        };
        await admitAttackRun(pair, run);
        await send('start', start);
        await send('holdings', holdings);
        await send('put', {
          'descriptor': descriptor,
          'offset': 0,
          'bytes': base64Encode(bytes.sublist(0, 1)),
        });
        final before = await sqlSnapshot(f.bDb);
        final protected = Map.of(f.bStore.states);
        if (terminal == 'incomplete') {
          await send('finish', {'complete': false, 'unsupported': 0});
        } else {
          await expectLater(
            terminal == 'unconfirmed'
                ? send('finish', {'complete': true, 'unsupported': 0})
                : send('put', {
                    'descriptor': descriptor,
                    'offset': 2,
                    'bytes': base64Encode(bytes.sublist(1)),
                  }),
            throwsA(anything),
          );
        }
        final status = statuses.last;
        final eventCount = diagnostics.length;
        for (final (action, data) in <(String, Map<String, Object?>)>[
          (
            'put',
            {
              'descriptor': descriptor,
              'offset': 1,
              'bytes': base64Encode(bytes.sublist(1)),
            },
          ),
          ('get', {'descriptor': descriptor, 'offset': 0, 'limit': 1024}),
          ('ackBoth', {'descriptor': descriptor, 'ack': {}}),
          ('page', {'ordinal': 0}),
          ('holdings', holdings),
          ('start', start),
        ]) {
          await expectLater(send(action, data), throwsA(anything));
          expect(
            pair.b.lastFailure.toString(),
            contains('Job sync run differs'),
            reason: action,
          );
          expect(await sqlSnapshot(f.bDb), before);
          expectJoinProtectedUnchanged(f.bStore, protected);
          expect(statuses.last, status);
          expect(diagnostics, hasLength(eventCount));
        }
        final fresh = await pair.a.syncNow();
        expect(fresh.complete, isTrue, reason: pair.a.lastFailure?.toString());
        final afterA = await sqlSnapshot(f.aDb);
        final afterB = await sqlSnapshot(f.bDb);
        final protectedA = Map.of(f.aStore.states);
        final protectedB = Map.of(f.bStore.states);
        final repeat = await pair.a.syncNow();
        expect(repeat.complete, isTrue, reason: pair.a.lastFailure?.toString());
        expect([repeat.sent, repeat.received], [0, 0]);
        expect(await sqlSnapshot(f.aDb), afterA);
        expect(await sqlSnapshot(f.bDb), afterB);
        expectJoinProtectedUnchanged(f.aStore, protectedA);
        expectJoinProtectedUnchanged(f.bStore, protectedB);
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }
  test(
    'simultaneous local starts settle before a fresh same-Pair sync',
    () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      await activateFixtureB(f);
      final pair = await openSyncPair(f);
      final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
      await Future.wait([pair.a.syncNow(), pair.b.syncNow()]);
      expect(pair.a.isRunning, isFalse);
      expect(pair.b.isRunning, isFalse);
      final fresh = await pair.a.syncNow();
      expect(fresh.complete, isTrue, reason: pair.a.lastFailure?.toString());
      for (final (commands, owner) in [
        (CompanyJobCommands(enrollment: f.aEnrollment), f.owner),
        (CompanyJobCommands(enrollment: f.bEnrollment), pair.ownerB),
      ]) {
        expect(
          (await commands.listJobs(ownerSession: owner)).map((job) => job.id),
          [source.jobId],
        );
      }
      final beforeA = await sqlSnapshot(f.aDb);
      final beforeB = await sqlSnapshot(f.bDb);
      final protectedA = Map.of(f.aStore.states);
      final protectedB = Map.of(f.bStore.states);
      final repeat = await pair.a.syncNow();
      expect(repeat.complete, isTrue, reason: pair.a.lastFailure?.toString());
      expect([repeat.sent, repeat.received], [0, 0]);
      expect(await sqlSnapshot(f.aDb), beforeA);
      expect(await sqlSnapshot(f.bDb), beforeB);
      expectJoinProtectedUnchanged(f.aStore, protectedA);
      expectJoinProtectedUnchanged(f.bStore, protectedB);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'completed run rejects fresh late actions and reuse of its terminal ID',
    () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      await activateFixtureB(f);
      final statuses = <String>[];
      final diagnostics = <CreatedJobSyncDiagnostic>[];
      final pair = await openSyncPair(
        f,
        onBStatus: statuses.add,
        onBDiagnostic: diagnostics.add,
      );
      final handling = pair.b.controller.onJoinMessage!;
      String? completedRun;
      pair.b.controller.onJoinMessage = (session, wire) async {
        if (completedRun == null) {
          final keys = pair.a.controller.pairedJoinSession!.keys;
          SecretKey key = keys.sendKey;
          for (final purpose in ['company-join', 'company-job-create-sync']) {
            key = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
              secretKey: key,
              nonce: utf8.encode(keys.id),
              info: utf8.encode(
                'wiredpart-v2/$purpose@1/${keys.sendDirection}',
              ),
            );
          }
          final header = {
            for (final field in [
              'v',
              'kind',
              'request',
              'recipient',
              'session',
              'direction',
            ])
              field: wire[field],
          };
          final bytes = await AesGcm.with256bits().decrypt(
            SecretBox(
              base64Decode(wire['ciphertext'] as String),
              nonce: base64Decode(wire['nonce'] as String),
              mac: Mac(base64Decode(wire['tag'] as String)),
            ),
            secretKey: key,
            aad: utf8.encode(canonicalJoinTest(header)),
          );
          completedRun =
              (jsonDecode(utf8.decode(bytes)) as Map)['run'] as String;
        }
        return handling(session, wire);
      };
      expect((await pair.a.syncNow()).complete, isTrue);
      final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
      final inventory = CreatedJobHoldingsInventory.local([source]);
      final before = await sqlSnapshot(f.bDb);
      final protected = Map.of(f.bStore.states);
      final status = statuses.last;
      final eventCount = diagnostics.length;
      for (final (action, data) in <(String, Map<String, Object?>)>[
        (
          'put',
          {
            'descriptor': inventory.descriptors.single,
            'offset': 0,
            'bytes': base64Encode(utf8.encode(source.operationBytes)),
          },
        ),
        (
          'get',
          {
            'descriptor': inventory.descriptors.single,
            'offset': 0,
            'limit': 1024,
          },
        ),
        ('ackBoth', {'descriptor': inventory.descriptors.single, 'ack': {}}),
        ('page', {'ordinal': 0}),
        (
          'start',
          {
            'inventory': inventory.meta,
            'store': f.a.receivingStoreGeneration!.value,
          },
        ),
      ]) {
        final wire = await syncAttackWire(
          pair.a.controller.pairedJoinSession!,
          base64Encode(f.b.identity!.publicKey),
          completedRun!,
          action,
          data,
        );
        await expectLater(pair.b.receive(wire), throwsA(anything));
        expect(
          pair.b.lastFailure.toString(),
          contains('Job sync run differs'),
          reason: action,
        );
        expect(await sqlSnapshot(f.bDb), before);
        expectJoinProtectedUnchanged(f.bStore, protected);
        expect(statuses.last, status);
        expect(diagnostics, hasLength(eventCount));
      }
      final repeat = await pair.a.syncNow();
      expect(repeat.complete, isTrue, reason: pair.a.lastFailure?.toString());
      expect([repeat.sent, repeat.received], [0, 0]);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'receiver channel opening and reply sealing have distinct failure stages',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final diagnostics = <CreatedJobSyncDiagnostic>[];
      late ({
        CompanyCreatedJobSync a,
        CompanyCreatedJobSync b,
        OwnerSession ownerB,
      })
      pair;
      pair = await openSyncPair(
        f,
        onBDiagnostic: diagnostics.add,
        onBStatus: (status) {
          if (status == 'Exchanging Job holdings with the verified peer.') {
            pair.b.availability.close();
          }
        },
      );
      final before = await sqlSnapshot(f.bDb);
      await expectLater(pair.b.receive({}), throwsA(anything));
      final opening = diagnostics.last.result!.failure!.stage.name;
      final inventory = CreatedJobHoldingsInventory.local(
        await f.aDb.select(f.aDb.companyJobs).get(),
      );
      final run = const Uuid().v4();
      await admitAttackRun(pair, run);
      final start = await syncAttackWire(
        pair.a.controller.pairedJoinSession!,
        base64Encode(f.b.identity!.publicKey),
        run,
        'start',
        {
          'inventory': inventory.meta,
          'store': f.a.receivingStoreGeneration!.value,
        },
      );
      await expectLater(pair.b.receive(start), throwsA(anything));
      final sealing = diagnostics.last.result!.failure!.stage.name;
      expect([opening, sealing], ['channelOpen', 'replySeal']);
      expect(await sqlSnapshot(f.bDb), before);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test(
    'same-Pair reproof invalidates earlier Job availability before Sync',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final ownerB = await f.bEnrollment.signIn('1234');
      late NearbyController a, b;
      final (bChannel, aChannel) = await joinChannels(
        onPaired: (bc, ac) {
          b = bc;
          a = ac;
        },
      );
      final aPair = a.pairedJoinSession;
      final bPair = b.pairedJoinSession;
      final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
      final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
      Future<({VerifiedPeerMembership a, VerifiedPeerMembership b})> verify(
        bool fromB,
      ) async {
        final initiator = fromB ? ba : aa;
        final responder = fromB ? aa : ba;
        final owner = fromB ? ownerB : f.owner;
        final peerOwner = fromB ? f.owner : ownerB;
        final channel = fromB ? bChannel : aChannel;
        final peerChannel = fromB ? aChannel : bChannel;
        final first = await initiator.beginPeerChallenge(
          channel,
          (await initiator.retainedPeers(session: owner)).single,
          session: owner,
        );
        final response = await responder.receivePeerChallenge(
          peerChannel,
          first,
          session: peerOwner,
        );
        final complete = await initiator.receivePeerResponse(channel, response);
        final done = await responder.receivePeerCompletion(
          peerChannel,
          complete,
        );
        final membership = await initiator.receivePeerAcknowledgment(
          channel,
          done.acknowledgment,
        );
        return fromB
            ? (a: done.membership, b: membership)
            : (a: membership, b: done.membership);
      }

      final first = await verify(true);
      final available = await CompanyJobSyncAvailability.open(
        enrollment: f.bEnrollment,
        owner: ownerB,
        peer: first.b,
      );
      final sync = CompanyCreatedJobSync(
        availability: available,
        controller: b,
      );
      addTearDown(sync.closeAndDrain);
      expect(sync.isLive, isTrue);
      final beforeA = await sqlSnapshot(f.aDb);
      final beforeB = await sqlSnapshot(f.bDb);
      final current = await verify(false);
      expect(a.pairedJoinSession, same(aPair));
      expect(b.pairedJoinSession, same(bPair));
      await expectLater(
        available.requireCurrent(),
        throwsA(
          isA<CompanyBootstrapRefusal>().having(
            (error) => error.message,
            'message',
            'Retained peer context changed',
          ),
        ),
      );
      expect(sync.isLive, isFalse);
      expect(available.requireLive, throwsA(isA<CompanyBootstrapRefusal>()));
      final refused = await sync.syncNow();
      expect(refused.complete, isFalse);
      expect(
        refused.message,
        contains('Stage preflight. Reason verificationChanged.'),
      );
      final fresh = await CompanyJobSyncAvailability.open(
        enrollment: f.bEnrollment,
        owner: ownerB,
        peer: current.b,
      );
      expect(fresh.requireLive, returnsNormally);
      fresh.close();
      expect(await sqlSnapshot(f.aDb), beforeA);
      expect(await sqlSnapshot(f.bDb), beforeB);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test(
    'Nearby rejection exposes a fixed reason without its arbitrary message',
    () {
      final result = CreatedJobSyncResult(
        0,
        0,
        false,
        0,
        failure: CreatedJobSyncFailure.fromError(
          const NearbyException('private /unsafe/key 192.0.2.1 secret-token'),
          CreatedJobSyncStage.startRequest,
        ),
      );
      expect(
        result.message,
        contains('Stage startRequest. Reason transportRejected.'),
      );
      expect(result.message, isNot(contains('private')));
      expect(result.message, isNot(contains('/unsafe/key')));
      expect(result.message, isNot(contains('192.0.2.1')));
      expect(result.message, isNot(contains('secret-token')));
    },
  );
  test(
    'closed availability explains an incomplete zero-count sync safely',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final statuses = <String>[];
      final diagnostics = <CreatedJobSyncDiagnostic>[];
      final pair = await openSyncPair(
        f,
        onAStatus: statuses.add,
        onADiagnostic: diagnostics.add,
      );
      pair.a.availability.close();
      final before = await sqlSnapshot(f.aDb);
      final result = await pair.a.syncNow();
      expect(result.complete, isFalse);
      expect(result.sent, 0);
      expect(result.received, 0);
      expect(result.message, contains('Stage preflight. Reason unavailable.'));
      expect(result.failure?.stage, CreatedJobSyncStage.preflight);
      expect(result.failure?.reason, CreatedJobSyncReason.unavailable);
      expect(statuses.last, result.message);
      expect(diagnostics.last.result, same(result));
      expect(await sqlSnapshot(f.aDb), before);
    },
  );
  for (final (error, reason) in <(Object, CreatedJobSyncReason)>[
    (
      const CompanyBootstrapRefusal('More Jobs pending; pair again'),
      CreatedJobSyncReason.moreJobsPending,
    ),
    (
      const CompanyBootstrapRefusal(
        'private /unsafe/key 192.0.2.1 secret-token',
      ),
      CreatedJobSyncReason.refused,
    ),
    (
      StateError('private /unsafe/key 192.0.2.1 secret-token'),
      CreatedJobSyncReason.unexpected,
    ),
    (
      const SocketException('private /unsafe/key 192.0.2.1 secret-token'),
      CreatedJobSyncReason.transportUnavailable,
    ),
    (
      TimeoutException('private /unsafe/key 192.0.2.1 secret-token'),
      CreatedJobSyncReason.timeout,
    ),
  ]) {
    test(
      'terminal ${reason.name} diagnostics exclude arbitrary exception data',
      () async {
        final f = await JoinFixture.create();
        await activateFixtureB(f);
        final statuses = <String>[];
        final pair = await openSyncPair(f, onAStatus: statuses.add);
        final before = await sqlSnapshot(f.aDb);
        final protected = Map.of(f.aStore.states);
        f.aStore.beforeRead = (_) => throw error;
        late CreatedJobSyncResult result;
        try {
          result = await pair.a.syncNow();
        } finally {
          f.aStore.beforeRead = null;
        }
        expect(result.complete, isFalse);
        expect(result.failure?.reason, reason);
        expect(
          result.message,
          contains('Stage preflight. Reason ${reason.name}.'),
        );
        expect(statuses.last, result.message);
        expect(statuses.join(' '), isNot(contains('private')));
        expect(statuses.join(' '), isNot(contains('/unsafe/key')));
        expect(statuses.join(' '), isNot(contains('192.0.2.1')));
        expect(statuses.join(' '), isNot(contains('secret-token')));
        expect(await sqlSnapshot(f.aDb), before);
        expectJoinProtectedUnchanged(f.aStore, protected);
      },
    );
  }
  test(
    'throwing status and diagnostic observers cannot fail sync or drain',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final diagnostics = <CreatedJobSyncDiagnostic>[];
      void status(String _) => throw StateError('observer failed');
      void diagnostic(CreatedJobSyncDiagnostic event) {
        diagnostics.add(event);
        throw StateError('observer failed');
      }

      final pair = await openSyncPair(
        f,
        onAStatus: status,
        onBStatus: status,
        onADiagnostic: diagnostic,
        onBDiagnostic: diagnostic,
      );
      final result = await pair.a.syncNow();
      expect(result.complete, isTrue, reason: result.failure?.message);
      expect(result.failure, isNull);
      expect(result.message, 'Job snapshot synced. Sent 1, received 0.');
      expect(await f.bDb.select(f.bDb.companyJobs).get(), hasLength(1));
      final terminalCount = diagnostics.length;
      await expectLater(pair.a.receive({}), throwsA(anything));
      expect(diagnostics, hasLength(terminalCount));
      expect(diagnostics.last.result, same(result));
      await pair.a.closeAndDrain();
      await pair.b.closeAndDrain();
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test(
    'rejected concurrent receiver start preserves the active local status',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final statuses = <String>[];
      final diagnostics = <CreatedJobSyncDiagnostic>[];
      final pair = await openSyncPair(
        f,
        onAStatus: statuses.add,
        onADiagnostic: diagnostics.add,
      );
      final entered = Completer<void>();
      final release = Completer<void>();
      f.aStore.beforeRead = (namespace) {
        if (namespace == f.a.namespace && !entered.isCompleted) {
          entered.complete();
          return release.future;
        }
        return null;
      };
      final active = pair.a.syncNow();
      try {
        await entered.future;
        final statusBefore = statuses.last;
        final inventory = CreatedJobHoldingsInventory.local(
          await f.bDb.select(f.bDb.companyJobs).get(),
        );
        final wire = await syncAttackWire(
          pair.b.controller.pairedJoinSession!,
          base64Encode(f.a.identity!.publicKey),
          const Uuid().v4(),
          'start',
          {
            'inventory': inventory.meta,
            'store': f.b.receivingStoreGeneration!.value,
          },
        );
        await expectLater(pair.a.receive(wire), throwsA(anything));
        expect(statuses.last, statusBefore);
        expect(
          diagnostics.where(
            (event) => event.kind == CreatedJobSyncDiagnosticKind.started,
          ),
          hasLength(1),
        );
        expect(
          diagnostics.where(
            (event) => event.kind == CreatedJobSyncDiagnosticKind.terminal,
          ),
          isEmpty,
        );
      } finally {
        f.aStore.beforeRead = null;
        final drain = pair.a.closeAndDrain();
        if (!release.isCompleted) release.complete();
        await active;
        await drain;
      }
    },
  );
  test('512 descriptor codec inventory remains paged and bounded with cached ACK stores', () {
    final descriptors = List.generate(512, (index) {
      final id = '00000000-0000-4000-8000-${index.toString().padLeft(12, '0')}';
      return <String, Object?>{
        'origin': id,
        'request': id,
        'job': id,
        'author': id,
        'installation': id,
        'operation': 'f' * 64,
        'command': 'f' * 64,
        'digest': 'f' * 64,
        'length': 65536,
      };
    });
    final digest = hashes.sha256
        .convert(utf8.encode(canonicalJoinTest(descriptors)))
        .toString();
    final remote = CreatedJobHoldingsInventory.remote({
      'count': 512,
      'pages': 16,
      'digest': digest,
    });
    var aggregate = 0;
    var largest = 0;
    for (var ordinal = 0; ordinal < 16; ordinal++) {
      final page = {
        'ordinal': ordinal,
        'digest': digest,
        'items': descriptors.skip(ordinal * 32).take(32).toList(),
        'confirmedStores': List.filled(32, descriptors.first['job']),
      };
      final size = utf8.encode(canonicalJoinTest(page)).length;
      aggregate += size;
      if (size > largest) largest = size;
      expect(size, lessThanOrEqualTo(33 * 1024));
      remote.acceptPage(page);
      if (ordinal == 0) {
        expect(() => remote.acceptPage(page), throwsA(anything));
      }
    }
    expect(remote.pages, 16);
    expect(remote.complete, isTrue);
    expect(aggregate, lessThanOrEqualTo(528 * 1024));
    final maximumCombinedInventory = CreatedJobHoldingsInventory.remote({
      'count': 1024,
      'pages': 32,
      'digest': digest,
    });
    expect(maximumCombinedInventory.count, 1024);
    expect(maximumCombinedInventory.pages, 32);
    expect(maximumCombinedInventory.complete, isFalse);
    expect(
      () => CreatedJobHoldingsInventory.remote({
        'count': 1025,
        'pages': 33,
        'digest': digest,
      }),
      throwsA(anything),
    );
    final duplicateItems = [descriptors.first, descriptors.first];
    final duplicateDigest = hashes.sha256
        .convert(utf8.encode(canonicalJoinTest(duplicateItems)))
        .toString();
    final duplicate = CreatedJobHoldingsInventory.remote({
      'count': 2,
      'pages': 1,
      'digest': duplicateDigest,
    });
    expect(
      () => duplicate.acceptPage({
        'ordinal': 0,
        'digest': duplicateDigest,
        'items': duplicateItems,
        'confirmedStores': [null, null],
      }),
      throwsA(anything),
    );
    expect(duplicate.complete, isFalse);
    stdout.writeln(
      'Synthetic descriptor codec only: page=$largest bytes aggregate=$aggregate bytes count=512',
    );
  });

  test(
    'business permission requires both user and device scopes on both sides',
    () {
      final allowed = <String, Object?>{
        'shops': ['shop'],
        'capabilities': ['createJob'],
      };
      for (var denied = 0; denied < 4; denied++) {
        final entries = List.generate(
          4,
          (_) => Map<String, Object?>.from(allowed),
        );
        entries[denied]['capabilities'] = <String>[];
        expect(
          () => requireCreatedJobSyncCapabilities(
            localUser: entries[0],
            localDevice: entries[1],
            peerUser: entries[2],
            peerDevice: entries[3],
            shop: 'shop',
          ),
          throwsA(anything),
        );
      }
      expect(
        () => requireCreatedJobSyncCapabilities(
          localUser: allowed,
          localDevice: allowed,
          peerUser: allowed,
          peerDevice: allowed,
          shop: 'other',
        ),
        throwsA(anything),
      );
    },
  );

  test('logical65536 byte codec reassembles without claiming semantic Job admission', () {
    final raw = Uint8List.fromList(List.generate(65536, (i) => i % 251));
    final buffer = CreatedJobTransferBuffer(
      length: raw.length,
      digest: hashes.sha256.convert(raw).toString(),
    );
    expect(() => buffer.bytes, throwsA(anything));
    for (
      var offset = 0;
      offset < raw.length;
      offset += kCreatedJobSyncChunkBytes
    ) {
      final end = offset + kCreatedJobSyncChunkBytes > raw.length
          ? raw.length
          : offset + kCreatedJobSyncChunkBytes;
      buffer.append(offset, base64Encode(raw.sublist(offset, end)));
    }
    expect(buffer.bytes, raw);
    expect(() => buffer.append(65536, 'AA=='), throwsA(anything));
    expect(
      () => CreatedJobTransferBuffer(length: 65537, digest: '0' * 64),
      throwsA(anything),
    );
    final gap = CreatedJobTransferBuffer(
      length: 2,
      digest: hashes.sha256.convert([1, 2]).toString(),
    );
    expect(() => gap.append(1, 'AQ=='), throwsA(anything));
    expect(() => gap.append(0, 'AQID'), throwsA(anything));
    expect(() => gap.append(0, 'AwQ='), throwsA(anything));
  });

  test('retained peer cannot claim completed snapshot before transferring missing Jobs', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final statuses = <String>[];
    final diagnostics = <CreatedJobSyncDiagnostic>[];
    final pair = await openSyncPair(
      f,
      onBStatus: statuses.add,
      onBDiagnostic: diagnostics.add,
    );
    final inventory = CreatedJobHoldingsInventory.local(
      await f.aDb.select(f.aDb.companyJobs).get(),
    );
    final run = const Uuid().v4();
    Future<void> send(String action, Map<String, Object?> data) async {
      final wire = await syncAttackWire(
        pair.a.controller.pairedJoinSession!,
        base64Encode(f.b.identity!.publicKey),
        run,
        action,
        data,
      );
      await pair.a.controller.exchangeCompanyMessage(
        wire,
        disclosure: pair.a.availability,
      );
    }

    await admitAttackRun(pair, run);
    await send('start', {
      'inventory': inventory.meta,
      'store': f.a.receivingStoreGeneration!.value,
    });
    await send('holdings', {
      'ordinal': 0,
      'digest': inventory.digest,
      'items': inventory.page(0),
      'confirmedStores': [for (final _ in inventory.page(0)) null],
    });
    final before = await sqlSnapshot(f.bDb);
    await expectLater(
      send('finish', {'complete': true, 'unsupported': 0}),
      throwsA(anything),
    );
    expect(pair.b.lastFailure.toString(), contains('unconfirmed Job snapshot'));
    expect(
      statuses.last,
      contains('Stage confirmation. Reason unconfirmedSnapshot.'),
    );
    expect(diagnostics.last.result?.complete, isFalse);
    expect(
      diagnostics.last.result?.failure?.reason,
      CreatedJobSyncReason.unconfirmedSnapshot,
    );
    expect(await sqlSnapshot(f.bDb), before);
    expect(await f.bDb.select(f.bDb.companyJobs).get(), isEmpty);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
    'incoming finish retires responder state so a late put cannot commit',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final statuses = <String>[];
      final diagnostics = <CreatedJobSyncDiagnostic>[];
      final pair = await openSyncPair(
        f,
        onBStatus: statuses.add,
        onBDiagnostic: diagnostics.add,
      );
      addTearDown(pair.a.closeAndDrain);
      addTearDown(pair.b.closeAndDrain);
      final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
      final inventory = CreatedJobHoldingsInventory.local([source]);
      final run = const Uuid().v4();
      Future<void> send(String action, Map<String, Object?> data) async {
        final wire = await syncAttackWire(
          pair.a.controller.pairedJoinSession!,
          base64Encode(f.b.identity!.publicKey),
          run,
          action,
          data,
        );
        await pair.a.controller.exchangeCompanyMessage(
          wire,
          disclosure: pair.a.availability,
        );
      }

      await admitAttackRun(pair, run);
      await send('start', {
        'inventory': inventory.meta,
        'store': f.a.receivingStoreGeneration!.value,
      });
      await send('holdings', {
        'ordinal': 0,
        'digest': inventory.digest,
        'items': inventory.page(0),
        'confirmedStores': [for (final _ in inventory.page(0)) null],
      });
      await send('finish', {'complete': false, 'unsupported': 0});
      expect(
        diagnostics.last.result?.failure?.reason,
        CreatedJobSyncReason.unconfirmedSnapshot,
      );
      expect(statuses.last, contains('Job sync incomplete.'));
      expect(await f.bDb.select(f.bDb.companyJobs).get(), isEmpty);
      final before = await sqlSnapshot(f.bDb);
      final protected = Map.of(f.bStore.states);
      final raw = utf8.encode(source.operationBytes);
      expect(raw.length, lessThanOrEqualTo(kCreatedJobSyncChunkBytes));
      await expectLater(
        send('put', {
          'descriptor': inventory.descriptors.single,
          'offset': 0,
          'bytes': base64Encode(raw),
        }),
        throwsA(anything),
      );
      expect(pair.b.lastFailure.toString(), contains('Job sync run differs'));
      expect(await sqlSnapshot(f.bDb), before);
      expectJoinProtectedUnchanged(f.bStore, protected);
      expect(await f.bDb.select(f.bDb.companyJobs).get(), isEmpty);
      final repeated = await pair.a.syncNow();
      expect(
        repeated.complete,
        isTrue,
        reason: '${pair.a.lastFailure}; ${pair.b.lastFailure}',
      );
      expect(await f.bDb.select(f.bDb.companyJobs).get(), hasLength(1));
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'known revoked retained peer receives no business inventory or Job writes',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final pair = await openSyncPair(f);
      await advanceJoinFloor(
        f.aStore,
        f.a.namespace,
        'revocation.device.${pair.ownerB.identity.deviceId}',
        1,
      );
      final before = await sqlSnapshot(f.bDb);
      final pins = Map.of(f.bStore.states);
      final result = await pair.a.syncNow();
      expect(result.complete, isFalse);
      expect(await sqlSnapshot(f.bDb), before);
      expectJoinProtectedUnchanged(f.bStore, pins);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test('invalid actor, occupied Job ID and closed availability refuse without writes', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final owner = await f.bEnrollment.signIn('1234');
    final available = await receiverAvailability(f, owner);
    final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
    final commands = CompanyJobCommands(enrollment: f.bEnrollment);
    final bad = jsonDecode(source.operationBytes) as Map<String, dynamic>;
    (bad['body'] as Map)['user'] = const Uuid().v4();
    var before = await sqlSnapshot(f.bDb);
    var protected = Map.of(f.bStore.states);
    await expectLater(
      commands.applyIncomingCreate(
        Uint8List.fromList(utf8.encode(canonicalJoinTest(bad))),
        ownerSession: owner,
        availability: available,
      ),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.bDb), before);
    expectJoinProtectedUnchanged(f.bStore, protected);
    await commands.createJob(
      CreateJob(
        companyId: owner.identity.companyId,
        shopId: owner.identity.shopId,
        jobId: source.jobId,
        requestId: const Uuid().v4(),
        name: 'Existing local Job',
      ),
      ownerSession: owner,
    );
    before = await sqlSnapshot(f.bDb);
    protected = Map.of(f.bStore.states);
    await expectLater(
      commands.applyIncomingCreate(
        Uint8List.fromList(utf8.encode(source.operationBytes)),
        ownerSession: owner,
        availability: available,
      ),
      throwsA(isA<JobLineRefusal>()),
    );
    expect(await sqlSnapshot(f.bDb), before);
    expectJoinProtectedUnchanged(f.bStore, protected);
    available.close();
    await expectLater(
      commands.applyIncomingCreate(
        Uint8List.fromList(utf8.encode(source.operationBytes)),
        ownerSession: owner,
        availability: available,
      ),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.bDb), before);
    expectJoinProtectedUnchanged(f.bStore, protected);
  }, timeout: const Timeout(Duration(minutes: 2)));

  for (final fault in ['sign-out', 'floor']) {
    test(
      'last protected await rejects $fault before incoming SQL commit',
      () async {
        final f = await JoinFixture.create();
        await activateFixtureB(f);
        final owner = await f.bEnrollment.signIn('1234');
        final available = await receiverAvailability(f, owner);
        final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
        var fired = false;
        Future<void>? changed;
        final commands = CompanyJobCommands(
          enrollment: f.bEnrollment,
          beforeCommit: () async {
            var reads = 0;
            f.bStore.onRead = (namespace) {
              if (namespace == f.b.namespace && ++reads == 2) {
                f.bStore.onRead = null;
                fired = true;
                changed = fault == 'sign-out'
                    ? f.bEnrollment.signOut()
                    : advanceJoinFloor(
                        f.bStore,
                        f.b.namespace,
                        'credential.${owner.identity.userId}',
                        99,
                      );
                unawaited(changed!);
              }
            };
          },
        );
        await expectLater(
          commands.applyIncomingCreate(
            Uint8List.fromList(utf8.encode(source.operationBytes)),
            ownerSession: owner,
            availability: available,
          ),
          throwsA(anything),
        );
        await changed;
        f.bStore.onRead = null;
        expect(fired, isTrue);
        expect(await f.bDb.select(f.bDb.jobs).get(), isEmpty);
        expect(await f.bDb.select(f.bDb.companyJobs).get(), isEmpty);
        final state = jsonDecode(
          utf8.decode(f.bStore.states[f.b.namespace]!.bytes),
        ) as Map;
        if (fault == 'floor') {
          expect(state['pendingCommand'], isNotNull);
          expect(f.b.readiness, InstallationReadiness.needsRecovery);
          expect(
            (state['floors'] as Map)['credential.${owner.identity.userId}'],
            99,
          );
        } else {
          expect(state['pendingCommand'], isNull);
        }
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }

  test('committed incoming receipt reconciles after lost completion and cold reopen', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final owner = await f.bEnrollment.signIn('1234');
    final available = await receiverAvailability(f, owner);
    final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
    final commands = CompanyJobCommands(
      enrollment: f.bEnrollment,
      afterCommit: () async {
        throw StateError('synthetic lost completion');
      },
    );
    await expectLater(
      commands.applyIncomingCreate(
        Uint8List.fromList(utf8.encode(source.operationBytes)),
        ownerSession: owner,
        availability: available,
      ),
      throwsA(anything),
    );
    final committed = (await f.bDb.select(f.bDb.companyJobs).get()).single;
    expect(
      (jsonDecode(utf8.decode(f.bStore.states[f.b.namespace]!.bytes))
          as Map)['pendingCommand'],
      isNotNull,
    );
    await f.reopenB();
    final reopened = await f.bEnrollment.signIn('1234');
    expect(
      (await CompanyJobCommands(enrollment: f.bEnrollment)
              .listJobs(ownerSession: reopened))
          .single
          .id,
      source.jobId,
    );
    expect((await f.bDb.select(f.bDb.companyJobs).get()).single, committed);
    expect(
      (jsonDecode(utf8.decode(f.bStore.states[f.b.namespace]!.bytes))
          as Map)['pendingCommand'],
      isNull,
    );
  }, timeout: const Timeout(Duration(minutes: 2)));
  test('default chunks recover lost applied ACK through fresh proof and cold receiver restart', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final bo = await f.bEnrollment.signIn('1234');
    await CompanyJobCommands(enrollment: f.bEnrollment).createJob(
      CreateJob(
        companyId: bo.identity.companyId,
        shopId: bo.identity.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: '\u00e0${List.filled(2047, '\u0301').join()}',
      ),
      ownerSession: bo,
    );
    final first = await openSyncPair(f);
    var lost = false;
    first.b.controller.onJoinMessage = (_, wire) async {
      final reply = await first.b.receive(wire);
      if (!lost && (await f.bDb.select(f.bDb.companyJobs).get()).length == 2) {
        lost = true;
        throw StateError(
          'synthetic lost reply after durable incoming admission',
        );
      }
      return reply;
    };
    final pending = await first.a.syncNow();
    expect(lost, isTrue);
    expect(pending.complete, isFalse);
    expect(await f.aDb.select(f.aDb.companyJobs).get(), hasLength(1));
    expect(await f.bDb.select(f.bDb.companyJobs).get(), hasLength(2));
    first.a.close();
    first.b.close();
    await f.reopenB();
    expect(f.bEnrollment.currentSession, isNull);
    final resumed = await openSyncPair(f);
    final result = await resumed.a.syncNow();
    expect(
      result.complete,
      isTrue,
      reason: '${resumed.a.lastFailure}; ${resumed.b.lastFailure}',
    );
    expect(await f.aDb.select(f.aDb.companyJobs).get(), hasLength(2));
    expect(await f.bDb.select(f.bDb.companyJobs).get(), hasLength(2));
    expect(await f.aDb.select(f.aDb.companyJobPeerAcks).get(), hasLength(2));
    expect(await f.bDb.select(f.bDb.companyJobPeerAcks).get(), hasLength(2));
    final records = await f.aDb.select(f.aDb.companyJobs).get();
    final acks = await f.aDb.select(f.aDb.companyJobPeerAcks).get();
    stdout.writeln(
      'Constructible signed domain sizes: operations=${records.map((r) => utf8.encode(r.operationBytes).length).toList()} incomingReceipts=${records.where((r) => !r.outgoing).map((r) => utf8.encode(r.receiptBytes).length).toList()} ACKs=${acks.map((r) => utf8.encode(r.ackBytes).length).toList()}',
    );
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('durable ACKs skip a shared prefix so a constrained fresh pair advances', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final first = await openSyncPair(f);
    expect(
      (await first.a.syncNow()).complete,
      isTrue,
      reason: '${first.a.lastFailure}; ${first.b.lastFailure}',
    );
    await first.a.closeAndDrain();
    await first.b.closeAndDrain();
    await CompanyJobCommands(enrollment: f.aEnrollment).createJob(
      CreateJob(
        companyId: f.owner.identity.companyId,
        shopId: f.owner.identity.shopId,
        jobId: const Uuid().v4(),
        requestId: 'ffffffff-ffff-4fff-bfff-ffffffffffff',
        name: 'Later offline Job',
      ),
      ownerSession: f.owner,
    );
    final resumed = await openSyncPair(f);
    // Seven setup RPCs leave seven for the transfer guard and its reserve.
    const remainingBudget = 14;
    for (final sync in [resumed.a, resumed.b]) {
      final channel = sync.controller.pairedJoinSession!;
      for (var i = 0; channel.remainingReceivedNonces > remainingBudget; i++) {
        channel.reserveReceivedNonce(base64Encode(List<int>.filled(12, i)));
      }
      expect(channel.remainingReceivedNonces, remainingBudget);
    }
    final actions = <String>[];
    final trace = <String>[];
    final handling = resumed.b.controller.onJoinMessage!;
    final keys = resumed.a.controller.pairedJoinSession!.keys;
    SecretKey key = keys.sendKey;
    for (final purpose in ['company-join', 'company-job-create-sync']) {
      key = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: key,
        nonce: utf8.encode(keys.id),
        info: utf8.encode('wiredpart-v2/$purpose@1/${keys.sendDirection}'),
      );
    }
    int remaining(CompanyCreatedJobSync sync) =>
        sync.controller.pairedJoinSession!.remainingReceivedNonces;
    resumed.b.controller.onJoinMessage = (session, wire) async {
      final header = {
        for (final field in [
          'v',
          'kind',
          'request',
          'recipient',
          'session',
          'direction',
        ])
          field: wire[field],
      };
      final bytes = await AesGcm.with256bits().decrypt(
        SecretBox(
          base64Decode(wire['ciphertext'] as String),
          nonce: base64Decode(wire['nonce'] as String),
          mac: Mac(base64Decode(wire['tag'] as String)),
        ),
        secretKey: key,
        aad: utf8.encode(canonicalJoinTest(header)),
      );
      final action =
          (jsonDecode(utf8.decode(bytes)) as Map)['action'] as String;
      actions.add(action);
      trace.add('$action A=${remaining(resumed.a)} B=${remaining(resumed.b)}');
      return handling(session, wire);
    };
    final result = await resumed.a.syncNow();
    expect(
      result.complete,
      isTrue,
      reason:
          '${resumed.a.lastFailure}; ${resumed.b.lastFailure}; '
          'stage=${result.failure?.stage.name} sent=${result.sent} received=${result.received}; '
          'trace=$trace; final A=${remaining(resumed.a)} B=${remaining(resumed.b)}',
    );
    expect(actions, [
      'profile',
      'start',
      'holdings',
      'page',
      'put',
      'ackBoth',
      'finish',
    ]);
    expect([remaining(resumed.a), remaining(resumed.b)], [7, 7]);
    stdout.writeln('Constrained sync trace: $trace; final A=7 B=7.');
    expect(result.sent, 1);
    expect(await f.bDb.select(f.bDb.companyJobs).get(), hasLength(2));
    expect(await f.bDb.select(f.bDb.companyJobPeerAcks).get(), hasLength(2));
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('one held receive rejects overlap, permits retry and drains before close completes', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final pair = await openSyncPair(f);
    var entered = Completer<void>();
    var released = Completer<void>();
    addTearDown(() {
      f.bStore.beforeRead = null;
      if (!released.isCompleted) {
        released.complete();
      }
    });
    f.bStore.beforeRead = (namespace) {
      if (namespace == f.b.namespace && !entered.isCompleted) {
        entered.complete();
        return released.future;
      }
      return null;
    };
    final first = expectLater(pair.b.receive({}), throwsA(anything));
    await entered.future;
    expect(pair.b.syncNow, throwsA(isA<CompanyBootstrapRefusal>()));
    await expectLater(
      pair.b.receive({}),
      throwsA(predicate((e) => e.toString().contains('receiving a request'))),
    );
    expect(pair.b.lastFailure, isNull);
    released.complete();
    await first;
    f.bStore.beforeRead = null;
    final retried = await pair.a.syncNow();
    expect(
      retried.complete,
      isTrue,
      reason: '${pair.a.lastFailure}; ${pair.b.lastFailure}',
    );
    final sql = await sqlSnapshot(f.bDb);
    final protected = Map.of(f.bStore.states);
    entered = Completer<void>();
    released = Completer<void>();
    f.bStore.beforeRead = (namespace) {
      if (namespace == f.b.namespace && !entered.isCompleted) {
        entered.complete();
        return released.future;
      }
      return null;
    };
    final held = expectLater(pair.b.receive({}), throwsA(anything));
    await entered.future;
    var settled = false;
    final drain = pair.b.closeAndDrain().then((_) => settled = true);
    await Future<void>.delayed(Duration.zero);
    expect(settled, isFalse);
    expect(() => pair.b.availability.requireLive(), throwsA(anything));
    await expectLater(pair.b.receive({}), throwsA(anything));
    released.complete();
    await held;
    await drain;
    expect(settled, isTrue);
    f.bStore.beforeRead = null;
    expect(await sqlSnapshot(f.bDb), sql);
    expectJoinProtectedUnchanged(f.bStore, protected);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
    'preconsumed pair quota stays pending without resetting nonce state',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final pair = await openSyncPair(f);
      final channel = pair.a.controller.pairedJoinSession!;
      await expectLater(
        pair.a.controller.exchangeCompanyMessage({'kind': 'created-jobs'}),
        throwsA(anything),
      );
      for (var i = 0; channel.remainingReceivedNonces > 3; i++) {
        channel.reserveReceivedNonce(base64Encode(List<int>.filled(12, i)));
      }
      final before = await sqlSnapshot(f.bDb);
      final protected = Map.of(f.bStore.states);
      final result = await pair.a.syncNow();
      expect(result.complete, isFalse);
      expect(channel.remainingReceivedNonces, 3);
      expect(await sqlSnapshot(f.bDb), before);
      expectJoinProtectedUnchanged(f.bStore, protected);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'responder sign-out after preparing reply prevents response disclosure',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final pair = await openSyncPair(f);
      final before = await sqlSnapshot(f.bDb);
      Future<void>? signingOut;
      pair.b.controller.onJoinMessage = (_, wire) async {
        final reply = await pair.b.receive(wire);
        signingOut = f.bEnrollment.signOut();
        unawaited(signingOut!);
        return reply;
      };
      final result = await pair.a.syncNow();
      await signingOut;
      expect(result.complete, isFalse);
      expect(result.sent, 0);
      expect(result.received, 0);
      expect(await sqlSnapshot(f.bDb), before);
      expect(f.bEnrollment.currentSession, isNull);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
  test(
    'one Sync Now exchanges offline Jobs both directions and repeat is a no-op',
    () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      await activateFixtureB(f);
      final bo = await f.bEnrollment.signIn('1234');
      final scope = bo.identity;
      await CompanyJobCommands(enrollment: f.bEnrollment).createJob(
        CreateJob(
          companyId: scope.companyId,
          shopId: scope.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          name: 'Offline member Job',
        ),
        ownerSession: bo,
      );
      final aOriginal = (await f.aDb.select(f.aDb.companyJobs).get()).single;
      final bOriginal = (await f.bDb.select(f.bDb.companyJobs).get()).single;
      late NearbyController ac;
      late NearbyController bc;
      final (bChannel, aChannel) = await joinChannels(
        onPaired: (b, a) {
          bc = b;
          ac = a;
        },
      );
      final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
      final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
      final first = await aa.beginPeerChallenge(
        aChannel,
        (await aa.retainedPeers(session: f.owner)).single,
        session: f.owner,
      );
      final response = await ba.receivePeerChallenge(
        bChannel,
        first,
        session: bo,
      );
      final complete = await aa.receivePeerResponse(aChannel, response);
      final completed = await ba.receivePeerCompletion(bChannel, complete);
      final aPeer = await aa.receivePeerAcknowledgment(
        aChannel,
        completed.acknowledgment,
      );
      final aSync = CompanyCreatedJobSync(
        onStatus: (s) =>
            stdout.writeln('${DateTime.now().toUtc().toIso8601String()} A $s'),
        availability: await CompanyJobSyncAvailability.open(
          enrollment: f.aEnrollment,
          owner: f.owner,
          peer: aPeer,
        ),
        controller: ac,
        chunkBytes: 1024,
      );
      final bSync = CompanyCreatedJobSync(
        onStatus: (s) =>
            stdout.writeln('${DateTime.now().toUtc().toIso8601String()} B $s'),
        availability: await CompanyJobSyncAvailability.open(
          enrollment: f.bEnrollment,
          owner: bo,
          peer: completed.membership,
        ),
        controller: bc,
        chunkBytes: 1024,
      );
      ac.onJoinMessage = (_, wire) => aSync.receive(wire);
      bc.onJoinMessage = (_, wire) => bSync.receive(wire);
      final result = await aSync.syncNow();
      expect(
        result.complete,
        isTrue,
        reason: '${aSync.lastFailure}; ${bSync.lastFailure}',
      );
      expect(result.sent, 1);
      expect(result.received, 1);
      final expected = {aOriginal.jobId, bOriginal.jobId};
      expect(
        (await CompanyJobCommands(enrollment: f.aEnrollment)
                .listJobs(ownerSession: f.owner))
            .map((j) => j.id)
            .toSet(),
        expected,
      );
      expect(
        (await CompanyJobCommands(enrollment: f.bEnrollment)
                .listJobs(ownerSession: bo))
            .map((j) => j.id)
            .toSet(),
        expected,
      );
      for (final db in [f.aDb, f.bDb]) {
        final rows = await db.select(db.companyJobs).get();
        expect(rows.map((r) => r.operationBytes).toSet(), {
          aOriginal.operationBytes,
          bOriginal.operationBytes,
        });
        expect(await db.select(db.companyJobPeerAcks).get(), hasLength(2));
      }
      final beforeA = await sqlSnapshot(f.aDb);
      final beforeB = await sqlSnapshot(f.bDb);
      final protectedA = Map.of(f.aStore.states);
      final protectedB = Map.of(f.bStore.states);
      final repeated = await aSync.syncNow();
      expect(repeated.complete, isTrue, reason: aSync.lastFailure?.toString());
      expect(repeated.sent, 0);
      expect(repeated.received, 0);
      expect(await sqlSnapshot(f.aDb), beforeA);
      expect(await sqlSnapshot(f.bDb), beforeB);
      expectJoinProtectedUnchanged(f.aStore, protectedA);
      expectJoinProtectedUnchanged(f.bStore, protectedB);

      expect(aSync.isLive, isTrue);
      aSync.availability.close();
      expect(aSync.isLive, isFalse);
      final unavailable = await aSync.syncNow();
      expect(unavailable.complete, isFalse);
      expect(unavailable.sent, 0);
      expect(unavailable.received, 0);
      expect(unavailable.message, isNot(contains('More Jobs pending')));
      expect(unavailable.message, contains('incomplete'));
      expect(await sqlSnapshot(f.aDb), beforeA);
      expect(await sqlSnapshot(f.bDb), beforeB);
      expectJoinProtectedUnchanged(f.aStore, protectedA);
      expectJoinProtectedUnchanged(f.bStore, protectedB);
    },
    timeout: const Timeout(Duration(minutes: 4)),
  );
  test(
    'receiver admits an original signed offline Job without reauthoring',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final owner = await f.bEnrollment.signIn('1234');
      final source = (await f.aDb.select(f.aDb.companyJobs).get()).single;
      await expectLater(
        JobLineCommands(
          authorization: JobLineAuthorization(db: f.bDb, installation: f.b),
        ).applyIncoming(Uint8List.fromList(utf8.encode(source.operationBytes))),
        throwsA(isA<JobLineRefusal>()),
      );
      final available = await receiverAvailability(f, owner);
      final commands = CompanyJobCommands(enrollment: f.bEnrollment);
      final receipt = await commands.applyIncomingCreate(
        Uint8List.fromList(utf8.encode(source.operationBytes)),
        ownerSession: owner,
        availability: available,
      );
      final jobs = await commands.listJobs(ownerSession: owner);
      expect(jobs.map((j) => j.id), [source.jobId]);
      final received = (await f.bDb.select(f.bDb.companyJobs).get()).single;
      expect(received.operationBytes, source.operationBytes);
      expect(received.outgoing, isFalse);
      final sql = await sqlSnapshot(f.bDb);
      final protected = Map.of(f.bStore.states);
      expect(
        await commands.applyIncomingCreate(
          Uint8List.fromList(utf8.encode(source.operationBytes)),
          ownerSession: owner,
          availability: available,
        ),
        receipt,
      );
      expect(await sqlSnapshot(f.bDb), sql);
      expectJoinProtectedUnchanged(f.bStore, protected);
    },
  );
}

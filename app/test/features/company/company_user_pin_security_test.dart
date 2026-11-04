import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';

import 'company_join_test.dart'
    show
        JoinFixture,
        canonicalJoinTest,
        sqlSnapshot,
        advanceJoinFloor,
        expectJoinProtectedUnchanged;
import 'company_user_disable_domain_test.dart'
    show provisionDisableFixture, disablePeers, disableJob;

Future<Map<String, Object?>> _exchangePolicy(
  JoinFixture f,
  String userId,
) async {
  final p = await disablePeers(f);
  final target = await f.aEnrollment.verifyUserLifecycleOffer(
    await f.bEnrollment.createUserLifecycleOffer(p.b, userId: userId),
    p.a,
  );
  final source = await f.bEnrollment.verifyUserLifecycleOffer(
    await f.aEnrollment.createUserLifecycleOffer(p.a, userId: userId),
    p.b,
  );
  final policy = (await f.aEnrollment.prepareUserDisablePolicy(p.a, target))!;
  final receipt = await f.bEnrollment.acceptUserDisablePolicy(
    policy,
    p.b,
    source,
  );
  await f.aEnrollment.acceptUserDisableReceipt(receipt, p.a, userId: userId);
  return receipt!;
}

void main() {
  for (final resetCount in [0, 2]) {
    test(
      '${resetCount == 0 ? 'legacy v2' : 'current v3'} terminal provisioning status preserves pending and confirmed lifecycle',
      () async {
        final f = await JoinFixture.create();
        final user = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Casey',
          pin: '0123',
        );
        final initial = await provisionDisableFixture(f, user.userId);
        for (var epoch = 1; epoch <= resetCount; epoch++) {
          await f.aEnrollment.resetRestrictedUserPin(
            owner: f.owner,
            userId: user.userId,
            requestId: const Uuid().v4(),
            expectedCredentialVersion: epoch,
            pin: epoch == 1 ? '4567' : '6789',
          );
        }
        await f.aEnrollment.disableRestrictedUser(
          owner: f.owner,
          userId: user.userId,
          requestId: const Uuid().v4(),
        );

        Future<void> expectStatus(String? target, bool confirmed) async {
          final protected = Map.of(f.aStore.states);
          final sql = await sqlSnapshot(f.aDb);
          final status = (await f.aEnrollment.userProvisionStatus(
            f.owner,
            userId: user.userId,
          ))!;
          expect(status.userId, user.userId);
          expect(status.disabled, isTrue);
          expect(status.targetDeviceId, target);
          expect(status.confirmed, confirmed);
          final lifecycle = (await f.aEnrollment.userLifecycleStatus(
            userId: user.userId,
          ))!;
          expect(lifecycle.userId, user.userId);
          expect(lifecycle.disabled, isTrue);
          expect(lifecycle.credentialVersion, resetCount + 1);
          expect(lifecycle.targetDeviceId, target);
          expect(lifecycle.confirmed, confirmed);
          expectJoinProtectedUnchanged(f.aStore, protected);
          expect(await sqlSnapshot(f.aDb), sql);
        }

        await expectStatus(resetCount == 0 ? initial.a.deviceId : null, false);
        final p = await disablePeers(f);
        final target = await f.aEnrollment.verifyUserLifecycleOffer(
          await f.bEnrollment.createUserLifecycleOffer(
            p.b,
            userId: user.userId,
          ),
          p.a,
        );
        final source = await f.bEnrollment.verifyUserLifecycleOffer(
          await f.aEnrollment.createUserLifecycleOffer(
            p.a,
            userId: user.userId,
          ),
          p.b,
        );
        final policy = (await f.aEnrollment.prepareUserDisablePolicy(
          p.a,
          target,
        ))!;
        await expectStatus(p.a.deviceId, false);
        final receipt = await f.bEnrollment.acceptUserDisablePolicy(
          policy,
          p.b,
          source,
        );
        await f.aEnrollment.acceptUserDisableReceipt(
          receipt!,
          p.a,
          userId: user.userId,
        );
        await expectStatus(p.a.deviceId, true);
      },
      timeout: const Timeout(Duration(seconds: 90)),
    );
  }

  test(
    'current terminal state refuses a legacy receipt envelope without mutation',
    () async {
      final f = await JoinFixture.create();
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Casey',
        pin: '0123',
      );
      await provisionDisableFixture(f, user.userId);
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 1,
        pin: '4567',
      );
      await f.aEnrollment.disableRestrictedUser(
        owner: f.owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
      );
      final p = await disablePeers(f);
      final protected = Map.of(f.aStore.states);
      final sql = await sqlSnapshot(f.aDb);
      await expectLater(
        f.aEnrollment.acceptUserDisableReceipt(
          {
            'body': {'kind': 'company.user.disable.receipt@1'},
            'signature': '',
          },
          p.a,
          userId: user.userId,
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, protected);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  test('current floor three preserves anchored history, spent receipts and held old proof', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    final request = const Uuid().v4();
    final first = await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: user.userId,
      requestId: request,
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    final firstDelivery = await _exchangePolicy(f, user.userId);
    await f.bEnrollment.signInUser(user.userId, '4567');
    final oldJob = await disableJob(f.bEnrollment, 'Unseen epoch two');
    final oldRow = (await f.bDb.select(f.bDb.companyJobs).get()).singleWhere(
      (r) => r.jobId == oldJob,
    );
    final proof = Map<String, Object?>.from(
      (jsonDecode(oldRow.operationBytes) as Map)['authorization'] as Map,
    );
    await f.bEnrollment.signIn('1234');
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 2,
      pin: '6789',
    );
    await _exchangePolicy(f, user.userId);
    for (final pair in [(f.a, f.aStore, f.aDb), (f.b, f.bStore, f.bDb)]) {
      await advanceJoinFloor(
        pair.$2,
        pair.$1.namespace,
        'credential.${user.userId}',
        3,
      );
      await pair.$1.readCompanyTrust(pair.$3);
    }
    await f.aEnrollment.signIn('1234');
    await f.bEnrollment.signIn('1234');
    expect(
      (await f.aEnrollment.userLifecycleStatus(userId: user.userId))!
          .credentialVersion,
      3,
    );
    final slot = companyUserNamespace(f.a.namespace);
    final before = f.aStore.states[slot]!;
    final sql = await sqlSnapshot(f.aDb);
    final replay = await f.aEnrollment.resetRestrictedUserPin(
      owner: f.aEnrollment.currentSession!,
      userId: user.userId,
      requestId: request,
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    final resumed = await f.aEnrollment.resumeRestrictedUserPinReset(
      owner: f.aEnrollment.currentSession!,
      userId: user.userId,
      requestId: request,
      expectedCredentialVersion: 1,
    );
    expect(replay.certificateBytes, first.certificateBytes);
    expect(replay.isCurrent, isFalse);
    expect(resumed.isCurrent, isFalse);
    expect(f.aStore.states[slot]!.revision, before.revision);
    expect(
      base64Encode(f.aStore.states[slot]!.bytes) == base64Encode(before.bytes),
      isTrue,
    );
    expect(await sqlSnapshot(f.aDb), sql);
    final trust = (await f.a.readCompanyTrust(f.aDb))!;
    await expectLater(
      CompanyUserStateCertificate.verify(
        first.certificateBytes,
        db: f.aDb,
        trust: trust,
        floors: f.a.knownSecurityFloors,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final peers = await disablePeers(f);
    await f.aEnrollment.acceptUserDisableReceipt(
      firstDelivery,
      peers.a,
      userId: user.userId,
    );
    final held = await peers.a.prepareCreateCommand(
      f.aEnrollment.currentSession!,
    );
    expect(await held.isCreateActorDisabled(proof), isTrue);
    expect(
      (await f.bDb.select(f.bDb.companyJobs).get()).singleWhere(
        (r) => r.jobId == oldJob,
      ),
      oldRow,
    );
  }, timeout: const Timeout(Duration(seconds: 90)));

  test(
    'terminal current replay is exact and rootless Owner cannot reset',
    () async {
      final f = await JoinFixture.create();
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Casey',
        pin: '0123',
      );
      await provisionDisableFixture(f, user.userId);
      final beforeB = f.bStore.states[companyUserNamespace(f.b.namespace)]!;
      await expectLater(
        f.bEnrollment.resetRestrictedUserPin(
          owner: f.bEnrollment.currentSession!,
          userId: user.userId,
          requestId: const Uuid().v4(),
          expectedCredentialVersion: 1,
          pin: '4567',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expect(
        f.bStore.states[companyUserNamespace(f.b.namespace)]!.revision,
        beforeB.revision,
      );
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 1,
        pin: '4567',
      );
      final request = const Uuid().v4();
      final receipt = await f.aEnrollment.disableRestrictedUser(
        owner: f.owner,
        userId: user.userId,
        requestId: request,
      );
      final before = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
      final sql = await sqlSnapshot(f.aDb);
      final replay = await f.aEnrollment.disableRestrictedUser(
        owner: f.owner,
        userId: user.userId,
        requestId: request,
      );
      expect(replay.proofBytes, receipt.proofBytes);
      await expectLater(
        f.aEnrollment.resetRestrictedUserPin(
          owner: f.owner,
          userId: user.userId,
          requestId: const Uuid().v4(),
          expectedCredentialVersion: 2,
          pin: '6789',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expect(
        f.aStore.states[companyUserNamespace(f.a.namespace)]!.revision,
        before.revision,
      );
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  test('lost protected response and concurrent attempt decrement survive projection clear', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    final slot = companyUserNamespace(f.a.namespace);
    var decremented = false;
    f.aStore.loseNextUserReply = true;
    f.aStore.beforeRead = (namespace) {
      if (namespace != slot || decremented) return null;
      final saved = f.aStore.states[slot]!;
      final raw = jsonDecode(utf8.decode(saved.bytes)) as Map;
      if (raw['v'] != 3 || raw['j'] == null) return null;
      return () async {
        if ((await f.aDb.select(f.aDb.companyUserEvents).get()).length != 2) {
          return;
        }
        decremented = true;
        raw['a'] = 6;
        await f.aStore.delegate.compareAndSwapState(
          slot,
          expectedRevision: saved.revision,
          nextRevision: const Uuid().v4(),
          bytes: Uint8List.fromList(utf8.encode(canonicalJoinTest(raw))),
        );
      }();
    };
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    f.aStore.beforeRead = null;
    final saved = jsonDecode(utf8.decode(f.aStore.states[slot]!.bytes)) as Map;
    expect(decremented, isTrue);
    expect(saved['j'], isNull);
    expect(saved['a'], 6);
  });

  test(
    'sign-out at final account read refuses reset without mutation',
    () async {
      final f = await JoinFixture.create();
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Casey',
        pin: '0123',
      );
      final slot = companyUserNamespace(f.a.namespace);
      final before = f.aStore.states[slot]!;
      final sql = await sqlSnapshot(f.aDb);
      var reads = 0;
      Future<void>? cancellation;
      f.aStore.beforeRead = (namespace) {
        if (namespace == slot && ++reads == 2) {
          cancellation = f.aEnrollment.signOut();
        }
        return null;
      };
      await expectLater(
        f.aEnrollment.resetRestrictedUserPin(
          owner: f.owner,
          userId: user.userId,
          requestId: const Uuid().v4(),
          expectedCredentialVersion: 1,
          pin: '4567',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      f.aStore.beforeRead = null;
      await cancellation;
      expect(reads, greaterThanOrEqualTo(2));
      expect(f.aStore.states[slot]!.revision, before.revision);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  test(
    'missing anchored history still permits independent Owner Job',
    () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Casey',
        pin: '0123',
      );
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 1,
        pin: '4567',
      );
      await f.aDb.customStatement(
        'DELETE FROM company_user_events WHERE sequence = 1',
      );
      await expectLater(
        f.aEnrollment.signInUser(user.userId, '4567'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      await f.aEnrollment.signIn('1234');
      final id = await disableJob(
        f.aEnrollment,
        'Independent Owner after audit rollback',
      );
      expect(
        (await f.aDb.select(f.aDb.jobs).get()).map((r) => r.id),
        contains(id),
      );
    },
  );

  test('higher public state fences old PIN before malformed private material and retry preserves attempts', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    var p = await disablePeers(f);
    var target = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: user.userId),
      p.a,
    );
    var source = await f.bEnrollment.verifyUserLifecycleOffer(
      await f.aEnrollment.createUserLifecycleOffer(p.a, userId: user.userId),
      p.b,
    );
    final policy = (await f.aEnrollment.prepareUserDisablePolicy(p.a, target))!;
    final malformed = Map<String, Object?>.from(
      jsonDecode(canonicalJoinTest(policy)) as Map,
    );
    (malformed['secret'] as Map)['ciphertext'] = base64Encode([1, 2, 3]);
    await expectLater(
      f.bEnrollment.acceptUserDisablePolicy(malformed, p.b, source),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final status = (await f.bEnrollment.userLifecycleStatus(
      userId: user.userId,
    ))!;
    expect(status.credentialVersion, 2);
    expect(status.awaitingCredential, isTrue);
    await expectLater(
      f.bEnrollment.signInUser(user.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.bEnrollment.signIn('1234');
    p = await disablePeers(f);
    target = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: user.userId),
      p.a,
    );
    source = await f.bEnrollment.verifyUserLifecycleOffer(
      await f.aEnrollment.createUserLifecycleOffer(p.a, userId: user.userId),
      p.b,
    );
    final retry = (await f.aEnrollment.prepareUserDisablePolicy(p.a, target))!;
    final receipt = await f.bEnrollment.acceptUserDisablePolicy(
      retry,
      p.b,
      source,
    );
    await f.aEnrollment.acceptUserDisableReceipt(
      receipt,
      p.a,
      userId: user.userId,
    );
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: user.userId))!
          .attemptsRemaining,
      status.attemptsRemaining,
    );
    await f.bEnrollment.signInUser(user.userId, '4567');
  });

  test('bounded public suffix resumes before disclosing the latest private credential', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    for (var epoch = 1; epoch <= 17; epoch++) {
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: epoch,
        pin: '4567',
      );
    }
    await advanceJoinFloor(
      f.aStore,
      f.a.namespace,
      'credential.${user.userId}',
      18,
    );
    await f.a.readCompanyTrust(f.aDb);
    await f.aEnrollment.signIn('1234');
    var p = await disablePeers(f);
    var target = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: user.userId),
      p.a,
    );
    var source = await f.bEnrollment.verifyUserLifecycleOffer(
      await f.aEnrollment.createUserLifecycleOffer(p.a, userId: user.userId),
      p.b,
    );
    final partial = (await f.aEnrollment.prepareUserDisablePolicy(
      p.a,
      target,
    ))!;
    expect((partial['events'] as List).length, 16);
    expect(partial['more'], isTrue);
    expect(partial['secret'], isNull);
    final receipt = await f.bEnrollment.acceptUserDisablePolicy(
      partial,
      p.b,
      source,
    );
    await f.aEnrollment.acceptUserDisableReceipt(
      receipt,
      p.a,
      userId: user.userId,
    );
    final pending = (await f.bEnrollment.userLifecycleStatus(
      userId: user.userId,
    ))!;
    expect(pending.credentialVersion, 17);
    expect(pending.awaitingCredential, isTrue);
    expect(
      (await f.aEnrollment.userLifecycleStatus(userId: user.userId))!.confirmed,
      isFalse,
    );
    await expectLater(
      f.bEnrollment.signInUser(user.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.bEnrollment.signIn('1234');
    p = await disablePeers(f);
    target = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: user.userId),
      p.a,
    );
    source = await f.bEnrollment.verifyUserLifecycleOffer(
      await f.aEnrollment.createUserLifecycleOffer(p.a, userId: user.userId),
      p.b,
    );
    final finalPolicy = (await f.aEnrollment.prepareUserDisablePolicy(
      p.a,
      target,
    ))!;
    expect((finalPolicy['events'] as List).length, 1);
    expect(finalPolicy['more'], isFalse);
    expect(finalPolicy['secret'], isNotNull);
    final done = await f.bEnrollment.acceptUserDisablePolicy(
      finalPolicy,
      p.b,
      source,
    );
    await f.aEnrollment.acceptUserDisableReceipt(
      done,
      p.a,
      userId: user.userId,
    );
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: user.userId))!
          .credentialVersion,
      18,
    );
    await f.bEnrollment.signInUser(user.userId, '4567');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('incoming terminal policy preserves a concurrent remaining-attempt decrement', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    await _exchangePolicy(f, user.userId);
    await f.aEnrollment.disableRestrictedUser(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
    );
    final p = await disablePeers(f);
    final target = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: user.userId),
      p.a,
    );
    final source = await f.bEnrollment.verifyUserLifecycleOffer(
      await f.aEnrollment.createUserLifecycleOffer(p.a, userId: user.userId),
      p.b,
    );
    final policy = (await f.aEnrollment.prepareUserDisablePolicy(p.a, target))!;
    final slot = companyUserNamespace(f.b.namespace);
    var reads = 0;
    var decremented = false;
    f.bStore.beforeRead = (namespace) {
      if (namespace != slot || ++reads != 2) return null;
      return () async {
        final saved = f.bStore.states[slot]!;
        final raw = jsonDecode(utf8.decode(saved.bytes)) as Map;
        raw['a'] = 7;
        await f.bStore.delegate.compareAndSwapState(
          slot,
          expectedRevision: saved.revision,
          nextRevision: const Uuid().v4(),
          bytes: Uint8List.fromList(utf8.encode(canonicalJoinTest(raw))),
        );
        decremented = true;
      }();
    };
    await f.bEnrollment.acceptUserDisablePolicy(policy, p.b, source);
    f.bStore.beforeRead = null;
    expect(decremented, isTrue);
    final status = (await f.bEnrollment.userLifecycleStatus(
      userId: user.userId,
    ))!;
    expect(status.disabled, isTrue);
    expect(status.attemptsRemaining, 7);
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('same public checkpoint from another signed store binding cannot overwrite slot receipt', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    final p = await disablePeers(f);
    final target = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: user.userId),
      p.a,
    );
    final originalOffer = await f.aEnrollment.createUserLifecycleOffer(
      p.a,
      userId: user.userId,
    );
    final source = await f.bEnrollment.verifyUserLifecycleOffer(
      originalOffer,
      p.b,
    );
    final policy = (await f.aEnrollment.prepareUserDisablePolicy(p.a, target))!;
    await f.bEnrollment.acceptUserDisablePolicy(policy, p.b, source);
    final slot = companyUserNamespace(f.b.namespace);
    final before = f.bStore.states[slot]!;
    final changed = Map<String, Object?>.from(
      jsonDecode(canonicalJoinTest(originalOffer)) as Map,
    );
    final body = changed['body'] as Map;
    (body['binding'] as List)[4] = const Uuid().v4();
    final primary =
        jsonDecode(utf8.decode(f.aStore.states[f.a.namespace]!.bytes)) as Map;
    final key = await Ed25519().newKeyPairFromSeed(
      base64Decode(primary['seed'] as String),
    );
    changed['signature'] = base64Encode(
      (await Ed25519().sign(
        utf8.encode(
          'wiredpart.company.user.lifecycle.offer@2:${canonicalJoinTest(body)}',
        ),
        keyPair: key,
      )).bytes,
    );
    final verified = await f.bEnrollment.verifyUserLifecycleOffer(changed, p.b);
    final publicReplay = {
      ...policy,
      'source': body['binding'],
      'events': <String>[],
      'secret': null,
    };
    await f.bEnrollment.acceptUserDisablePolicy(publicReplay, p.b, verified);
    expect(f.bStore.states[slot]!.revision, before.revision);
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: user.userId))!
          .awaitingCredential,
      isFalse,
    );
    expect((await f.bDb.select(f.bDb.companyUserDeliveries).get()).length, 2);
  });
}

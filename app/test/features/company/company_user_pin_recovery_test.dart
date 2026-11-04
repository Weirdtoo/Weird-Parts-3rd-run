import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';

import 'company_join_test.dart' show JoinFixture, sqlSnapshot;
import 'company_user_disable_domain_test.dart'
    show provisionDisableFixture, disableSync, disableJob, disablePeers;

bool _hasSecretLeaf(Object? value, Set<String> secrets) {
  if (value is Map) {
    return value.keys.any(
          (key) => const {
            'pin',
            'pinSalt',
            'pinVerifier',
            'salt',
            'verifier',
          }.contains(key),
        ) ||
        value.values.any((v) => _hasSecretLeaf(v, secrets));
  }
  if (value is List) return value.any((v) => _hasSecretLeaf(v, secrets));
  if (value is String) {
    if (secrets.contains(value)) return true;
    if (value.startsWith('{') || value.startsWith('[')) {
      try {
        return _hasSecretLeaf(jsonDecode(value), secrets);
      } catch (_) {
        return false;
      }
    }
  }
  return false;
}

void main() {
  test('direct authenticated public suffix precedes exact private credential delivery', () async {
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
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 2,
      pin: '6789',
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
    expect((policy['events'] as List).length, 2);
    final receipt = await f.bEnrollment.acceptUserDisablePolicy(
      policy,
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
          .credentialVersion,
      3,
    );
    expect(
      (await f.aEnrollment.userLifecycleStatus(userId: user.userId))!.confirmed,
      isTrue,
    );
    await expectLater(
      f.bEnrollment.signInUser(user.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await expectLater(
      f.bEnrollment.signInUser(user.userId, '4567'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.bEnrollment.signInUser(user.userId, '6789');
  });
  test('authenticated reset propagation holds unseen old work and preserves historical receipts and Owner exchange', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    await f.bEnrollment.signInUser(user.userId, '0123');
    final historicalId = await disableJob(
      f.bEnrollment,
      'Historical user work',
    );
    await f.bEnrollment.signIn('1234');
    var pair = await disableSync(f);
    final first = await pair.a.syncNow();
    expect(
      first.complete,
      isTrue,
      reason: '${first.message} ${pair.b.lastFailure}',
    );
    final historical = (await f.aDb.select(f.aDb.companyJobs).get())
        .singleWhere((r) => r.jobId == historicalId);
    await f.bEnrollment.signInUser(user.userId, '0123');
    final unseenId = await disableJob(f.bEnrollment, 'Unseen old credential');
    final unseen = (await f.bDb.select(f.bDb.companyJobs).get()).singleWhere(
      (r) => r.jobId == unseenId,
    );
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.aEnrollment.currentSession!,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    await f.bEnrollment.signInUser(user.userId, '0123');
    await f.bEnrollment.signIn('1234');
    final ownerA = await disableJob(f.aEnrollment, 'Independent Owner A');
    final ownerB = await disableJob(f.bEnrollment, 'Independent Owner B');
    pair = await disableSync(f);
    final result = await pair.a.syncNow();
    expect(result.held, 1, reason: '${result.message} ${pair.b.lastFailure}');
    expect(result.sent, 1);
    expect(result.received, 1);
    expect(
      (await f.aDb.select(f.aDb.companyJobs).get()).map((r) => r.jobId),
      containsAll([historicalId, ownerA, ownerB]),
    );
    expect(
      (await f.bDb.select(f.bDb.companyJobs).get()).singleWhere(
        (r) => r.jobId == unseenId,
      ),
      unseen,
    );
    expect(
      (await f.aDb.select(f.aDb.companyJobs).get()).singleWhere(
        (r) => r.jobId == historicalId,
      ),
      historical,
    );
    final repeat = await pair.a.syncNow();
    expect(repeat.held, 1, reason: '${repeat.message} ${pair.b.lastFailure}');
    expect(repeat.sent, 0);
    expect(repeat.received, 0);
    await expectLater(
      f.bEnrollment.signInUser(user.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.bEnrollment.signInUser(user.userId, '4567');
    await disableJob(f.bEnrollment, 'New credential work');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
    'failed unspent request cannot silently reset a newer credential epoch',
    () async {
      final f = await JoinFixture.create();
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Casey',
        pin: '0123',
      );
      final request = const Uuid().v4();
      Future<void>? cancellation;
      var revoked = false;
      f.aStore.beforeRead = (namespace) {
        if (namespace == companyUserNamespace(f.a.namespace) && !revoked) {
          revoked = true;
          cancellation = f.aEnrollment.signOut();
        }
        return null;
      };
      await expectLater(
        f.aEnrollment.resetRestrictedUserPin(
          expectedCredentialVersion: 1,
          owner: f.owner,
          userId: user.userId,
          requestId: request,
          pin: '4567',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      f.aStore.beforeRead = null;
      await cancellation;
      final owner = await f.aEnrollment.signIn('1234');
      await f.aEnrollment.resetRestrictedUserPin(
        expectedCredentialVersion: 1,
        owner: owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        pin: '6789',
      );
      final before = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
      final sql = await sqlSnapshot(f.aDb);
      await expectLater(
        f.aEnrollment.resetRestrictedUserPin(
          expectedCredentialVersion: 1,
          owner: owner,
          userId: user.userId,
          requestId: request,
          pin: '4567',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expect(
        f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
        before.bytes,
      );
      expect(
        f.aStore.states[companyUserNamespace(f.a.namespace)]!.revision,
        before.revision,
      );
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );
  test(
    'caller-owned transaction refuses before protected reset or projection',
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
      await f.aDb.transaction(() async {
        await expectLater(
          f.aEnrollment.resetRestrictedUserPin(
            expectedCredentialVersion: 1,
            owner: f.owner,
            userId: user.userId,
            requestId: const Uuid().v4(),
            pin: '4567',
          ),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
        await expectLater(
          f.aEnrollment.reconcileUserPinRecovery(),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
      });
      expect(f.aStore.states[slot]!.bytes, before.bytes);
      expect(f.aStore.states[slot]!.revision, before.revision);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );
  test('authority Owner recovers lockout once and same request cannot refill attempts', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    for (var i = 0; i < 8; i++) {
      await expectLater(
        f.aEnrollment.signInUser(user.userId, '9999'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    }
    final owner = await f.aEnrollment.signIn('1234');
    final request = const Uuid().v4();
    final receipt = await f.aEnrollment.resetRestrictedUserPin(
      expectedCredentialVersion: 1,
      owner: owner,
      userId: user.userId,
      requestId: request,
      pin: '4567',
    );
    expect(receipt.credentialVersion, 2);
    expect(receipt.userId, user.userId);
    await expectLater(
      f.aEnrollment.signInUser(user.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final afterFailure = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
    final ownerAgain = await f.aEnrollment.signIn('1234');
    final duplicate = await f.aEnrollment.resetRestrictedUserPin(
      expectedCredentialVersion: 1,
      owner: ownerAgain,
      userId: user.userId,
      requestId: request,
      pin: '4567',
    );
    expect(duplicate.certificateBytes, receipt.certificateBytes);
    expect(
      f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
      afterFailure.bytes,
    );
    final selected = await f.aEnrollment.signInUser(user.userId, '4567');
    expect(selected, isA<RestrictedUserSession>());
    expect(selected.identity.userId, user.userId);
    final events = await f.aDb
        .customSelect('SELECT * FROM company_user_events ORDER BY sequence')
        .get();
    expect(events.length, 2);
    final private =
        (jsonDecode(utf8.decode(afterFailure.bytes)) as Map)['p'] as List;
    expect(
      _hasSecretLeaf(events.map((r) => r.data).toList(), {
        '4567',
        ...private.skip(1).cast<String>(),
      }),
      isFalse,
    );
  });

  test('second offline reset supersedes private delivery and old request stays spent', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    final firstRequest = const Uuid().v4();
    final first = await f.aEnrollment.resetRestrictedUserPin(
      expectedCredentialVersion: 1,
      owner: f.owner,
      userId: user.userId,
      requestId: firstRequest,
      pin: '4567',
    );
    final second = await f.aEnrollment.resetRestrictedUserPin(
      expectedCredentialVersion: 2,
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      pin: '6789',
    );
    expect(second.credentialVersion, 3);
    final before = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
    final replay = await f.aEnrollment.resetRestrictedUserPin(
      expectedCredentialVersion: 1,
      owner: f.owner,
      userId: user.userId,
      requestId: firstRequest,
      pin: '4567',
    );
    expect(replay.certificateBytes, first.certificateBytes);
    expect(replay.isCurrent, isFalse);
    expect(
      f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
      before.bytes,
    );
    expect(
      (await f.aDb.customSelect('SELECT * FROM company_user_events').get())
          .length,
      3,
    );
    await expectLater(
      f.aEnrollment.signInUser(user.userId, '4567'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.aEnrollment.signInUser(user.userId, '6789');
  });

  test('protected reset forward-completes a failed SQL projection without a second reset', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    final request = const Uuid().v4();
    await f.aDb.customStatement(
      "CREATE TRIGGER fail_projection BEFORE INSERT ON company_user_events BEGIN SELECT RAISE(ABORT, 'synthetic projection fault'); END",
    );
    await expectLater(
      f.aEnrollment.resetRestrictedUserPin(
        expectedCredentialVersion: 1,
        owner: f.owner,
        userId: user.userId,
        requestId: request,
        pin: '4567',
      ),
      throwsA(anything),
    );
    final protected = jsonDecode(
      utf8.decode(f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes),
    ) as Map;
    expect(protected['v'], 3);
    expect(protected['j'], isNotNull);
    expect(
      (await f.aDb.customSelect('SELECT * FROM company_user_events').get()),
      isEmpty,
    );
    await f.aDb.customStatement('DROP TRIGGER fail_projection');
    final resumed = await f.aEnrollment.resumeRestrictedUserPinReset(
      expectedCredentialVersion: 1,
      owner: f.owner,
      userId: user.userId,
      requestId: request,
    );
    expect(resumed.credentialVersion, 2);
    expect(
      (await f.aDb.customSelect('SELECT * FROM company_user_events').get())
          .length,
      2,
    );
    final saved = jsonDecode(
      utf8.decode(f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes),
    ) as Map;
    expect(saved['j'], isNull);
  });

  test('missing anchored public history fences reset and login while terminal stays terminal', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await f.aEnrollment.resetRestrictedUserPin(
      expectedCredentialVersion: 1,
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      pin: '4567',
    );
    await f.aDb.customStatement(
      'DELETE FROM company_user_events WHERE sequence = 1',
    );
    final before = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
    final sqlBefore = await sqlSnapshot(f.aDb);
    await expectLater(
      f.aEnrollment.resetRestrictedUserPin(
        expectedCredentialVersion: 1,
        owner: f.owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        pin: '6789',
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await expectLater(
      f.aEnrollment.signInUser(user.userId, '4567'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(
      f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
      before.bytes,
    );
    expect(await sqlSnapshot(f.aDb), sqlBefore);
  });
}

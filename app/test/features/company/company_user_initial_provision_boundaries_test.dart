import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';

import 'company_join_test.dart' show JoinFixture, activateFixtureB, sqlSnapshot;
import 'company_user_initial_provision_test.dart'
    show
        initialProvisionBundle,
        initialProvisionPeers,
        protectedUnchanged,
        provisionInitialUser,
        thirdInstallation;

final class _PrivateExportObserver extends DartCryptography {
  int privateSignatures = 0;

  @override
  Ed25519 ed25519() => _ObservedPrivateExport(this);
}

final class _ObservedPrivateExport extends DartEd25519 {
  _ObservedPrivateExport(this.observer);
  final _PrivateExportObserver observer;

  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
    PublicKey? publicKey,
  }) async {
    final signature = await super.sign(
      message,
      keyPair: keyPair,
      publicKey: publicKey,
    );
    final prefix = utf8.encode(
      'wiredpart.company.user.initial-provision.private@2:',
    );
    if (message.length >= prefix.length &&
        List.generate(
          prefix.length,
          (i) => message[i] == prefix[i],
        ).every((same) => same)) {
      observer.privateSignatures++;
    }
    return signature;
  }
}

void main() {
  test('another user consent cannot authorize receiving an existing user bundle', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final first = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Selected builder',
      pin: '0123',
    );
    final second = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Offered builder',
      pin: '4567',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, second.userId);
    final c = await thirdInstallation(f);
    await provisionInitialUser(f.aEnrollment, c.enrollment, first.userId);
    final selected = await c.enrollment.signInUser(first.userId, '0123');
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    try {
      final secondBundle = await initialProvisionBundle(
        f.aEnrollment,
        c.enrollment,
        second.userId,
        peers.a,
        peers.b,
        requestId: const Uuid().v4(),
      );
      // Consent for the first user supersedes the earlier second-user consent.
      await initialProvisionBundle(
        f.aEnrollment,
        c.enrollment,
        first.userId,
        peers.a,
        peers.b,
        requestId: const Uuid().v4(),
      );
      final beforeSql = await sqlSnapshot(c.db);
      final beforeProtected = Map.of(c.store.states);
      await expectLater(
        c.enrollment.acceptUserProvision(secondBundle, peer: peers.b),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expect(await sqlSnapshot(c.db), beforeSql);
      expect(protectedUnchanged(c.store, beforeProtected), isTrue);
      expect(c.enrollment.currentCompanySession, same(selected));
      expect(
        (await c.enrollment.listCompanyUsers()).map((user) => user.userId),
        isNot(contains(second.userId)),
      );
    } finally {
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 4)));

  for (final third in [false, true]) {
    test(
      'rootless Owner on ${third ? 'C' : 'D1'} cannot issue or create a user',
      () async {
        final f = await JoinFixture.create();
        await activateFixtureB(f);
        await f.bEnrollment.signIn('1234');
        final user = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Existing builder',
          pin: '4567',
        );
        await provisionInitialUser(f.aEnrollment, f.bEnrollment, user.userId);
        final c = third ? await thirdInstallation(f) : null;
        final enrollment = c?.enrollment ?? f.bEnrollment;
        final db = c?.db ?? f.bDb;
        final store = c?.store ?? f.bStore;
        if (c != null) {
          await provisionInitialUser(f.aEnrollment, enrollment, user.userId);
        }
        final rootlessOwner = enrollment.currentSession!;
        expect(rootlessOwner.identity.userId, f.owner.identity.userId);
        expect(rootlessOwner.identity.isAuthorityOwner, isFalse);
        final peers = await initialProvisionPeers(enrollment, f.aEnrollment);
        try {
          final beforeSql = await sqlSnapshot(db);
          final beforeProtected = Map.of(store.states);
          await expectLater(
            enrollment.prepareUserProvisionInvitation(
              owner: rootlessOwner,
              peer: peers.a,
              userId: user.userId,
              requestId: const Uuid().v4(),
            ),
            throwsA(isA<CompanyBootstrapRefusal>()),
          );
          await expectLater(
            enrollment.createRestrictedUser(
              owner: rootlessOwner,
              requestId: const Uuid().v4(),
              name: 'Refused rootless grant',
              pin: '6789',
            ),
            throwsA(isA<CompanyBootstrapRefusal>()),
          );
          expect(await sqlSnapshot(db), beforeSql);
          expect(protectedUnchanged(store, beforeProtected), isTrue);
          expect(enrollment.currentSession, same(rootlessOwner));
        } finally {
          await peers.ac.dispose();
          await peers.bc.dispose();
        }
      },
      timeout: const Timeout(Duration(minutes: 4)),
    );
  }

  for (final signOut in [true, false]) {
    test(
      'receiver ${signOut ? 'signout' : 'session replacement'} before accept refuses without mutation',
      () async {
        final f = await JoinFixture.create();
        await activateFixtureB(f);
        await f.bEnrollment.signIn('1234');
        final first = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Selected builder',
          pin: '0123',
        );
        final second = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Offered builder',
          pin: '4567',
        );
        await provisionInitialUser(f.aEnrollment, f.bEnrollment, second.userId);
        final c = await thirdInstallation(f);
        await provisionInitialUser(f.aEnrollment, c.enrollment, first.userId);
        final selected = await c.enrollment.signInUser(first.userId, '0123');
        final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
        try {
          final bundle = await initialProvisionBundle(
            f.aEnrollment,
            c.enrollment,
            second.userId,
            peers.a,
            peers.b,
            requestId: const Uuid().v4(),
          );
          if (signOut) {
            await c.enrollment.signOut();
          } else {
            await c.enrollment.signInUser(first.userId, '0123');
          }
          expect(selected.isValid, isFalse);
          final beforeSql = await sqlSnapshot(c.db);
          final beforeProtected = Map.of(c.store.states);
          await expectLater(
            c.enrollment.acceptUserProvision(bundle, peer: peers.b),
            throwsA(isA<CompanyBootstrapRefusal>()),
          );
          expect(await sqlSnapshot(c.db), beforeSql);
          expect(protectedUnchanged(c.store, beforeProtected), isTrue);
          expect(
            (await c.enrollment.listCompanyUsers()).map((user) => user.userId),
            isNot(contains(second.userId)),
          );
        } finally {
          await peers.ac.dispose();
          await peers.bc.dispose();
        }
      },
      timeout: const Timeout(Duration(minutes: 4)),
    );
  }

  test('seventeen real rotations retain sequence 18 and refuse initial profile history overflow', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Rotated builder',
      pin: '0123',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, user.userId);
    for (var version = 1; version <= 17; version++) {
      final receipt = await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: version,
        pin: (2000 + version).toString(),
      );
      expect(receipt.credentialVersion, version + 1);
    }
    final c = await thirdInstallation(f);
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    try {
      final history = (await f.aDb.select(f.aDb.companyUserEvents).get())
          .where((event) => event.userId == user.userId)
          .toList();
      expect(
        history.map((event) => event.sequence).toSet(),
        containsAll(List.generate(17, (i) => i + 2)),
      );
      expect(history.where((event) => event.sequence == 18), hasLength(1));
      expect(
        (await f.aEnrollment.userLifecycleStatus(userId: user.userId))!
            .credentialVersion,
        18,
      );
      final beforeSourceSql = await sqlSnapshot(f.aDb);
      final beforeSourceProtected = Map.of(f.aStore.states);
      final beforeRecipientSql = await sqlSnapshot(c.db);
      final beforeRecipientProtected = Map.of(c.store.states);
      await expectLater(
        initialProvisionBundle(
          f.aEnrollment,
          c.enrollment,
          user.userId,
          peers.a,
          peers.b,
          requestId: const Uuid().v4(),
        ),
        throwsA(
          isA<CompanyBootstrapRefusal>().having(
            (failure) => failure.toString(),
            'reason',
            contains('Initial user history exceeds profile'),
          ),
        ),
      );
      expect(await sqlSnapshot(f.aDb), beforeSourceSql);
      expect(protectedUnchanged(f.aStore, beforeSourceProtected), isTrue);
      expect(await sqlSnapshot(c.db), beforeRecipientSql);
      expect(protectedUnchanged(c.store, beforeRecipientProtected), isTrue);
    } finally {
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 12)));

  test('128 actual Owner authorizations fill capacity and 129th refuses before private export', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Capacity builder',
      pin: '0123',
    );
    final grantCount =
        (await f.aDb.select(f.aDb.companyUserCredentialGrants).get()).length;
    final original = Cryptography.instance;
    expect(identical(original, DartCryptography.defaultInstance), isTrue);
    final observer = _PrivateExportObserver();
    try {
      for (var batch = 0; batch < 32; batch++) {
        final peers = await initialProvisionPeers(f.aEnrollment, f.bEnrollment);
        try {
          for (var offset = 0; offset < 4; offset++) {
            final bundle = await initialProvisionBundle(
              f.aEnrollment,
              f.bEnrollment,
              user.userId,
              peers.a,
              peers.b,
              requestId: const Uuid().v4(),
            );
            expect(bundle.keys, containsAll(['box', 'issuance']));
          }
          expect(
            (await f.aDb.select(f.aDb.companyUserCredentialGrants).get())
                .length,
            grantCount + (batch + 1) * 4,
          );
        } finally {
          await peers.ac.dispose();
          await peers.bc.dispose();
        }
      }
      expect(
        (await f.aDb.select(f.aDb.companyUserCredentialGrants).get()).length,
        grantCount + 128,
      );
      Cryptography.instance = observer;
      final peers = await initialProvisionPeers(f.aEnrollment, f.bEnrollment);
      try {
        final sourceSql = await sqlSnapshot(f.aDb);
        final sourceProtected = Map.of(f.aStore.states);
        final recipientSql = await sqlSnapshot(f.bDb);
        final recipientProtected = Map.of(f.bStore.states);
        await expectLater(
          initialProvisionBundle(
            f.aEnrollment,
            f.bEnrollment,
            user.userId,
            peers.a,
            peers.b,
            requestId: const Uuid().v4(),
          ),
          throwsA(
            isA<CompanyBootstrapRefusal>().having(
              (failure) => failure.toString(),
              'reason',
              contains('Initial user authorization capacity reached'),
            ),
          ),
        );
        expect(observer.privateSignatures, 0);
        expect(await sqlSnapshot(f.aDb), sourceSql);
        expect(protectedUnchanged(f.aStore, sourceProtected), isTrue);
        expect(await sqlSnapshot(f.bDb), recipientSql);
        expect(protectedUnchanged(f.bStore, recipientProtected), isTrue);
      } finally {
        await peers.ac.dispose();
        await peers.bc.dispose();
      }
    } finally {
      Cryptography.instance = original;
    }
  }, timeout: const Timeout(Duration(minutes: 30)));
}

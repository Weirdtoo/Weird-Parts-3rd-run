import 'dart:io';
import 'dart:convert';
import 'dart:async';

import 'package:drift/native.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';

import 'company_join_test.dart'
    show
        JoinFixture,
        JoinActivationStore,
        activateFixtureB,
        joinChannels,
        sqlSnapshot;
import 'company_created_job_sync_test.dart' show syncAttackWire;

String initialTestCanonical(Object? value) {
  Object? sort(Object? v) => v is Map
      ? {for (final k in v.keys.cast<String>().toList()..sort()) k: sort(v[k])}
      : v is List
      ? v.map(sort).toList()
      : v;
  return jsonEncode(sort(value));
}

Future<Map<String, Object?>> authenticatedUserProbeFault(
  NearbyPairedJoinSession pair,
  Map<String, Object?> wire,
  void Function(Map<String, Object?> body) change,
) async {
  final keys = pair.keys;
  final kdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final join = await kdf.deriveKey(
    secretKey: keys.sendKey,
    nonce: utf8.encode(keys.id),
    info: utf8.encode('wiredpart-v2/company-join@1/${keys.sendDirection}'),
  );
  final user = await kdf.deriveKey(
    secretKey: join,
    nonce: utf8.encode(keys.id),
    info: utf8.encode(
      'wiredpart-v2/company-user-provision@1/${keys.sendDirection}',
    ),
  );
  final header = Map<String, Object?>.from(wire)
    ..remove('nonce')
    ..remove('ciphertext')
    ..remove('tag');
  final aad = utf8.encode(initialTestCanonical(header));
  final plain = await AesGcm.with256bits().decrypt(
    SecretBox(
      base64Decode(wire['ciphertext'] as String),
      nonce: base64Decode(wire['nonce'] as String),
      mac: Mac(base64Decode(wire['tag'] as String)),
    ),
    secretKey: user,
    aad: aad,
  );
  final signed = Map<String, Object?>.from(
    jsonDecode(utf8.decode(plain)) as Map,
  );
  final body = Map<String, Object?>.from(signed['body'] as Map);
  change(body);
  signed['body'] = body;
  final changed = await AesGcm.with256bits().encrypt(
    utf8.encode(initialTestCanonical(signed)),
    secretKey: user,
    aad: aad,
  );
  return {
    ...header,
    'nonce': base64Encode(changed.nonce),
    'ciphertext': base64Encode(changed.cipherText),
    'tag': base64Encode(changed.mac.bytes),
  };
}

final class HoldInstalledSignature extends DartCryptography {
  final entered = Completer<void>();
  final release = Completer<void>();
  @override
  Ed25519 ed25519() => _HeldInstalledSignature(this);
}

final class _HeldInstalledSignature extends DartEd25519 {
  _HeldInstalledSignature(this.owner);
  final HoldInstalledSignature owner;
  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
    PublicKey? publicKey,
  }) async {
    final result = await super.sign(
      message,
      keyPair: keyPair,
      publicKey: publicKey,
    );
    final prefix = utf8.encode(
      'wiredpart.company.user.initial-provision.installed@2:',
    );
    if (message.length >= prefix.length &&
        !owner.entered.isCompleted &&
        List.generate(
          prefix.length,
          (i) => message[i] == prefix[i],
        ).every((v) => v)) {
      owner.entered.complete();
      await owner.release.future;
    }
    return result;
  }
}

final class ObserveInitialWireSignature extends DartCryptography {
  ObserveInitialWireSignature(this.observed);
  final void Function() observed;
  @override
  Ed25519 ed25519() => _ObservedInitialWireSignature(this);
}

final class _ObservedInitialWireSignature extends DartEd25519 {
  _ObservedInitialWireSignature(this.owner);
  final ObserveInitialWireSignature owner;
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
      'wiredpart.company.user.initial-provision.issuance@2:',
    );
    if (message.length >= prefix.length &&
        List.generate(
          prefix.length,
          (i) => message[i] == prefix[i],
        ).every((v) => v)) {
      owner.observed();
    }
    return signature;
  }
}

bool protectedBytesEqual(
  ProtectedInstallationState a,
  ProtectedInstallationState b,
) =>
    a.bytes.length == b.bytes.length &&
    List.generate(
      a.bytes.length,
      (i) => a.bytes[i] == b.bytes[i],
    ).every((same) => same);

bool protectedUnchanged(
  JoinActivationStore store,
  Map<String, ProtectedInstallationState> before,
) =>
    store.states.length == before.length &&
    before.entries.every((entry) {
      final now = store.states[entry.key];
      return now != null &&
          now.revision == entry.value.revision &&
          now.bytes.length == entry.value.bytes.length &&
          List.generate(
            now.bytes.length,
            (i) => now.bytes[i] == entry.value.bytes[i],
          ).every((v) => v);
    });

Future<Map<String, Object?>> initialProvisionBundle(
  CompanyEnrollment authority,
  CompanyEnrollment recipient,
  String userId,
  VerifiedPeerMembership sender,
  VerifiedPeerMembership receiver, {
  String? requestId,
}) async {
  var invitation = await authority.prepareUserProvisionInvitation(
    owner: authority.currentSession!,
    peer: sender,
    userId: userId,
    requestId: requestId,
  );
  if (invitation['kind'] == 'user-initial-provision-probe@2') {
    invitation = await authority.receiveUserProvisionNegotiation(
      await recipient.receiveUserProvisionNegotiation(
        invitation,
        peer: receiver,
      ),
      peer: sender,
    );
  }
  final request = await recipient.acceptUserProvisionInvitation(
    await recipient.receiveUserProvisionInvitation(invitation, peer: receiver),
  );
  return authority.prepareUserProvision(
    owner: authority.currentSession!,
    peer: sender,
    request: await authority.receiveUserProvisionRequest(request, peer: sender),
  );
}

Future<
  ({
    VerifiedPeerMembership a,
    VerifiedPeerMembership b,
    NearbyController ac,
    NearbyController bc,
  })
>
initialProvisionPeers(
  CompanyEnrollment authority,
  CompanyEnrollment recipient, {
  Future<void> Function(CompanyPeerProofCheckpoint)? onSourceCheckpoint,
}) async {
  final sender = authority.currentCompanySession!;
  final receiver = recipient.currentCompanySession!;
  late NearbyController ac, bc;
  final (bChannel, aChannel) = await joinChannels(
    onPaired: (b, a) {
      bc = b;
      ac = a;
    },
  );
  final aa = CompanyPeerAuthentication(
    enrollment: authority,
    onProofCheckpoint: onSourceCheckpoint,
  );
  final ba = CompanyPeerAuthentication(enrollment: recipient);
  final selected = (await aa.retainedPeers(session: sender))
      .singleWhere((p) => p.deviceId == receiver.identity.deviceId);
  final first = await aa.beginPeerChallenge(
    aChannel,
    selected,
    session: sender,
  );
  final second = await ba.receivePeerChallenge(
    bChannel,
    first,
    session: receiver,
  );
  final third = await aa.receivePeerResponse(aChannel, second);
  final done = await ba.receivePeerCompletion(bChannel, third);
  final a = await aa.receivePeerAcknowledgment(aChannel, done.acknowledgment);
  return (a: a, b: done.membership, ac: ac, bc: bc);
}

Future<void> provisionInitialUser(
  CompanyEnrollment authority,
  CompanyEnrollment recipient,
  String userId, {
  String? requestId,
}) async {
  final peers = await initialProvisionPeers(authority, recipient);
  try {
    final bundle = await initialProvisionBundle(
      authority,
      recipient,
      userId,
      peers.a,
      peers.b,
      requestId: requestId,
    );
    final ack = await recipient.acceptUserProvision(bundle, peer: peers.b);
    await authority.acceptUserProvisionReceipt(
      ack,
      peer: peers.a,
      userId: userId,
    );
  } finally {
    await peers.ac.dispose();
    await peers.bc.dispose();
  }
}

Future<
  ({
    AppDatabase db,
    JoinActivationStore store,
    InstallationSecurity installation,
    CompanyEnrollment enrollment,
  })
>
thirdInstallation(JoinFixture f) async {
  final db = AppDatabase.forTesting(
    NativeDatabase(File('${f.root.path}/c.sqlite')),
  );
  addTearDown(db.close);
  final store = JoinActivationStore();
  final installation = InstallationSecurity(
    store: store,
    namespace: 'synthetic.initial-c',
  );
  await installation.start(db);
  final enrollment = CompanyEnrollment(installation: installation, db: db);
  final cj = CompanyJoin(enrollment: enrollment);
  final aj = CompanyJoin(enrollment: f.aEnrollment);
  final (cc, ac) = await joinChannels();
  await cj.acceptProvision(
    await cj.receiveProvision(
      cc,
      await aj.approveJoin(
        ac,
        await aj.receiveJoinRequest(ac, await cj.beginJoin(cc)),
        ownerSession: f.aEnrollment.currentSession!,
      ),
    ),
  );
  cc.close();
  ac.close();
  await enrollment.signIn('1234');
  return (
    db: db,
    store: store,
    installation: installation,
    enrollment: enrollment,
  );
}

Future<void> transferCurrentUser(
  CompanyEnrollment authority,
  CompanyEnrollment recipient,
  String userId, {
  bool interruptPrivate = false,
}) async {
  final peers = await initialProvisionPeers(authority, recipient);
  try {
    final target = await authority.verifyUserLifecycleOffer(
      await recipient.createUserLifecycleOffer(peers.b, userId: userId),
      peers.a,
    );
    final source = await recipient.verifyUserLifecycleOffer(
      await authority.createUserLifecycleOffer(peers.a, userId: userId),
      peers.b,
    );
    final policy = await authority.prepareUserDisablePolicy(peers.a, target);
    expect(policy, isNotNull);
    if (interruptPrivate) {
      final secret = Map<String, Object?>.from(policy!['secret'] as Map);
      final tag = base64Decode(secret['tag'] as String);
      tag[0] ^= 1;
      final receiver = CompanyCreatedJobSync(
        availability: await CompanyJobSyncAvailability.open(
          enrollment: recipient,
          owner: recipient.currentCompanySession!,
          peer: peers.b,
        ),
        controller: peers.bc,
      );
      try {
        final run = const Uuid().v4();
        final users =
            (await authority.listCompanyUsers())
                .skip(1)
                .map((u) => u.userId)
                .toList()
              ..sort();
        final key = base64Encode(recipient.installation.identity!.publicKey);
        await receiver.receive(
          await syncAttackWire(
            peers.ac.pairedJoinSession!,
            key,
            run,
            'profile',
            {
              'profile': '$kCompanyUserProfile/job.create.authorization@4',
              'capacity': kCompanyUserCapacity,
              'users': users,
            },
          ),
        );
        await receiver.receive(
          await syncAttackWire(
            peers.ac.pairedJoinSession!,
            key,
            run,
            'policyOffer',
            {
              'offer': await authority.createUserLifecycleOffer(
                peers.a,
                userId: userId,
              ),
            },
          ),
        );
        // Authenticated-message fault injection. Outer AEAD remains valid;
        // only the nested private credential tag is damaged.
        await expectLater(
          receiver.receive(
            await syncAttackWire(
              peers.ac.pairedJoinSession!,
              key,
              run,
              'policy',
              {
                'policy': {
                  ...policy,
                  'secret': {...secret, 'tag': base64Encode(tag)},
                },
              },
            ),
          ),
          throwsA(isA<Exception>()),
        );
      } finally {
        await receiver.closeAndDrain();
      }
      return;
    }
    final receipt = await recipient.acceptUserDisablePolicy(
      policy,
      peers.b,
      source,
    );
    await authority.acceptUserDisableReceipt(receipt, peers.a, userId: userId);
  } finally {
    await peers.ac.dispose();
    await peers.bc.dispose();
  }
}

void main() {
  test('target reset during final awaited peer check prevents sealed credential release', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'B builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: b.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '2345',
    );
    final c = await thirdInstallation(f);
    final reached = Completer<void>();
    final release = Completer<void>();
    var sealed = false;
    var checks = 0;
    final peers = await initialProvisionPeers(
      f.aEnrollment,
      c.enrollment,
      onSourceCheckpoint: (stage) async {
        if (sealed &&
            stage == CompanyPeerProofCheckpoint.afterExporter &&
            ++checks == 3) {
          reached.complete();
          await release.future;
        }
      },
    );
    final original = Cryptography.instance;
    try {
      final cSql = await sqlSnapshot(c.db);
      final cProtected = Map.of(c.store.states);
      Cryptography.instance = ObserveInitialWireSignature(() => sealed = true);
      final pending = initialProvisionBundle(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        peers.a,
        peers.b,
      );
      await reached.future.timeout(const Duration(seconds: 45));
      Cryptography.instance = original;
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: b.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 2,
        pin: '3456',
      );
      release.complete();
      await expectLater(pending, throwsA(isA<CompanyBootstrapRefusal>()));
      expect(
        (await f.aEnrollment.userLifecycleStatus(userId: b.userId))!
            .credentialVersion,
        3,
      );
      expect(await sqlSnapshot(c.db), cSql);
      expect(protectedUnchanged(c.store, cProtected), isTrue);
    } finally {
      Cryptography.instance = original;
      if (!release.isCompleted) release.complete();
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('malformed pending authorization before first CAS cannot disappear as legacy', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final a = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'A builder',
      pin: '0123',
    );
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'B builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, a.userId);
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    final c = await thirdInstallation(f);
    await provisionInitialUser(f.aEnrollment, c.enrollment, a.userId);
    await c.enrollment.signInUser(a.userId, '0123');
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    final namespace = companyUserNamespace(c.installation.namespace, slot: 2);
    var interrupted = false;
    try {
      final bundle = await initialProvisionBundle(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        peers.a,
        peers.b,
      );
      c.store.beforeRead = (name) {
        if (interrupted || name != namespace || c.db.hasCallerTransaction)
          return null;
        return (() async {
          final rows = await c.db
              .select(c.db.companyUserCredentialGrants)
              .get();
          if (rows.any((r) => r.userId == b.userId)) {
            interrupted = true;
            throw StateError(
              'simulated interruption before first protected user CAS',
            );
          }
        })();
      };
      await expectLater(
        c.enrollment.acceptUserProvision(bundle, peer: peers.b),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    } finally {
      c.store.beforeRead = null;
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
    expect(interrupted, isTrue);
    expect(c.store.states.containsKey(namespace), isFalse);
    await c.enrollment.signInUser(a.userId, '0123');
    await c.db.customStatement(
      'UPDATE company_user_credential_grants SET grant_bytes = ? WHERE company_id = ? AND user_id = ?',
      ['{}', f.owner.identity.companyId, b.userId],
    );
    final beforeSql = await sqlSnapshot(c.db);
    final beforeProtected = Map.of(c.store.states);
    await expectLater(
      provisionInitialUser(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        requestId: const Uuid().v4(),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(c.db), beforeSql);
    expect(protectedUnchanged(c.store, beforeProtected), isTrue);
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('policy ACK and historic store receipt cannot report current credential confirmation', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'B builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    expect(
      (await f.aEnrollment.userProvisionStatus(
        f.owner,
        userId: b.userId,
      ))!.confirmed,
      isTrue,
    );
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: b.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '2345',
    );
    final c = await thirdInstallation(f);
    await transferCurrentUser(f.aEnrollment, c.enrollment, b.userId);
    expect(
      (await f.aEnrollment.userProvisionStatus(
        f.owner,
        userId: b.userId,
      ))!.confirmed,
      isFalse,
    );
    await provisionInitialUser(f.aEnrollment, c.enrollment, b.userId);
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    try {
      final old = await f.aEnrollment.userProvisionStatus(
        f.owner,
        userId: b.userId,
        peer: peers.a,
      );
      expect(old!.confirmed, isFalse);
      final probe = await f.aEnrollment.prepareUserProvisionInvitation(
        owner: f.owner,
        peer: peers.a,
        userId: b.userId,
      );
      await f.aEnrollment.receiveUserProvisionNegotiation(
        await c.enrollment.receiveUserProvisionNegotiation(
          probe,
          peer: peers.b,
        ),
        peer: peers.a,
      );
      expect(
        (await f.aEnrollment.userProvisionStatus(
          f.owner,
          userId: b.userId,
          peer: peers.a,
        ))!.confirmed,
        isTrue,
      );
    } finally {
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 4)));
  test('inbound provenance changed after authorization is refused at exact private CAS', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final a = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'A builder',
      pin: '0123',
    );
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'B builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, a.userId);
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: b.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '2345',
    );
    final c = await thirdInstallation(f);
    await provisionInitialUser(f.aEnrollment, c.enrollment, a.userId);
    await c.enrollment.signInUser(a.userId, '0123');
    await transferCurrentUser(
      f.aEnrollment,
      c.enrollment,
      b.userId,
      interruptPrivate: true,
    );
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    final reached = Completer<void>();
    final release = Completer<void>();
    var intercepted = false;
    final namespace = companyUserNamespace(c.installation.namespace, slot: 2);
    try {
      final bundle = await initialProvisionBundle(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        peers.a,
        peers.b,
      );
      c.store.beforeRead = (name) {
        if (intercepted || name != namespace || c.db.hasCallerTransaction)
          return null;
        return (() async {
          final rows = await c.db
              .select(c.db.companyUserCredentialGrants)
              .get();
          if (!rows.any((r) => r.userId == b.userId)) return;
          intercepted = true;
          reached.complete();
          await release.future;
        })();
      };
      final pending = c.enrollment.acceptUserProvision(bundle, peer: peers.b);
      await reached.future.timeout(const Duration(seconds: 45));
      c.store.beforeRead = null;
      final target = await c.enrollment.verifyUserLifecycleOffer(
        await f.aEnrollment.createUserLifecycleOffer(peers.a, userId: b.userId),
        peers.b,
      );
      final outbound = await c.enrollment.prepareUserDisablePolicy(
        peers.b,
        target,
      );
      expect(outbound!['secret'], isNull);
      final beforeSql = await sqlSnapshot(c.db);
      final beforeProtected = Map.of(c.store.states);
      release.complete();
      await expectLater(pending, throwsA(isA<CompanyBootstrapRefusal>()));
      expect(await sqlSnapshot(c.db), beforeSql);
      expect(protectedUnchanged(c.store, beforeProtected), isTrue);
      expect(
        (await c.enrollment.userLifecycleStatus(userId: b.userId))!
            .awaitingCredential,
        isTrue,
      );
    } finally {
      c.store.beforeRead = null;
      if (!release.isCompleted) release.complete();
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
  test('authenticated malformed probes and changed recipient store refuse before admission', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Existing builder',
      pin: '0123',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, user.userId);
    final c = await thirdInstallation(f);
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    try {
      final probe = await f.aEnrollment.prepareUserProvisionInvitation(
        owner: f.owner,
        peer: peers.a,
        userId: user.userId,
      );
      expect(probe['kind'], 'user-initial-provision-probe@2');
      final beforeSql = await sqlSnapshot(c.db);
      final beforeProtected = Map.of(c.store.states);
      for (final fault in <void Function(Map<String, Object?>)>[
        (b) => b['v'] = 2.0,
        (b) => b['profile'] = 'unsupported',
        (b) => b['capacity'] = 3,
        (b) => b['unknown'] = true,
        (b) => b['request'] = const Uuid().v4(),
        (b) => b['recipient'] = {...b['recipient'] as Map, 'unknown': true},
      ]) {
        final bad = await authenticatedUserProbeFault(
          peers.ac.pairedJoinSession!,
          probe,
          fault,
        );
        await expectLater(
          c.enrollment.receiveUserProvisionNegotiation(bad, peer: peers.b),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
        expect(await sqlSnapshot(c.db), beforeSql);
        expect(protectedUnchanged(c.store, beforeProtected), isTrue);
      }
      final response = await c.enrollment.receiveUserProvisionNegotiation(
        probe,
        peer: peers.b,
      );
      final invitation = await f.aEnrollment.receiveUserProvisionNegotiation(
        response,
        peer: peers.a,
      );
      final binding = jsonDecode(
        (await c.db.settingsDao.getSetting(kInstallationBindingKey))!,
      ) as Map;
      binding['store'] = const Uuid().v4();
      await c.db.settingsDao.setSetting(
        kInstallationBindingKey,
        jsonEncode(binding),
      );
      final changedSql = await sqlSnapshot(c.db);
      final rootSql = await sqlSnapshot(f.aDb);
      await expectLater(
        c.enrollment.receiveUserProvisionInvitation(invitation, peer: peers.b),
        throwsA(
          predicate((e) => e is CompanyBootstrapRefusal || e is StateError),
        ),
      );
      expect(await sqlSnapshot(c.db), changedSql);
      expect(protectedUnchanged(c.store, beforeProtected), isTrue);
      expect(await sqlSnapshot(f.aDb), rootSql);
    } finally {
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 4)));
  test(
    'first explicit version-two provision never downgrades a later invitation',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      await f.bEnrollment.signIn('1234');
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Existing builder',
        pin: '0123',
      );
      await provisionInitialUser(
        f.aEnrollment,
        f.bEnrollment,
        user.userId,
        requestId: const Uuid().v4(),
      );
      await expectLater(
        f.bEnrollment.signInUser(user.userId, '9999'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      await f.bEnrollment.signIn('1234');
      final before = Map.of(f.bStore.states);
      await provisionInitialUser(f.aEnrollment, f.bEnrollment, user.userId);
      expect(protectedUnchanged(f.bStore, before), isTrue);
    },
    timeout: const Timeout(Duration(minutes: 4)),
  );

  test('current head changed after actual installed signature cannot return or store stale ACK', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final a = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'A builder',
      pin: '0123',
    );
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'B builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, a.userId);
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: b.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '2345',
    );
    final c = await thirdInstallation(f);
    await provisionInitialUser(f.aEnrollment, c.enrollment, a.userId);
    await c.enrollment.signInUser(a.userId, '0123');
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    final originalCrypto = Cryptography.instance;
    final hook = HoldInstalledSignature();
    try {
      final bundle = await initialProvisionBundle(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        peers.a,
        peers.b,
      );
      Cryptography.instance = hook;
      final pending = c.enrollment.acceptUserProvision(bundle, peer: peers.b);
      await hook.entered.future.timeout(const Duration(seconds: 45));
      Cryptography.instance = originalCrypto;
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: b.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 2,
        pin: '3456',
      );
      final target = await f.aEnrollment.verifyUserLifecycleOffer(
        await c.enrollment.createUserLifecycleOffer(peers.b, userId: b.userId),
        peers.a,
      );
      final source = await c.enrollment.verifyUserLifecycleOffer(
        await f.aEnrollment.createUserLifecycleOffer(peers.a, userId: b.userId),
        peers.b,
      );
      final current = await f.aEnrollment.prepareUserDisablePolicy(
        peers.a,
        target,
      );
      final receipt = await c.enrollment.acceptUserDisablePolicy(
        current,
        peers.b,
        source,
      );
      await f.aEnrollment.acceptUserDisableReceipt(
        receipt,
        peers.a,
        userId: b.userId,
      );
      hook.release.complete();
      await expectLater(pending, throwsA(isA<CompanyBootstrapRefusal>()));
      final grants = await f.aDb
          .select(f.aDb.companyUserCredentialGrants)
          .get();
      expect(
        grants.where((r) {
          final body = (jsonDecode(r.grantBytes) as Map)['body'] as Map;
          return body['kind'] == 'company.user.credential.grant@1' &&
              body['user'] == b.userId &&
              (body['recipient'] as List)[0] ==
                  c.enrollment.currentCompanySession!.identity.deviceId;
        }),
        isEmpty,
      );
      final deliveries = await c.db.select(c.db.companyUserDeliveries).get();
      expect(
        deliveries.where(
          (r) =>
              r.userId == b.userId &&
              ((jsonDecode(r.receiptBytes) as Map)['body'] as Map)['kind'] ==
                  'company.user.initial-provision.installed@2',
        ),
        isEmpty,
      );
      expect(
        (await c.enrollment.userLifecycleStatus(userId: b.userId))!
            .credentialVersion,
        3,
      );
      final installedThree = Map.of(c.store.states);
      final oldAuthorization =
          (await c.db.select(c.db.companyUserCredentialGrants).get())
              .where((r) => r.userId == b.userId)
              .toList();
      await provisionInitialUser(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        requestId: const Uuid().v4(),
      );
      expect(protectedUnchanged(c.store, installedThree), isTrue);
      expect(
        await c.db.select(c.db.companyUserCredentialGrants).get(),
        containsAll(oldAuthorization),
      );
      await c.enrollment.signInUser(b.userId, '3456');
    } finally {
      Cryptography.instance = originalCrypto;
      if (!hook.release.isCompleted) hook.release.complete();
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
  test(
    'existing B4 installs its history on empty C without another reset',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      await f.bEnrollment.signIn('1234');
      final b = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Existing B',
        pin: '1235',
      );
      await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
      for (final (version, pin) in [(1, '2345'), (2, '3456'), (3, '4567')]) {
        await f.aEnrollment.resetRestrictedUserPin(
          owner: f.owner,
          userId: b.userId,
          requestId: const Uuid().v4(),
          expectedCredentialVersion: version,
          pin: pin,
        );
      }
      final sourceEvents = await f.aDb.select(f.aDb.companyUserEvents).get();
      final d1Protected = Map.of(f.bStore.states);
      final c = await thirdInstallation(f);
      final sourceProtected = Map.of(f.aStore.states);
      await provisionInitialUser(f.aEnrollment, c.enrollment, b.userId);
      expect(
        (await c.enrollment.userLifecycleStatus(userId: b.userId))!
            .credentialVersion,
        4,
      );
      expect(await f.aDb.select(f.aDb.companyUserEvents).get(), sourceEvents);
      expect(protectedUnchanged(f.aStore, sourceProtected), isTrue);
      expect(protectedUnchanged(f.bStore, d1Protected), isTrue);
      expect(await c.db.select(c.db.companyUserEvents).get(), hasLength(4));
      await c.enrollment.signOut();
      final reopened = InstallationSecurity(
        store: c.store,
        namespace: c.installation.namespace,
      );
      await reopened.start(c.db);
      final enrollment = CompanyEnrollment(installation: reopened, db: c.db);
      expect(enrollment.currentCompanySession, isNull);
      final session = await enrollment.signInUser(b.userId, '4567');
      expect(session.identity.userId, b.userId);
      expect(reopened.identity!.id, c.installation.identity!.id);
      expect(c.store.maximumBytes, lessThanOrEqualTo(kInstallationStateLimit));
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
  test('request collision crosses user rows and restricted issuer cannot export ungranted B', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final a = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'A builder',
      pin: '0123',
    );
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'B builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, a.userId);
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    final c = await thirdInstallation(f);
    final request = const Uuid().v4();
    await provisionInitialUser(
      f.aEnrollment,
      c.enrollment,
      a.userId,
      requestId: request,
    );
    final beforeSql = await sqlSnapshot(f.aDb);
    final beforeProtected = Map.of(f.aStore.states);
    final cSql = await sqlSnapshot(c.db);
    final cProtected = Map.of(c.store.states);
    await expectLater(
      provisionInitialUser(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        requestId: request,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(f.aDb), beforeSql);
    expect(protectedUnchanged(f.aStore, beforeProtected), isTrue);
    expect(await sqlSnapshot(c.db), cSql);
    expect(protectedUnchanged(c.store, cProtected), isTrue);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: b.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '2345',
    );
    await f.aEnrollment.signInUser(a.userId, '0123');
    await c.enrollment.signInUser(a.userId, '0123');
    final peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    try {
      final target = await f.aEnrollment.verifyUserLifecycleOffer(
        await c.enrollment.createUserLifecycleOffer(peers.b, userId: b.userId),
        peers.a,
      );
      final rootSql = await sqlSnapshot(f.aDb);
      final rootProtected = Map.of(f.aStore.states);
      await expectLater(
        f.aEnrollment.prepareUserDisablePolicy(peers.a, target),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expect(await sqlSnapshot(f.aDb), rootSql);
      expect(protectedUnchanged(f.aStore, rootProtected), isTrue);
      expect(
        (await c.enrollment.listCompanyUsers()).map((u) => u.userId),
        isNot(contains(b.userId)),
      );
    } finally {
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('ambiguous partial rejects new request after outbound rewrite and recovers through Owner Sync', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final a = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'A builder',
      pin: '0123',
    );
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'B builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, a.userId);
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: b.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '2345',
    );
    final c = await thirdInstallation(f);
    await provisionInitialUser(f.aEnrollment, c.enrollment, a.userId);
    await c.enrollment.signInUser(a.userId, '0123');
    var peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    final r0 = const Uuid().v4();
    final bundle = await initialProvisionBundle(
      f.aEnrollment,
      c.enrollment,
      b.userId,
      peers.a,
      peers.b,
      requestId: r0,
    );
    final namespace = companyUserNamespace(c.installation.namespace, slot: 2);
    c.store.onRead = (name) {
      final saved = c.store.states[name];
      if (name != namespace || saved == null) return;
      final state = jsonDecode(utf8.decode(saved.bytes)) as Map;
      if (state['v'] == 3 && state['p'] == null && state['j'] == null) {
        throw StateError(
          'simulated interruption before private credential CAS',
        );
      }
    };
    await expectLater(
      c.enrollment.acceptUserProvision(bundle, peer: peers.b),
      throwsA(isA<Exception>()),
    );
    c.store.onRead = null;
    await peers.ac.dispose();
    await peers.bc.dispose();
    await c.enrollment.signInUser(a.userId, '0123');
    final partialSql = await sqlSnapshot(c.db);
    final partialProtected = Map.of(c.store.states);
    await expectLater(
      provisionInitialUser(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        requestId: r0,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(c.db), partialSql);
    expect(protectedUnchanged(c.store, partialProtected), isTrue);
    peers = await initialProvisionPeers(f.aEnrollment, c.enrollment);
    try {
      final target = await c.enrollment.verifyUserLifecycleOffer(
        await f.aEnrollment.createUserLifecycleOffer(peers.a, userId: b.userId),
        peers.b,
      );
      final public = await c.enrollment.prepareUserDisablePolicy(
        peers.b,
        target,
      );
      expect(public!['secret'], isNull);
    } finally {
      await peers.ac.dispose();
      await peers.bc.dispose();
    }
    final outbound =
        jsonDecode(utf8.decode(c.store.states[namespace]!.bytes)) as Map;
    expect((outbound['o'] as List)[0], 0);
    expect(outbound['p'] == null, isTrue);
    await c.db.customStatement(
      'DELETE FROM company_user_credential_grants WHERE company_id = ? AND user_id = ?',
      [f.owner.identity.companyId, b.userId],
    );
    final attackedSql = await sqlSnapshot(c.db);
    final attackedProtected = Map.of(c.store.states);
    final r1 = const Uuid().v4();
    await expectLater(
      provisionInitialUser(
        f.aEnrollment,
        c.enrollment,
        b.userId,
        requestId: r1,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(c.db), attackedSql);
    expect(protectedUnchanged(c.store, attackedProtected), isTrue);
    await transferCurrentUser(f.aEnrollment, c.enrollment, b.userId);
    await provisionInitialUser(
      f.aEnrollment,
      c.enrollment,
      b.userId,
      requestId: r1,
    );
    expect(
      (await c.enrollment.userLifecycleStatus(userId: b.userId))!
          .credentialVersion,
      2,
    );
    await c.enrollment.signInUser(b.userId, '2345');
    expect(c.store.maximumBytes, lessThanOrEqualTo(kInstallationStateLimit));
  }, timeout: const Timeout(Duration(minutes: 6)));
  test('selected A receives existing B4 on third install and grants survive later B5', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final a = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'First builder',
      pin: '0123',
    );
    final b = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Second builder',
      pin: '1235',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, a.userId);
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, b.userId);
    final originalD1 =
        f.bStore.states[companyUserNamespace(f.b.namespace, slot: 2)]!;
    final oldGrants = await f.aDb
        .select(f.aDb.companyUserCredentialGrants)
        .get();
    for (final (version, pin) in [(1, '2345'), (2, '3456'), (3, '4567')]) {
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: b.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: version,
        pin: pin,
      );
    }
    final c = await thirdInstallation(f);
    await provisionInitialUser(f.aEnrollment, c.enrollment, a.userId);
    expect(
      (await c.enrollment.listCompanyUsers()).map((u) => u.userId),
      isNot(contains(b.userId)),
    );
    await c.enrollment.signInUser(a.userId, '0123');
    await transferCurrentUser(
      f.aEnrollment,
      c.enrollment,
      b.userId,
      interruptPrivate: true,
    );
    final publicState = await c.enrollment.userLifecycleStatus(
      userId: b.userId,
    );
    expect(publicState!.credentialVersion, 4);
    expect(publicState.awaitingCredential, isTrue);
    final before = c
        .store
        .states[companyUserNamespace(c.installation.namespace, slot: 2)]!;
    await provisionInitialUser(f.aEnrollment, c.enrollment, b.userId);
    expect(c.enrollment.currentCompanySession!.identity.userId, a.userId);
    final installed = await c.enrollment.userLifecycleStatus(userId: b.userId);
    expect(installed!.credentialVersion, 4);
    expect(installed.awaitingCredential, isFalse);
    expect(installed.attemptsRemaining, publicState.attemptsRemaining);
    expect(
      protectedBytesEqual(
        f.bStore.states[companyUserNamespace(f.b.namespace, slot: 2)]!,
        originalD1,
      ),
      isTrue,
    );
    expect(
      await f.aDb.select(f.aDb.companyUserCredentialGrants).get(),
      containsAll(oldGrants),
    );
    await transferCurrentUser(f.aEnrollment, c.enrollment, b.userId);
    final deliveries = await f.aDb.select(f.aDb.companyUserDeliveries).get();
    final forB = deliveries
        .where(
          (r) =>
              r.userId == b.userId &&
              r.peerDeviceId ==
                  c.enrollment.currentCompanySession!.identity.deviceId,
        )
        .toList();
    expect(forB, hasLength(2));
    expect(forB.map((r) => r.publicHead).toSet(), hasLength(1));
    expect(forB.map((r) => r.bindingCommitment).toSet(), hasLength(2));
    final userNamespace = companyUserNamespace(
      c.installation.namespace,
      slot: 2,
    );
    // One wrong PIN consumes B's budget without affecting selected A's rights.
    await expectLater(
      c.enrollment.signInUser(b.userId, '9999'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await c.enrollment.signInUser(a.userId, '0123');
    final spent = c.store.states[userNamespace]!;
    await provisionInitialUser(f.aEnrollment, c.enrollment, b.userId);
    expect(protectedBytesEqual(c.store.states[userNamespace]!, spent), isTrue);
    expect(c.store.states[userNamespace]!.revision, spent.revision);
    await provisionInitialUser(
      f.aEnrollment,
      c.enrollment,
      b.userId,
      requestId: const Uuid().v4(),
    );
    expect(protectedBytesEqual(c.store.states[userNamespace]!, spent), isTrue);
    expect(c.store.states[userNamespace]!.revision, spent.revision);
    await c.enrollment.signInUser(b.userId, '4567');
    expect(
      (await c.enrollment.userLifecycleStatus(userId: b.userId))!
          .credentialVersion,
      4,
    );
    await c.enrollment.signInUser(a.userId, '0123');
    expect(
      protectedBytesEqual(before, c.store.states[userNamespace]!),
      isFalse,
    );

    // This is a later legitimate rotation, separate from initial no-reset proof.
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: b.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 4,
      pin: '5678',
    );
    await f.aEnrollment.signInUser(a.userId, '0123');
    await transferCurrentUser(f.aEnrollment, c.enrollment, b.userId);
    await transferCurrentUser(f.aEnrollment, f.bEnrollment, b.userId);
    expect(
      (await c.enrollment.userLifecycleStatus(userId: b.userId))!
          .credentialVersion,
      5,
    );
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: b.userId))!
          .credentialVersion,
      5,
    );
    await c.enrollment.signInUser(b.userId, '5678');
    await f.bEnrollment.signInUser(b.userId, '5678');
  }, timeout: const Timeout(Duration(minutes: 5)));
  test('an existing credential-one user reaches a third installation without reset', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    await f.bEnrollment.signIn('1234');
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Existing builder',
      pin: '0123',
    );
    await provisionInitialUser(f.aEnrollment, f.bEnrollment, user.userId);
    final oldRecipient = f.bStore.states[companyUserNamespace(f.b.namespace)]!;
    final oldAuthority = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
    final oldGrants = await f.aDb
        .select(f.aDb.companyUserCredentialGrants)
        .get();

    final cDb = AppDatabase.forTesting(
      NativeDatabase(File('${f.root.path}/c.sqlite')),
    );
    addTearDown(cDb.close);
    final cStore = JoinActivationStore();
    final c = InstallationSecurity(
      store: cStore,
      namespace: 'synthetic.initial-c',
    );
    await c.start(cDb);
    final ce = CompanyEnrollment(installation: c, db: cDb);
    final cj = CompanyJoin(enrollment: ce);
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final (cc, ac) = await joinChannels();
    await cj.acceptProvision(
      await cj.receiveProvision(
        cc,
        await aj.approveJoin(
          ac,
          await aj.receiveJoinRequest(ac, await cj.beginJoin(cc)),
          ownerSession: f.owner,
        ),
      ),
    );
    cc.close();
    ac.close();
    await ce.signIn('1234');
    expect(c.identity!.id, isNot(f.b.identity!.id));
    expect(c.identity!.publicKey, isNot(f.b.identity!.publicKey));

    await provisionInitialUser(f.aEnrollment, ce, user.userId);
    final selected = await ce.signInUser(user.userId, '0123');
    expect(selected.identity.userId, user.userId);
    expect(
      selected.identity.deviceId,
      isNot(f.bEnrollment.currentSession!.identity.deviceId),
    );
    expect(
      protectedBytesEqual(
        f.bStore.states[companyUserNamespace(f.b.namespace)]!,
        oldRecipient,
      ),
      isTrue,
    );
    expect(
      f.bStore.states[companyUserNamespace(f.b.namespace)]!.revision,
      oldRecipient.revision,
    );
    expect(
      protectedBytesEqual(
        f.aStore.states[companyUserNamespace(f.a.namespace)]!,
        oldAuthority,
      ),
      isTrue,
    );
    expect(
      await f.aDb.select(f.aDb.companyUserCredentialGrants).get(),
      containsAll(oldGrants),
    );
    expect(
      (await ce.listCompanyUsers())
          .singleWhere((u) => u.userId == user.userId)
          .capabilities,
      ['createJob'],
    );
  }, timeout: const Timeout(Duration(minutes: 4)));
}

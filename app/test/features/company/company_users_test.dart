import 'dart:convert';
import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';

import 'company_join_test.dart'
    show
        JoinFixture,
        sqlSnapshot,
        expectJoinProtectedUnchanged,
        activateFixtureB,
        joinChannels;

import 'company_created_job_sync_test.dart' show syncAttackWire;
import '../job_line_commands/atomic_job_line_support.dart' show AtomicFixture;

class _HoldCredentialSignature extends DartCryptography {
  final entered = Completer<void>();
  final release = Completer<void>();
  @override
  Ed25519 ed25519() => _HeldCredentialEd25519(this);
}

class _HeldCredentialEd25519 extends DartEd25519 {
  _HeldCredentialEd25519(this.owner);
  final _HoldCredentialSignature owner;
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
    final prefix = utf8.encode('wiredpart.company.user.pin.issuance@1:');
    if (message.length >= prefix.length &&
        List.generate(
          prefix.length,
          (i) => message[i] == prefix[i],
        ).every((v) => v) &&
        !owner.entered.isCompleted) {
      owner.entered.complete();
      await owner.release.future;
    }
    return signature;
  }
}

Future<
  ({
    VerifiedPeerMembership a,
    VerifiedPeerMembership b,
    NearbyController ac,
    NearbyController bc,
  })
>
_peers(
  JoinFixture f, {
  CompanyEnrollment? enrollmentA,
  CompanySession? sessionA,
  CompanySession? sessionB,
}) async {
  final aEnrollment = enrollmentA ?? f.aEnrollment;
  final ownerB =
      sessionB ??
      f.bEnrollment.currentSession ??
      await f.bEnrollment.signIn('1234');
  final selectedA = sessionA ?? aEnrollment.currentSession!;
  late NearbyController aController, bController;
  final (bc, ac) = await joinChannels(
    onPaired: (b, a) {
      aController = a;
      bController = b;
    },
  );
  final aa = CompanyPeerAuthentication(enrollment: aEnrollment);
  final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
  final challenge = await aa.beginPeerChallenge(
    ac,
    (await aa.retainedPeers(session: selectedA)).single,
    session: selectedA,
  );
  final response = await ba.receivePeerChallenge(
    bc,
    challenge,
    session: ownerB,
  );
  final completion = await aa.receivePeerResponse(ac, response);
  final done = await ba.receivePeerCompletion(bc, completion);
  final aPeer = await aa.receivePeerAcknowledgment(ac, done.acknowledgment);
  return (a: aPeer, b: done.membership, ac: aController, bc: bController);
}

Future<Map<String, Object?>> _readSyncFrame(
  NearbyPairedJoinSession pair,
  Map<String, Object?> wire,
) async {
  final keys = pair.keys;
  final join = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: keys.receiveKey,
    nonce: utf8.encode(keys.id),
    info: utf8.encode('wiredpart-v2/company-join@1/${keys.receiveDirection}'),
  );
  final sync = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: join,
    nonce: utf8.encode(keys.id),
    info: utf8.encode(
      'wiredpart-v2/company-job-create-sync@1/${keys.receiveDirection}',
    ),
  );
  final header = Map<String, Object?>.from(wire)
    ..remove('nonce')
    ..remove('ciphertext')
    ..remove('tag');
  final plain = await AesGcm.with256bits().decrypt(
    SecretBox(
      base64Decode(wire['ciphertext'] as String),
      nonce: base64Decode(wire['nonce'] as String),
      mac: Mac(base64Decode(wire['tag'] as String)),
    ),
    secretKey: sync,
    aad: utf8.encode(_canonical(header)),
  );
  return Map<String, Object?>.from(jsonDecode(utf8.decode(plain)) as Map);
}

String _canonical(Object? value) {
  Object? sort(Object? v) => v is Map
      ? {for (final k in v.keys.cast<String>().toList()..sort()) k: sort(v[k])}
      : v is List
      ? v.map(sort).toList()
      : v;
  return jsonEncode(sort(value));
}

Future<Map<String, Object?>> _malformedPrivateEnvelope(
  JoinFixture f,
  NearbyPairedJoinSession pair,
  Map<String, Object?> original,
  String privateText,
) async {
  final keys = pair.keys;
  final join = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: keys.sendKey,
    nonce: utf8.encode(keys.id),
    info: utf8.encode('wiredpart-v2/company-join@1/${keys.sendDirection}'),
  );
  final user = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: join,
    nonce: utf8.encode(keys.id),
    info: utf8.encode(
      'wiredpart-v2/company-user-provision@1/${keys.sendDirection}',
    ),
  );
  final box = Map<String, Object?>.from(original['box'] as Map);
  final header = Map<String, Object?>.from(box)
    ..remove('nonce')
    ..remove('ciphertext')
    ..remove('tag');
  final encrypted = await AesGcm.with256bits().encrypt(
    utf8.encode(privateText),
    secretKey: user,
    aad: utf8.encode(_canonical(header)),
  );
  final changedBox = {
    ...header,
    'nonce': base64Encode(encrypted.nonce),
    'ciphertext': base64Encode(encrypted.cipherText),
    'tag': base64Encode(encrypted.mac.bytes),
  };
  final issuance =
      Map<String, Object?>.from((original['issuance'] as Map)['body'] as Map)
        ..['box'] = hashes.sha256
            .convert(utf8.encode(_canonical(changedBox)))
            .toString();
  final installation =
      jsonDecode(utf8.decode(f.aStore.states[f.a.namespace]!.bytes)) as Map;
  final signature = await Ed25519().sign(
    utf8.encode(
      'wiredpart.company.user.provision.issuance@1:${_canonical(issuance)}',
    ),
    keyPair: await Ed25519().newKeyPairFromSeed(
      base64Decode(installation['seed'] as String),
    ),
  );
  return {
    'box': changedBox,
    'issuance': {'body': issuance, 'signature': base64Encode(signature.bytes)},
  };
}

void main() {
  test('two restricted users provision in reverse order with independent PIN attempts', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final first = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'First builder',
      pin: '0123',
    );
    final legacy = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
    final second = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Second builder',
      pin: '4567',
    );
    expect(second.userId, isNot(first.userId));
    expect(
      f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
      legacy.bytes,
    );
    for (final user in [second, first]) {
      await f.bEnrollment.signIn('1234');
      final peer = await _peers(f);
      final request = await f.bEnrollment.prepareUserProvisionRequest(
        peer: peer.b,
        requestId: const Uuid().v4(),
        userId: user.userId,
      );
      final wire = await f.aEnrollment.prepareUserProvision(
        owner: f.owner,
        peer: peer.a,
        request: await f.aEnrollment.receiveUserProvisionRequest(
          request,
          peer: peer.a,
        ),
      );
      final ack = await f.bEnrollment.acceptUserProvision(wire, peer: peer.b);
      await f.aEnrollment.acceptUserProvisionReceipt(
        ack,
        peer: peer.a,
        userId: user.userId,
      );
    }
    final grants = await f.aDb
        .customSelect('SELECT grant_bytes FROM company_user_credential_grants')
        .get();
    expect(grants, hasLength(2));
    for (final row in grants) {
      final grant = jsonDecode(row.read<String>('grant_bytes')) as Map;
      expect((grant['body'] as Map)['purpose'], 'existing-credential-updates');
      expect((grant['body'] as Map).keys, isNot(contains('p')));
      expect((grant['body'] as Map).keys, isNot(contains('rootSeed')));
    }
    expect(
      (await f.bEnrollment.listCompanyUsers())
          .skip(1)
          .map((user) => user.userId),
      unorderedEquals([first.userId, second.userId]),
    );
    await expectLater(
      f.bEnrollment.signInUser(first.userId, '4567'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await expectLater(
      f.bEnrollment.signInUser(second.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.bEnrollment.signInUser(first.userId, '0123');
    await f.bEnrollment.signInUser(second.userId, '4567');
    for (var attempt = 0; attempt < 8; attempt++) {
      await expectLater(
        f.bEnrollment.signInUser(second.userId, '9999'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    }
    await expectLater(
      f.bEnrollment.signInUser(second.userId, '4567'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final firstSession = await f.bEnrollment.signInUser(first.userId, '0123');
    expect(firstSession.identity.userId, first.userId);
    expect(firstSession.identity.deviceId, isNot(f.owner.identity.deviceId));
    await f.closeAndCheckOwnerData();
  });

  test('two users keep Job authorship and targeted second-user recovery across reversed locators', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final first = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Same name',
      pin: '0123',
    );
    final second = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Same name',
      pin: '4567',
    );
    for (final user in [second, first]) {
      final peers = await _peers(f);
      final request = await f.bEnrollment.prepareUserProvisionRequest(
        peer: peers.b,
        requestId: const Uuid().v4(),
        userId: user.userId,
      );
      final wire = await f.aEnrollment.prepareUserProvision(
        owner: f.aEnrollment.currentSession!,
        peer: peers.a,
        request: await f.aEnrollment.receiveUserProvisionRequest(
          request,
          peer: peers.a,
        ),
      );
      final ack = await f.bEnrollment.acceptUserProvision(wire, peer: peers.b);
      final before = Map.of(f.aStore.states);
      await expectLater(
        f.aEnrollment.acceptUserProvisionReceipt(
          ack,
          peer: peers.a,
          userId: user == first ? second.userId : first.userId,
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, before);
      // The refused ACK consumed its envelope nonce; retry the actual transfer
      // to obtain a fresh authenticated ACK, preserving the pending request.
      final retryWire = await f.aEnrollment.prepareUserProvision(
        owner: f.aEnrollment.currentSession!,
        peer: peers.a,
        request: await f.aEnrollment.receiveUserProvisionRequest(
          request,
          peer: peers.a,
        ),
      );
      final retryAck = await f.bEnrollment.acceptUserProvision(
        retryWire,
        peer: peers.b,
      );
      await f.aEnrollment.acceptUserProvisionReceipt(
        retryAck,
        peer: peers.a,
        userId: user.userId,
      );
    }
    final jobs = <String, (String, String)>{};
    for (final enrollment in [f.aEnrollment, f.bEnrollment]) {
      for (final user in [first, second]) {
        final session = await enrollment.signInUser(
          user.userId,
          user == first ? '0123' : '4567',
        );
        final command = CreateJob(
          companyId: session.identity.companyId,
          shopId: session.identity.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          name: 'Attributed restricted work',
        );
        await CompanyJobCommands(enrollment: enrollment)
            .createJob(command, ownerSession: session);
        jobs[command.jobId] = (user.userId, session.identity.deviceId);
      }
      await enrollment.signIn('1234');
    }
    final peers = await _peers(f);
    final a = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: f.aEnrollment,
        owner: f.aEnrollment.currentSession!,
        peer: peers.a,
      ),
      controller: peers.ac,
    );
    final b = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: f.bEnrollment,
        owner: f.bEnrollment.currentSession!,
        peer: peers.b,
      ),
      controller: peers.bc,
    );
    peers.ac.onJoinMessage = (_, wire) => a.receive(wire);
    peers.bc.onJoinMessage = (_, wire) => b.receive(wire);
    final result = await a.syncNow();
    expect(
      result.complete,
      isTrue,
      reason: '${result.message}; receiver ${b.lastFailure}',
    );
    for (final db in [f.aDb, f.bDb]) {
      final rows = await db.select(db.companyJobs).get();
      for (final entry in jobs.entries) {
        final row = rows.singleWhere((row) => row.jobId == entry.key);
        final body = (jsonDecode(row.operationBytes) as Map)['body'] as Map;
        expect(body['user'], entry.value.$1);
        expect(body['device'], entry.value.$2);
      }
    }
    await a.closeAndDrain();
    await b.closeAndDrain();
    final firstA = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
    final firstB =
        f.bStore.states[companyUserNamespace(f.b.namespace, slot: 2)]!;
    Future<void> exchangeSecond() async {
      final current = await _peers(f);
      final target = await f.aEnrollment.verifyUserLifecycleOffer(
        await f.bEnrollment.createUserLifecycleOffer(
          current.b,
          userId: second.userId,
        ),
        current.a,
      );
      final source = await f.bEnrollment.verifyUserLifecycleOffer(
        await f.aEnrollment.createUserLifecycleOffer(
          current.a,
          userId: second.userId,
        ),
        current.b,
      );
      final policy = await f.aEnrollment.prepareUserDisablePolicy(
        current.a,
        target,
      );
      final receipt = await f.bEnrollment.acceptUserDisablePolicy(
        policy,
        current.b,
        source,
      );
      await f.aEnrollment.acceptUserDisableReceipt(
        receipt,
        current.a,
        userId: second.userId,
      );
    }

    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.aEnrollment.currentSession!,
      userId: second.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '6789',
    );
    await exchangeSecond();
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: second.userId))!
          .credentialVersion,
      2,
    );
    await expectLater(
      f.bEnrollment.signInUser(second.userId, '4567'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.bEnrollment.signInUser(second.userId, '6789');
    await f.bEnrollment.signIn('1234');
    await f.aEnrollment.disableRestrictedUser(
      owner: f.aEnrollment.currentSession!,
      userId: second.userId,
      requestId: const Uuid().v4(),
    );
    await exchangeSecond();
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: second.userId))!
          .disabled,
      isTrue,
    );
    expect(
      f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
      firstA.bytes,
    );
    expect(
      f.bStore.states[companyUserNamespace(f.b.namespace, slot: 2)]!.bytes,
      firstB.bytes,
    );
    final firstState = await f.bEnrollment.signInUser(first.userId, '0123');
    expect(firstState.identity.userId, first.userId);
    await expectLater(
      f.bEnrollment.signInUser(second.userId, '6789'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
  }, timeout: const Timeout(Duration(minutes: 4)));

  test(
    'two users reset refuses a sign-out during final collection validation',
    () async {
      final f = await JoinFixture.create();
      await f.aEnrollment.createRestrictedUser(
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
      final before = Map.of(f.aStore.states);
      final sql = await sqlSnapshot(f.aDb);
      final entered = Completer<void>();
      final release = Completer<void>();
      addTearDown(() {
        f.aStore.beforeRead = null;
        if (!release.isCompleted) release.complete();
      });
      f.aStore.beforeRead = (namespace) {
        if (!entered.isCompleted &&
            namespace == companyUserNamespace(f.a.namespace, slot: 2) &&
            StackTrace.current.toString().contains(
              'CompanyUsers._writeUserAccount',
            )) {
          entered.complete();
          return release.future;
        }
        return null;
      };
      final resetting = f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: second.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 1,
        pin: '6789',
      );
      final outcome = expectLater(
        resetting,
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      await entered.future.timeout(const Duration(seconds: 15));
      final signingOut = f.aEnrollment.signOut();
      expect(f.owner.isValid, isFalse);
      release.complete();
      await outcome;
      await signingOut;
      expectJoinProtectedUnchanged(f.aStore, before);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  test(
    'old signed provisioning profile refuses before private account export',
    () async {
      final f = await JoinFixture.create();
      await activateFixtureB(f);
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'First',
        pin: '0123',
      );
      final peers = await _peers(f);
      final request = await f.bEnrollment.prepareUserProvisionRequest(
        peer: peers.b,
        requestId: const Uuid().v4(),
        userId: user.userId,
      );
      final body = Map<String, Object?>.from(request['body'] as Map)
        ..remove('profile')
        ..remove('capacity');
      final base =
          jsonDecode(utf8.decode(f.bStore.states[f.b.namespace]!.bytes)) as Map;
      final signature = await Ed25519().sign(
        utf8.encode(
          'wiredpart.company.user.provision.request@1:${_canonical(body)}',
        ),
        keyPair: await Ed25519().newKeyPairFromSeed(
          base64Decode(base['seed'] as String),
        ),
      );
      final before = Map.of(f.aStore.states);
      final sql = await sqlSnapshot(f.aDb);
      await expectLater(
        f.aEnrollment.receiveUserProvisionRequest({
          'body': body,
          'signature': base64Encode(signature.bytes),
        }, peer: peers.a),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, before);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  for (final ownerSelected in [true, false]) {
    test(
      '${ownerSelected ? 'owner' : 'restricted'} selection sign-out during first custody read never publishes a session',
      () async {
        final f = await JoinFixture.create();
        final user = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Sam Builder',
          pin: '0123',
        );
        final before = Map.of(f.aStore.states);
        final entered = Completer<void>();
        final release = Completer<void>();
        addTearDown(() {
          if (!release.isCompleted) release.complete();
        });
        f.aStore.beforeRead = (namespace) {
          if (!entered.isCompleted &&
              namespace == companyCustodyNamespace(f.a.namespace)) {
            entered.complete();
            return release.future;
          }
          return null;
        };
        final signingIn = f.aEnrollment.signInUser(
          ownerSelected ? f.owner.identity.userId : user.userId,
          ownerSelected ? '1234' : '0123',
        );
        await entered.future.timeout(const Duration(seconds: 10));
        await f.aEnrollment.signOut();
        release.complete();
        await expectLater(signingIn, throwsA(isA<CompanyBootstrapRefusal>()));
        expect(f.aEnrollment.currentCompanySession, isNull);
        expect(f.aEnrollment.currentSession, isNull);
        expectJoinProtectedUnchanged(f.aStore, before);
      },
    );
  }

  test('restricted sign-out during final custody read never publishes a cancelled session', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Sam Builder',
      pin: '0123',
    );
    var reserved = false;
    var custodyReadsAfterReset = 0;
    final entered = Completer<void>();
    final release = Completer<void>();
    f.aStore.beforeRead = (namespace) {
      final account = jsonDecode(
        utf8.decode(
          f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
        ),
      ) as Map;
      if (account['a'] == 7) reserved = true;
      if (reserved &&
          account['a'] == 8 &&
          namespace == companyCustodyNamespace(f.a.namespace)) {
        custodyReadsAfterReset++;
        if (custodyReadsAfterReset == 6) {
          entered.complete();
          return release.future;
        }
      }
      return null;
    };
    final signingIn = f.aEnrollment.signInUser(user.userId, '0123');
    await entered.future.timeout(const Duration(seconds: 10));
    await f.aEnrollment.signOut();
    release.complete();
    await expectLater(signingIn, throwsA(isA<CompanyBootstrapRefusal>()));
    expect(f.aEnrollment.currentCompanySession, isNull);
    expect(f.aEnrollment.currentSession, isNull);
  });
  test('device sync permit follows the selected account', () async {
    final f = await JoinFixture.create();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Sam Builder',
      pin: '0123',
    );
    final selected = await f.aEnrollment.signInUser(user.userId, '0123');
    final permit = await f.aEnrollment.deviceSyncPermit();
    expect(permit.identity.userId, selected.identity.userId);
    expect(f.aEnrollment.currentSession, isNull);
    expect(await permit.run(() async => 'selected'), 'selected');
    await f.aEnrollment.signIn('1234');
    expect(permit.requireLive, throwsA(isA<CompanyBootstrapRefusal>()));
    await expectLater(
      permit.requireCurrent(),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
  });
  test(
    'device sync permit refuses a changed protected store generation',
    () async {
      final f = await JoinFixture.create();
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Sam Builder',
        pin: '0123',
      );
      await f.aEnrollment.signInUser(user.userId, '0123');
      final permit = await f.aEnrollment.deviceSyncPermit();
      final entered = Completer<void>();
      final release = Completer<void>();
      f.aStore.beforeRead = (namespace) {
        if (namespace == f.a.namespace && !entered.isCompleted) {
          entered.complete();
          return release.future;
        }
        return null;
      };
      final checking = permit.requireCurrent();
      await entered.future.timeout(const Duration(seconds: 10));
      f.aStore.beforeRead = null;
      final previous = f.aStore.states[f.a.namespace]!;
      final changed =
          jsonDecode(utf8.decode(previous.bytes)) as Map<String, dynamic>;
      changed['store'] = const Uuid().v4();
      await f.aStore.compareAndSwapState(
        f.a.namespace,
        expectedRevision: previous.revision,
        nextRevision: const Uuid().v4(),
        bytes: Uint8List.fromList(utf8.encode(jsonEncode(changed))),
      );
      release.complete();
      await expectLater(checking, throwsA(anything));
    },
  );
  for (final operation in ['reset', 'disable']) {
    test(
      'device sync permit refuses selected user $operation during protected read',
      () async {
        final f = await JoinFixture.create();
        final user = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Sam Builder',
          pin: '0123',
        );
        await f.aEnrollment.signInUser(user.userId, '0123');
        final permit = await f.aEnrollment.deviceSyncPermit();
        final administrator = CompanyEnrollment(installation: f.a, db: f.aDb);
        final owner = await administrator.signIn('1234');
        final entered = Completer<void>();
        final release = Completer<void>();
        f.aStore.beforeRead = (namespace) {
          if (namespace == companyUserNamespace(f.a.namespace) &&
              !entered.isCompleted) {
            entered.complete();
            return release.future;
          }
          return null;
        };
        final checking = permit.requireCurrent();
        await entered.future.timeout(const Duration(seconds: 10));
        f.aStore.beforeRead = null;
        if (operation == 'reset') {
          await administrator.resetRestrictedUserPin(
            owner: owner,
            userId: user.userId,
            requestId: const Uuid().v4(),
            expectedCredentialVersion: 1,
            pin: '4567',
          );
        } else {
          await administrator.disableRestrictedUser(
            owner: owner,
            userId: user.userId,
            requestId: const Uuid().v4(),
          );
        }
        release.complete();
        await expectLater(checking, throwsA(anything));
      },
    );
  }
  test(
    'a supplied restricted session cannot validate a legacy v1 Job-line proof',
    () async {
      final f = await JoinFixture.create();
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Sam Builder',
        pin: '0123',
      );
      final restricted = await f.aEnrollment.signInUser(user.userId, '0123');
      final legacy = await AtomicFixture.create();
      addTearDown(legacy.dispose);
      final command = legacy.command(
        const JobLinePatch(notes: SetField('Legacy proof')),
      );
      final proof = await legacy.session(0, command);
      expect(() => proof.validateLiveOwner(null), returnsNormally);
      expect(
        () => proof.validateLiveOwner(restricted),
        throwsA(isA<JobLineRefusal>()),
      );
    },
  );
  for (final phase in ['during receive', 'after validation', 'mid prepare']) {
    test(
      'verified user target snapshot survives caller map mutation $phase',
      () async {
        final f = await JoinFixture.create();
        await activateFixtureB(f);
        final user = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Sam Builder',
          pin: '0123',
        );
        final peers = await _peers(f);
        final requestId = const Uuid().v4();
        final raw = await f.bEnrollment.prepareUserProvisionRequest(
          peer: peers.b,
          requestId: requestId,
          userId: user.userId,
        );
        final originalBody = jsonDecode(jsonEncode(raw['body'])) as Map;
        void mutate() {
          final body = raw['body'] as Map;
          body['request'] = const Uuid().v4();
          (body['recipient'] as List)[4] = const Uuid().v4();
        }

        var changed = false;
        if (phase == 'during receive') {
          f.aStore.beforeRead = (namespace) {
            if (!changed && namespace == f.a.namespace) {
              changed = true;
              mutate();
            }
            return null;
          };
        }
        final verified = await f.aEnrollment.receiveUserProvisionRequest(
          raw,
          peer: peers.a,
        );
        f.aStore.beforeRead = null;
        if (phase == 'after validation') mutate();
        if (phase == 'mid prepare') {
          f.aStore.beforeRead = (namespace) {
            if (!changed && namespace == companyUserNamespace(f.a.namespace)) {
              changed = true;
              mutate();
            }
            return null;
          };
        }
        final wire = await f.aEnrollment.prepareUserProvision(
          owner: f.owner,
          peer: peers.a,
          request: verified,
        );
        final issuance = (wire['issuance'] as Map)['body'] as Map;
        expect(verified.requestId, requestId);
        expect(issuance['request'], requestId);
        expect(issuance['recipient'], originalBody['recipient']);
        final saved = jsonDecode(
          utf8.decode(
            f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
          ),
        ) as Map;
        expect((saved['o'] as List)[1], requestId);
        expect((saved['o'] as List).sublist(2), originalBody['recipient']);
        await f.bEnrollment.acceptUserProvision(wire, peer: peers.b);
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }
  for (final loss in ['sign-out', 'channel close']) {
    test(
      'final user provisioning disclosure refuses $loss during last account read',
      () async {
        final f = await JoinFixture.create();
        await activateFixtureB(f);
        final created = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Sam Builder',
          pin: '0123',
        );
        final peers = await _peers(f);
        final request = await f.aEnrollment.receiveUserProvisionRequest(
          await f.bEnrollment.prepareUserProvisionRequest(
            peer: peers.b,
            requestId: const Uuid().v4(),
            userId: created.userId,
          ),
          peer: peers.a,
        );
        final beforeSql = await sqlSnapshot(f.aDb);
        var finalDisclosureReadReached = false;
        var disclosed = false;
        Future<void>? signingOut;
        f.aStore.beforeRead = (namespace) {
          if (namespace != companyUserNamespace(f.a.namespace) ||
              finalDisclosureReadReached) {
            return null;
          }
          final raw =
              jsonDecode(utf8.decode(f.aStore.states[namespace]!.bytes)) as Map;
          final outgoing = raw['o'];
          // The final disclosure read follows the durable outgoing intent.
          // Earlier collection-validation reads must not trigger this fault.
          if (outgoing is List &&
              outgoing.length == 8 &&
              outgoing[0] == 0 &&
              outgoing[1] == request.requestId) {
            finalDisclosureReadReached = true;
            if (loss == 'sign-out') {
              signingOut = f.aEnrollment.signOut();
              unawaited(signingOut!);
            } else {
              peers.ac.pairedJoinSession!.revoke();
            }
          }
          return null;
        };
        await expectLater(() async {
          await f.aEnrollment.prepareUserProvision(
            owner: f.owner,
            peer: peers.a,
            request: request,
          );
          disclosed = true;
        }(), throwsA(isA<CompanyBootstrapRefusal>()));
        await signingOut;
        expect(finalDisclosureReadReached, isTrue);
        expect(disclosed, isFalse);
        final saved = jsonDecode(
          utf8.decode(
            f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
          ),
        ) as Map;
        expect(saved['a'], 8);
        expect(saved['r'], isNull);
        expect((saved['o'] as List)[1], request.requestId);
        expect(await sqlSnapshot(f.aDb), beforeSql);
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  }
  test('tampered recipient, version and malformed decrypted secret payload refuse without state or disclosure', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final created = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Sam Builder',
      pin: '0123',
    );
    final peers = await _peers(f);
    final offer = await f.bEnrollment.prepareUserProvisionRequest(
      peer: peers.b,
      requestId: const Uuid().v4(),
      userId: created.userId,
    );
    final wire = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: peers.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        offer,
        peer: peers.a,
      ),
    );
    final before = Map<String, ProtectedInstallationState>.of(f.bStore.states);
    final sql = await sqlSnapshot(f.bDb);
    for (final field in ['recipient', 'v', 'company']) {
      final bad = jsonDecode(jsonEncode(wire)) as Map<String, dynamic>;
      final body = (bad['issuance'] as Map)['body'] as Map;
      if (field == 'recipient') {
        (body['recipient'] as List)[4] = const Uuid().v4();
      }
      if (field == 'v') {
        body['v'] = 2;
      }
      if (field == 'company') {
        body['company'] = const Uuid().v4();
      }
      await expectLater(
        f.bEnrollment.acceptUserProvision(
          Map<String, Object?>.from(bad),
          peer: peers.b,
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.bStore, before);
    }
    const marker = 'private-decrypted-secret-marker';
    final malformed = await _malformedPrivateEnvelope(
      f,
      peers.ac.pairedJoinSession!,
      wire,
      '{"credential":"$marker',
    );
    await expectLater(
      f.bEnrollment.acceptUserProvision(malformed, peer: peers.b),
      throwsA(
        isA<CompanyBootstrapRefusal>().having(
          (e) => e.toString(),
          'private payload omitted',
          isNot(contains(marker)),
        ),
      ),
    );
    expectJoinProtectedUnchanged(f.bStore, before);
    expect(await sqlSnapshot(f.bDb), sql);
  }, timeout: const Timeout(Duration(minutes: 2)));
  test('lost creation and recipient CAS replies resume one logical transfer after owner service restart', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    f.aStore.loseNextUserReply = true;
    final created = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: '😀' * 16,
      pin: '0123',
    );
    final first = await _peers(f);
    final invite = await f.bEnrollment.receiveUserProvisionInvitation(
      await f.aEnrollment.prepareUserProvisionInvitation(
        owner: f.owner,
        peer: first.a,
        userId: created.userId,
      ),
      peer: first.b,
    );
    final offer = await f.bEnrollment.acceptUserProvisionInvitation(invite);
    final wire = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: first.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        offer,
        peer: first.a,
      ),
    );
    f.bStore.loseNextUserReply = true;
    await f.bEnrollment.acceptUserProvision(wire, peer: first.b);
    await expectLater(
      f.bEnrollment.signInUser(created.userId, '9999'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final previousB = f.bStore.states[companyUserNamespace(f.b.namespace)]!;
    await f.aEnrollment.signOut();
    final restartedA = CompanyEnrollment(installation: f.a, db: f.aDb);
    final owner = await restartedA.signIn('1234');
    final fresh = await _peers(f, enrollmentA: restartedA);
    final renewed = await f.bEnrollment.receiveUserProvisionInvitation(
      await restartedA.prepareUserProvisionInvitation(
        owner: owner,
        peer: fresh.a,
        userId: created.userId,
      ),
      peer: fresh.b,
    );
    expect(renewed.requestId, invite.requestId);
    expect(renewed.userId, created.userId);
    final secondWire = await restartedA.prepareUserProvision(
      owner: owner,
      peer: fresh.a,
      request: await restartedA.receiveUserProvisionRequest(
        await f.bEnrollment.acceptUserProvisionInvitation(renewed),
        peer: fresh.a,
      ),
    );
    expect(jsonEncode(secondWire), isNot(jsonEncode(wire)));
    final ack = await f.bEnrollment.acceptUserProvision(
      secondWire,
      peer: fresh.b,
    );
    expect(
      f.bStore.states[companyUserNamespace(f.b.namespace)]!.bytes,
      previousB.bytes,
    );
    await restartedA.acceptUserProvisionReceipt(
      ack,
      peer: fresh.a,
      userId: created.userId,
    );
    expect(
      f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes.length,
      lessThanOrEqualTo(2048),
    );
    expect(
      f.bStore.states[companyUserNamespace(f.b.namespace)]!.bytes.length,
      lessThanOrEqualTo(2048),
    );
    expect((await restartedA.listCompanyUsers()).last.userId, created.userId);
    expect(
      (await f.bEnrollment.listCompanyUsers()).last.userId,
      created.userId,
    );
  }, timeout: const Timeout(Duration(minutes: 2)));
  test(
    'the additional user namespace admits exactly the reviewed companion',
    () {
      expect(companyUserNamespace('production'), 'production.company-user-1');
      expect(
        companyUserNamespace('synthetic.user-test'),
        'synthetic.user-test.company-user-1',
      );
      validateInstallationNamespace('production.company-user-2');
      expect(
        companyUserNamespace('production', slot: 2),
        'production.company-user-2',
      );
      expect(
        () => companyUserNamespace('production.company-custody'),
        throwsArgumentError,
      );
      expect(
        () => companyCustodyNamespace('production.company-user-1'),
        throwsArgumentError,
      );
    },
  );
  for (final malformed in ['json', 'base64']) {
    test(
      'malformed private account $malformed returns a constant public refusal',
      () async {
        final f = await JoinFixture.create();
        final created = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Sam Builder',
          pin: '0123',
        );
        const marker = 'private-test-secret-marker';
        final namespace = companyUserNamespace(f.a.namespace);
        final prior = f.aStore.states[namespace]!;
        final value =
            jsonDecode(utf8.decode(prior.bytes)) as Map<String, dynamic>;
        (value['p'] as List)[1] = '$marker!';
        final damaged = malformed == 'json'
            ? '{"p":"$marker'
            : _canonical(value);
        f.aStore.states[namespace] = ProtectedInstallationState(
          const Uuid().v4(),
          Uint8List.fromList(utf8.encode(damaged)),
        );
        final before = Map<String, ProtectedInstallationState>.of(
          f.aStore.states,
        );
        await expectLater(
          f.aEnrollment.signInUser(created.userId, '0123'),
          throwsA(
            isA<CompanyBootstrapRefusal>().having(
              (e) => e.toString(),
              'sanitized public error',
              isNot(contains(marker)),
            ),
          ),
        );
        expectJoinProtectedUnchanged(f.aStore, before);
        expect(
          (await f.aEnrollment.listCompanyUsers()).last.available,
          isFalse,
        );
      },
    );
  }
  test('selected user verifies another current author original Job', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
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
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.owner,
      userId: second.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '6789',
    );
    final author = await f.aEnrollment.signInUser(second.userId, '6789');
    final command = CreateJob(
      companyId: author.identity.companyId,
      shopId: author.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Other author',
    );
    final commands = CompanyJobCommands(enrollment: f.aEnrollment);
    await commands.createJob(command, ownerSession: author);
    final selected = await f.aEnrollment.signInUser(first.userId, '0123');
    final verified = await commands.verifySyncRecord(command.jobId, selected);
    expect(
      (jsonDecode(verified.operationBytes)['body'] as Map)['user'],
      second.userId,
    );
    expect(f.aEnrollment.currentCompanySession, same(selected));
  });

  test(
    'selected new epoch holds its own old pending Job without acknowledgment',
    () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      await activateFixtureB(f);
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Selected',
        pin: '0123',
      );
      final initial = await _peers(f);
      final request = await f.bEnrollment.prepareUserProvisionRequest(
        peer: initial.b,
        requestId: const Uuid().v4(),
        userId: user.userId,
      );
      final bundle = await f.aEnrollment.prepareUserProvision(
        owner: f.owner,
        peer: initial.a,
        request: await f.aEnrollment.receiveUserProvisionRequest(
          request,
          peer: initial.a,
        ),
      );
      final receipt = await f.bEnrollment.acceptUserProvision(
        bundle,
        peer: initial.b,
      );
      await f.aEnrollment.acceptUserProvisionReceipt(
        receipt,
        peer: initial.a,
        userId: user.userId,
      );
      await initial.ac.dispose();
      await initial.bc.dispose();
      final oldSession = await f.aEnrollment.signInUser(user.userId, '0123');
      final oldJob = CreateJob(
        companyId: oldSession.identity.companyId,
        shopId: oldSession.identity.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: 'Old epoch pending',
      );
      await CompanyJobCommands(enrollment: f.aEnrollment)
          .createJob(oldJob, ownerSession: oldSession);
      final owner = await f.aEnrollment.signIn('1234');
      await f.aEnrollment.resetRestrictedUserPin(
        owner: owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 1,
        pin: '4567',
      );
      final delivery = await _peers(f);
      final target = await f.aEnrollment.verifyUserLifecycleOffer(
        await f.bEnrollment.createUserLifecycleOffer(
          delivery.b,
          userId: user.userId,
        ),
        delivery.a,
      );
      final source = await f.bEnrollment.verifyUserLifecycleOffer(
        await f.aEnrollment.createUserLifecycleOffer(
          delivery.a,
          userId: user.userId,
        ),
        delivery.b,
      );
      final policy = await f.aEnrollment.prepareUserDisablePolicy(
        delivery.a,
        target,
      );
      final delivered = await f.bEnrollment.acceptUserDisablePolicy(
        policy,
        delivery.b,
        source,
      );
      await f.aEnrollment.acceptUserDisableReceipt(
        delivered,
        delivery.a,
        userId: user.userId,
      );
      await delivery.ac.dispose();
      await delivery.bc.dispose();
      final aSession = await f.aEnrollment.signInUser(user.userId, '4567');
      final bSession = await f.bEnrollment.signInUser(user.userId, '4567');
      final peers = await _peers(f, sessionA: aSession, sessionB: bSession);
      final a = CompanyCreatedJobSync(
        availability: await CompanyJobSyncAvailability.open(
          enrollment: f.aEnrollment,
          owner: aSession,
          peer: peers.a,
        ),
        controller: peers.ac,
      );
      final b = CompanyCreatedJobSync(
        availability: await CompanyJobSyncAvailability.open(
          enrollment: f.bEnrollment,
          owner: bSession,
          peer: peers.b,
        ),
        controller: peers.bc,
      );
      peers.ac.onJoinMessage = (_, wire) => a.receive(wire);
      peers.bc.onJoinMessage = (_, wire) => b.receive(wire);
      final result = await a.syncNow();
      expect(result.complete, isFalse);
      expect(result.held, greaterThanOrEqualTo(1));
      expect(
        (await f.aDb.select(f.aDb.companyJobs).get()).where(
          (row) => row.jobId == oldJob.jobId,
        ),
        hasLength(1),
      );
      expect(
        (await f.bDb.select(f.bDb.companyJobs).get()).where(
          (row) => row.jobId == oldJob.jobId,
        ),
        isEmpty,
      );
      for (final db in [f.aDb, f.bDb]) {
        expect(
          await (db.select(
            db.companyJobPeerAcks,
          )..where((row) => row.requestId.equals(oldJob.requestId))).get(),
          isEmpty,
        );
      }
      expect(f.aEnrollment.currentCompanySession, same(aSession));
      expect(f.bEnrollment.currentCompanySession, same(bSession));
      await a.closeAndDrain();
      await b.closeAndDrain();
      await peers.ac.dispose();
      await peers.bc.dispose();
    },
    timeout: const Timeout(Duration(minutes: 7)),
  );

  test('selected restricted users synchronize existing credentials and both authors jobs', () async {
    final stopwatch = Stopwatch()..start();
    final f = await JoinFixture.create(allowOwnerAdditions: true);
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
    final initial = await _peers(f);
    for (final user in [first, second]) {
      final request = await f.bEnrollment.prepareUserProvisionRequest(
        peer: initial.b,
        requestId: const Uuid().v4(),
        userId: user.userId,
      );
      final bundle = await f.aEnrollment.prepareUserProvision(
        owner: f.aEnrollment.currentSession!,
        peer: initial.a,
        request: await f.aEnrollment.receiveUserProvisionRequest(
          request,
          peer: initial.a,
        ),
      );
      final ack = await f.bEnrollment.acceptUserProvision(
        bundle,
        peer: initial.b,
      );
      await f.aEnrollment.acceptUserProvisionReceipt(
        ack,
        peer: initial.a,
        userId: user.userId,
      );
    }
    await initial.ac.dispose();
    await initial.bc.dispose();
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.aEnrollment.currentSession!,
      userId: second.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '6789',
    );
    final secondSession = await f.aEnrollment.signInUser(second.userId, '6789');
    final secondJob = CreateJob(
      companyId: secondSession.identity.companyId,
      shopId: secondSession.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Second author',
    );
    await CompanyJobCommands(enrollment: f.aEnrollment)
        .createJob(secondJob, ownerSession: secondSession);
    final selectedB = await f.bEnrollment.signInUser(first.userId, '0123');
    final firstJob = CreateJob(
      companyId: selectedB.identity.companyId,
      shopId: selectedB.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'First author',
    );
    await CompanyJobCommands(enrollment: f.bEnrollment)
        .createJob(firstJob, ownerSession: selectedB);
    final selectedA = await f.aEnrollment.signInUser(first.userId, '0123');
    final freshPairStart = stopwatch.elapsed;
    final peers = await _peers(f, sessionA: selectedA, sessionB: selectedB);
    final a = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: f.aEnrollment,
        owner: selectedA,
        peer: peers.a,
      ),
      controller: peers.ac,
    );
    final b = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: f.bEnrollment,
        owner: selectedB,
        peer: peers.b,
      ),
      controller: peers.bc,
    );
    peers.ac.onJoinMessage = (_, wire) => a.receive(wire);
    peers.bc.onJoinMessage = (_, wire) => b.receive(wire);
    final result = await a.syncNow();
    expect(
      result.complete,
      isTrue,
      reason:
          '${result.message}; sender ${a.lastFailure}; receiver ${b.lastFailure}',
    );
    expect(f.aEnrollment.currentCompanySession, same(selectedA));
    expect(f.bEnrollment.currentCompanySession, same(selectedB));
    expect(f.aEnrollment.currentSession, isNull);
    expect(f.bEnrollment.currentSession, isNull);
    for (final db in [f.aDb, f.bDb]) {
      final rows = await db.select(db.companyJobs).get();
      expect(rows.where((r) => r.jobId == firstJob.jobId), hasLength(1));
      expect(rows.where((r) => r.jobId == secondJob.jobId), hasLength(1));
      expect(
        (jsonDecode(
              rows.singleWhere((r) => r.jobId == firstJob.jobId).operationBytes,
            )['body']
            as Map)['user'],
        first.userId,
      );
      expect(
        (jsonDecode(
              rows
                  .singleWhere((r) => r.jobId == secondJob.jobId)
                  .operationBytes,
            )['body']
            as Map)['user'],
        second.userId,
      );
    }
    final repeat = await a.syncNow();
    expect(repeat.complete, isTrue);
    expect(repeat.sent, 0);
    expect(repeat.received, 0);
    expect(
      stopwatch.elapsed - freshPairStart,
      lessThan(const Duration(minutes: 5)),
    );
    expect(
      peers.ac.pairedJoinSession!.timeUntilExpiry,
      greaterThan(Duration.zero),
    );
    await a.closeAndDrain();
    await b.closeAndDrain();
    await peers.ac.dispose();
    await peers.bc.dispose();
    await expectLater(
      f.bEnrollment.signInUser(second.userId, '4567'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final resetUser = await f.bEnrollment.signInUser(second.userId, '6789');
    expect(resetUser.identity.userId, second.userId);
  }, timeout: const Timeout(Duration(minutes: 7)));

  test(
    'restricted policy delivers an owner authorized existing credential',
    () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      await activateFixtureB(f);
      final selected = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Selected',
        pin: '0123',
      );
      final other = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Other',
        pin: '4567',
      );
      final initial = await _peers(f);
      for (final user in [selected, other]) {
        final request = await f.bEnrollment.prepareUserProvisionRequest(
          peer: initial.b,
          requestId: const Uuid().v4(),
          userId: user.userId,
        );
        final bundle = await f.aEnrollment.prepareUserProvision(
          owner: f.aEnrollment.currentSession!,
          peer: initial.a,
          request: await f.aEnrollment.receiveUserProvisionRequest(
            request,
            peer: initial.a,
          ),
        );
        final ack = await f.bEnrollment.acceptUserProvision(
          bundle,
          peer: initial.b,
        );
        await f.aEnrollment.acceptUserProvisionReceipt(
          ack,
          peer: initial.a,
          userId: user.userId,
        );
      }
      await initial.ac.dispose();
      await initial.bc.dispose();
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.aEnrollment.currentSession!,
        userId: other.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 1,
        pin: '6789',
      );
      final author = await f.aEnrollment.signInUser(other.userId, '6789');
      final command = CreateJob(
        companyId: author.identity.companyId,
        shopId: author.identity.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: 'Other author',
      );
      final commands = CompanyJobCommands(enrollment: f.aEnrollment);
      await commands.createJob(command, ownerSession: author);
      final aSession = await f.aEnrollment.signInUser(selected.userId, '0123');
      final bSession = await f.bEnrollment.signInUser(selected.userId, '0123');
      final peers = await _peers(f, sessionA: aSession, sessionB: bSession);
      final target = await f.aEnrollment.verifyUserLifecycleOffer(
        await f.bEnrollment.createUserLifecycleOffer(
          peers.b,
          userId: other.userId,
        ),
        peers.a,
      );
      final source = await f.bEnrollment.verifyUserLifecycleOffer(
        await f.aEnrollment.createUserLifecycleOffer(
          peers.a,
          userId: other.userId,
        ),
        peers.b,
      );
      final grant =
          (await f.aDb.select(f.aDb.companyUserCredentialGrants).get())
              .singleWhere((row) => row.userId == other.userId);
      await f.aDb.customStatement(
        'DELETE FROM company_user_credential_grants WHERE company_id = ? AND user_id = ? AND grant_key = ?',
        [grant.companyId, grant.userId, grant.grantKey],
      );
      final deletedSql = await sqlSnapshot(f.aDb);
      final deletedProtected = Map.of(f.aStore.states);
      await expectLater(
        f.aEnrollment.prepareUserDisablePolicy(peers.a, target),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expect(await sqlSnapshot(f.aDb), deletedSql);
      expectJoinProtectedUnchanged(f.aStore, deletedProtected);
      await f.aDb.customStatement(
        'INSERT INTO company_user_credential_grants (company_id, user_id, grant_key, grant_bytes) VALUES (?, ?, ?, ?)',
        [grant.companyId, grant.userId, grant.grantKey, grant.grantBytes],
      );
      final originalGrant =
          jsonDecode(grant.grantBytes) as Map<String, dynamic>;
      for (final field in [
        'signature',
        'creation',
        'source',
        'recipient',
        'purpose',
      ]) {
        final altered = jsonDecode(grant.grantBytes) as Map<String, dynamic>;
        if (field == 'signature') {
          altered['signature'] = base64Encode(List.filled(64, 0));
        } else {
          (altered['body'] as Map<String, dynamic>)[field] =
              field == 'source' || field == 'recipient' ? [] : 'altered';
        }
        await f.aDb.customStatement(
          'UPDATE company_user_credential_grants SET grant_bytes = ? WHERE company_id = ? AND user_id = ? AND grant_key = ?',
          [_canonical(altered), grant.companyId, grant.userId, grant.grantKey],
        );
        final before = await sqlSnapshot(f.aDb);
        final protected = Map.of(f.aStore.states);
        await expectLater(
          f.aEnrollment.prepareUserDisablePolicy(peers.a, target),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
        expect(await sqlSnapshot(f.aDb), before);
        expectJoinProtectedUnchanged(f.aStore, protected);
      }
      await f.aDb.customStatement(
        'UPDATE company_user_credential_grants SET grant_bytes = ? WHERE company_id = ? AND user_id = ? AND grant_key = ?',
        [
          _canonical(originalGrant),
          grant.companyId,
          grant.userId,
          grant.grantKey,
        ],
      );
      final policy = await f.aEnrollment.prepareUserDisablePolicy(
        peers.a,
        target,
      );
      final receipt = await f.bEnrollment.acceptUserDisablePolicy(
        policy,
        peers.b,
        source,
      );
      expect(receipt, isNotNull);
      final reversePolicy = await f.bEnrollment.prepareUserDisablePolicy(
        peers.b,
        source,
      );
      await f.aEnrollment.acceptUserDisableReceipt(
        receipt,
        peers.a,
        userId: other.userId,
      );
      final reverseReceipt = await f.aEnrollment.acceptUserDisablePolicy(
        reversePolicy,
        peers.a,
        target,
      );
      await f.bEnrollment.acceptUserDisableReceipt(
        reverseReceipt,
        peers.b,
        userId: other.userId,
      );
      final availability = await CompanyJobSyncAvailability.open(
        enrollment: f.aEnrollment,
        owner: aSession,
        peer: peers.a,
      );
      expect(
        await f.aEnrollment.isCompanyUserOperationHeld(other.userId, 2),
        isFalse,
      );
      final saved = await commands.verifySyncRecord(
        command.jobId,
        aSession,
        availability: availability,
      );
      expect(
        (jsonDecode(saved.operationBytes)['body'] as Map)['user'],
        other.userId,
      );
      expect(f.aEnrollment.currentCompanySession, same(aSession));
      expect(f.bEnrollment.currentCompanySession, same(bSession));
      await peers.ac.dispose();
      await peers.bc.dispose();
      await expectLater(
        f.bEnrollment.signInUser(other.userId, '4567'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expect(
        (await f.bEnrollment.signInUser(other.userId, '6789')).identity.userId,
        other.userId,
      );
    },
    timeout: const Timeout(Duration(minutes: 7)),
  );

  test('restricted receiver accepts original owner name details and lifecycle operations', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Receiver',
      pin: '0123',
    );
    final initial = await _peers(f);
    final request = await f.bEnrollment.prepareUserProvisionRequest(
      peer: initial.b,
      requestId: const Uuid().v4(),
      userId: user.userId,
    );
    final bundle = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: initial.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        request,
        peer: initial.a,
      ),
    );
    final ack = await f.bEnrollment.acceptUserProvision(
      bundle,
      peer: initial.b,
    );
    await f.aEnrollment.acceptUserProvisionReceipt(
      ack,
      peer: initial.a,
      userId: user.userId,
    );
    await initial.ac.dispose();
    await initial.bc.dispose();
    final author = CompanyJobCommands(enrollment: f.aEnrollment);
    var view = (await author.listJobViews(ownerSession: f.owner)).single;
    final rename = RenameJob(
      companyId: f.owner.identity.companyId,
      shopId: f.owner.identity.shopId,
      jobId: view.baseJob.id,
      requestId: const Uuid().v4(),
      creationDigest: view.creationDigest,
      observedHeads: [],
      name: 'Owner name',
      observedLifecycleHeads: view.lifecycle.lifecycleHeads,
    );
    await author.renameJob(rename, ownerSession: f.owner);
    view = (await author.listJobViews(ownerSession: f.owner)).single;
    final details = PatchJobDetails(
      companyId: f.owner.identity.companyId,
      shopId: f.owner.identity.shopId,
      jobId: view.baseJob.id,
      requestId: const Uuid().v4(),
      creationDigest: view.creationDigest,
      patch: const JobDetailsPatch(notes: SetField('Owner details')),
      observedHeads: {JobDetailField.notes: []},
      observedLifecycleHeads: view.lifecycle.lifecycleHeads,
    );
    await author.patchJobDetails(details, ownerSession: f.owner);
    view = (await author.listJobViews(ownerSession: f.owner)).single;
    final lifecycle = SetJobLifecycle(
      companyId: f.owner.identity.companyId,
      shopId: f.owner.identity.shopId,
      jobId: view.baseJob.id,
      requestId: const Uuid().v4(),
      creationDigest: view.creationDigest,
      observed: view.lifecycle.context,
      choice: JobLifecycleChoice.deleted,
    );
    await author.setJobLifecycle(lifecycle, ownerSession: f.owner);
    final selected = await f.bEnrollment.signInUser(user.userId, '0123');
    final before = await sqlSnapshot(f.bDb);
    await expectLater(
      f.bEnrollment.issueRenameJobAssertion(rename),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await expectLater(
      f.bEnrollment.issueJobDetailsAssertion(details),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await expectLater(
      f.bEnrollment.issueJobLifecycleAssertion(lifecycle),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(f.bDb), before);
    final peers = await _peers(f, sessionB: selected);
    final availability = await CompanyJobSyncAvailability.open(
      enrollment: f.bEnrollment,
      owner: selected,
      peer: peers.b,
    );
    final receiver = CompanyJobCommands(enrollment: f.bEnrollment);
    final creation =
        (await f.aDb.select(f.aDb.companyJobs).get()).single.operationBytes;
    final name =
        (await f.aDb.select(f.aDb.companyJobNames).get()).single.operationBytes;
    final detail = (await f.aDb.select(f.aDb.companyJobDetails).get())
        .single
        .operationBytes;
    final state = (await f.aDb.select(f.aDb.companyJobLifecycles).get())
        .single
        .operationBytes;
    Uint8List bytes(String value) => Uint8List.fromList(utf8.encode(value));
    await receiver.applyIncomingCreate(
      bytes(creation),
      ownerSession: selected,
      availability: availability,
    );
    await receiver.applyIncomingName(
      bytes(name),
      ownerSession: selected,
      availability: availability,
    );
    await receiver.applyIncomingDetails(
      bytes(detail),
      ownerSession: selected,
      availability: availability,
    );
    await receiver.applyIncomingLifecycle(
      bytes(state),
      ownerSession: selected,
      availability: availability,
    );
    expect(
      (await f.bDb.select(f.bDb.companyJobNames).get()).single.operationBytes,
      name,
    );
    expect(
      (await f.bDb.select(f.bDb.companyJobDetails).get()).single.operationBytes,
      detail,
    );
    expect(
      (await f.bDb.select(f.bDb.companyJobLifecycles).get())
          .single
          .operationBytes,
      state,
    );
    expect(f.bEnrollment.currentCompanySession, same(selected));
    await peers.ac.dispose();
    await peers.bc.dispose();
  }, timeout: const Timeout(Duration(minutes: 3)));

  for (final fault in ['signout', 'reset', 'disable', 'store', 'channel']) {
    test('private credential delivery refuses $fault after signing', () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      await activateFixtureB(f);
      final selected = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Selected',
        pin: '0123',
      );
      final targetUser = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Target',
        pin: '4567',
      );
      final initial = await _peers(f);
      for (final user in [selected, targetUser]) {
        final request = await f.bEnrollment.prepareUserProvisionRequest(
          peer: initial.b,
          requestId: const Uuid().v4(),
          userId: user.userId,
        );
        final bundle = await f.aEnrollment.prepareUserProvision(
          owner: f.owner,
          peer: initial.a,
          request: await f.aEnrollment.receiveUserProvisionRequest(
            request,
            peer: initial.a,
          ),
        );
        final ack = await f.bEnrollment.acceptUserProvision(
          bundle,
          peer: initial.b,
        );
        await f.aEnrollment.acceptUserProvisionReceipt(
          ack,
          peer: initial.a,
          userId: user.userId,
        );
      }
      await initial.ac.dispose();
      await initial.bc.dispose();
      await f.aEnrollment.resetRestrictedUserPin(
        owner: f.owner,
        userId: targetUser.userId,
        requestId: const Uuid().v4(),
        expectedCredentialVersion: 1,
        pin: '6789',
      );
      final administrator = CompanyEnrollment(installation: f.a, db: f.aDb);
      final admin = await administrator.signIn('1234');
      final a = await f.aEnrollment.signInUser(selected.userId, '0123');
      final b = await f.bEnrollment.signInUser(selected.userId, '0123');
      final peers = await _peers(f, sessionA: a, sessionB: b);
      final target = await f.aEnrollment.verifyUserLifecycleOffer(
        await f.bEnrollment.createUserLifecycleOffer(
          peers.b,
          userId: targetUser.userId,
        ),
        peers.a,
      );
      final provider = _HoldCredentialSignature();
      Cryptography.instance = provider;
      try {
        final pending = f.aEnrollment.prepareUserDisablePolicy(peers.a, target);
        await provider.entered.future.timeout(const Duration(seconds: 60));
        Cryptography.instance = DartCryptography.defaultInstance;
        if (fault == 'signout') {
          await f.aEnrollment.signOut();
        } else if (fault == 'reset') {
          await administrator.resetRestrictedUserPin(
            owner: admin,
            userId: selected.userId,
            requestId: const Uuid().v4(),
            expectedCredentialVersion: 1,
            pin: '9876',
          );
        } else if (fault == 'disable') {
          await administrator.disableRestrictedUser(
            owner: admin,
            userId: selected.userId,
            requestId: const Uuid().v4(),
          );
        } else if (fault == 'store') {
          final previous = f.aStore.states[f.a.namespace]!;
          final changed =
              jsonDecode(utf8.decode(previous.bytes)) as Map<String, dynamic>;
          changed['store'] = const Uuid().v4();
          await f.aStore.compareAndSwapState(
            f.a.namespace,
            expectedRevision: previous.revision,
            nextRevision: const Uuid().v4(),
            bytes: Uint8List.fromList(utf8.encode(jsonEncode(changed))),
          );
        } else {
          await peers.ac.dispose();
        }
        provider.release.complete();
        await expectLater(pending, throwsA(anything));
      } finally {
        Cryptography.instance = DartCryptography.defaultInstance;
        if (!provider.release.isCompleted) provider.release.complete();
        if (fault != 'channel') await peers.ac.dispose();
        await peers.bc.dispose();
      }
    }, timeout: const Timeout(Duration(minutes: 4)));
  }

  test('restricted sync refuses private delivery without the owner recipient grant', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final selected = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Selected',
      pin: '0123',
    );
    final other = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Other',
      pin: '4567',
    );
    final initial = await _peers(f);
    final request = await f.bEnrollment.prepareUserProvisionRequest(
      peer: initial.b,
      requestId: const Uuid().v4(),
      userId: selected.userId,
    );
    final bundle = await f.aEnrollment.prepareUserProvision(
      owner: f.aEnrollment.currentSession!,
      peer: initial.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        request,
        peer: initial.a,
      ),
    );
    final ack = await f.bEnrollment.acceptUserProvision(
      bundle,
      peer: initial.b,
    );
    await f.aEnrollment.acceptUserProvisionReceipt(
      ack,
      peer: initial.a,
      userId: selected.userId,
    );
    await initial.ac.dispose();
    await initial.bc.dispose();
    await f.aEnrollment.resetRestrictedUserPin(
      owner: f.aEnrollment.currentSession!,
      userId: other.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '6789',
    );
    final aSession = await f.aEnrollment.signInUser(selected.userId, '0123');
    final bSession = await f.bEnrollment.signInUser(selected.userId, '0123');
    final peers = await _peers(f, sessionA: aSession, sessionB: bSession);
    final target = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(
        peers.b,
        userId: other.userId,
      ),
      peers.a,
    );
    final beforeSql = await sqlSnapshot(f.aDb);
    final beforeProtected = Map.of(f.aStore.states);
    await expectLater(
      f.aEnrollment.prepareUserDisablePolicy(peers.a, target),
      throwsA(
        isA<CompanyBootstrapRefusal>().having(
          (error) => error.message,
          'reason',
          'Owner authorization required for private credential delivery',
        ),
      ),
    );
    expect(await sqlSnapshot(f.aDb), beforeSql);
    expectJoinProtectedUnchanged(f.aStore, beforeProtected);
    expect(f.aEnrollment.currentCompanySession, same(aSession));
    await f.aDb.customStatement(
      'ALTER TABLE company_user_credential_grants ADD COLUMN unexpected TEXT',
    );
    final malformedSql = await sqlSnapshot(f.aDb);
    final malformedProtected = Map.of(f.aStore.states);
    await expectLater(
      f.aEnrollment.prepareUserDisablePolicy(peers.a, target),
      throwsA(isA<StateError>()),
    );
    expect(await sqlSnapshot(f.aDb), malformedSql);
    expectJoinProtectedUnchanged(f.aStore, malformedProtected);
    await peers.ac.dispose();
    await peers.bc.dispose();
  }, timeout: const Timeout(Duration(minutes: 7)));

  test('malformed grant schema refuses Owner acknowledgment before protected mutation', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Target',
      pin: '0123',
    );
    final peers = await _peers(f);
    final request = await f.bEnrollment.prepareUserProvisionRequest(
      peer: peers.b,
      requestId: const Uuid().v4(),
      userId: user.userId,
    );
    final bundle = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: peers.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        request,
        peer: peers.a,
      ),
    );
    final ack = await f.bEnrollment.acceptUserProvision(bundle, peer: peers.b);
    await f.aDb.customStatement(
      'ALTER TABLE company_user_credential_grants ADD COLUMN unexpected TEXT',
    );
    final beforeSql = await sqlSnapshot(f.aDb);
    final beforeProtected = Map.of(f.aStore.states);
    await expectLater(
      f.aEnrollment.acceptUserProvisionReceipt(
        ack,
        peer: peers.a,
        userId: user.userId,
      ),
      throwsA(isA<StateError>()),
    );
    expect(await sqlSnapshot(f.aDb), beforeSql);
    expectJoinProtectedUnchanged(f.aStore, beforeProtected);
    await peers.ac.dispose();
    await peers.bc.dispose();
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('v4 user Jobs sync through owner channel with same retained device and exact original user', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    await activateFixtureB(f);
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Sam Builder',
      pin: '0123',
    );
    final selected = await f.aEnrollment.signInUser(user.userId, '0123');
    final command = CreateJob(
      companyId: selected.identity.companyId,
      shopId: selected.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Sam original author',
    );
    await CompanyJobCommands(enrollment: f.aEnrollment)
        .createJob(command, ownerSession: selected);
    await f.aEnrollment.signIn('1234');
    final peers = await _peers(f);
    final source = (await f.aDb.select(f.aDb.companyJobs).get()).singleWhere(
      (r) => r.jobId == command.jobId,
    );
    final beforeProvisionSql = await sqlSnapshot(f.bDb);
    final beforeProvisionProtected = Map.of(f.bStore.states);
    await expectLater(
      CompanyJobCommands(enrollment: f.bEnrollment).applyIncomingCreate(
        Uint8List.fromList(utf8.encode(source.operationBytes)),
        ownerSession: f.bEnrollment.currentSession!,
        availability: await CompanyJobSyncAvailability.open(
          enrollment: f.bEnrollment,
          owner: f.bEnrollment.currentSession!,
          peer: peers.b,
        ),
      ),
      throwsA(
        isA<CompanyBootstrapRefusal>().having(
          (error) => error.message,
          'missing protected account',
          'Current user account unavailable',
        ),
      ),
    );
    expect(await sqlSnapshot(f.bDb), beforeProvisionSql);
    expectJoinProtectedUnchanged(f.bStore, beforeProvisionProtected);
    final request = await f.bEnrollment.prepareUserProvisionRequest(
      peer: peers.b,
      requestId: const Uuid().v4(),
      userId: user.userId,
    );
    final bundle = await f.aEnrollment.prepareUserProvision(
      owner: f.aEnrollment.currentSession!,
      peer: peers.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        request,
        peer: peers.a,
      ),
    );
    final ack = await f.bEnrollment.acceptUserProvision(bundle, peer: peers.b);
    await f.aEnrollment.acceptUserProvisionReceipt(
      ack,
      peer: peers.a,
      userId: user.userId,
    );
    final a = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: f.aEnrollment,
        owner: f.aEnrollment.currentSession!,
        peer: peers.a,
      ),
      controller: peers.ac,
    );
    final b = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: f.bEnrollment,
        owner: f.bEnrollment.currentSession!,
        peer: peers.b,
      ),
      controller: peers.bc,
    );
    peers.ac.onJoinMessage = (_, wire) => a.receive(wire);
    peers.bc.onJoinMessage = (_, wire) => b.receive(wire);
    final first = await a.syncNow();
    expect(
      first.complete,
      isTrue,
      reason: '${first.message}; receiver ${b.lastFailure}',
    );
    final received = (await f.bDb.select(f.bDb.companyJobs).get()).singleWhere(
      (r) => r.jobId == command.jobId,
    );
    expect(received.operationBytes, source.operationBytes);
    expect(jsonDecode(received.auditBytes)['originalUser'], user.userId);
    expect(
      jsonDecode(received.auditBytes)['originalDevice'],
      selected.identity.deviceId,
    );
    final beforeRelay = await sqlSnapshot(f.aDb);
    await expectLater(
      CompanyJobCommands(enrollment: f.aEnrollment).applyIncomingCreate(
        Uint8List.fromList(utf8.encode(received.operationBytes)),
        ownerSession: f.aEnrollment.currentSession!,
        availability: await CompanyJobSyncAvailability.open(
          enrollment: f.aEnrollment,
          owner: f.aEnrollment.currentSession!,
          peer: peers.a,
        ),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(f.aDb), beforeRelay);
    expect((await a.syncNow()).complete, isTrue);
    expect(
      (await f.bDb.select(f.bDb.companyJobs).get()).where(
        (r) => r.jobId == command.jobId,
      ),
      hasLength(1),
    );
    a.close();
    b.close();
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
    'legacy sync profile receives no inventory or additional-user Job bytes',
    () async {
      final f = await JoinFixture.create(allowOwnerAdditions: true);
      await activateFixtureB(f);
      final user = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Sam pending',
        pin: '0123',
      );
      final selected = await f.aEnrollment.signInUser(user.userId, '0123');
      final command = CreateJob(
        companyId: selected.identity.companyId,
        shopId: selected.identity.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: 'Pending additional-user Job',
      );
      await CompanyJobCommands(enrollment: f.aEnrollment)
          .createJob(command, ownerSession: selected);
      final original = (await f.aDb.select(f.aDb.companyJobs).get())
          .singleWhere((r) => r.jobId == command.jobId);
      expect(
        jsonDecode(original.operationBytes)['authorization']['body']['v'],
        4,
      );
      await f.aEnrollment.signIn('1234');
      final peers = await _peers(f);
      final a = CompanyCreatedJobSync(
        availability: await CompanyJobSyncAvailability.open(
          enrollment: f.aEnrollment,
          owner: f.aEnrollment.currentSession!,
          peer: peers.a,
        ),
        controller: peers.ac,
      );
      final disclosed = <Map<String, Object?>>[];
      peers.bc.companySyncDisclosure = await CompanyJobSyncAvailability.open(
        enrollment: f.bEnrollment,
        owner: f.bEnrollment.currentSession!,
        peer: peers.b,
      );
      peers.bc.onJoinMessage = (pair, wire) async {
        final body = await _readSyncFrame(pair, wire);
        disclosed.add(body);
        return syncAttackWire(
          pair,
          base64Encode(f.a.identity!.publicKey),
          body['run'] as String,
          'profile.reply',
          {},
          'company.job.sync@6',
        );
      };
      final before = await sqlSnapshot(f.bDb);
      final result = await a.syncNow();
      expect(result.complete, isFalse);
      expect(disclosed, hasLength(1));
      expect(disclosed.single['protocol'], 'company.job.sync@7');
      expect(disclosed.single['action'], 'profile');
      expect(disclosed.single['data'], {
        'profile': '$kCompanyUserProfile/job.create.authorization@4',
        'capacity': kCompanyUserCapacity,
        'users': [user.userId],
      });
      expect(await sqlSnapshot(f.bDb), before);
      expect(
        (await f.aDb.select(f.aDb.companyJobs).get()).every((r) => r.outgoing),
        isTrue,
      );
      final pending = (await f.aDb.select(f.aDb.companyJobs).get()).singleWhere(
        (r) => r.jobId == command.jobId,
      );
      expect(pending.operationBytes, original.operationBytes);
      expect(pending.auditBytes, original.auditBytes);
      expect(pending.receiptBytes, original.receiptBytes);
      expect(pending.outgoing, isTrue);
      a.close();
    },
  );
  for (final fault in ['missing', 'credential', 'binding', 'certificate']) {
    test(
      'restricted Create Job rolls back if its account changes before commit: $fault',
      () async {
        final f = await JoinFixture.create(allowOwnerAdditions: true);
        final created = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Sam Builder',
          pin: '0123',
        );
        final user = await f.aEnrollment.signInUser(created.userId, '0123');
        final before = await sqlSnapshot(f.aDb);
        final action = CreateJob(
          companyId: user.identity.companyId,
          shopId: user.identity.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          name: 'Must not commit',
        );
        await expectLater(
          CompanyJobCommands(
            enrollment: f.aEnrollment,
            beforeCommit: () async {
              final namespace = companyUserNamespace(f.a.namespace);
              final old = f.aStore.states[namespace]!;
              if (fault == 'missing') {
                f.aStore.states.remove(namespace);
              } else {
                final changed =
                    jsonDecode(utf8.decode(old.bytes)) as Map<String, dynamic>;
                if (fault == 'credential') {
                  (changed['p'] as List)[2] = base64Encode(
                    List<int>.filled(32, 42),
                  );
                }
                if (fault == 'binding') {
                  (changed['b'] as List)[3] = const Uuid().v4();
                }
                if (fault == 'certificate') {
                  changed['c'] = (changed['c'] as String).replaceFirst(
                    'Sam Builder',
                    'Other Actor',
                  );
                }
                f.aStore.states[namespace] = ProtectedInstallationState(
                  const Uuid().v4(),
                  Uint8List.fromList(utf8.encode(jsonEncode(changed))),
                );
              }
            },
          ).createJob(action, ownerSession: user),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
        expect(await sqlSnapshot(f.aDb), before);
        expect(
          (await f.aDb.select(f.aDb.companyJobs).get()).where(
            (j) => j.jobId == action.jobId,
          ),
          isEmpty,
        );
      },
    );
  }
  test('lost Owner provisioning context cannot mint a grant from an old acknowledgment', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Receiver',
      pin: '0123',
    );
    final first = await _peers(f);
    final requestId = const Uuid().v4();
    final request = await f.bEnrollment.prepareUserProvisionRequest(
      peer: first.b,
      requestId: requestId,
      userId: user.userId,
    );
    final bundle = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: first.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        request,
        peer: first.a,
      ),
    );
    final ack = await f.bEnrollment.acceptUserProvision(bundle, peer: first.b);
    await f.aEnrollment.signOut();
    await expectLater(
      f.aEnrollment.acceptUserProvisionReceipt(
        ack,
        peer: first.a,
        userId: user.userId,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(
      await f.aDb.select(f.aDb.companyUserCredentialGrants).get(),
      isEmpty,
    );
    await first.ac.dispose();
    await first.bc.dispose();
    final owner = await f.aEnrollment.signIn('1234');
    final fresh = await _peers(f);
    final retryRequest = await f.bEnrollment.prepareUserProvisionRequest(
      peer: fresh.b,
      requestId: requestId,
      userId: user.userId,
    );
    final retryBundle = await f.aEnrollment.prepareUserProvision(
      owner: owner,
      peer: fresh.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        retryRequest,
        peer: fresh.a,
      ),
    );
    final retryAck = await f.bEnrollment.acceptUserProvision(
      retryBundle,
      peer: fresh.b,
    );
    await f.aEnrollment.acceptUserProvisionReceipt(
      retryAck,
      peer: fresh.a,
      userId: user.userId,
    );
    expect(
      await f.aDb.select(f.aDb.companyUserCredentialGrants).get(),
      hasLength(1),
    );
    await fresh.ac.dispose();
    await fresh.bc.dispose();
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('authenticated provisioning preserves recipient identity and PIN attempts on retry', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final originalB = f.b.identity!;
    final created = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Sam Builder',
      pin: '0123',
    );
    final peer = await _peers(f);
    final requestId = const Uuid().v4();
    final request = await f.bEnrollment.prepareUserProvisionRequest(
      peer: peer.b,
      requestId: requestId,
      userId: created.userId,
    );
    final beforeSql = await sqlSnapshot(f.bDb);
    final wire = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: peer.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        request,
        peer: peer.a,
      ),
    );
    final ack = await f.bEnrollment.acceptUserProvision(wire, peer: peer.b);
    await f.aEnrollment.acceptUserProvisionReceipt(
      ack,
      peer: peer.a,
      userId: created.userId,
    );
    expect(await sqlSnapshot(f.bDb), beforeSql);
    expect(f.b.identity!.id, originalB.id);
    expect(f.b.identity!.publicKey, originalB.publicKey);
    expect(
      (await f.bEnrollment.listCompanyUsers()).last.userId,
      created.userId,
    );
    await expectLater(
      f.bEnrollment.signInUser(created.userId, '9999'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final beforeAttempts =
        f.bStore.states[companyUserNamespace(f.b.namespace)]!;
    await f.bEnrollment.signIn('1234');
    final fresh = await _peers(f);
    final retry = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: fresh.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        await f.bEnrollment.prepareUserProvisionRequest(
          peer: fresh.b,
          requestId: requestId,
          userId: created.userId,
        ),
        peer: fresh.a,
      ),
    );
    expect(jsonEncode(retry), isNot(jsonEncode(wire)));
    final retryAck = await f.bEnrollment.acceptUserProvision(
      retry,
      peer: fresh.b,
    );
    expect(
      f.bStore.states[companyUserNamespace(f.b.namespace)]!.bytes,
      beforeAttempts.bytes,
    );
    final existingGrant =
        (await f.aDb.select(f.aDb.companyUserCredentialGrants).get()).single;
    await f.aDb.customStatement(
      'UPDATE company_user_credential_grants SET grant_bytes = ? WHERE company_id = ? AND user_id = ? AND grant_key = ?',
      [
        'collision',
        existingGrant.companyId,
        existingGrant.userId,
        existingGrant.grantKey,
      ],
    );
    final collisionSql = await sqlSnapshot(f.aDb);
    await expectLater(
      f.aEnrollment.acceptUserProvisionReceipt(
        retryAck,
        peer: fresh.a,
        userId: created.userId,
      ),
      throwsA(
        isA<CompanyBootstrapRefusal>().having(
          (e) => e.message,
          'reason',
          'Credential grant collision',
        ),
      ),
    );
    expect(await sqlSnapshot(f.aDb), collisionSql);
    await f.aDb.customStatement(
      'UPDATE company_user_credential_grants SET grant_bytes = ? WHERE company_id = ? AND user_id = ? AND grant_key = ?',
      [
        existingGrant.grantBytes,
        existingGrant.companyId,
        existingGrant.userId,
        existingGrant.grantKey,
      ],
    );
    final recoveryRequest = await f.bEnrollment.prepareUserProvisionRequest(
      peer: fresh.b,
      requestId: requestId,
      userId: created.userId,
    );
    final recoveryBundle = await f.aEnrollment.prepareUserProvision(
      owner: f.owner,
      peer: fresh.a,
      request: await f.aEnrollment.receiveUserProvisionRequest(
        recoveryRequest,
        peer: fresh.a,
      ),
    );
    final recoveryAck = await f.bEnrollment.acceptUserProvision(
      recoveryBundle,
      peer: fresh.b,
    );
    await f.aEnrollment.acceptUserProvisionReceipt(
      recoveryAck,
      peer: fresh.a,
      userId: created.userId,
    );
    final grants = await f.aDb.select(f.aDb.companyUserCredentialGrants).get();
    expect(grants, hasLength(1));
    expect(grants.single.grantBytes, existingGrant.grantBytes);
    await f.reopenB();
    final selected = await f.bEnrollment.signInUser(created.userId, '0123');
    expect(selected.identity.userId, created.userId);
    expect(selected.identity.deviceId, isNot(f.owner.identity.deviceId));
    final command = CreateJob(
      companyId: selected.identity.companyId,
      shopId: selected.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Sam on B',
    );
    await CompanyJobCommands(enrollment: f.bEnrollment)
        .createJob(command, ownerSession: selected);
    final saved = (await f.bDb.select(f.bDb.companyJobs).get()).single;
    expect(jsonDecode(saved.operationBytes)['body']['user'], created.userId);
    expect(
      jsonDecode(saved.operationBytes)['body']['device'],
      selected.identity.deviceId,
    );
  });
  test('owner creates one immutable restricted account without changing business data', () async {
    final f = await JoinFixture.create();
    final beforeSql = await sqlSnapshot(f.aDb);
    final beforeIdentity = f.a.identity!;
    final request = const Uuid().v4();
    final receipt = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: request,
      name: 'Sam Builder',
      pin: '0123',
    );
    expect(Uuid.isValidUUID(fromString: receipt.userId), isTrue);
    expect(receipt.userId, isNot(f.owner.identity.userId));
    expect(receipt.name, 'Sam Builder');
    final certificate = jsonDecode(receipt.certificateBytes) as Map;
    expect(certificate['body']['kind'], 'company.user.authority@1');
    expect(certificate['body']['capabilities'], ['createJob']);
    expect(certificate['body']['credential'], 1);
    expect(certificate['body']['permission'], 1);
    expect(certificate['body']['request'], request);
    for (final secret in ['pin', 'salt', 'verifier', 'credentialDigest']) {
      expect(certificate['body'].containsKey(secret), isFalse);
    }
    final users = await f.aEnrollment.listCompanyUsers();
    expect(users.map((u) => u.userId), [
      f.owner.identity.userId,
      receipt.userId,
    ]);
    expect(users.last.name, 'Sam Builder');
    expect(users.last.capabilities, ['createJob']);
    expect(users.last.available, isTrue);
    expect(await sqlSnapshot(f.aDb), beforeSql);
    expect(f.a.identity!.id, beforeIdentity.id);
    expect(f.a.identity!.generation, beforeIdentity.generation);
    final state = Map<String, ProtectedInstallationState>.of(f.aStore.states);
    final retry = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: request,
      name: 'Sam Builder',
      pin: '0123',
    );
    expect(retry.certificateBytes, receipt.certificateBytes);
    expect(retry.commitment, receipt.commitment);
    expectJoinProtectedUnchanged(f.aStore, state);
    for (final changed in [
      (request: request, name: 'Other Name', pin: '0123'),
      (request: request, name: 'Sam Builder', pin: '1234'),
    ]) {
      await expectLater(
        f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: changed.request,
          name: changed.name,
          pin: changed.pin,
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, state);
      expect(await sqlSnapshot(f.aDb), beforeSql);
    }
    expect(f.aStore.maximumBytes, lessThanOrEqualTo(kInstallationStateLimit));
  });

  test(
    'signed-out issuer and invalid input cannot reserve an account',
    () async {
      final f = await JoinFixture.create();
      final beforeSql = await sqlSnapshot(f.aDb);
      final before = Map<String, ProtectedInstallationState>.of(
        f.aStore.states,
      );
      for (final name in ['', 'x' * 65, '\u0000hidden', '😀' * 17]) {
        await expectLater(
          f.aEnrollment.createRestrictedUser(
            owner: f.owner,
            requestId: const Uuid().v4(),
            name: name,
            pin: '0123',
          ),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
        expectJoinProtectedUnchanged(f.aStore, before);
      }
      await f.aEnrollment.signOut();
      await expectLater(
        f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Sam Builder',
          pin: '0123',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, before);
      expect(await sqlSnapshot(f.aDb), beforeSql);
    },
  );

  test('restricted root-device session creates its own v4 Job and cannot rename it', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    final receipt = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Sam Builder',
      pin: '0123',
    );
    final user = await f.aEnrollment.signInUser(receipt.userId, '0123');
    expect(user, isA<RestrictedUserSession>());
    expect(user, isNot(isA<OwnerSession>()));
    expect(f.owner.isValid, isFalse);
    final action = CreateJob(
      companyId: user.identity.companyId,
      shopId: user.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Sam offline Job',
    );
    final commands = CompanyJobCommands(enrollment: f.aEnrollment);
    final jobReceipt = await commands.createJob(action, ownerSession: user);
    final saved = (await f.aDb.select(f.aDb.companyJobs).get()).singleWhere(
      (r) => r.jobId == action.jobId,
    );
    final operation = jsonDecode(saved.operationBytes) as Map;
    expect(operation['body']['user'], receipt.userId);
    expect(operation['body']['device'], f.owner.identity.deviceId);
    expect(operation['authorization']['body']['v'], 4);
    expect(operation['authorization']['body']['user'], receipt.userId);
    expect(
      operation['authorization']['userAuthority'],
      receipt.certificateBytes,
    );
    expect(jsonDecode(saved.auditBytes)['originalUser'], receipt.userId);
    final beforeSql = await sqlSnapshot(f.aDb);
    await expectLater(
      f.aEnrollment.issueRenameJobAssertion(
        RenameJob(
          companyId: action.companyId,
          shopId: action.shopId,
          jobId: action.jobId,
          requestId: const Uuid().v4(),
          creationDigest: saved.operationCommitment,
          observedHeads: const [],
          name: 'Unauthorized rename',
        ),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(f.aDb), beforeSql);
    expect(
      (await commands.createJob(action, ownerSession: user)).bytes,
      jobReceipt.bytes,
    );
    final nextOwner = await f.aEnrollment.signIn('1234');
    expect(user.isValid, isFalse);
    expect(nextOwner.identity.userId, f.owner.identity.userId);
    await expectLater(
      commands.createJob(action, ownerSession: user),
      throwsA(anything),
    );
    expect(
      (await commands.listJobs(ownerSession: nextOwner)).map((j) => j.id),
      contains(action.jobId),
    );
  });

  test('restricted attempt budget survives restart and does not consume owner attempts', () async {
    final f = await JoinFixture.create();
    final receipt = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Sam Builder',
      pin: '0123',
    );
    for (var attempt = 0; attempt < 8; attempt++) {
      await expectLater(
        f.aEnrollment.signInUser(receipt.userId, '9999'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    }
    final reopened = CompanyEnrollment(installation: f.a, db: f.aDb);
    expect(reopened.currentSession, isNull);
    await expectLater(
      reopened.signInUser(receipt.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final owner = await reopened.signIn('1234');
    expect(owner.identity.userId, f.owner.identity.userId);
    final before = Map<String, ProtectedInstallationState>.of(f.aStore.states);
    final retry = await reopened.createRestrictedUser(
      owner: owner,
      requestId:
          (jsonDecode(receipt.certificateBytes) as Map)['body']['request']
              as String,
      name: 'Sam Builder',
      pin: '0123',
    );
    expect(retry.userId, receipt.userId);
    expectJoinProtectedUnchanged(f.aStore, before);
    await expectLater(
      reopened.signInUser(receipt.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
  });
}

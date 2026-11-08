import 'dart:convert';
import 'dart:io';
import 'dart:async';
import 'dart:typed_data';

import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';
import 'package:wired_parts/features/nearby/nearby_discovery.dart';
import 'package:wired_parts/features/nearby/nearby_protocol.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';
import 'package:uuid/uuid.dart';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as hashes;

import 'company_job_test_support.dart';

final class JoinTestDiscovery implements NearbyDiscovery {
  final controller = StreamController<List<NearbyPeer>>.broadcast();
  int port = 0;
  @override
  Stream<List<NearbyPeer>> get peers => controller.stream;
  @override
  Future<void> start({
    required String deviceId,
    required String name,
    required int port,
    required List<String> ips,
  }) async {
    this.port = port;
  }

  @override
  Future<void> updateAdvertisement({
    required String name,
    required int port,
    required List<String> ips,
  }) async {
    this.port = port;
  }

  @override
  Future<void> stop() async {}
}

Future<(NearbyJoinChannel, NearbyJoinChannel)> joinChannels({
  void Function(NearbyController b, NearbyController a)? onPaired,
  NearbyTransportObserver? onReceiverTransport,
  NearbyJoinReceiveObserver? onReceiverJoinReceive,
}) async {
  final bd = JoinTestDiscovery();
  final ad = JoinTestDiscovery();
  NearbyController make(
    String alias,
    JoinTestDiscovery discovery, {
    NearbyTransportObserver? onTransport,
    NearbyJoinReceiveObserver? onJoinReceive,
  }) => NearbyController(
    deviceId: alias,
    deviceName: alias,
    discovery: discovery,
    companyJoin: true,
    bindAddress: InternetAddress.loopbackIPv4,
    localIps: () async => ['127.0.0.1'],
    onTransportObservation: onTransport,
    onJoinReceiveObservation: onJoinReceive,
    collectPayload: () async =>
        throw StateError('Join must not collect a shop'),
    applyPayload: (_) async => throw StateError('Join must not replace a shop'),
  );
  final b = make(
    'encounter-b',
    bd,
    onTransport: onReceiverTransport,
    onJoinReceive: onReceiverJoinReceive,
  );
  final a = make('encounter-a', ad);
  addTearDown(() async {
    await b.dispose();
    await a.dispose();
    await bd.controller.close();
    await ad.controller.close();
  });
  await b.start();
  await a.start();
  await b.pair(
    NearbyPeer(
      deviceId: 'encounter-a',
      name: 'encounter-a',
      host: '127.0.0.1',
      port: ad.port,
    ),
  );
  expect(a.state.verifyCode, b.state.verifyCode);
  await a.confirmCode();
  await b.confirmCode();
  expect(a.state.phase, NearbyPhase.paired);
  expect(b.state.phase, NearbyPhase.paired);
  onPaired?.call(b, a);
  return (
    await NearbyJoinChannel.fromPairedSession(b.pairedJoinSession!),
    await NearbyJoinChannel.fromPairedSession(a.pairedJoinSession!),
  );
}

Future<Map<String, Object?>> sqlSnapshot(AppDatabase db) async => {
  for (final table in db.allTables)
    table.actualTableName:
        (await db
                .customSelect('SELECT * FROM "${table.actualTableName}"')
                .get())
            .map((r) => jsonEncode(r.data))
            .toList()
          ..sort(),
};

String canonicalJoinTest(Object? value) {
  Object? sorted(Object? value) {
    if (value is Map) {
      final keys = value.keys.cast<String>().toList()..sort();
      return {for (final key in keys) key: sorted(value[key])};
    }
    if (value is List) return value.map(sorted).toList();
    return value;
  }

  return jsonEncode(sorted(value));
}

enum JoinStoreCapacityFault { issuerReservation, recipientReservation }

final class TestProtectedStoreCapacityRefusal implements Exception {
  const TestProtectedStoreCapacityRefusal();
}

final class JoinActivationStore
    implements InstallationSecureStore, RecoveryFilePublisher {
  final delegate = JobTestStore();
  Map<String, ProtectedInstallationState> get states => delegate.states;
  JoinStoreCapacityFault? refuseNextCapacityAt;
  int capacityRefusalCount = 0;
  void Function(String namespace)? onRead;
  Future<void>? Function(String namespace)? beforeRead;
  @override
  Future<ProtectedInstallationState?> readState(String namespace) {
    onRead?.call(namespace);
    final barrier = beforeRead?.call(namespace);
    if (barrier != null) {
      return barrier.then((_) => delegate.readState(namespace));
    }
    return delegate.readState(namespace);
  }

  @override
  Future<void> writeRecoveryFileExclusive(String path, Uint8List bytes) =>
      delegate.writeRecoveryFileExclusive(path, bytes);
  bool loseNextBaseActivationReply = false;
  bool loseNextUserReply = false;
  int maximumBytes = 0;
  @override
  Future<String> compareAndSwapState(
    String namespace, {
    required String? expectedRevision,
    required String nextRevision,
    required Uint8List bytes,
  }) async {
    if (bytes.length > maximumBytes) maximumBytes = bytes.length;
    final after = jsonDecode(utf8.decode(bytes)) as Map;
    final issuerEnrollment = after['enrollment'];
    final recipientActivation = after['activation'];
    final issuerReservation =
        issuerEnrollment is Map && issuerEnrollment['pending'] is Map;
    final recipientReservation =
        after['v'] == 2 &&
        after['status'] == 'pending' &&
        recipientActivation is Map &&
        recipientActivation['after'] == null;
    if ((refuseNextCapacityAt == JoinStoreCapacityFault.issuerReservation &&
            issuerReservation) ||
        (refuseNextCapacityAt == JoinStoreCapacityFault.recipientReservation &&
            recipientReservation)) {
      refuseNextCapacityAt = null;
      capacityRefusalCount++;
      throw const TestProtectedStoreCapacityRefusal();
    }
    final prior = states[namespace];
    final wasUnjoined =
        prior != null &&
        (jsonDecode(utf8.decode(prior.bytes)) as Map)['companyTrust'] == null;
    final result = await delegate.compareAndSwapState(
      namespace,
      expectedRevision: expectedRevision,
      nextRevision: nextRevision,
      bytes: bytes,
    );
    if (loseNextUserReply && namespace.endsWith('.company-user-1')) {
      loseNextUserReply = false;
      throw StateError('Lost protected user CAS response');
    }
    if (loseNextBaseActivationReply &&
        wasUnjoined &&
        after['companyTrust'] != null) {
      loseNextBaseActivationReply = false;
      throw StateError('lost reply after successful activation base CAS');
    }
    return result;
  }
}

typedef OwnerDataSnapshot = ({
  List<Job> jobs,
  List<CompanyJob> history,
  String packageSha256,
});

final class JoinFixture {
  JoinFixture(
    this.root,
    this.aDb,
    this.bDb,
    this.aStore,
    this.bStore,
    this.a,
    this.b,
    this.aEnrollment,
    this.bEnrollment,
    this.owner,
  );
  final Directory root;
  final AppDatabase aDb;
  AppDatabase bDb;
  final JoinActivationStore aStore;
  final JoinActivationStore bStore;
  final InstallationSecurity a;
  InstallationSecurity b;
  final CompanyEnrollment aEnrollment;
  CompanyEnrollment bEnrollment;
  final OwnerSession owner;
  OwnerDataSnapshot? _ownerData;
  Future<void>? _closing;
  bool allowOwnerAdditions = false;
  static Future<JoinFixture> create({bool allowOwnerAdditions = false}) async {
    final root = Directory.systemTemp.createTempSync('join-durable-');
    final aDb = AppDatabase.forTesting(
      NativeDatabase(File('${root.path}/a.sqlite')),
    );
    final bDb = AppDatabase.forTesting(
      NativeDatabase(File('${root.path}/b.sqlite')),
    );
    final aStore = JoinActivationStore();
    final bStore = JoinActivationStore();
    final a = InstallationSecurity(
      store: aStore,
      namespace: 'synthetic.durable-a',
    );
    final b = InstallationSecurity(
      store: bStore,
      namespace: 'synthetic.durable-b',
    );
    await a.start(aDb);
    await b.start(bDb);
    final ae = CompanyEnrollment(installation: a, db: aDb);
    final be = CompanyEnrollment(installation: b, db: bDb);
    await ae.create(
      companyName: 'Synthetic durable crew',
      policy: CompanyContinuityPolicy.localContinuity,
      pin: '1234',
      recoveryPassphrase: 'synthetic durable authority phrase',
      recoveryFile: File('${root.path}/a.wpca'),
    );
    final fixture = JoinFixture(
      root,
      aDb,
      bDb,
      aStore,
      bStore,
      a,
      b,
      ae,
      be,
      await ae.signIn('1234'),
    );
    addTearDown(fixture.closeAndCheckOwnerData);
    fixture.allowOwnerAdditions = allowOwnerAdditions;
    await seedExistingOwnerJob(fixture);
    fixture._ownerData = await captureOwnerData(fixture);
    return fixture;
  }

  Future<void> closeAndCheckOwnerData() => _closing ??= _close();

  Future<void> _close() async {
    try {
      final ownerData = _ownerData;
      if (ownerData != null) {
        if (allowOwnerAdditions) {
          expect(await aDb.select(aDb.jobs).get(), containsAll(ownerData.jobs));
          expect(
            await aDb.select(aDb.companyJobs).get(),
            containsAll(ownerData.history),
          );
          expect(
            hashes.sha256
                .convert(await File('${root.path}/a.wpca').readAsBytes())
                .toString(),
            ownerData.packageSha256,
          );
        } else {
          await expectOwnerDataUnchanged(this, ownerData);
        }
      }
    } finally {
      await aDb.close();
      await bDb.close();
      await root.delete(recursive: true);
    }
  }

  Future<void> reopenB() async {
    await bEnrollment.signOut();
    await bDb.close();
    bDb = AppDatabase.forTesting(NativeDatabase(File('${root.path}/b.sqlite')));
    b = InstallationSecurity(store: bStore, namespace: b.namespace);
    await b.start(bDb);
    bEnrollment = CompanyEnrollment(installation: b, db: bDb);
  }
}

Future<void> advanceJoinFloor(
  JoinActivationStore store,
  String namespace,
  String key,
  int version,
) async {
  final prior = store.states[namespace]!;
  final body = jsonDecode(utf8.decode(prior.bytes)) as Map<String, dynamic>;
  body['floors'] = {...body['floors'] as Map, key: version};
  await store.compareAndSwapState(
    namespace,
    expectedRevision: prior.revision,
    nextRevision: const Uuid().v4(),
    bytes: Uint8List.fromList(utf8.encode(jsonEncode(body))),
  );
}

Future<void> activateFixtureB(JoinFixture f) async {
  final (bc, ac) = await joinChannels();
  final aj = CompanyJoin(enrollment: f.aEnrollment);
  final bj = CompanyJoin(enrollment: f.bEnrollment);
  final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
  await bj.acceptProvision(
    await bj.receiveProvision(
      bc,
      await aj.approveJoin(ac, request, ownerSession: f.owner),
    ),
  );
  bc.close();
  ac.close();
}

Future<void> seedExistingOwnerJob(JoinFixture f) async {
  await CompanyJobCommands(enrollment: f.aEnrollment).createJob(
    CreateJob(
      companyId: f.owner.identity.companyId,
      shopId: f.owner.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Original owner Job',
    ),
    ownerSession: f.owner,
  );
}

Future<OwnerDataSnapshot> captureOwnerData(JoinFixture f) async => (
  jobs: await f.aDb.select(f.aDb.jobs).get(),
  history: await f.aDb.select(f.aDb.companyJobs).get(),
  packageSha256: hashes.sha256
      .convert(await File('${f.root.path}/a.wpca').readAsBytes())
      .toString(),
);

Future<void> expectOwnerDataUnchanged(
  JoinFixture f,
  OwnerDataSnapshot before,
) async {
  expect(await f.aDb.select(f.aDb.jobs).get(), before.jobs);
  expect(await f.aDb.select(f.aDb.companyJobs).get(), before.history);
  final packageSha256 = hashes.sha256
      .convert(await File('${f.root.path}/a.wpca').readAsBytes())
      .toString();
  expect(packageSha256, before.packageSha256);
}

void expectJoinProtectedUnchanged(
  JoinActivationStore store,
  Map<String, ProtectedInstallationState> prior,
) {
  expect(store.states.keys, prior.keys);
  for (final key in prior.keys) {
    expect(store.states[key]!.revision, prior[key]!.revision);
    expect(
      base64Encode(store.states[key]!.bytes) == base64Encode(prior[key]!.bytes),
      isTrue,
      reason: 'protected bytes unchanged',
    );
  }
}

Future<Map<String, Object?>> unknownPeerProofWire(
  NearbyPairedJoinSession pair,
  String recipient,
) async {
  final keys = pair.keys;
  final key = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: keys.sendKey,
    nonce: utf8.encode(keys.id),
    info: utf8.encode('wiredpart-v2/company-join@1/${keys.sendDirection}'),
  );
  final recipientTag = await Hmac.sha256().calculateMac(
    utf8.encode('wiredpart.company.join.recipient@1:${keys.id}:$recipient'),
    secretKey: key,
  );
  final header = {
    'v': 1,
    'kind': 'peer-init',
    'request': const Uuid().v4(),
    'recipient': base64Encode(recipientTag.bytes),
    'session': keys.id,
    'direction': keys.sendDirection,
  };
  final body = {
    'v': 1,
    'nonce': base64Encode(List<int>.filled(32, 19)),
    'signature': base64Encode(List<int>.filled(64, 0)),
  };
  final box = await AesGcm.with256bits().encrypt(
    utf8.encode(canonicalJoinTest(body)),
    secretKey: key,
    aad: utf8.encode(canonicalJoinTest(header)),
  );
  return {
    ...header,
    'nonce': base64Encode(box.nonce),
    'ciphertext': base64Encode(box.cipherText),
    'tag': base64Encode(box.mac.bytes),
  };
}

Future<CompanyEnrollment> enrollAdditionalFixtureC(JoinFixture f) async {
  final db = AppDatabase.forTesting(
    NativeDatabase(File('${f.root.path}/additional-c.sqlite')),
  );
  addTearDown(db.close);
  final installation = InstallationSecurity(
    store: JoinActivationStore(),
    namespace: 'synthetic.additional-c',
  );
  await installation.start(db);
  final enrollment = CompanyEnrollment(installation: installation, db: db);
  final guest = CompanyJoin(enrollment: enrollment);
  final issuer = CompanyJoin(enrollment: f.aEnrollment);
  final (cc, ac) = await joinChannels();
  final request = await issuer.receiveJoinRequest(
    ac,
    await guest.beginJoin(cc),
  );
  await guest.acceptProvision(
    await guest.receiveProvision(
      cc,
      await issuer.approveJoin(ac, request, ownerSession: f.owner),
    ),
  );
  cc.close();
  ac.close();
  return enrollment;
}

void main() {
  test('final ACK rejects unrelated C floor plus same-instance reconcile with current authority guard', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final ce = await enrollAdditionalFixtureC(f);
    final cIdentity = (await ce.readIdentity())!;
    final bo = await f.bEnrollment.signIn('1234');
    var armed = false;
    var changed = false;
    var expected = Map.of(f.aStore.states);
    final aa = CompanyPeerAuthentication(
      enrollment: f.aEnrollment,
      onProofCheckpoint: (at) async {
        if (armed &&
            !changed &&
            at == CompanyPeerProofCheckpoint.afterExporter) {
          changed = true;
          await advanceJoinFloor(
            f.aStore,
            f.a.namespace,
            'revocation.device.${cIdentity.deviceId}',
            1,
          );
          await f.a.reconcile(
            f.aDb,
          ); // refreshes the SAME mutable cache and persisted revision
          expected = Map.of(f.aStore.states);
        }
      },
    );
    final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
    final (bc, ac) = await joinChannels();
    final selected = (await aa.retainedPeers(session: f.owner))
        .singleWhere((p) => p.deviceId == bo.identity.deviceId);
    final first = await aa.beginPeerChallenge(ac, selected, session: f.owner);
    final second = await ba.receivePeerChallenge(bc, first, session: bo);
    final third = await aa.receivePeerResponse(ac, second);
    final result = await ba.receivePeerCompletion(bc, third);
    final before = await sqlSnapshot(f.aDb);
    armed = true;
    await expectLater(
      aa.receivePeerAcknowledgment(ac, result.acknowledgment),
      throwsA(anything),
    );
    expect(changed, isTrue);
    expect(await sqlSnapshot(f.aDb), before);
    expectJoinProtectedUnchanged(f.aStore, expected);
  });

  test('unknown initiator reflection and cross-channel proofs disclose no responder identity or durable writes', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final bo = await f.bEnrollment.signIn('1234');
    final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
    final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
    late NearbyPairedJoinSession sender;
    final (bc, ac) = await joinChannels(
      onPaired: (b, _) => sender = b.pairedJoinSession!,
    );
    final beforeA = await sqlSnapshot(f.aDb);
    final beforeB = await sqlSnapshot(f.bDb);
    final protectedA = Map.of(f.aStore.states);
    final protectedB = Map.of(f.bStore.states);
    final unknown = await unknownPeerProofWire(
      sender,
      base64Encode(f.a.identity!.publicKey),
    );
    await expectLater(
      aa.receivePeerChallenge(ac, unknown, session: f.owner),
      throwsA(anything),
    );
    final first = await ba.beginPeerChallenge(
      bc,
      (await ba.retainedPeers(session: bo)).single,
      session: bo,
    );
    await expectLater(
      ba.receivePeerChallenge(bc, first, session: bo),
      throwsA(anything),
    );
    final (_, otherA) = await joinChannels();
    await expectLater(
      aa.receivePeerChallenge(otherA, first, session: f.owner),
      throwsA(anything),
    );
    // A's original retained binding still works; none of the rejected wires
    // installs a key, changes a credential or causes a responder proof.
    final response = await aa.receivePeerChallenge(ac, first, session: f.owner);
    expect(response['kind'], 'peer-response');
    expect(jsonEncode(response), isNot(contains(f.owner.identity.companyId)));
    expect(await sqlSnapshot(f.aDb), beforeA);
    expect(await sqlSnapshot(f.bDb), beforeB);
    expectJoinProtectedUnchanged(f.aStore, protectedA);
    expectJoinProtectedUnchanged(f.bStore, protectedB);
  });

  test('signed member certificates cannot change issuer user scope versions or delegation', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final row =
        (await f.aDb.select(f.aDb.companyMembershipCertificates).get()).single;
    final before = await sqlSnapshot(f.aDb);
    final protected = Map.of(f.aStore.states);
    final changes = <void Function(Map)>[
      (b) => b['company'] = const Uuid().v4(),
      (b) => b['shop'] = const Uuid().v4(),
      (b) => b['depth'] = 2,
      (b) => b['delegable'] = true,
      (b) => (b['issuer'] as Map)['kind'] = 'arbitraryRoot',
      (b) => (b['issuer'] as Map)['grant'] = const Uuid().v4(),
      (b) => (b['recipient'] as Map)['key'] = base64Encode(
        List<int>.filled(32, 1),
      ),
      (b) => (b['recipient'] as Map)['user'] = const Uuid().v4(),
      (b) => (b['recipient'] as Map)['credential'] = 2,
      (b) => (b['recipient'] as Map)['permission'] = 2,
      (b) => (b['recipient'] as Map)['capabilities'] = [
        'createJob',
        'enrollDevice',
      ],
      (b) => b['extra'] = true,
    ];
    for (final change in changes) {
      final signed = jsonDecode(row.proofBytes) as Map;
      change(signed['body'] as Map);
      await expectLater(
        resolveCompanyMembership(
          db: f.aDb,
          installation: f.a,
          certificateBytes: canonicalJoinTest(signed),
        ),
        throwsA(anything),
      );
    }
    expect(await sqlSnapshot(f.aDb), before);
    expectJoinProtectedUnchanged(f.aStore, protected);
    final bo = await f.bEnrollment.signIn('1234');
    final cDb = AppDatabase.forTesting(
      NativeDatabase(File('${f.root.path}/unjoined-c.sqlite')),
    );
    addTearDown(cDb.close);
    final c = InstallationSecurity(
      store: JoinActivationStore(),
      namespace: 'synthetic.unjoined-c',
    );
    await c.start(cDb);
    final (cc, bc2) = await joinChannels();
    final memberJoin = CompanyJoin(enrollment: f.bEnrollment);
    final request = await memberJoin.receiveJoinRequest(
      bc2,
      await CompanyJoin(
        enrollment: CompanyEnrollment(installation: c, db: cDb),
      ).beginJoin(cc),
    );
    final bBefore = await sqlSnapshot(f.bDb);
    final bProtected = Map.of(f.bStore.states);
    await expectLater(
      memberJoin.approveJoin(bc2, request, ownerSession: bo),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.bDb), bBefore);
    expectJoinProtectedUnchanged(f.bStore, bProtected);
  });

  test('committed B lost reply retries same consent and one production Job without restart', () async {
    final f = await JoinFixture.create();
    final (bc, ac) = await joinChannels();
    var lost = false;
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(
      enrollment: f.bEnrollment,
      afterCommit: () async {
        if (!lost) {
          lost = true;
          throw StateError('committed reply lost');
        }
      },
    );
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    final preview = await bj.receiveProvision(
      bc,
      await aj.approveJoin(ac, request, ownerSession: f.owner),
    );
    await expectLater(bj.acceptProvision(preview), throwsA(anything));
    expect(await f.bDb.select(f.bDb.companyJoinEvents).get(), hasLength(1));
    final accepted = await bj.acceptProvision(preview);
    final owner = await f.bEnrollment.signIn('1234');
    await CompanyJobCommands(enrollment: f.bEnrollment).createJob(
      CreateJob(
        companyId: accepted.companyId,
        shopId: accepted.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: 'After consent lost reply',
      ),
      ownerSession: owner,
    );
    expect(await f.bDb.select(f.bDb.companyJoinEvents).get(), hasLength(1));
    expect(
      await f.bDb.select(f.bDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
    expect(await f.bDb.select(f.bDb.companyJobs).get(), hasLength(1));
  });

  test('issuer committed lost reply returns original provision without duplicate grant or events', () async {
    final f = await JoinFixture.create();
    final (bc, ac) = await joinChannels();
    var lost = false;
    final aj = CompanyJoin(
      enrollment: f.aEnrollment,
      afterCommit: () async {
        if (!lost) {
          lost = true;
          throw StateError('provision reply lost');
        }
      },
    );
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    await expectLater(
      aj.approveJoin(ac, request, ownerSession: f.owner),
      throwsA(anything),
    );
    final before = await sqlSnapshot(f.aDb);
    final saved = jsonDecode(
      (await f.aDb.select(f.aDb.companyJoinEvents).get()).single.evidenceBytes,
    ) as Map;
    final wire = await aj.approveJoin(ac, request, ownerSession: f.owner);
    expect(canonicalJoinTest(wire), canonicalJoinTest(saved['wire']));
    expect(await sqlSnapshot(f.aDb), before);
    await bj.acceptProvision(await bj.receiveProvision(bc, wire));
    expect(
      await f.aDb.select(f.aDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
    expect(
      await f.bDb.select(f.bDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
  });

  test('eight fresh approved provisions exhaust one immutable grant without refill', () async {
    final f = await JoinFixture.create();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    String? certificate;
    for (var attempt = 1; attempt <= 9; attempt++) {
      final (bc, ac) = await joinChannels();
      final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
      if (attempt <= 8) {
        await aj.approveJoin(ac, request, ownerSession: f.owner);
        final row =
            (await f.aDb.select(f.aDb.companyMembershipCertificates).get())
                .single;
        certificate ??= row.proofBytes;
        expect(row.proofBytes, certificate);
        expect(
          await f.aDb.select(f.aDb.companyJoinEvents).get(),
          hasLength(attempt),
        );
      } else {
        final before = await sqlSnapshot(f.aDb);
        final protected = Map.of(f.aStore.states);
        await expectLater(
          aj.approveJoin(ac, request, ownerSession: f.owner),
          throwsA(anything),
        );
        expect(await sqlSnapshot(f.aDb), before);
        expectJoinProtectedUnchanged(f.aStore, protected);
      }
      bc.close();
      ac.close();
    }
    expect(f.aStore.maximumBytes, lessThanOrEqualTo(kInstallationStateLimit));
  });

  test('issuer capacity refusal preserves owner data and retries the same request once', () async {
    final f = await JoinFixture.create();
    final ownerData = await captureOwnerData(f);
    expect(ownerData.jobs, hasLength(1));
    expect(ownerData.history, hasLength(1));

    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc, ac) = await joinChannels();
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    final beforeSql = await sqlSnapshot(f.aDb);
    final beforeProtected = Map.of(f.aStore.states);
    f.aStore.refuseNextCapacityAt = JoinStoreCapacityFault.issuerReservation;

    await expectLater(
      aj.approveJoin(ac, request, ownerSession: f.owner),
      throwsA(isA<TestProtectedStoreCapacityRefusal>()),
    );

    expect(f.aStore.capacityRefusalCount, 1);
    expect(f.aStore.refuseNextCapacityAt, isNull);
    expect(await sqlSnapshot(f.aDb), beforeSql);
    expectJoinProtectedUnchanged(f.aStore, beforeProtected);
    expect(
      await f.aDb.select(f.aDb.companyMembershipCertificates).get(),
      isEmpty,
    );
    expect(await f.aDb.select(f.aDb.companyJoinEvents).get(), isEmpty);
    await expectOwnerDataUnchanged(f, ownerData);

    final wire = await aj.approveJoin(ac, request, ownerSession: f.owner);
    final accepted = await bj.receiveProvision(bc, wire);
    final identity = await bj.acceptProvision(accepted);
    expect(identity.companyId, f.owner.identity.companyId);
    expect(identity.userId, f.owner.identity.userId);
    expect(
      await f.aDb.select(f.aDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
    expect(await f.aDb.select(f.aDb.companyJoinRequests).get(), hasLength(1));
    expect(await f.aDb.select(f.aDb.companyJoinEvents).get(), hasLength(1));
    expect(
      await f.bDb.select(f.bDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
    expect(await f.bDb.select(f.bDb.companyJoinRequests).get(), hasLength(1));
    expect(await f.bDb.select(f.bDb.companyJoinEvents).get(), hasLength(1));
    expect(f.aStore.capacityRefusalCount, 1);
    await expectOwnerDataUnchanged(f, ownerData);
    bc.close();
    ac.close();
  });

  test('recipient capacity refusal stays unjoined and retries the same approved provision', () async {
    final f = await JoinFixture.create();
    final ownerData = await captureOwnerData(f);
    expect(ownerData.jobs, hasLength(1));
    expect(ownerData.history, hasLength(1));

    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc, ac) = await joinChannels();
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    final wire = await aj.approveJoin(ac, request, ownerSession: f.owner);
    final preview = await bj.receiveProvision(bc, wire);
    final beforeSql = await sqlSnapshot(f.bDb);
    final beforeProtected = Map.of(f.bStore.states);
    f.bStore.refuseNextCapacityAt = JoinStoreCapacityFault.recipientReservation;

    await expectLater(
      bj.acceptProvision(preview),
      throwsA(isA<TestProtectedStoreCapacityRefusal>()),
    );

    expect(f.bStore.capacityRefusalCount, 1);
    expect(f.bStore.refuseNextCapacityAt, isNull);
    expect(await sqlSnapshot(f.bDb), beforeSql);
    expectJoinProtectedUnchanged(f.bStore, beforeProtected);
    expect(await f.bEnrollment.readStatus(), CompanyBootstrapStatus.unjoined);
    await expectOwnerDataUnchanged(f, ownerData);

    final identity = await bj.acceptProvision(preview);
    expect(identity.companyId, f.owner.identity.companyId);
    expect(identity.userId, f.owner.identity.userId);
    expect(
      await f.bDb.select(f.bDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
    expect(await f.bDb.select(f.bDb.companyJoinRequests).get(), hasLength(1));
    expect(await f.bDb.select(f.bDb.companyJoinEvents).get(), hasLength(1));
    expect(f.bStore.capacityRefusalCount, 1);
    await expectOwnerDataUnchanged(f, ownerData);
    bc.close();
    ac.close();
  });

  for (final checkpoint in CompanyPeerProofCheckpoint.values) {
    for (final change in ['signout', 'floor']) {
      test(
        'late $change at $checkpoint refuses proof after actual crypto without local admission',
        () async {
          final f = await JoinFixture.create();
          await activateFixtureB(f);
          final owner = await f.bEnrollment.signIn('1234');
          final peers = await CompanyPeerAuthentication(
            enrollment: f.bEnrollment,
          ).retainedPeers(session: owner);
          final (bc, _) = await joinChannels();
          final before = await sqlSnapshot(f.bDb);
          var expected = Map.of(f.bStore.states);
          var changed = false;
          final authentication = CompanyPeerAuthentication(
            enrollment: f.bEnrollment,
            onProofCheckpoint: (at) async {
              if (at != checkpoint || changed) return;
              changed = true;
              if (change == 'signout') {
                await f.bEnrollment.signOut();
              } else {
                await advanceJoinFloor(
                  f.bStore,
                  f.b.namespace,
                  'revocation.device.${owner.identity.deviceId}',
                  1,
                );
                expected = Map.of(f.bStore.states);
              }
            },
          );
          await expectLater(
            authentication.beginPeerChallenge(bc, peers.single, session: owner),
            throwsA(anything),
          );
          expect(changed, isTrue);
          expect(await sqlSnapshot(f.bDb), before);
          expectJoinProtectedUnchanged(f.bStore, expected);
        },
      );
    }
  }

  test('initiator receives no final capability when signout lands after acknowledgment exporter', () async {
    final f = await JoinFixture.create();
    await activateFixtureB(f);
    final bo = await f.bEnrollment.signIn('1234');
    var armed = false;
    var changed = false;
    final ba = CompanyPeerAuthentication(
      enrollment: f.bEnrollment,
      onProofCheckpoint: (at) async {
        if (armed &&
            !changed &&
            at == CompanyPeerProofCheckpoint.afterExporter) {
          changed = true;
          await f.bEnrollment.signOut();
        }
      },
    );
    final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
    final (bc, ac) = await joinChannels();
    final first = await ba.beginPeerChallenge(
      bc,
      (await ba.retainedPeers(session: bo)).single,
      session: bo,
    );
    final second = await aa.receivePeerChallenge(ac, first, session: f.owner);
    final third = await ba.receivePeerResponse(bc, second);
    final result = await aa.receivePeerCompletion(ac, third);
    final before = await sqlSnapshot(f.bDb);
    final protected = Map.of(f.bStore.states);
    armed = true;
    await expectLater(
      ba.receivePeerAcknowledgment(bc, result.acknowledgment),
      throwsA(anything),
    );
    expect(changed, isTrue);
    expect(await sqlSnapshot(f.bDb), before);
    expectJoinProtectedUnchanged(f.bStore, protected);
  });

  test('A retains valid B after C alone is known revoked and returns no proof to C', () async {
    final f = await JoinFixture.create();
    final (bc0, ac0) = await joinChannels();
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final request = await aj.receiveJoinRequest(ac0, await bj.beginJoin(bc0));
    await bj.acceptProvision(
      await bj.receiveProvision(
        bc0,
        await aj.approveJoin(ac0, request, ownerSession: f.owner),
      ),
    );
    bc0.close();
    ac0.close();
    final cDb = AppDatabase.forTesting(
      NativeDatabase(File('${f.root.path}/c.sqlite')),
    );
    addTearDown(cDb.close);
    final c = InstallationSecurity(
      store: JoinActivationStore(),
      namespace: 'synthetic.durable-c',
    );
    await c.start(cDb);
    final ce = CompanyEnrollment(installation: c, db: cDb);
    final cj = CompanyJoin(enrollment: ce);
    final (cc0, ac1) = await joinChannels();
    final cRequest = await aj.receiveJoinRequest(ac1, await cj.beginJoin(cc0));
    final cIdentity = await cj.acceptProvision(
      await cj.receiveProvision(
        cc0,
        await aj.approveJoin(ac1, cRequest, ownerSession: f.owner),
      ),
    );
    cc0.close();
    ac1.close();
    await advanceJoinFloor(
      f.aStore,
      f.a.namespace,
      'revocation.device.${cIdentity.deviceId}',
      1,
    );
    final ao = await f.aEnrollment.signIn('1234');
    final bo = await f.bEnrollment.signIn('1234');
    final co = await ce.signIn(
      '1234',
    ); // C has not learned A's offline revocation
    final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
    final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
    final ca = CompanyPeerAuthentication(enrollment: ce);
    final peers = await aa.retainedPeers(session: ao);
    expect(peers.map((p) => p.deviceId), [bo.identity.deviceId]);
    final (bc, ac) = await joinChannels();
    final first = await ba.beginPeerChallenge(
      bc,
      (await ba.retainedPeers(session: bo)).single,
      session: bo,
    );
    final second = await aa.receivePeerChallenge(ac, first, session: ao);
    final complete = await ba.receivePeerResponse(bc, second);
    final accepted = await aa.receivePeerCompletion(ac, complete);
    await ba.receivePeerAcknowledgment(bc, accepted.acknowledgment);
    bc.close();
    ac.close();
    final (cc, ac2) = await joinChannels();
    final before = await sqlSnapshot(f.aDb);
    final protected = Map.of(f.aStore.states);
    final revokedFirst = await ca.beginPeerChallenge(
      cc,
      (await ca.retainedPeers(session: co)).single,
      session: co,
    );
    await expectLater(
      aa.receivePeerChallenge(ac2, revokedFirst, session: ao),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.aDb), before);
    for (final key in protected.keys) {
      expect(f.aStore.states[key]!.revision, protected[key]!.revision);
      expect(
        base64Encode(f.aStore.states[key]!.bytes) ==
            base64Encode(protected[key]!.bytes),
        isTrue,
      );
    }
  });

  test('issuer revocation learned in approval hook rolls all SQL back and returns no provision', () async {
    final f = await JoinFixture.create();
    final before = await sqlSnapshot(f.aDb);
    final revocation = 'revocation.device.${f.owner.identity.deviceId}';
    final aj = CompanyJoin(
      enrollment: f.aEnrollment,
      beforeCommit: () =>
          advanceJoinFloor(f.aStore, f.a.namespace, revocation, 1),
    );
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc, ac) = await joinChannels();
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    await expectLater(
      aj.approveJoin(ac, request, ownerSession: f.owner),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.aDb), before);
    expect(
      (jsonDecode(utf8.decode(f.aStore.states[f.a.namespace]!.bytes))
          as Map)['floors'][revocation],
      1,
    );
    final custody = jsonDecode(
      utf8.decode(
        f.aStore.states[companyCustodyNamespace(f.a.namespace)]!.bytes,
      ),
    ) as Map;
    expect(custody['enrollment']['pending'], isNull);
  });

  test('fresh protected floor before B consent denies without SQL or protected changes', () async {
    final f = await JoinFixture.create();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc, ac) = await joinChannels();
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    final preview = await bj.receiveProvision(
      bc,
      await aj.approveJoin(ac, request, ownerSession: f.owner),
    );
    await advanceJoinFloor(
      f.bStore,
      f.b.namespace,
      'revocation.device.${f.owner.identity.deviceId}',
      1,
    );
    final before = await sqlSnapshot(f.bDb);
    final protected = Map.of(f.bStore.states);
    await expectLater(bj.acceptProvision(preview), throwsA(anything));
    expect(await sqlSnapshot(f.bDb), before);
    expect(f.bStore.states.keys, protected.keys);
    for (final key in protected.keys) {
      expect(f.bStore.states[key]!.revision, protected[key]!.revision);
      expect(
        base64Encode(f.bStore.states[key]!.bytes) ==
            base64Encode(protected[key]!.bytes),
        isTrue,
        reason: 'protected bytes unchanged',
      );
    }
  });

  test('lost base activation CAS reply reconciles exact pre-Join SQL binding after restart', () async {
    final f = await JoinFixture.create();
    final (bc, ac) = await joinChannels();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    final preview = await bj.receiveProvision(
      bc,
      await aj.approveJoin(ac, request, ownerSession: f.owner),
    );
    final bindingBefore = await f.bDb.settingsDao.getSetting(
      kInstallationBindingKey,
    );
    f.bStore.loseNextBaseActivationReply = true;
    await expectLater(bj.acceptProvision(preview), throwsA(anything));
    expect(
      await f.bDb.settingsDao.getSetting(kInstallationBindingKey),
      bindingBefore,
    );
    final namespace = companyCustodyNamespace(f.b.namespace);
    final pending =
        jsonDecode(utf8.decode(f.bStore.states[namespace]!.bytes)) as Map;
    expect(pending['status'], 'pending');
    final base =
        jsonDecode(utf8.decode(f.bStore.states[f.b.namespace]!.bytes)) as Map;
    expect(
      base['companyTrust'],
      isNotNull,
    ); // CAS actually succeeded; SQL update did not
    await f.reopenB();
    expect(await f.bEnrollment.readStatus(), CompanyBootstrapStatus.active);
    expect(
      (await f.bEnrollment.signIn('1234')).identity.deviceId,
      preview.identity.deviceId,
    );
    expect(
      await f.bDb.select(f.bDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
    expect(await f.bDb.select(f.bDb.companyJoinEvents).get(), hasLength(1));
    expect(f.aStore.maximumBytes, lessThanOrEqualTo(kInstallationStateLimit));
    expect(f.bStore.maximumBytes, lessThanOrEqualTo(kInstallationStateLimit));
  });

  test('cold retained A and B complete three fresh peer proofs without durable changes', () async {
    final f = await JoinFixture.create();
    final (oldB, oldA) = await joinChannels();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final request = await aj.receiveJoinRequest(oldA, await bj.beginJoin(oldB));
    await bj.acceptProvision(
      await bj.receiveProvision(
        oldB,
        await aj.approveJoin(oldA, request, ownerSession: f.owner),
      ),
    );
    await aj.acknowledgeJoin(
      oldA,
      await bj.activationAcknowledgment(oldB),
      ownerSession: f.owner,
    );
    oldA.close();
    oldB.close();
    await f.reopenB();
    await f.aEnrollment.signOut();
    final a2 = InstallationSecurity(store: f.aStore, namespace: f.a.namespace);
    await a2.start(f.aDb);
    final ae = CompanyEnrollment(installation: a2, db: f.aDb);
    final ao = await ae.signIn('1234');
    final bo = await f.bEnrollment.signIn('1234');
    final authA = CompanyPeerAuthentication(enrollment: ae);
    final authB = CompanyPeerAuthentication(enrollment: f.bEnrollment);
    final selected = (await authB.retainedPeers(session: bo)).single;
    final (bc, ac) = await joinChannels();
    final beforeA = await sqlSnapshot(f.aDb);
    final beforeB = await sqlSnapshot(f.bDb);
    final pinsA = Map.of(f.aStore.states);
    final pinsB = Map.of(f.bStore.states);
    final first = await authB.beginPeerChallenge(bc, selected, session: bo);
    expect(jsonEncode(first), isNot(contains(bo.identity.companyId)));
    expect(
      jsonEncode(first),
      isNot(contains(base64Encode(f.b.identity!.publicKey))),
    );
    final second = await authA.receivePeerChallenge(ac, first, session: ao);
    final third = await authB.receivePeerResponse(bc, second);
    final result = await authA.receivePeerCompletion(ac, third);
    final bCapability = await authB.receivePeerAcknowledgment(
      bc,
      result.acknowledgment,
    );
    expect(bCapability.deviceId, ao.identity.deviceId);
    expect(result.membership.deviceId, bo.identity.deviceId);
    await bCapability.requireCurrent();
    await result.membership.requireCurrent();
    expect(await sqlSnapshot(f.aDb), beforeA);
    expect(await sqlSnapshot(f.bDb), beforeB);
    for (final pair in [(f.aStore, pinsA), (f.bStore, pinsB)]) {
      for (final key in pair.$2.keys) {
        expect(pair.$1.states[key]!.revision, pair.$2[key]!.revision);
        expect(
          base64Encode(pair.$1.states[key]!.bytes) ==
              base64Encode(pair.$2[key]!.bytes),
          isTrue,
          reason: 'protected bytes unchanged',
        );
      }
    }
    await ae.signOut();
    await expectLater(result.membership.requireCurrent(), throwsA(anything));
    bc.close();
    await expectLater(bCapability.requireCurrent(), throwsA(anything));
  });

  test('signed-out approval and tampered provision refuse with complete local baselines unchanged', () async {
    final f = await JoinFixture.create();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc, ac) = await joinChannels();
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    await f.aEnrollment.signOut();
    final aBefore = await sqlSnapshot(f.aDb);
    final aProtected = Map.of(f.aStore.states);
    await expectLater(
      aj.approveJoin(ac, request, ownerSession: f.owner),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.aDb), aBefore);
    for (final key in aProtected.keys) {
      expect(f.aStore.states[key]!.revision, aProtected[key]!.revision);
      expect(
        base64Encode(f.aStore.states[key]!.bytes) ==
            base64Encode(aProtected[key]!.bytes),
        isTrue,
        reason: 'protected bytes unchanged',
      );
    }
    final live = await f.aEnrollment.signIn('1234');
    await expectLater(
      aj.approveJoin(ac, request, ownerSession: live),
      throwsA(anything),
    );
    final (bc2, ac2) = await joinChannels();
    final freshRequest = await aj.receiveJoinRequest(
      ac2,
      await bj.beginJoin(bc2),
    );
    final provision = await aj.approveJoin(
      ac2,
      freshRequest,
      ownerSession: live,
    );
    final bBefore = await sqlSnapshot(f.bDb);
    final bProtected = Map.of(f.bStore.states);
    final tag = base64Decode(provision['tag'] as String);
    tag[0] ^= 1;
    await expectLater(
      bj.receiveProvision(bc2, {...provision, 'tag': base64Encode(tag)}),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.bDb), bBefore);
    for (final key in bProtected.keys) {
      expect(f.bStore.states[key]!.revision, bProtected[key]!.revision);
      expect(
        base64Encode(f.bStore.states[key]!.bytes) ==
            base64Encode(bProtected[key]!.bytes),
        isTrue,
        reason: 'protected bytes unchanged',
      );
    }
  });

  test('issuer rejects deleted provisioning attempt instead of refilling retry history', () async {
    final f = await JoinFixture.create();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc, ac) = await joinChannels();
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    await aj.approveJoin(ac, request, ownerSession: f.owner);
    await f.aDb.delete(f.aDb.companyJoinEvents).go();
    final before = await sqlSnapshot(f.aDb);
    final protected = Map.of(f.aStore.states);
    await expectLater(
      aj.approveJoin(ac, request, ownerSession: f.owner),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.aDb), before);
    for (final key in protected.keys) {
      expect(f.aStore.states[key]!.revision, protected[key]!.revision);
      expect(
        base64Encode(f.aStore.states[key]!.bytes) ==
            base64Encode(protected[key]!.bytes),
        isTrue,
        reason: 'protected bytes unchanged',
      );
    }
  });

  test('provisioned preconsent crash resumes fresh request with one immutable grant and no B writes', () async {
    final f = await JoinFixture.create();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final (bc, ac) = await joinChannels();
    var bj = CompanyJoin(enrollment: f.bEnrollment);
    final baseline = await sqlSnapshot(f.bDb);
    final protected = Map.of(f.bStore.states);
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    final firstWire = await aj.approveJoin(ac, request, ownerSession: f.owner);
    await bj.receiveProvision(bc, firstWire); // preview only, no consent
    final cert =
        (await f.aDb.select(f.aDb.companyMembershipCertificates).get()).single;
    expect(await sqlSnapshot(f.bDb), baseline);
    for (final key in protected.keys) {
      expect(f.bStore.states[key]!.revision, protected[key]!.revision);
      expect(
        base64Encode(f.bStore.states[key]!.bytes) ==
            base64Encode(protected[key]!.bytes),
        isTrue,
        reason: 'protected bytes unchanged',
      );
    }
    bc.close();
    ac.close();
    await f.reopenB();
    bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc2, ac2) = await joinChannels();
    final newRequest = await aj.receiveJoinRequest(
      ac2,
      await bj.beginJoin(bc2),
    );
    expect(newRequest.requestId, isNot(request.requestId));
    final secondWire = await aj.approveJoin(
      ac2,
      newRequest,
      ownerSession: f.owner,
    );
    final preview = await bj.receiveProvision(bc2, secondWire);
    expect(await sqlSnapshot(f.bDb), baseline);
    await bj.acceptProvision(preview);
    expect(await f.aDb.select(f.aDb.companyMembershipCertificates).get(), [
      cert,
    ]);
    expect(await f.aDb.select(f.aDb.companyJoinRequests).get(), hasLength(1));
    expect(await f.aDb.select(f.aDb.companyJoinEvents).get(), hasLength(2));
    await expectLater(f.bEnrollment.signIn('9999'), throwsA(anything));
    final namespace = companyCustodyNamespace(f.b.namespace);
    final prior = f.bStore.states[namespace]!;
    expect((jsonDecode(utf8.decode(prior.bytes)) as Map)['attempts'], 7);
    await expectLater(
      bj.acceptProvision(preview),
      throwsA(anything),
    ); // sign-in closed the old channel; no budget refill
    expect(f.bStore.states[namespace]!.revision, prior.revision);
    expect(
      base64Encode(f.bStore.states[namespace]!.bytes) ==
          base64Encode(prior.bytes),
      isTrue,
      reason: 'protected bytes unchanged',
    );
    expect(
      (await f.bEnrollment.signIn('1234')).identity.userId,
      f.owner.identity.userId,
    );
  });

  test('consented activation rollback stays locked and fresh reapproval preserves pending budget', () async {
    final f = await JoinFixture.create();
    final aj = CompanyJoin(enrollment: f.aEnrollment);
    final (bc, ac) = await joinChannels();
    var bj = CompanyJoin(
      enrollment: f.bEnrollment,
      beforeCommit: () async => throw StateError('injected interruption'),
    );
    final before = await sqlSnapshot(f.bDb);
    final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
    final preview = await bj.receiveProvision(
      bc,
      await aj.approveJoin(ac, request, ownerSession: f.owner),
    );
    await expectLater(bj.acceptProvision(preview), throwsA(anything));
    expect(await sqlSnapshot(f.bDb), before);
    await f.reopenB();
    expect(
      await f.bEnrollment.readStatus(),
      CompanyBootstrapStatus.pendingJoin,
    );
    await expectLater(f.bEnrollment.signIn('1234'), throwsA(anything));
    bj = CompanyJoin(enrollment: f.bEnrollment);
    final (bc2, ac2) = await joinChannels();
    final request2 = await aj.receiveJoinRequest(ac2, await bj.beginJoin(bc2));
    await bj.acceptProvision(
      await bj.receiveProvision(
        bc2,
        await aj.approveJoin(ac2, request2, ownerSession: f.owner),
      ),
    );
    expect(
      (await f.bEnrollment.signIn('1234')).identity.userId,
      f.owner.identity.userId,
    );
    expect(
      await f.aDb.select(f.aDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
    expect(
      await f.bDb.select(f.bDb.companyMembershipCertificates).get(),
      hasLength(1),
    );
  });

  test(
    'canonical nonce spelling denies URL-safe alias of an admitted envelope',
    () async {
      final root = Directory.systemTemp.createTempSync('join-nonce-alias-');
      final db = AppDatabase.forTesting(
        NativeDatabase(File('${root.path}/b.sqlite')),
      );
      final installation = InstallationSecurity(
        store: JobTestStore(),
        namespace: 'synthetic.join-alias',
      );
      addTearDown(() async {
        await db.close();
        await root.delete(recursive: true);
      });
      await installation.start(db);
      late NearbyPairedJoinSession bPair;
      final (bc, ac) = await joinChannels(
        onPaired: (b, _) {
          bPair = b.pairedJoinSession!;
        },
      );
      final join = CompanyJoin(
        enrollment: CompanyEnrollment(installation: installation, db: db),
      );
      final emitted = await join.beginJoin(bc);
      final key = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: bPair.keys.sendKey,
        nonce: utf8.encode(bPair.keys.id),
        info: utf8.encode('wiredpart-v2/company-join@1/guest'),
      );
      final header = {...emitted}
        ..remove('nonce')
        ..remove('ciphertext')
        ..remove('tag');
      final aad = utf8.encode(canonicalJoinTest(header));
      final aes = AesGcm.with256bits();
      final original = await aes.decrypt(
        SecretBox(
          base64Decode(emitted['ciphertext'] as String),
          nonce: base64Decode(emitted['nonce'] as String),
          mac: Mac(base64Decode(emitted['tag'] as String)),
        ),
        secretKey: key,
        aad: aad,
      );
      // Rewrap the unchanged production request with a fixed valid AEAD nonce.
      final box = await aes.encrypt(
        original,
        secretKey: key,
        nonce: List<int>.filled(12, 251),
        aad: aad,
      );
      final nonce = base64Encode(box.nonce);
      expect(nonce, contains('+'));
      final canonical = {
        ...header,
        'nonce': nonce,
        'ciphertext': base64Encode(box.cipherText),
        'tag': base64Encode(box.mac.bytes),
      };
      final baseline = await sqlSnapshot(db);
      await join.receiveJoinRequest(ac, canonical);
      final alias = {
        ...canonical,
        'nonce': nonce.replaceAll('+', '-').replaceAll('/', '_'),
      };
      await expectLater(join.receiveJoinRequest(ac, alias), throwsA(anything));
      expect(await sqlSnapshot(db), baseline);
    },
  );
  test(
    'approved B retains same user PIN rootlessly and can create after restart',
    () async {
      final root = Directory.systemTemp.createTempSync('company-join-owner-');
      final aDb = AppDatabase.forTesting(
        NativeDatabase(File('${root.path}/a.sqlite')),
      );
      var bDb = AppDatabase.forTesting(
        NativeDatabase(File('${root.path}/b.sqlite')),
      );
      final aStore = JobTestStore();
      final bStore = JobTestStore();
      final a = InstallationSecurity(
        store: aStore,
        namespace: 'synthetic.join-a',
      );
      var b = InstallationSecurity(
        store: bStore,
        namespace: 'synthetic.join-b',
      );
      addTearDown(() async {
        await aDb.close();
        await bDb.close();
        await root.delete(recursive: true);
      });
      await a.start(aDb);
      await b.start(bDb);
      final aEnrollment = CompanyEnrollment(installation: a, db: aDb);
      var bEnrollment = CompanyEnrollment(installation: b, db: bDb);
      final identity = await aEnrollment.create(
        companyName: 'Synthetic shared crew',
        policy: CompanyContinuityPolicy.localContinuity,
        pin: '1234',
        recoveryPassphrase: 'synthetic join authority phrase',
        recoveryFile: File('${root.path}/a.wpca'),
      );
      final owner = await aEnrollment.signIn('1234');
      final aCommands = CompanyJobCommands(enrollment: aEnrollment);
      await aCommands.createJob(
        CreateJob(
          companyId: identity.companyId,
          shopId: identity.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          name: 'Original A Job',
        ),
        ownerSession: owner,
      );
      final aJobs = await aDb.select(aDb.jobs).get();
      final aHistory = await aDb.select(aDb.companyJobs).get();
      final aFacts = await aDb.select(aDb.companyAuthorityFacts).get();
      final (bc, ac) = await joinChannels();
      final aj = CompanyJoin(enrollment: aEnrollment);
      final bj = CompanyJoin(enrollment: bEnrollment);
      final bBefore = await sqlSnapshot(bDb);
      final bProtected = Map.of(bStore.states);
      final request = await aj.receiveJoinRequest(ac, await bj.beginJoin(bc));
      final provision = await aj.approveJoin(ac, request, ownerSession: owner);
      final preview = await bj.receiveProvision(bc, provision);
      expect(preview.identity.companyId, identity.companyId);
      expect(preview.identity.userId, identity.userId);
      expect(await sqlSnapshot(bDb), bBefore);
      expect(bStore.states.keys, bProtected.keys);
      for (final key in bProtected.keys) {
        expect(bStore.states[key]!.revision, bProtected[key]!.revision);
        expect(
          base64Encode(bStore.states[key]!.bytes) ==
              base64Encode(bProtected[key]!.bytes),
          isTrue,
          reason: 'protected bytes unchanged',
        );
      }
      await bj.acceptProvision(preview);
      final member = await bEnrollment.signIn('1234');
      expect(member.identity.userId, identity.userId);
      expect(member.identity.deviceId, isNot(identity.deviceId));
      final custody = jsonDecode(
        utf8.decode(bStore.states[companyCustodyNamespace(b.namespace)]!.bytes),
      ) as Map;
      expect(custody.containsKey('rootSeed'), isFalse);
      expect(custody.containsKey('recoverySeed'), isFalse);
      expect(
        await CompanyJobCommands(enrollment: bEnrollment)
            .listJobs(ownerSession: member),
        isEmpty,
      );
      await CompanyJobCommands(enrollment: bEnrollment).createJob(
        CreateJob(
          companyId: identity.companyId,
          shopId: identity.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          name: 'Local B Job',
        ),
        ownerSession: member,
      );
      expect(await aDb.select(aDb.jobs).get(), aJobs);
      expect(await aDb.select(aDb.companyJobs).get(), aHistory);
      expect(await aDb.select(aDb.companyAuthorityFacts).get(), aFacts);
      await bEnrollment.signOut();
      await bDb.close();
      bDb = AppDatabase.forTesting(
        NativeDatabase(File('${root.path}/b.sqlite')),
      );
      b = InstallationSecurity(store: bStore, namespace: b.namespace);
      await b.start(bDb);
      bEnrollment = CompanyEnrollment(installation: b, db: bDb);
      expect(bEnrollment.currentSession, isNull);
      final reopened = await bEnrollment.signIn('1234');
      expect(
        (await CompanyJobCommands(enrollment: bEnrollment)
                .listJobs(ownerSession: reopened))
            .single
            .name,
        'Local B Job',
      );
      final destination =
          Platform.environment['COMPANY_JOIN_DOWNGRADE_FIXTURE'];
      if (destination != null) {
        expect(File(destination).isAbsolute, isTrue);
        expect(File(destination).existsSync(), isFalse);
        final job = (await bDb.select(bDb.jobs).get()).single;
        final certificate =
            (await bDb.select(bDb.companyMembershipCertificates).get()).single;
        await bEnrollment.signOut();
        await bDb.close();
        final fixture = await File('${root.path}/b.sqlite').copy(destination);
        final bytes = await fixture.readAsBytes();
        File('$destination.expected.json').writeAsStringSync(
          jsonEncode({
            'schema': 7,
            'jobId': job.id,
            'grantId': certificate.grantId,
            'jobs': 1,
            'companyJobs': 1,
            'certificates': 1,
            'requests': 1,
            'activationEvents': 1,
            'sha256': hashes.sha256.convert(bytes).toString(),
            'byteLength': bytes.length,
          }),
        );
      }
    },
  );
  test('fresh Join request is encrypted and leaves B SQL and protected revisions unchanged', () async {
    final root = Directory.systemTemp.createTempSync('company-join-');
    final db = AppDatabase.forTesting(
      NativeDatabase(File('${root.path}/b.sqlite')),
    );
    final store = JobTestStore();
    final installation = InstallationSecurity(
      store: store,
      namespace: 'synthetic.join-b',
    );
    addTearDown(() async {
      await db.close();
      await root.delete(recursive: true);
    });
    await installation.start(db);
    final beforeSql = await sqlSnapshot(db);
    final before = Map.of(store.states);
    final (channel, _) = await joinChannels();
    final request = await CompanyJoin(
      enrollment: CompanyEnrollment(installation: installation, db: db),
    ).beginJoin(channel);
    expect(request['ciphertext'], isA<String>());
    expect(
      jsonEncode(request),
      isNot(contains(installation.identity!.id.value)),
    );
    expect(
      jsonEncode(request),
      isNot(contains(base64Encode(installation.identity!.publicKey))),
    );
    expect(await sqlSnapshot(db), beforeSql);
    expect(store.states.keys, before.keys);
    for (final key in before.keys) {
      expect(
        base64Encode(store.states[key]!.bytes) ==
            base64Encode(before[key]!.bytes),
        isTrue,
        reason: 'protected bytes unchanged',
      );
      expect(store.states[key]!.revision, before[key]!.revision);
    }
  });
  for (final mode in ['concurrent duplicate', 'new wrapper replay']) {
    test('Join rejects $mode within the same controller pairing', () async {
      final root = Directory.systemTemp.createTempSync('company-join-replay-');
      final db = AppDatabase.forTesting(
        NativeDatabase(File('${root.path}/b.sqlite')),
      );
      final installation = InstallationSecurity(
        store: JobTestStore(),
        namespace: 'synthetic.join-replay',
      );
      addTearDown(() async {
        await db.close();
        await root.delete(recursive: true);
      });
      await installation.start(db);
      final join = CompanyJoin(
        enrollment: CompanyEnrollment(installation: installation, db: db),
      );
      late NearbyPairedJoinSession capability;
      final (bc, ac) = await joinChannels(
        onPaired: (_, a) {
          capability = a.pairedJoinSession!;
        },
      );
      final wire = await join.beginJoin(bc);
      final baseline = await sqlSnapshot(db);
      if (mode == 'concurrent duplicate') {
        final results = await Future.wait([
          for (var i = 0; i < 2; i++)
            join
                .receiveJoinRequest(ac, wire)
                .then((_) => true, onError: (_) => false),
        ]);
        expect(results.where((v) => v), hasLength(1));
      } else {
        await join.receiveJoinRequest(ac, wire);
        final replacement = await NearbyJoinChannel.fromPairedSession(
          capability,
        );
        await expectLater(
          join.receiveJoinRequest(replacement, wire),
          throwsA(anything),
        );
        ac.close();
        await expectLater(
          NearbyJoinChannel.fromPairedSession(capability),
          throwsA(anything),
        );
      }
      expect(await sqlSnapshot(db), baseline);
    });
  }
}

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';
import 'package:uuid/uuid.dart';

import 'company_join_test.dart'
    show
        JoinFixture,
        activateFixtureB,
        joinChannels,
        sqlSnapshot,
        canonicalJoinTest,
        expectJoinProtectedUnchanged;

Future<
  ({
    VerifiedPeerMembership a,
    VerifiedPeerMembership b,
    NearbyController ac,
    NearbyController bc,
  })
>
disablePeers(JoinFixture f) async {
  final ownerB =
      f.bEnrollment.currentSession ?? await f.bEnrollment.signIn('1234');
  late NearbyController ac, bc;
  final (b, a) = await joinChannels(
    onPaired: (b, a) {
      bc = b;
      ac = a;
    },
  );
  final aa = CompanyPeerAuthentication(enrollment: f.aEnrollment);
  final ba = CompanyPeerAuthentication(enrollment: f.bEnrollment);
  final challenge = await aa.beginPeerChallenge(
    a,
    (await aa.retainedPeers(session: f.aEnrollment.currentSession!)).single,
    session: f.aEnrollment.currentSession!,
  );
  final response = await ba.receivePeerChallenge(b, challenge, session: ownerB);
  final completion = await aa.receivePeerResponse(a, response);
  final done = await ba.receivePeerCompletion(b, completion);
  final ap = await aa.receivePeerAcknowledgment(a, done.acknowledgment);
  return (a: ap, b: done.membership, ac: ac, bc: bc);
}

Future<
  ({
    VerifiedPeerMembership a,
    VerifiedPeerMembership b,
    NearbyController ac,
    NearbyController bc,
  })
>
provisionDisableFixture(JoinFixture f, String userId) async {
  await activateFixtureB(f);
  final p = await disablePeers(f);
  final signed = await f.bEnrollment.prepareUserProvisionRequest(
    peer: p.b,
    requestId: const Uuid().v4(),
    userId: userId,
  );
  final request = await f.aEnrollment.receiveUserProvisionRequest(
    signed,
    peer: p.a,
  );
  final bundle = await f.aEnrollment.prepareUserProvision(
    owner: f.aEnrollment.currentSession!,
    peer: p.a,
    request: request,
  );
  final ack = await f.bEnrollment.acceptUserProvision(bundle, peer: p.b);
  await f.aEnrollment.acceptUserProvisionReceipt(
    ack,
    peer: p.a,
    userId: userId,
  );
  return p;
}

Future<
  ({
    CompanyCreatedJobSync a,
    CompanyCreatedJobSync b,
    CompanyJobSyncAvailability aa,
    CompanyJobSyncAvailability ba,
  })
>
disableSync(JoinFixture f) async {
  final p = await disablePeers(f);
  final aa = await CompanyJobSyncAvailability.open(
    enrollment: f.aEnrollment,
    owner: f.aEnrollment.currentSession!,
    peer: p.a,
  );
  final ba = await CompanyJobSyncAvailability.open(
    enrollment: f.bEnrollment,
    owner: f.bEnrollment.currentSession!,
    peer: p.b,
  );
  final a = CompanyCreatedJobSync(availability: aa, controller: p.ac);
  final b = CompanyCreatedJobSync(availability: ba, controller: p.bc);
  p.ac.onJoinMessage = (_, wire) => a.receive(wire);
  p.bc.onJoinMessage = (_, wire) => b.receive(wire);
  return (a: a, b: b, aa: aa, ba: ba);
}

Future<String> disableJob(CompanyEnrollment enrollment, String name) async {
  final session = enrollment.currentCompanySession!;
  final jobId = const Uuid().v4();
  await CompanyJobCommands(enrollment: enrollment).createJob(
    CreateJob(
      companyId: session.identity.companyId,
      shopId: session.identity.shopId,
      jobId: jobId,
      requestId: const Uuid().v4(),
      name: name,
    ),
    ownerSession: session,
  );
  return jobId;
}

void main() {
  test('terminal state refuses damaged or old-format credentials and survives reset and recovery admission', () async {
    final f = await JoinFixture.create();
    final request = const Uuid().v4();
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: request,
      name: 'Casey',
      pin: '0123',
    );
    await f.aEnrollment.disableRestrictedUser(
      owner: f.owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
    );
    final slot = companyUserNamespace(f.a.namespace);
    final terminal = f.aStore.states[slot]!;
    final beforeSQL = await sqlSnapshot(f.aDb);
    for (final fault in [
      'missing',
      'json',
      'unknown-version',
      'v1-with-terminal-fields',
      'credential-in-tombstone',
      'signature',
    ]) {
      final body =
          jsonDecode(utf8.decode(terminal.bytes)) as Map<String, dynamic>;
      if (fault == 'unknown-version') body['v'] = 3;
      if (fault == 'v1-with-terminal-fields') body['v'] = 1;
      if (fault == 'credential-in-tombstone') {
        body['p'] = [1, 'private-marker!', 'private-marker!'];
      }
      if (fault == 'signature') (body['d'] as List)[2] = 'private-marker!';
      if (fault == 'missing') {
        f.aStore.states.remove(slot);
      } else {
        f.aStore.states[slot] = ProtectedInstallationState(
          const Uuid().v4(),
          Uint8List.fromList(
            utf8.encode(
              fault == 'json' ? '{"p":"private-marker' : jsonEncode(body),
            ),
          ),
        );
      }
      final damaged = Map.of(f.aStore.states);
      await expectLater(
        f.aEnrollment.signInUser(user.userId, '0123'),
        throwsA(
          isA<CompanyBootstrapRefusal>().having(
            (e) => e.toString(),
            'constant public error',
            isNot(contains('private-marker')),
          ),
        ),
      );
      expect(
        (await f.aEnrollment.listCompanyUsers()).where(
          (u) => u.userId == user.userId && u.available,
        ),
        isEmpty,
      );
      expectJoinProtectedUnchanged(f.aStore, damaged);
      expect(await sqlSnapshot(f.aDb), beforeSQL);
    }
    f.aStore.states[slot] = terminal;
    final preserved = Map.of(f.aStore.states);
    await expectLater(f.a.prepareReset(f.aDb), throwsStateError);
    await expectLater(
      f.aEnrollment.recover(
        policy: CompanyContinuityPolicy.localContinuity,
        sourceFile: File('${f.root.path}/a.wpca'),
        sourcePassphrase: 'synthetic durable authority phrase',
        newPin: '1234',
        newRecoveryPassphrase: 'terminal recovery phrase',
        newRecoveryFile: File('${f.root.path}/refused.wpca'),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.aStore, preserved);
    expect(await sqlSnapshot(f.aDb), beforeSQL);
    expect(File('${f.root.path}/refused.wpca').existsSync(), isFalse);
    final owner = await f.aEnrollment.signIn('1234');
    final noReuse = Map.of(f.aStore.states);
    await expectLater(
      f.aEnrollment.createRestrictedUser(
        owner: owner,
        requestId: request,
        name: 'Casey',
        pin: '0123',
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.aStore, noReuse);
    final second = await f.aEnrollment.createRestrictedUser(
      owner: owner,
      requestId: const Uuid().v4(),
      name: 'Independent builder',
      pin: '4567',
    );
    expect(second.userId, isNot(user.userId));
    expect(f.aStore.states[slot]!.revision, terminal.revision);
    expect(f.aStore.states[slot]!.bytes, terminal.bytes);
    final full = Map.of(f.aStore.states);
    await expectLater(
      f.aEnrollment.createRestrictedUser(
        owner: owner,
        requestId: const Uuid().v4(),
        name: 'Third builder',
        pin: '6789',
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.aStore, full);
    final bSlot = companyUserNamespace(f.b.namespace);
    f.bStore.states[bSlot] = terminal;
    await f.bEnrollment.recover(
      policy: CompanyContinuityPolicy.localContinuity,
      sourceFile: File('${f.root.path}/a.wpca'),
      sourcePassphrase: 'synthetic durable authority phrase',
      newPin: '1234',
      newRecoveryPassphrase: 'fresh terminal recovery phrase',
      newRecoveryFile: File('${f.root.path}/recovered-b.wpca'),
    );
    expect(f.bStore.states[bSlot]!.revision, terminal.revision);
    expect(f.bStore.states[bSlot]!.bytes, terminal.bytes);
    await expectLater(
      f.bEnrollment.signInUser(user.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final recovered = await f.bEnrollment.signIn('1234');
    final foreignProtected = Map.of(f.bStore.states);
    final foreignSql = await sqlSnapshot(f.bDb);
    // A copied terminal record still belongs to A's installation. Its occupied
    // locator fences the whole collection rather than becoming free capacity.
    await expectLater(
      f.bEnrollment.createRestrictedUser(
        owner: recovered,
        requestId: const Uuid().v4(),
        name: 'Independent recovered builder',
        pin: '4567',
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.bStore, foreignProtected);
    expect(await sqlSnapshot(f.bDb), foreignSql);
    expect(
      f.bStore.states.containsKey(companyUserNamespace(f.b.namespace, slot: 2)),
      isFalse,
    );
    expect(f.bStore.states[bSlot]!.revision, terminal.revision);
    expect(f.bStore.states[bSlot]!.bytes, terminal.bytes);
  }, timeout: const Timeout(Duration(minutes: 2)));
  test('held creation keeps dependent owner edits pending while independent owner work continues', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    await f.aEnrollment.signInUser(user.userId, '0123');
    final pending = await disableJob(f.aEnrollment, 'Pending user creation');
    final owner = await f.aEnrollment.signIn('1234');
    final commands = CompanyJobCommands(enrollment: f.aEnrollment);
    final view = (await commands.listJobViews(ownerSession: owner))
        .singleWhere((v) => v.baseJob.id == pending);
    await commands.renameJob(
      RenameJob(
        companyId: owner.identity.companyId,
        shopId: owner.identity.shopId,
        jobId: pending,
        requestId: const Uuid().v4(),
        creationDigest: view.creationDigest,
        observedHeads: view.nameHeads,
        observedLifecycleHeads: view.lifecycle.lifecycleHeads,
        name: 'Owner dependent edit',
      ),
      ownerSession: owner,
    );
    final other = await disableJob(f.bEnrollment, 'Independent owner B');
    await f.aEnrollment.disableRestrictedUser(
      owner: owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
    );
    final pair = await disableSync(f);
    final incoming = (await f.aDb.select(f.aDb.companyJobs).get()).singleWhere(
      (r) => r.jobId == pending,
    );
    final decision =
        (jsonDecode(
              utf8.decode(
                f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
              ),
            ) as Map)['d']
            as List;
    final before = await sqlSnapshot(f.bDb);
    await expectLater(
      CompanyJobCommands(
        enrollment: f.bEnrollment,
        beforeCommit: () async {
          final slot = companyUserNamespace(f.b.namespace);
          final old = f.bStore.states[slot]!;
          final body =
              jsonDecode(utf8.decode(old.bytes)) as Map<String, dynamic>;
          body['v'] = 2;
          body['p'] = null;
          body['d'] = [
            ...decision.take(3),
            [1, ...(body['o'] as List).skip(2)],
            null,
          ];
          f.bStore.states[slot] = ProtectedInstallationState(
            const Uuid().v4(),
            Uint8List.fromList(utf8.encode(jsonEncode(body))),
          );
        },
      ).applyIncomingCreateOutcome(
        Uint8List.fromList(utf8.encode(incoming.operationBytes)),
        ownerSession: f.bEnrollment.currentSession!,
        availability: pair.ba,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(f.bDb), before);
    final result = await pair.a.syncNow();
    expect(
      result.failure!.reason,
      CreatedJobSyncReason.unsupportedAuthor,
      reason: '${result.message} ${pair.b.lastFailure}',
    );
    expect(result.held, 2);
    expect(result.received, 1);
    expect(
      (await f.aDb.select(f.aDb.companyJobs).get()).map((r) => r.jobId),
      contains(other),
    );
    expect(
      (await f.bDb.select(f.bDb.companyJobs).get()).map((r) => r.jobId),
      isNot(contains(pending)),
    );
    expect(await f.bDb.select(f.bDb.companyJobNames).get(), isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));
  test('a signed disable arriving at held local commit rolls back every Job effect', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    final created = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, created.userId);
    await f.aEnrollment.disableRestrictedUser(
      owner: f.aEnrollment.currentSession!,
      userId: created.userId,
      requestId: const Uuid().v4(),
    );
    final decision =
        (jsonDecode(
              utf8.decode(
                f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes,
              ),
            ) as Map)['d']
            as List;
    final selected = await f.bEnrollment.signInUser(created.userId, '0123');
    final before = await sqlSnapshot(f.bDb);
    final command = CreateJob(
      companyId: selected.identity.companyId,
      shopId: selected.identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Must roll back',
    );
    final commands = CompanyJobCommands(
      enrollment: f.bEnrollment,
      beforeCommit: () async {
        final namespace = companyUserNamespace(f.b.namespace);
        final old = f.bStore.states[namespace]!;
        final changed =
            jsonDecode(utf8.decode(old.bytes)) as Map<String, dynamic>;
        changed['v'] = 2;
        changed['p'] = null;
        changed['d'] = [...decision.take(3), null, null];
        f.bStore.states[namespace] = ProtectedInstallationState(
          const Uuid().v4(),
          Uint8List.fromList(utf8.encode(jsonEncode(changed))),
        );
      },
    );
    await expectLater(
      commands.createJob(command, ownerSession: selected),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(f.bDb), before);
    await expectLater(
      commands.createJob(command, ownerSession: selected),
      throwsA(anything),
    );
    expect(await sqlSnapshot(f.bDb), before);
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: created.userId))!
          .disabled,
      isTrue,
    );
    await f.bEnrollment.signIn('1234');
    await disableJob(f.bEnrollment, 'Owner after held rollback');
  }, timeout: const Timeout(Duration(minutes: 2)));
  test('policy precedes inventory, admitted history survives and unseen work is held while owners sync', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    final user = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    await provisionDisableFixture(f, user.userId);
    await f.aEnrollment.signInUser(user.userId, '0123');
    final aj = await disableJob(f.aEnrollment, 'Historical A');
    await f.aEnrollment.signIn('1234');
    await f.bEnrollment.signInUser(user.userId, '0123');
    final bj = await disableJob(f.bEnrollment, 'Historical B');
    await f.bEnrollment.signIn('1234');
    var pair = await disableSync(f);
    final first = await pair.a.syncNow();
    expect(
      first.complete,
      isTrue,
      reason: '${first.message} ${pair.b.lastFailure}',
    );
    final historical = (await f.aDb.select(f.aDb.companyJobs).get())
        .singleWhere((r) => r.jobId == bj);
    await f.bEnrollment.signInUser(user.userId, '0123');
    final pending = await disableJob(f.bEnrollment, 'Offline unseen');
    final original = (await f.bDb.select(f.bDb.companyJobs).get()).singleWhere(
      (r) => r.jobId == pending,
    );
    await f.bEnrollment.signIn('1234');
    await f.aEnrollment.disableRestrictedUser(
      owner: f.aEnrollment.currentSession!,
      userId: user.userId,
      requestId: const Uuid().v4(),
    );
    final ownerA = await disableJob(f.aEnrollment, 'Owner A after disable');
    final ownerB = await disableJob(f.bEnrollment, 'Owner B after disable');
    pair = await disableSync(f);
    final result = await pair.a.syncNow();
    expect(
      result.held,
      1,
      reason: '${result.message} ${result.failure} ${pair.b.lastFailure}',
    );
    expect(result.complete, isFalse);
    expect(result.failure!.reason, CreatedJobSyncReason.unsupportedAuthor);
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: user.userId))!.disabled,
      isTrue,
    );
    expect(
      (await f.aEnrollment.userLifecycleStatus(userId: user.userId))!.confirmed,
      isTrue,
    );
    final aRows = await f.aDb.select(f.aDb.companyJobs).get();
    final bRows = await f.bDb.select(f.bDb.companyJobs).get();
    expect(aRows.map((r) => r.jobId), containsAll([aj, bj, ownerA, ownerB]));
    expect(
      bRows.map((r) => r.jobId),
      containsAll([aj, bj, ownerA, ownerB, pending]),
    );
    expect(aRows.map((r) => r.jobId), isNot(contains(pending)));
    expect(bRows.singleWhere((r) => r.jobId == pending), original);
    final commands = CompanyJobCommands(enrollment: f.aEnrollment);
    final before = await sqlSnapshot(f.aDb);
    final replay = await commands.applyIncomingCreateOutcome(
      Uint8List.fromList(utf8.encode(historical.operationBytes)),
      ownerSession: f.aEnrollment.currentSession!,
      availability: pair.aa,
    );
    expect(
      (replay as AppliedIncomingCreateJob).receiptBytes,
      historical.receiptBytes,
    );
    final held = await commands.applyIncomingCreateOutcome(
      Uint8List.fromList(utf8.encode(original.operationBytes)),
      ownerSession: f.aEnrollment.currentSession!,
      availability: pair.aa,
    );
    expect(held, isA<HeldIncomingCreateJob>());
    final tamperedProof = jsonDecode(original.operationBytes) as Map;
    (tamperedProof['authorization'] as Map)['membership'] = '{}';
    await expectLater(
      commands.applyIncomingCreateOutcome(
        Uint8List.fromList(utf8.encode(jsonEncode(tamperedProof))),
        ownerSession: f.aEnrollment.currentSession!,
        availability: pair.aa,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(f.aDb), before);
    final repeat = await pair.a.syncNow();
    expect(repeat.held, 1);
    expect(repeat.sent, 0);
    expect(repeat.received, 0);
    expect(await sqlSnapshot(f.aDb), before);
    expect(
      (await f.bDb.select(f.bDb.companyJobs).get()).singleWhere(
        (r) => r.jobId == pending,
      ),
      original,
    );
    final confirmations = await CompanyCreatedJobSync.confirmedPeerCounts(
      f.bEnrollment,
      f.bEnrollment.currentSession!,
    );
    expect(confirmations[pending] ?? 0, 0);
    expect(confirmations[bj], 1);
  }, timeout: const Timeout(Duration(minutes: 3)));
  test('terminal disable preserves audit identity and attempts while owner continues', () async {
    final f = await JoinFixture.create(allowOwnerAdditions: true);
    final created = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: '\\' * 64,
      pin: '0123',
    );
    await expectLater(
      f.aEnrollment.signInUser(created.userId, '9999'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final owner = await f.aEnrollment.signIn('1234');
    final before = Map.of(f.aStore.states);
    final original = jsonDecode(
      utf8.decode(before[companyUserNamespace(f.a.namespace)]!.bytes),
    ) as Map;
    final request = const Uuid().v4();
    var reads = 0;
    f.aStore.beforeRead = (namespace) async {
      if (namespace == companyUserNamespace(f.a.namespace) && ++reads == 2) {
        final current = f.aStore.states[namespace]!;
        final competing =
            jsonDecode(utf8.decode(current.bytes)) as Map<String, dynamic>;
        competing['a'] = 6;
        await f.aStore.compareAndSwapState(
          namespace,
          expectedRevision: current.revision,
          nextRevision: const Uuid().v4(),
          bytes: Uint8List.fromList(utf8.encode(jsonEncode(competing))),
        );
        f.aStore.loseNextUserReply = true;
      }
    };
    await f.aEnrollment.disableRestrictedUser(
      owner: owner,
      userId: created.userId,
      requestId: request,
    );
    f.aStore.beforeRead = null;
    final saved = Map.of(f.aStore.states);
    final disabled = jsonDecode(
      utf8.decode(saved[companyUserNamespace(f.a.namespace)]!.bytes),
    ) as Map;
    expect(disabled['c'], original['c']);
    expect(disabled['o'], original['o']);
    expect(disabled['r'], original['r']);
    expect(disabled['a'], 6);
    expect(disabled['p'], isNull);
    expect(saved[f.a.namespace]!.bytes, before[f.a.namespace]!.bytes);
    expect(
      saved[companyCustodyNamespace(f.a.namespace)]!.bytes,
      before[companyCustodyNamespace(f.a.namespace)]!.bytes,
    );
    await f.aEnrollment.disableRestrictedUser(
      owner: owner,
      userId: created.userId,
      requestId: request,
    );
    expectJoinProtectedUnchanged(f.aStore, saved);
    await expectLater(
      f.aEnrollment.disableRestrictedUser(
        owner: owner,
        userId: created.userId,
        requestId: const Uuid().v4(),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final commands = CompanyJobCommands(enrollment: f.aEnrollment);
    await commands.createJob(
      CreateJob(
        companyId: owner.identity.companyId,
        shopId: owner.identity.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: 'Owner continues',
      ),
      ownerSession: owner,
    );
    expect((await f.aEnrollment.listCompanyUsers()).last.disabled, isTrue);
    await expectLater(
      f.aEnrollment.signInUser(created.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(
      (await f.aEnrollment.userLifecycleStatus(userId: created.userId))!
          .attemptsRemaining,
      6,
    );
  });

  test('rootless peer applies signed decision and repeats receipt without refill or owner transport loss', () async {
    final f = await JoinFixture.create();
    final created = await f.aEnrollment.createRestrictedUser(
      owner: f.owner,
      requestId: const Uuid().v4(),
      name: '\\' * 64,
      pin: '0123',
    );
    var p = await provisionDisableFixture(f, created.userId);
    final rootless = f.bEnrollment.currentSession!;
    final bBefore = Map.of(f.bStore.states);
    await expectLater(
      f.bEnrollment.disableRestrictedUser(
        owner: rootless,
        userId: created.userId,
        requestId: const Uuid().v4(),
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.bStore, bBefore);
    await expectLater(
      f.bEnrollment.signInUser(created.userId, '9999'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await f.bEnrollment.signIn('1234');
    p = await disablePeers(f);
    final oldRecord = jsonDecode(
      utf8.decode(f.aStore.states[companyUserNamespace(f.a.namespace)]!.bytes),
    ) as Map;
    final oldRequest = await f.aEnrollment.receiveUserProvisionRequest(
      await f.bEnrollment.prepareUserProvisionRequest(
        peer: p.b,
        requestId: (oldRecord['o'] as List)[1] as String,
        userId: created.userId,
      ),
      peer: p.a,
    );
    final staleProvision = await f.aEnrollment.prepareUserProvision(
      owner: f.aEnrollment.currentSession!,
      peer: p.a,
      request: oldRequest,
    );
    final staleReceipt = await f.bEnrollment.acceptUserProvision(
      staleProvision,
      peer: p.b,
    );
    final decisionReceipt = await f.aEnrollment.disableRestrictedUser(
      owner: f.aEnrollment.currentSession!,
      userId: created.userId,
      requestId: const Uuid().v4(),
    );
    await p.a.requireCurrent();
    await p.b.requireCurrent();
    var targetA = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: created.userId),
      p.a,
    );
    var sourceB = await f.bEnrollment.verifyUserLifecycleOffer(
      await f.aEnrollment.createUserLifecycleOffer(p.a, userId: created.userId),
      p.b,
    );
    var policy = (await f.aEnrollment.prepareUserDisablePolicy(p.a, targetA))!;
    final beforeSQL = await sqlSnapshot(f.bDb);
    final beforeAttempts = (await f.bEnrollment.userLifecycleStatus(
      userId: created.userId,
    ))!.attemptsRemaining;
    for (final key in ['recipient', 'disable', 'certificate', 'v']) {
      final bad = Map<String, Object?>.from(
        jsonDecode(jsonEncode(policy)) as Map,
      );
      if (key == 'recipient') (bad[key] as List)[4] = const Uuid().v4();
      if (key == 'disable') (bad[key] as List)[1] = const Uuid().v4();
      if (key == 'certificate') bad[key] = '${bad[key]} ';
      if (key == 'v') bad[key] = 2;
      final untouched = Map.of(f.bStore.states);
      await expectLater(
        f.bEnrollment.acceptUserDisablePolicy(bad, p.b, sourceB),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.bStore, untouched);
    }
    f.bStore.loseNextUserReply = true;
    final lostAck = (await f.bEnrollment.acceptUserDisablePolicy(
      policy,
      p.b,
      sourceB,
    ))!;
    final disabledA = Map.of(f.aStore.states);
    final disabledB = Map.of(f.bStore.states);
    await expectLater(
      f.bEnrollment.acceptUserProvision(staleProvision, peer: p.b),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    await expectLater(
      f.aEnrollment.acceptUserProvisionReceipt(
        staleReceipt,
        peer: p.a,
        userId: created.userId,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.aStore, disabledA);
    expectJoinProtectedUnchanged(f.bStore, disabledB);
    await f.reopenB();
    await f.bEnrollment.signIn('1234');
    p = await disablePeers(f);
    targetA = await f.aEnrollment.verifyUserLifecycleOffer(
      await f.bEnrollment.createUserLifecycleOffer(p.b, userId: created.userId),
      p.a,
    );
    sourceB = await f.bEnrollment.verifyUserLifecycleOffer(
      await f.aEnrollment.createUserLifecycleOffer(p.a, userId: created.userId),
      p.b,
    );
    policy = (await f.aEnrollment.prepareUserDisablePolicy(p.a, targetA))!;
    final ack = (await f.bEnrollment.acceptUserDisablePolicy(
      policy,
      p.b,
      sourceB,
    ))!;
    expect(jsonEncode(ack), jsonEncode(lostAck));
    final resumed = f.bStore.states[companyUserNamespace(f.b.namespace)]!;
    final prior = disabledB[companyUserNamespace(f.b.namespace)]!;
    expect(resumed.revision, prior.revision);
    expect(resumed.bytes, prior.bytes);
    final conflict = Map<String, Object?>.from(
      jsonDecode(jsonEncode(policy)) as Map,
    );
    final conflictBody = Map<String, Object?>.from(
      (jsonDecode(decisionReceipt.proofBytes) as Map)['body'] as Map,
    )..['request'] = const Uuid().v4();
    final custody = jsonDecode(
      utf8.decode(
        f.aStore.states[companyCustodyNamespace(f.a.namespace)]!.bytes,
      ),
    ) as Map;
    final signature = await Ed25519().sign(
      utf8.encode(
        'wiredpart.company.user.disable@1:${canonicalJoinTest(conflictBody)}',
      ),
      keyPair: await Ed25519().newKeyPairFromSeed(
        base64Decode(custody['rootSeed'] as String),
      ),
    );
    conflict['disable'] = [
      1,
      conflictBody['request'],
      base64Encode(signature.bytes),
    ];
    final immutable = Map.of(f.bStore.states);
    await expectLater(
      f.bEnrollment.acceptUserDisablePolicy(conflict, p.b, sourceB),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.bStore, immutable);
    await f.aEnrollment.acceptUserDisableReceipt(
      ack,
      p.a,
      userId: created.userId,
    );
    final rootSaved = Map.of(f.aStore.states);
    final reversed = Map<String, Object?>.from(policy)
      ..['source'] = policy['recipient']
      ..['recipient'] = policy['source'];
    await expectLater(
      f.aEnrollment.acceptUserDisablePolicy(reversed, p.a, targetA),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expectJoinProtectedUnchanged(f.aStore, rootSaved);
    final after = Map.of(f.bStore.states);
    for (final entry in [
      f.aStore.states[companyUserNamespace(f.a.namespace)]!,
      f.bStore.states[companyUserNamespace(f.b.namespace)]!,
    ]) {
      expect(entry.bytes.length, lessThanOrEqualTo(2048));
      final record = jsonDecode(utf8.decode(entry.bytes)) as Map;
      expect(record['c'], isA<String>());
      expect(record['o'], isNotNull);
      expect(record['r'], isNotNull);
      expect((record['d'] as List)[3], isNotNull);
      expect((record['d'] as List)[4], isNotNull);
    }
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: created.userId))!
          .attemptsRemaining,
      beforeAttempts,
    );
    await f.bEnrollment.acceptUserDisablePolicy(policy, p.b, sourceB);
    expectJoinProtectedUnchanged(f.bStore, after);
    expect(await sqlSnapshot(f.bDb), beforeSQL);
    await p.a.requireCurrent();
    await p.b.requireCurrent();
    expect(
      (await f.aEnrollment.userLifecycleStatus(userId: created.userId))!
          .confirmed,
      isTrue,
    );
    expect(
      (await f.bEnrollment.userLifecycleStatus(userId: created.userId))!
          .disabled,
      isTrue,
    );
    await f.reopenB();
    await expectLater(
      f.bEnrollment.signInUser(created.userId, '0123'),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect((await f.bEnrollment.listCompanyUsers()).last.disabled, isTrue);
  }, timeout: const Timeout(Duration(minutes: 2)));

  for (final checkpoint in [1, 2]) {
    test(
      'owner sign-out during account read $checkpoint returns no disable and mutates nothing',
      () async {
        final f = await JoinFixture.create();
        final created = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Casey',
          pin: '0123',
        );
        final before = Map.of(f.aStore.states);
        var reads = 0;
        Future<void>? cancellation;
        f.aStore.beforeRead = (namespace) {
          if (namespace == companyUserNamespace(f.a.namespace) &&
              ++reads == checkpoint) {
            cancellation = f.aEnrollment.signOut();
          }
          return null;
        };
        await expectLater(
          f.aEnrollment.disableRestrictedUser(
            owner: f.owner,
            userId: created.userId,
            requestId: const Uuid().v4(),
          ),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
        await cancellation;
        expect(f.aEnrollment.currentCompanySession, isNull);
        expectJoinProtectedUnchanged(f.aStore, before);
      },
    );
  }
}

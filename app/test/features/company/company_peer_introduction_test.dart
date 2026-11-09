import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:drift/native.dart';
import 'package:flutter/foundation.dart' show debugPrintSynchronously;
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart'
    show CompanyJobCommands, CompanyJobSyncCommands, CreateJob;
import 'package:wired_parts/features/nearby/nearby_controller.dart'
    show NearbyController;

import 'company_join_test.dart'
    show
        JoinActivationStore,
        JoinFixture,
        advanceJoinFloor,
        joinChannels,
        sqlSnapshot;
import 'company_user_initial_provision_test.dart'
    show initialProvisionPeers, provisionInitialUser;

const _fixturePin = '1234';
const _selectedPin = '0123';

Future<CompanyIdentity> _activate(
  JoinFixture fixture,
  CompanyEnrollment member, {
  bool acknowledge = true,
  int? timedSequence,
  bool acknowledgeOverLoopback = false,
}) async {
  Future<T> measure<T>(String phase, Future<T> Function() action) async {
    if (timedSequence == null) return action();
    final clock = Stopwatch()..start();
    try {
      return await action();
    } finally {
      debugPrintSynchronously(
        'Dense Join phase: sequence=$timedSequence, phase=$phase, '
        'ms=${clock.elapsedMilliseconds}',
      );
    }
  }

  late final NearbyController childController;
  late final NearbyController issuerController;
  final (childChannel, issuerChannel) = await joinChannels(
    onPaired: (child, issuer) {
      childController = child;
      issuerController = issuer;
    },
  );
  try {
    final issuer = CompanyJoin(enrollment: fixture.aEnrollment);
    final child = CompanyJoin(enrollment: member);
    final request = await measure('request', () async {
      return issuer.receiveJoinRequest(
        issuerChannel,
        await child.beginJoin(childChannel),
      );
    });
    final provision = await measure(
      'approve',
      () => issuer.approveJoin(
        issuerChannel,
        request,
        ownerSession: fixture.owner,
      ),
    );
    final identity = await measure('accept', () async {
      return child.acceptProvision(
        await child.receiveProvision(childChannel, provision),
      );
    });
    if (acknowledge) {
      final ack = await measure(
        'prepareAck',
        () => child.activationAcknowledgment(childChannel),
      );
      Future<void> acceptAck(Map<String, Object?> wire) => measure(
        'issuerAck',
        () => issuer.acknowledgeJoin(
          issuerChannel,
          wire,
          ownerSession: fixture.owner,
        ),
      );
      if (acknowledgeOverLoopback) {
        Future<void>? issuerCallback;
        issuerController.onJoinMessage = (_, wire) async {
          final pending = acceptAck(wire);
          issuerCallback = pending;
          await pending;
          return {'ok': true};
        };
        try {
          await measure(
            'loopbackAck',
            () => childController.sendJoinMessage(ack),
          );
          debugPrintSynchronously('Dense ACK sender: outcome=accepted');
        } catch (error) {
          debugPrintSynchronously(
            'Dense ACK sender: outcome=failed, type=${error.runtimeType}',
          );
          rethrow;
        } finally {
          final pending = issuerCallback;
          if (pending == null) {
            debugPrintSynchronously('Dense ACK handler: outcome=not-started');
          } else {
            try {
              await pending;
              debugPrintSynchronously('Dense ACK handler: outcome=accepted');
            } catch (error) {
              debugPrintSynchronously(
                'Dense ACK handler: outcome=failed, type=${error.runtimeType}',
              );
            }
          }
        }
      } else {
        await acceptAck(ack);
      }
    }
    return identity;
  } finally {
    childChannel.close();
    issuerChannel.close();
    await childController.dispose();
    await issuerController.dispose();
  }
}

Future<CreatedJobSyncResult> _sync(
  CompanyEnrollment issuer,
  CompanyEnrollment member, {
  bool memberInitiates = false,
  bool memberConsent = true,
}) => _withSync(
  issuer,
  member,
  (sync) => sync.syncNow(),
  memberInitiates: memberInitiates,
  memberConsent: memberConsent,
);

Future<T> _withSync<T>(
  CompanyEnrollment issuer,
  CompanyEnrollment member,
  Future<T> Function(CompanyCreatedJobSync) run, {
  bool memberInitiates = false,
  bool memberConsent = true,
}) async {
  final peers = await initialProvisionPeers(issuer, member);
  CompanyCreatedJobSync? issuerSync;
  CompanyCreatedJobSync? memberSync;
  try {
    issuerSync = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: issuer,
        owner: issuer.currentCompanySession!,
        peer: peers.a,
        peerRosterConsent: true,
      ),
      controller: peers.ac,
    );
    memberSync = CompanyCreatedJobSync(
      availability: await CompanyJobSyncAvailability.open(
        enrollment: member,
        owner: member.currentCompanySession!,
        peer: peers.b,
        peerRosterConsent: memberConsent,
      ),
      controller: peers.bc,
    );
    peers.ac.onJoinMessage = (_, wire) => issuerSync!.receive(wire);
    peers.bc.onJoinMessage = (_, wire) => memberSync!.receive(wire);
    return await run(memberInitiates ? memberSync : issuerSync);
  } finally {
    await memberSync?.closeAndDrain();
    await issuerSync?.closeAndDrain();
    await peers.bc.dispose();
    await peers.ac.dispose();
  }
}

Future<List<String>> _retained(CompanyEnrollment enrollment) async {
  final authentication = CompanyPeerAuthentication(enrollment: enrollment);
  final peers = await authentication.retainedPeers(
    session: enrollment.currentCompanySession!,
  );
  return peers.map((peer) => peer.deviceId).toList();
}

Future<void> _direct(
  CompanyEnrollment left,
  CompanyEnrollment right, {
  required bool expectSuccess,
  bool sendChallengeOverLoopback = false,
  Future<void> Function(VerifiedPeerMembership, VerifiedPeerMembership)?
  afterVerification,
}) async {
  late final NearbyController responderController;
  late final NearbyController initiatorController;
  final (rightChannel, leftChannel) = await joinChannels(
    onPaired: (right, left) {
      responderController = right;
      initiatorController = left;
    },
  );
  try {
    final initiator = CompanyPeerAuthentication(enrollment: left);
    final responder = CompanyPeerAuthentication(enrollment: right);
    final leftSession = left.currentCompanySession!;
    final rightSession = right.currentCompanySession!;
    final peers = await initiator.retainedPeers(session: leftSession);
    final target = peers.singleWhere(
      (peer) => peer.deviceId == rightSession.identity.deviceId,
    );
    final first = await initiator.beginPeerChallenge(
      leftChannel,
      target,
      session: leftSession,
    );
    Future<Map<String, Object?>> respond(Map<String, Object?> wire) => responder
        .receivePeerChallenge(rightChannel, wire, session: rightSession);
    Future<Map<String, Object?>> sendChallenge() async {
      late final Map<String, Object?> response;
      late final int responderMillis;
      responderController.onJoinMessage = (_, wire) async {
        final clock = Stopwatch()..start();
        response = await respond(wire);
        responderMillis = clock.elapsedMilliseconds;
        return {'ok': true};
      };
      final clock = Stopwatch()..start();
      await initiatorController.sendJoinMessage(first);
      debugPrintSynchronously(
        'Dense direct challenge: responderMs=$responderMillis, '
        'loopbackAckMs=${clock.elapsedMilliseconds}',
      );
      return response;
    }

    final pendingResponse = sendChallengeOverLoopback
        ? sendChallenge()
        : respond(first);
    if (!expectSuccess) {
      await expectLater(
        pendingResponse,
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      return;
    }
    final second = await pendingResponse;
    final third = await initiator.receivePeerResponse(leftChannel, second);
    final done = await responder.receivePeerCompletion(rightChannel, third);
    final verified = await initiator.receivePeerAcknowledgment(
      leftChannel,
      done.acknowledgment,
    );
    await verified.requireCurrent();
    await done.membership.requireCurrent();
    expect(verified.deviceId, rightSession.identity.deviceId);
    expect(done.membership.deviceId, leftSession.identity.deviceId);
    await afterVerification?.call(verified, done.membership);
  } finally {
    rightChannel.close();
    leftChannel.close();
  }
}

Future<void> _measureSlotReads(
  JoinFixture fixture,
  CompanyEnrollment member,
  String rootId,
  String peerId,
) async {
  final prefix = '${fixture.b.namespace}.peer-intro-';
  final accepted = fixture.bStore.states['${prefix}2']!;
  expect(accepted.bytes.length, lessThanOrEqualTo(kInstallationStateLimit));

  Future<void> measure(String label) => _measureRetainedSlots(
    label,
    fixture.bStore,
    member,
    [rootId, peerId],
    accepted.bytes.length,
  );

  await measure('sparse');
  final fault = jsonDecode(utf8.decode(accepted.bytes)) as Map;
  fault['v'] = 99;
  final badBytes = Uint8List.fromList(utf8.encode(jsonEncode(fault)));
  final occupied = <String>[];
  for (var slot = 1; slot <= 128; slot++) {
    if (slot == 2) continue;
    final namespace = '$prefix$slot';
    occupied.add(namespace);
    fixture.bStore.states[namespace] = ProtectedInstallationState(
      const Uuid().v4(),
      badBytes,
    );
  }
  try {
    await measure('all occupied, 127 malformed');
  } finally {
    for (final namespace in occupied) {
      fixture.bStore.states.remove(namespace);
    }
  }
}

Future<void> _measureRetainedSlots(
  String label,
  JoinActivationStore store,
  CompanyEnrollment member,
  List<String> expected,
  int maxRecordBytes,
) async {
  final prefix = '${member.installation.namespace}.peer-intro-';
  final reads = <String>[];
  store.onRead = (namespace) {
    if (namespace.startsWith(prefix)) reads.add(namespace);
  };
  final clock = Stopwatch()..start();
  late final List<String> retained;
  try {
    retained = await _retained(member);
  } finally {
    clock.stop();
    store.onRead = null;
  }
  expect(retained, unorderedEquals(expected));
  expect(reads, hasLength(128));
  expect(reads.toSet(), hasLength(128));
  debugPrintSynchronously(
    'Peer slots $label: retained=${retained.length}, reads=${reads.length}, '
    'ms=${clock.elapsedMilliseconds}, maxRecordBytes=$maxRecordBytes',
  );
}

void main() {
  test('production peer introduction namespaces accept only canonical sequence slots', () {
    for (final slot in [1, 64, 128]) {
      validateInstallationNamespace('production.peer-intro-$slot');
    }
    for (final suffix in ['0', '01', '129', '+1', '-1', '1.extra']) {
      expect(
        () => validateInstallationNamespace('production.peer-intro-$suffix'),
        throwsArgumentError,
      );
    }
    expect(
      () => companyCustodyNamespace('production.peer-intro-1'),
      throwsArgumentError,
    );
  });
  test('activated members learn via manual Sync Now and verify after issuer closes', () async {
    final fixture = await JoinFixture.create();
    await _activate(fixture, fixture.bEnrollment);
    final cPath = File.fromUri(fixture.root.uri.resolve('intro-c.sqlite'));
    var cDb = AppDatabase.forTesting(NativeDatabase(cPath));
    addTearDown(() => cDb.close());
    final cStore = JoinActivationStore();
    var cInstallation = InstallationSecurity(
      store: cStore,
      namespace: 'synthetic.peer-introduction-c',
    );
    await cInstallation.start(cDb);
    var c = CompanyEnrollment(installation: cInstallation, db: cDb);
    await _activate(fixture, c);
    final acknowledgments = await fixture.aDb
        .customSelect(
          "SELECT COUNT(*) AS count FROM company_join_events WHERE ordinal = 9 AND kind = 'ack'",
        )
        .getSingle();
    expect(acknowledgments.read<int>('count'), 2);

    final issuer = fixture.aEnrollment;
    final b = fixture.bEnrollment;
    await b.signIn(_fixturePin);
    await c.signIn(_fixturePin);
    final a = await issuer.createRestrictedUser(
      owner: fixture.owner,
      requestId: const Uuid().v4(),
      name: 'Crew',
      pin: _selectedPin,
    );
    await provisionInitialUser(issuer, b, a.userId);
    await provisionInitialUser(issuer, c, a.userId);
    final issuerSession = await issuer.signInUser(a.userId, _selectedPin);
    final bSession = await b.signInUser(a.userId, _selectedPin);
    final cSession = await c.signInUser(a.userId, _selectedPin);
    final rootId = fixture.owner.identity.deviceId;
    final bId = bSession.identity.deviceId;
    final cId = cSession.identity.deviceId;

    expect(await _retained(b), [rootId]);
    expect(await _retained(c), [rootId]);
    fixture.bStore.loseNextPeerIntroductionReply = true;
    final first = await _sync(issuer, b);
    expect(fixture.bStore.loseNextPeerIntroductionReply, isFalse);
    expect(first.complete, isTrue, reason: first.message);
    expect(
      await _retained(b),
      unorderedEquals([rootId, cId]),
      reason: 'An acknowledged member should be learned by manual Sync Now.',
    );
    await _measureSlotReads(fixture, b, rootId, cId);
    final slot = '${fixture.b.namespace}.peer-intro-2';
    final saved = fixture.bStore.states[slot]!;
    final repeat = await _sync(issuer, b);
    expect(repeat.complete, isTrue, reason: repeat.message);
    expect(fixture.bStore.states[slot]!.revision, saved.revision);
    expect(await _retained(c), [rootId]);
    await _direct(b, c, expectSuccess: false);
    final second = await _sync(issuer, c, memberInitiates: true);
    expect(second.complete, isTrue, reason: second.message);
    expect(await _retained(c), unorderedEquals([rootId, bId]));
    expect(issuer.currentCompanySession, same(issuerSession));
    expect(b.currentCompanySession, same(bSession));
    expect(c.currentCompanySession, same(cSession));

    await issuer.signOut();
    await fixture.reopenB();
    await c.signOut();
    await cDb.close();
    cDb = AppDatabase.forTesting(NativeDatabase(cPath));
    cInstallation = InstallationSecurity(
      store: cStore,
      namespace: cInstallation.namespace,
    );
    await cInstallation.start(cDb);
    c = CompanyEnrollment(installation: cInstallation, db: cDb);
    final reopenedB = await fixture.bEnrollment.signInUser(
      a.userId,
      _selectedPin,
    );
    final reopenedC = await c.signInUser(a.userId, _selectedPin);
    expect(reopenedB.identity.deviceId, bId);
    expect(reopenedC.identity.deviceId, cId);
    expect(reopenedB.identity.userId, a.userId);
    expect(reopenedC.identity.userId, a.userId);
    expect(reopenedB.identity.isAuthorityOwner, isFalse);
    expect(reopenedC.identity.isAuthorityOwner, isFalse);
    expect(issuer.currentCompanySession, isNull);
    final directClock = Stopwatch()..start();
    await _direct(
      fixture.bEnrollment,
      c,
      expectSuccess: true,
      afterVerification: (_, receiver) async {
        final jobId = const Uuid().v4();
        await CompanyJobCommands(enrollment: fixture.bEnrollment).createJob(
          CreateJob(
            companyId: reopenedB.identity.companyId,
            shopId: reopenedB.identity.shopId,
            jobId: jobId,
            requestId: const Uuid().v4(),
            name: 'Crew member Job',
          ),
          ownerSession: reopenedB,
        );
        final authored =
            (await fixture.bDb.select(fixture.bDb.companyJobs).get())
                .singleWhere((row) => row.jobId == jobId);
        final source = jsonDecode(authored.operationBytes)['body'] as Map;
        expect(source['user'], a.userId);
        expect(source['device'], bId);
        final before = await sqlSnapshot(cDb);
        final available = await CompanyJobSyncAvailability.open(
          enrollment: c,
          owner: reopenedC,
          peer: receiver,
        );
        final slot = '${cInstallation.namespace}.peer-intro-1';
        final saved = cStore.states[slot]!;
        var fired = false;
        try {
          final commands = CompanyJobCommands(
            enrollment: c,
            beforeCommit: () async {
              fired = true;
              final body = jsonDecode(utf8.decode(saved.bytes)) as Map;
              ((body['certificate'] as Map)['body'] as Map)['company'] =
                  const Uuid().v4();
              await cStore.compareAndSwapState(
                slot,
                expectedRevision: saved.revision,
                nextRevision: const Uuid().v4(),
                bytes: Uint8List.fromList(utf8.encode(jsonEncode(body))),
              );
            },
          );
          await expectLater(
            commands.applyIncomingCreate(
              Uint8List.fromList(utf8.encode(authored.operationBytes)),
              ownerSession: reopenedC,
              availability: available,
            ),
            throwsA(anything),
          );
          expect(
            fired,
            isTrue,
            reason: 'Reach the held command commit boundary.',
          );
          expect(await sqlSnapshot(cDb), before);
        } finally {
          available.close();
        }
      },
    );
    debugPrintSynchronously(
      'Direct Pair, verification and held fault: ${directClock.elapsedMilliseconds}ms',
    );
    expect(directClock.elapsed, lessThan(const Duration(minutes: 5)));
    expect(await _retained(c), [rootId]);

    final bEnrollment = fixture.bEnrollment;
    final authentication = CompanyPeerAuthentication(enrollment: bEnrollment);
    final cached = (await authentication.retainedPeers(session: reopenedB))
        .singleWhere((peer) => peer.deviceId == cId);
    await advanceJoinFloor(
      fixture.bStore,
      fixture.b.namespace,
      'revocation.device.$cId',
      1,
    );
    final selectedAfterFloor = await bEnrollment.signInUser(
      a.userId,
      _selectedPin,
    );
    expect(await _retained(bEnrollment), [rootId]);
    final (otherChannel, retainedChannel) = await joinChannels();
    try {
      await expectLater(
        authentication.beginPeerChallenge(
          retainedChannel,
          cached,
          session: selectedAfterFloor,
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    } finally {
      retainedChannel.close();
      otherChannel.close();
    }
  }, timeout: const Timeout(Duration(minutes: 7)));

  test('only acknowledged peers are offered and a changed installed slot cannot be acknowledged', () async {
    final fixture = await JoinFixture.create();
    final b = fixture.bEnrollment;
    final issuer = fixture.aEnrollment;
    await _activate(fixture, b);
    final cDb = AppDatabase.forTesting(
      NativeDatabase(
        File.fromUri(fixture.root.uri.resolve('pending-intro.sqlite')),
      ),
    );
    addTearDown(cDb.close);
    final cInstallation = InstallationSecurity(
      store: JoinActivationStore(),
      namespace: 'synthetic.peer-introduction-pending',
    );
    await cInstallation.start(cDb);
    final c = CompanyEnrollment(installation: cInstallation, db: cDb);
    await _activate(fixture, c, acknowledge: false);
    await b.signIn(_fixturePin);
    final rootOnly = [fixture.owner.identity.deviceId];
    final withoutAck = await _sync(issuer, b);
    expect(withoutAck.complete, isTrue, reason: withoutAck.message);
    expect(await _retained(b), rootOnly);

    late final NearbyController childController;
    late final NearbyController issuerController;
    final (childChannel, issuerChannel) = await joinChannels(
      onPaired: (child, issuer) {
        childController = child;
        issuerController = issuer;
      },
    );
    try {
      await CompanyJoin(enrollment: issuer).acknowledgeJoin(
        issuerChannel,
        await CompanyJoin(enrollment: c).activationAcknowledgment(childChannel),
        ownerSession: fixture.owner,
      );
    } finally {
      childChannel.close();
      issuerChannel.close();
      await childController.dispose();
      await issuerController.dispose();
    }
    final compatible = await _sync(issuer, b, memberConsent: false);
    expect(compatible.complete, isTrue, reason: compatible.message);
    expect(await _retained(b), rootOnly);

    final baseline = await sqlSnapshot(fixture.bDb);
    final slot = '${fixture.b.namespace}.peer-intro-2';
    var corruptedAfterCas = false;
    fixture.bStore.beforeRead = (namespace) {
      final saved = fixture.bStore.states[slot];
      if (namespace != fixture.b.namespace || saved == null) return null;
      fixture.bStore.beforeRead = null;
      corruptedAfterCas = true;
      final value =
          jsonDecode(utf8.decode(saved.bytes)) as Map<String, dynamic>;
      value['v'] = 99;
      return fixture.bStore
          .compareAndSwapState(
            slot,
            expectedRevision: saved.revision,
            nextRevision: const Uuid().v4(),
            bytes: Uint8List.fromList(utf8.encode(jsonEncode(value))),
          )
          .then<void>((_) {});
    };
    try {
      final result = await _sync(issuer, b);
      expect(corruptedAfterCas, isTrue);
      expect(
        result.complete,
        isFalse,
        reason: 'The introduction slot changed before its receipt.',
      );
    } finally {
      fixture.bStore.beforeRead = null;
    }
    expect(await sqlSnapshot(fixture.bDb), baseline);
    expect(await _retained(b), rootOnly);
    fixture.bStore.beforeRead = (namespace) => namespace == slot
        ? Future<void>.error(PlatformException(code: 'installation_corrupt'))
        : null;
    try {
      expect(await _retained(b), rootOnly);
    } finally {
      fixture.bStore.beforeRead = null;
    }
  }, timeout: const Timeout(Duration(minutes: 6)));

  test(
    'issuer floor change at final roster custody read prevents disclosure',
    () async {
      final fixture = await JoinFixture.create();
      final issuer = fixture.aEnrollment;
      final recipient = fixture.bEnrollment;
      await _activate(fixture, recipient);

      final path = File.fromUri(fixture.root.uri.resolve('floor-peer.sqlite'));
      final db = AppDatabase.forTesting(NativeDatabase(path));
      addTearDown(db.close);
      final installation = InstallationSecurity(
        store: JoinActivationStore(),
        namespace: 'synthetic.peer-roster-floor',
      );
      await installation.start(db);
      final candidate = CompanyEnrollment(installation: installation, db: db);
      await _activate(fixture, candidate);
      final candidateSession = await candidate.signIn(_fixturePin);
      await recipient.signIn(_fixturePin);

      final store = fixture.aStore;
      final rootNamespace = fixture.a.namespace;
      final custody = companyCustodyNamespace(rootNamespace);
      final priorCustody = store.states[custody]!.revision;
      final priorRecipient = await sqlSnapshot(fixture.bDb);
      final slot = '${fixture.b.namespace}.peer-intro-2';
      expect(fixture.bStore.states[slot], isNull);
      var injected = false;
      store.beforeRead = (namespace) {
        if (namespace != custody) return null;
        // Select the direct disclosure custody read, including after awaits.
        // The nested requireCurrent read must keep using the original floor.
        final rosterFrame = StackTrace.current
            .toString()
            .split('\n')
            .firstWhere(
              (frame) => frame.contains('_CompanyPeerRoster.'),
              orElse: () => '',
            );
        if (!rosterFrame.contains(
          '_CompanyPeerRoster.requireDisclosureCurrent',
        )) {
          return null;
        }
        store.beforeRead = null;
        injected = true;
        return advanceJoinFloor(
          store,
          rootNamespace,
          'revocation.device.${candidateSession.identity.deviceId}',
          1,
        );
      };

      try {
        final result = await _sync(issuer, recipient);
        expect(injected, isTrue, reason: 'The one-shot fault must have fired.');
        expect(
          fixture.bStore.states[slot],
          isNull,
          reason: 'A refused run must not disclose the revoked certificate.',
        );
        expect(result.complete, isFalse);
      } finally {
        store.beforeRead = null;
      }
      expect(store.states[custody]!.revision, priorCustody);
      expect(await sqlSnapshot(fixture.bDb), priorRecipient);
      expect(await _retained(recipient), [fixture.owner.identity.deviceId]);
    },
    timeout: const Timeout(Duration(minutes: 6)),
  );

  test(
    'manual roster pages advance past eight peers on the same Pair',
    () async {
      final fixture = await JoinFixture.create();
      final issuer = fixture.aEnrollment;
      final recipient = fixture.bEnrollment;
      await _activate(fixture, recipient);
      for (var index = 2; index <= 10; index++) {
        final path = File.fromUri(
          fixture.root.uri.resolve('page-child-$index.sqlite'),
        );
        final db = AppDatabase.forTesting(NativeDatabase(path));
        try {
          final installation = InstallationSecurity(
            store: JoinActivationStore(),
            namespace: 'synthetic.peer-roster-page-$index',
          );
          await installation.start(db);
          await _activate(
            fixture,
            CompanyEnrollment(installation: installation, db: db),
          );
        } finally {
          await db.close();
        }
      }
      final acknowledgments = await fixture.aDb
          .customSelect(
            "SELECT COUNT(*) AS count FROM company_join_events WHERE ordinal = 9 AND kind = 'ack'",
          )
          .getSingle();
      expect(acknowledgments.read<int>('count'), 10);
      await recipient.signIn(_fixturePin);

      final prefix = '${fixture.b.namespace}.peer-intro-';
      Map<int, String> revisions() => {
        for (final row in fixture.bStore.states.entries)
          if (row.key.startsWith(prefix))
            int.parse(row.key.substring(prefix.length)): row.value.revision,
      };
      await _withSync(issuer, recipient, (sync) async {
        final first = await sync.syncNow();
        expect(first.complete, isTrue, reason: first.message);
        expect(first.peerRosterMore, isTrue);
        final firstPage = revisions();
        expect(
          firstPage.keys,
          unorderedEquals(List.generate(8, (index) => index + 2)),
        );

        final second = await sync.syncNow();
        expect(second.complete, isTrue, reason: second.message);
        expect(second.peerRosterMore, isFalse);
        expect([second.sent, second.received], [0, 0]);
        final secondPage = revisions();
        expect(
          secondPage.keys,
          unorderedEquals(List.generate(9, (index) => index + 2)),
        );
        expect(secondPage, containsPair(10, isNotEmpty));
        for (final row in firstPage.entries) {
          expect(secondPage[row.key], row.value);
        }

        final repeat = await sync.syncNow();
        expect(repeat.complete, isTrue, reason: repeat.message);
        expect(repeat.peerRosterMore, isFalse);
        expect([repeat.sent, repeat.received], [0, 0]);
        expect(revisions(), secondPage);
      });
    },
    timeout: const Timeout(Duration(minutes: 7)),
  );

  final capacityMode = Platform.environment['WP_RUN_DENSE_PEER_ROSTER'];
  final ackProbe = capacityMode == 'ack-probe';
  test(
    ackProbe
        ? 'bounded signed joins measure the production loopback activation ACK'
        : 'full activated roster fits protected slots and cold direct verification',
    () async {
      const capacity = 128;
      const pageSize = 8;
      const ackProbeLimit = 48;
      final fixture = await JoinFixture.create();
      final issuer = fixture.aEnrollment;
      final dense = fixture.bEnrollment;
      final enrollmentClock = Stopwatch()..start();
      final denseIdentity = await _activate(fixture, dense);
      final otherDeviceIds = <String>[];

      Future<int> ackCount() async {
        final rows = await fixture.aDb
            .customSelect(
              "SELECT COUNT(*) AS count FROM company_join_events WHERE ordinal = 9 AND kind = 'ack'",
            )
            .getSingle();
        return rows.read<int>('count');
      }

      final lastSequence = ackProbe ? ackProbeLimit : capacity - 1;
      for (var sequence = 2; sequence <= lastSequence; sequence++) {
        final path = File.fromUri(
          fixture.root.uri.resolve('dense-$sequence.sqlite'),
        );
        final db = AppDatabase.forTesting(NativeDatabase(path));
        try {
          final installation = InstallationSecurity(
            store: JoinActivationStore(),
            namespace: 'synthetic.peer-roster-dense-$sequence',
          );
          await installation.start(db);
          final identity = await _activate(
            fixture,
            CompanyEnrollment(installation: installation, db: db),
            timedSequence: sequence % 16 == 0 ? sequence : null,
            acknowledgeOverLoopback: ackProbe && sequence == ackProbeLimit,
          );
          otherDeviceIds.add(identity.deviceId);
        } finally {
          await db.close();
          if (ackProbe && sequence == ackProbeLimit) {
            try {
              debugPrintSynchronously(
                'Dense ACK ledger: sequence=$sequence, count=${await ackCount()}',
              );
            } catch (error) {
              debugPrintSynchronously(
                'Dense ACK ledger: outcome=read-failed, type=${error.runtimeType}',
              );
            }
          }
        }
        if (sequence % 16 == 0) {
          debugPrintSynchronously(
            'Dense roster activation: count=$sequence, '
            'ms=${enrollmentClock.elapsedMilliseconds}',
          );
        }
      }
      if (ackProbe) {
        expect(await ackCount(), ackProbeLimit);
        return;
      }

      final sparseFile = File.fromUri(
        fixture.root.uri.resolve('dense-sparse.sqlite'),
      );
      final sparseStore = JoinActivationStore();
      const sparseNamespace = 'synthetic.peer-roster-dense-sparse';
      var sparseDb = AppDatabase.forTesting(NativeDatabase(sparseFile));
      addTearDown(() => sparseDb.close());
      Future<CompanyEnrollment> openSparse() async {
        final installation = InstallationSecurity(
          store: sparseStore,
          namespace: sparseNamespace,
        );
        await installation.start(sparseDb);
        return CompanyEnrollment(installation: installation, db: sparseDb);
      }

      var sparse = await openSparse();
      final sparseIdentity = await _activate(fixture, sparse);
      otherDeviceIds.add(sparseIdentity.deviceId);
      debugPrintSynchronously(
        'Dense roster activation: count=$capacity, '
        'ms=${enrollmentClock.elapsedMilliseconds}',
      );

      expect(await ackCount(), capacity);
      final beforeIssuer = jsonEncode(await sqlSnapshot(fixture.aDb));
      final beforeIssuerProtected = Map.of(fixture.aStore.states);
      final excessDb = AppDatabase.forTesting(
        NativeDatabase(
          File.fromUri(fixture.root.uri.resolve('dense-excess.sqlite')),
        ),
      );
      addTearDown(excessDb.close);
      final excessStore = JoinActivationStore();
      final excessInstallation = InstallationSecurity(
        store: excessStore,
        namespace: 'synthetic.peer-roster-dense-excess',
      );
      await excessInstallation.start(excessDb);
      final beforeExcess = jsonEncode(await sqlSnapshot(excessDb));
      final beforeExcessProtected = Map.of(excessStore.states);
      await expectLater(
        _activate(
          fixture,
          CompanyEnrollment(installation: excessInstallation, db: excessDb),
        ),
        throwsA(
          isA<CompanyBootstrapRefusal>().having(
            (error) => error.message,
            'message',
            'Enrollment capacity reached',
          ),
        ),
      );
      expect(
        jsonEncode(await sqlSnapshot(fixture.aDb)) == beforeIssuer,
        isTrue,
        reason: 'Issuer SQL state must remain unchanged when at capacity.',
      );
      expect(fixture.aStore.states, beforeIssuerProtected);
      expect(
        jsonEncode(await sqlSnapshot(excessDb)) == beforeExcess,
        isTrue,
        reason: 'Excess SQL state must remain unchanged when at capacity.',
      );
      expect(excessStore.states, beforeExcessProtected);

      await dense.signIn(_fixturePin);
      await sparse.signIn(_fixturePin);
      final crew = await issuer.createRestrictedUser(
        owner: fixture.owner,
        requestId: const Uuid().v4(),
        name: 'Crew',
        pin: _selectedPin,
      );
      await provisionInitialUser(issuer, dense, crew.userId);
      await provisionInitialUser(issuer, sparse, crew.userId);
      await issuer.signInUser(crew.userId, _selectedPin);
      await dense.signInUser(crew.userId, _selectedPin);
      await sparse.signInUser(crew.userId, _selectedPin);

      Map<int, ProtectedInstallationState> slots(
        JoinActivationStore store,
        String namespace,
      ) {
        final prefix = '$namespace.peer-intro-';
        return {
          for (final row in store.states.entries)
            if (row.key.startsWith(prefix))
              int.parse(row.key.substring(prefix.length)): row.value,
        };
      }

      int maxBytes(Map<int, ProtectedInstallationState> records) => records
          .values
          .map((record) => record.bytes.length)
          .reduce((a, b) => a > b ? a : b);

      final rootId = fixture.owner.identity.deviceId;
      final sparseResult = await _sync(issuer, sparse);
      expect(sparseResult.complete, isTrue, reason: sparseResult.message);
      expect(sparseResult.peerRosterMore, isTrue);
      final sparseRecords = slots(sparseStore, sparseNamespace);
      expect(
        sparseRecords.keys,
        unorderedEquals(List.generate(pageSize, (i) => i + 1)),
      );
      await _measureRetainedSlots('valid sparse', sparseStore, sparse, [
        rootId,
        denseIdentity.deviceId,
        ...otherDeviceIds.take(7),
      ], maxBytes(sparseRecords));

      final issuerJob =
          (await fixture.aDb.select(fixture.aDb.companyJobs).get()).single;
      final denseClock = Stopwatch()..start();
      var retained = 0;
      var pageCount = 0;
      // A Pair has a finite authenticated frame budget. Use fresh Pairs
      // between batches and resume from the persisted roster checkpoint.
      const pagesPerPair = 4;
      const expectedPages = 16;
      for (var batch = 0; batch < expectedPages ~/ pagesPerPair; batch++) {
        await _withSync(issuer, dense, (sync) async {
          for (var page = 0; page < pagesPerPair; page++) {
            final result = await sync.syncNow();
            expect(result.complete, isTrue, reason: result.message);
            pageCount++;
            retained += pageCount < expectedPages ? pageSize : pageSize - 1;
            expect(result.peerRosterMore, pageCount < expectedPages);
            expect([
              result.sent,
              result.received,
            ], pageCount == 1 ? [1, 0] : [0, 0]);
            if (pageCount == 1) {
              final delivered =
                  (await dense.db.select(dense.db.companyJobs).get()).single;
              expect(delivered.jobId, issuerJob.jobId);
              expect(
                delivered.operationBytes == issuerJob.operationBytes,
                isTrue,
                reason: 'The received original Job must retain its signed attribution.',
              );
            }
            expect(
              slots(fixture.bStore, fixture.b.namespace).keys,
              unorderedEquals(List.generate(retained, (i) => i + 2)),
            );
            debugPrintSynchronously(
              'Dense roster page: page=$pageCount, retained=$retained, '
              'ms=${denseClock.elapsedMilliseconds}',
            );
          }
        });
      }
      expect(pageCount, expectedPages);
      final records = slots(fixture.bStore, fixture.b.namespace);
      expect(records, hasLength(capacity - 1));
      expect(maxBytes(records), lessThanOrEqualTo(kInstallationStateLimit));
      final repeat = await _sync(issuer, dense);
      expect(repeat.complete, isTrue, reason: repeat.message);
      expect(repeat.peerRosterMore, isFalse);
      expect([repeat.sent, repeat.received], [0, 0]);
      expect(slots(fixture.bStore, fixture.b.namespace), records);

      await issuer.signOut();
      await fixture.closeIssuerAndCheckOwnerData();
      await fixture.reopenB();
      await sparse.signOut();
      await sparseDb.close();
      sparseDb = AppDatabase.forTesting(NativeDatabase(sparseFile));
      sparse = await openSparse();
      final reopenedDense = await fixture.bEnrollment.signInUser(
        crew.userId,
        _selectedPin,
      );
      final reopenedSparse = await sparse.signInUser(crew.userId, _selectedPin);
      expect(reopenedDense.identity.deviceId, denseIdentity.deviceId);
      expect(reopenedSparse.identity.deviceId, sparseIdentity.deviceId);
      for (final session in [reopenedDense, reopenedSparse]) {
        expect(session.identity.userId, crew.userId);
        expect(session.identity.isAuthorityOwner, isFalse);
      }
      expect(issuer.currentCompanySession, isNull);
      await _measureRetainedSlots(
        'valid dense',
        fixture.bStore,
        fixture.bEnrollment,
        [rootId, ...otherDeviceIds],
        maxBytes(records),
      );

      final directClock = Stopwatch()..start();
      await _direct(
        sparse,
        fixture.bEnrollment,
        expectSuccess: true,
        sendChallengeOverLoopback: true,
      );
      debugPrintSynchronously(
        'Dense cold direct Pair and proof: ms=${directClock.elapsedMilliseconds}',
      );
    },
    skip: capacityMode == '1' || ackProbe ? false : 'Set WP_RUN_DENSE_PEER_ROSTER=1 or ack-probe to run the capacity test',
    timeout: Timeout(Duration(minutes: ackProbe ? 20 : 45)),
  );
}

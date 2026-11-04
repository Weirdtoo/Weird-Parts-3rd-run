import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';

import 'company_join_test.dart'
    show JoinFixture, expectJoinProtectedUnchanged, sqlSnapshot;

void main() {
  test(
    'malformed occupied second slot fences the whole user collection',
    () async {
      final f = await JoinFixture.create();
      final first = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'First builder',
        pin: '0123',
      );
      final secondSlot = companyUserNamespace(f.a.namespace, slot: 2);
      f.aStore.states[secondSlot] = ProtectedInstallationState(
        const Uuid().v4(),
        Uint8List.fromList(utf8.encode('{"v":99}')),
      );
      final protected = Map.of(f.aStore.states);
      final sql = await sqlSnapshot(f.aDb);

      final choices = await f.aEnrollment.listCompanyUsers();
      expect(choices.where((choice) => choice.userId == first.userId), isEmpty);
      expect(choices.where((choice) => !choice.available).single.userId, '');
      expectJoinProtectedUnchanged(f.aStore, protected);
      await expectLater(
        f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Second builder',
          pin: '4567',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, protected);
      await expectLater(
        f.aEnrollment.signInUser(first.userId, '0123'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, protected);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  test(
    'duplicate signed user identity in two occupied slots fails closed',
    () async {
      final f = await JoinFixture.create();
      final first = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'First builder',
        pin: '0123',
      );
      final original = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
      f.aStore.states[companyUserNamespace(
        f.a.namespace,
        slot: 2,
      )] = ProtectedInstallationState(
        const Uuid().v4(),
        Uint8List.fromList(original.bytes),
      );
      final protected = Map.of(f.aStore.states);
      final sql = await sqlSnapshot(f.aDb);

      final choices = await f.aEnrollment.listCompanyUsers();
      expect(choices.where((choice) => choice.userId == first.userId), isEmpty);
      expect(choices.where((choice) => !choice.available).single.userId, '');
      expectJoinProtectedUnchanged(f.aStore, protected);
      await expectLater(
        f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Second builder',
          pin: '4567',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, protected);
      await expectLater(
        f.aEnrollment.signInUser(first.userId, '0123'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, protected);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  test(
    'creation retry preserves its account and cannot allocate a third user',
    () async {
      final f = await JoinFixture.create();
      final request = const Uuid().v4();
      final first = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: request,
        name: 'First builder',
        pin: '0123',
      );
      final firstSlot = companyUserNamespace(f.a.namespace);
      final original = f.aStore.states[firstSlot]!;
      final beforeRetry = Map.of(f.aStore.states);
      final retry = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: request,
        name: 'First builder',
        pin: '0123',
      );
      expect(retry.userId, first.userId);
      expect(retry.certificateBytes, first.certificateBytes);
      expectJoinProtectedUnchanged(f.aStore, beforeRetry);
      await expectLater(
        f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: request,
          name: 'Different builder',
          pin: '0123',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, beforeRetry);

      final second = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Second builder',
        pin: '4567',
      );
      expect(second.userId, isNot(first.userId));
      expect(f.aStore.states[firstSlot]!.revision, original.revision);
      expect(
        base64Encode(f.aStore.states[firstSlot]!.bytes) ==
            base64Encode(original.bytes),
        isTrue,
        reason: 'first protected user bytes unchanged',
      );
      expect(
        (await f.aEnrollment.listCompanyUsers())
            .where((choice) => choice.userId != f.owner.identity.userId)
            .map((choice) => choice.userId),
        unorderedEquals([first.userId, second.userId]),
      );
      final full = Map.of(f.aStore.states);
      final sql = await sqlSnapshot(f.aDb);
      await expectLater(
        f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Third builder',
          pin: '6789',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      expectJoinProtectedUnchanged(f.aStore, full);
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );

  test(
    'equal opaque revisions cannot route a user two PIN attempt to user one',
    () async {
      final f = await JoinFixture.create();
      final first = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'First builder',
        pin: '0123',
      );
      final second = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Second builder',
        pin: '4567',
      );
      final firstSlot = companyUserNamespace(f.a.namespace);
      final secondSlot = companyUserNamespace(f.a.namespace, slot: 2);
      final sharedRevision = const Uuid().v4();
      for (final slot in [firstSlot, secondSlot]) {
        f.aStore.states[slot] = ProtectedInstallationState(
          sharedRevision,
          Uint8List.fromList(f.aStore.states[slot]!.bytes),
        );
      }
      final protected = Map.of(f.aStore.states);
      final sql = await sqlSnapshot(f.aDb);
      await expectLater(
        f.aEnrollment.signInUser(second.userId, '0123'),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      for (final entry in protected.entries) {
        if (entry.key == secondSlot) continue;
        expect(f.aStore.states[entry.key]!.revision, entry.value.revision);
        expect(
          base64Encode(f.aStore.states[entry.key]!.bytes) ==
              base64Encode(entry.value.bytes),
          isTrue,
          reason: 'unselected protected bytes unchanged',
        );
      }
      expect(f.aStore.states[secondSlot]!.revision, isNot(sharedRevision));
      final expectedSecond =
          jsonDecode(utf8.decode(protected[secondSlot]!.bytes)) as Map;
      expectedSecond['a'] = 7;
      expect(
        jsonEncode(
              jsonDecode(utf8.decode(f.aStore.states[secondSlot]!.bytes)),
            ) ==
            jsonEncode(expectedSecond),
        isTrue,
        reason: 'only the selected user attempt count changed',
      );
      expect(
        (await f.aEnrollment.userLifecycleStatus(userId: first.userId))!
            .attemptsRemaining,
        8,
      );
      expect(
        (await f.aEnrollment.userLifecycleStatus(userId: second.userId))!
            .attemptsRemaining,
        7,
      );
      expect(await sqlSnapshot(f.aDb), sql);
    },
  );
  test(
    'creating user two forward-completes only user one durable journal intent',
    () async {
      final f = await JoinFixture.create();
      final first = await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'First',
        pin: '0123',
      );
      final slot = companyUserNamespace(f.a.namespace);
      var interrupted = false;
      f.aStore.beforeRead = (namespace) {
        if (namespace == slot && !interrupted) {
          final raw =
              jsonDecode(utf8.decode(f.aStore.states[slot]!.bytes)) as Map;
          if (raw['v'] == 3 && raw['j'] != null) {
            interrupted = true;
            throw StateError('Synthetic projection interruption');
          }
        }
        return null;
      };
      await expectLater(
        f.aEnrollment.resetRestrictedUserPin(
          owner: f.owner,
          userId: first.userId,
          requestId: const Uuid().v4(),
          expectedCredentialVersion: 1,
          pin: '4567',
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      f.aStore.beforeRead = null;
      expect(interrupted, isTrue);
      final pending =
          jsonDecode(utf8.decode(f.aStore.states[slot]!.bytes)) as Map;
      expect(pending['j'] != null, isTrue);
      final expected = {...pending, 'j': null};
      await f.aEnrollment.createRestrictedUser(
        owner: f.owner,
        requestId: const Uuid().v4(),
        name: 'Second',
        pin: '6789',
      );
      final completed =
          jsonDecode(utf8.decode(f.aStore.states[slot]!.bytes)) as Map;
      expect(
        jsonEncode(completed) == jsonEncode(expected),
        isTrue,
        reason: 'only saved journal intent clears',
      );
      final history = await sqlSnapshot(f.aDb);
      final stable = Map.of(f.aStore.states);
      await f.aEnrollment.userLifecycleStatus(userId: first.userId);
      expectJoinProtectedUnchanged(f.aStore, stable);
      expect(await sqlSnapshot(f.aDb), history);
      expect((await f.aDb.select(f.aDb.companyUserEvents).get()).length, 2);
    },
  );
}

import 'dart:convert';
import 'dart:io';

import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';

import '../../tool/company_users_native_validation.dart';
import '../../tool/nearby_lan_validation.dart'
    show validationInstallationNamespace;
import '../features/company/company_join_test.dart'
    show
        JoinActivationStore,
        sqlSnapshot,
        expectJoinProtectedUnchanged,
        canonicalJoinTest;

const _run = 'g2-users-20261024-disable-a';

final class _Fixture {
  _Fixture(
    this.root,
    this.db,
    this.store,
    this.installation,
    this.enrollment,
    this.userId,
    this.active,
  );
  final Directory root;
  final AppDatabase db;
  final JoinActivationStore store;
  final InstallationSecurity installation;
  final CompanyEnrollment enrollment;
  final String userId;
  final ProtectedInstallationState active;

  static Future<_Fixture> create({bool disable = true}) async {
    final root = Directory.systemTemp.createTempSync(
      'disabled-api-probe-test-',
    );
    final db = AppDatabase.forTesting(
      NativeDatabase(File('${root.path}/probe.sqlite')),
    );
    final store = JoinActivationStore();
    final installation = InstallationSecurity(
      store: store,
      namespace: validationInstallationNamespace(run: _run, roleName: 'sender'),
    );
    await installation.start(db);
    final enrollment = CompanyEnrollment(installation: installation, db: db);
    addTearDown(() async {
      store.onRead = null;
      store.beforeRead = null;
      await enrollment.signOut();
      await db.close();
      await root.delete(recursive: true);
    });
    await enrollment.create(
      companyName: 'Synthetic probe',
      policy: CompanyContinuityPolicy.localContinuity,
      pin: '1234',
      recoveryPassphrase: 'Synthetic probe recovery phrase',
      recoveryFile: File('${root.path}/authority.wpca'),
    );
    final owner = await enrollment.signIn('1234');
    final user = await enrollment.createRestrictedUser(
      owner: owner,
      requestId: const Uuid().v4(),
      name: 'Synthetic restricted user',
      pin: '0123',
    );
    final active = store.states[companyUserNamespace(installation.namespace)]!;
    await CompanyJobCommands(enrollment: enrollment).createJob(
      CreateJob(
        companyId: owner.identity.companyId,
        shopId: owner.identity.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: 'Existing owner history',
      ),
      ownerSession: owner,
    );
    if (disable) {
      await enrollment.disableRestrictedUser(
        owner: owner,
        userId: user.userId,
        requestId: const Uuid().v4(),
      );
    }
    await enrollment.signOut();
    final fixture = _Fixture(
      root,
      db,
      store,
      installation,
      enrollment,
      user.userId,
      active,
    );
    return fixture;
  }

  Future<Map<String, Object?>?> probe({
    bool enabled = true,
    bool validationEnabled = true,
    bool initialized = true,
    String run = _run,
    String role = 'sender',
    String? expectedUserId,
    String? revision,
  }) => runCompanyUserDisabledApiProbe(
    enrollment: enrollment,
    enabled: enabled,
    validationEnabled: validationEnabled,
    initialized: initialized,
    run: run,
    roleName: role,
    expectedUserId: expectedUserId ?? userId,
    sourceRevision: revision ?? 'a' * 40,
    sourceTree: 'b' * 40,
  );
}

void main() {
  test('safe native projection reports actual replacement epoch without credential material', () async {
    final f = await _Fixture.create(disable: false);
    final owner = await f.enrollment.signIn('1234');
    await f.enrollment.resetRestrictedUserPin(
      owner: owner,
      userId: f.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    final result = await readCompanyUserValidationProjection(
      f.enrollment,
      f.installation,
      run: _run,
      roleName: 'sender',
    );
    expect((result['certificatePublic'] as Map)['credentialVersion'], 2);
    expect(result['awaitingCredential'], isFalse);
    expect(result['credentialReceiptSaved'], isFalse);
    expect(
      result.keys,
      unorderedEquals([
        'present',
        'byteLength',
        'available',
        'disabled',
        'attemptsRemaining',
        'disableReceiptSaved',
        'awaitingCredential',
        'credentialReceiptSaved',
        'certificatePublic',
        'capacity',
        'byteLengths',
        'users',
      ]),
    );
    expect(
      (result['certificatePublic'] as Map).keys,
      unorderedEquals(['userId', 'credentialVersion', 'permissionVersion']),
    );
  });
  test(
    'default-off probe makes no authorization or protected-store calls',
    () async {
      final f = await _Fixture.create();
      f.store.onRead = (_) => throw StateError('default-off-read');
      expect(
        await runCompanyUserDisabledApiProbe(
          enrollment: f.enrollment,
          validationEnabled: false,
          initialized: false,
          run: 'invalid',
          roleName: 'invalid',
          expectedUserId: 'invalid',
          sourceRevision: 'invalid',
          sourceTree: 'invalid',
        ),
        isNull,
      );
      expect(f.enrollment.currentCompanySession, isNull);
    },
  );

  test('probe refuses metadata and workspace guards before reading protected state', () async {
    final f = await _Fixture.create();
    var reads = 0;
    f.store.onRead = (_) {
      reads++;
    };
    for (final attempt in <Future<Object?> Function()>[
      () => f.probe(validationEnabled: false),
      () => f.probe(initialized: false),
      () => f.probe(run: 'g2-users-20261024-other'),
      () => f.probe(role: 'other'),
      () => f.probe(revision: 'invalid'),
    ]) {
      await expectLater(attempt(), throwsStateError);
    }
    expect(reads, 0);
  });

  test('probe refuses wrong identity and active, missing, or corrupt policy without writes', () async {
    final f = await _Fixture.create();
    final slot = companyUserNamespace(f.installation.namespace);
    final disabled = f.store.states[slot]!;
    await expectLater(
      f.probe(expectedUserId: const Uuid().v4()),
      throwsStateError,
    );
    f.store.states[slot] = f.active;
    await expectLater(f.probe(), throwsStateError);
    expect(f.store.states[slot]!.revision, f.active.revision);
    f.store.states.remove(slot);
    await expectLater(f.probe(), throwsStateError);
    expect(f.store.states.containsKey(slot), isFalse);
    f.store.states[slot] = ProtectedInstallationState(
      disabled.revision,
      utf8.encode('private-corrupt-marker'),
    );
    Object? refusal;
    try {
      await f.probe();
    } catch (error) {
      refusal = error;
    }
    expect(refusal, isA<StateError>());
    expect('$refusal', isNot(contains('private-corrupt-marker')));
    expect(f.enrollment.currentCompanySession, isNull);
  });

  test(
    'probe refuses an existing Owner session without signing it out',
    () async {
      final f = await _Fixture.create();
      final owner = await f.enrollment.signIn('1234');
      final protected = Map.of(f.store.states);
      await expectLater(f.probe(), throwsStateError);
      expect(f.enrollment.currentCompanySession, same(owner));
      expectJoinProtectedUnchanged(f.store, protected);
    },
  );

  test('opt-in disabled API probe calls production refusal paths without state changes', () async {
    final f = await _Fixture.create();
    final protected = Map.of(f.store.states);
    final sql = await sqlSnapshot(f.db);
    final result = await f.probe();
    expect(result, isNotNull);
    expect(result!['oldPinDenied'], isTrue);
    expect(result['noSession'], isTrue);
    expect(result['commandAuthorizationDenied'], isTrue);
    expect(result['protectedStateUnchanged'], isTrue);
    expect(result['sqlUnchanged'], isTrue);
    expect(
      result.values.every(
        (value) => value is bool || value == 'disabled login and unauthenticated Create Job authorization only',
      ),
      isTrue,
    );
    expect(f.enrollment.currentCompanySession, isNull);
    expectJoinProtectedUnchanged(f.store, protected);
    expect(await sqlSnapshot(f.db), sql);
    expect(jsonEncode(result).contains('0123'), isFalse);
  });

  test('probe rejects unexpected production sign-in success and drains the session', () async {
    final f = await _Fixture.create();
    final slot = companyUserNamespace(f.installation.namespace);
    var switched = false;
    f.store.onRead = (namespace) {
      if (!switched &&
          namespace == slot &&
          StackTrace.current.toString().contains('signInUser')) {
        switched = true;
        f.store.states[slot] = f.active;
      }
    };
    await expectLater(f.probe(), throwsStateError);
    expect(switched, isTrue);
    expect(f.enrollment.currentCompanySession, isNull);
  });

  for (final operation in ['signInUser', 'issueCreateJobAssertion']) {
    test(
      'probe sanitizes unexpected $operation errors and leaves no session',
      () async {
        final f = await _Fixture.create();
        var injected = false;
        f.store.onRead = (_) {
          if (StackTrace.current.toString().contains(operation)) {
            injected = true;
            throw StateError('private-operation-error-marker');
          }
        };
        Object? refusal;
        try {
          await f.probe();
        } catch (error) {
          refusal = error;
        }
        expect(injected, isTrue);
        expect(refusal, isA<StateError>());
        expect('$refusal', isNot(contains('private-operation-error-marker')));
        expect(f.enrollment.currentCompanySession, isNull);
      },
    );
    test('probe rejects a different typed refusal from $operation', () async {
      final f = await _Fixture.create();
      var injected = false;
      f.store.onRead = (_) {
        if (StackTrace.current.toString().contains(operation)) {
          injected = true;
          throw const CompanyBootstrapRefusal('Different refusal');
        }
      };
      await expectLater(f.probe(), throwsStateError);
      expect(injected, isTrue);
      expect(f.enrollment.currentCompanySession, isNull);
    });
  }

  test(
    'probe detects a revision-only protected-state change during refusal',
    () async {
      final f = await _Fixture.create();
      final slot = companyUserNamespace(f.installation.namespace);
      var changed = false;
      f.store.onRead = (namespace) {
        if (!changed &&
            namespace == slot &&
            StackTrace.current.toString().contains('signInUser')) {
          changed = true;
          f.store.states[slot] = ProtectedInstallationState(
            const Uuid().v4(),
            f.store.states[slot]!.bytes,
          );
        }
      };
      await expectLater(f.probe(), throwsStateError);
      expect(changed, isTrue);
      expect(f.enrollment.currentCompanySession, isNull);
    },
  );

  test('probe detects SQL mutation during the actual unauthenticated command refusal', () async {
    final f = await _Fixture.create();
    var changed = false;
    f.store.beforeRead = (_) {
      if (!changed &&
          StackTrace.current.toString().contains('issueCreateJobAssertion')) {
        changed = true;
        return f.db.customStatement('UPDATE company_jobs SET outgoing = 0');
      }
      return null;
    };
    await expectLater(f.probe(), throwsStateError);
    expect(changed, isTrue);
    expect(f.enrollment.currentCompanySession, isNull);
  });

  test('probe detects byte-only protected-state change despite unchanged policy and revision', () async {
    final f = await _Fixture.create();
    final slot = companyUserNamespace(f.installation.namespace);
    var changed = false;
    f.store.onRead = (namespace) {
      if (!changed &&
          namespace == slot &&
          StackTrace.current.toString().contains('signInUser')) {
        changed = true;
        final state = f.store.states[slot]!;
        final value = jsonDecode(utf8.decode(state.bytes)) as Map;
        value['a'] = value['a'] == 0 ? 1 : 0;
        f.store.states[slot] = ProtectedInstallationState(
          state.revision,
          utf8.encode(canonicalJoinTest(value)),
        );
      }
    };
    await expectLater(f.probe(), throwsStateError);
    expect(changed, isTrue);
    f.store.onRead = null;
    expect(
      (await f.enrollment.userLifecycleStatus(userId: f.userId))!.disabled,
      isTrue,
    );
    expect(f.enrollment.currentCompanySession, isNull);
  });
}

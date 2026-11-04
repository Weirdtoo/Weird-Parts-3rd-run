import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sqlite3/sqlite3.dart' as sqlite;
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/backup/backup_store.dart';
import 'package:wired_parts/features/backup/backup_codec.dart';
import 'package:wired_parts/features/company/company_store_markers.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:uuid/uuid.dart';

import 'company_join_test.dart'
    show JoinActivationStore, sqlSnapshot, expectJoinProtectedUnchanged;

void main() {
  test('encrypted stale company input is refused and reopen preserves spent reset history', () async {
    final directory = Directory.systemTemp.createTempSync('user-stale-backup-');
    final file = File('${directory.path}/shop.sqlite');
    var db = AppDatabase.forTesting(NativeDatabase(file));
    final store = JoinActivationStore();
    var installation = InstallationSecurity(
      store: store,
      namespace: 'synthetic.pin-backup',
    );
    await installation.start(db);
    var enrollment = CompanyEnrollment(installation: installation, db: db);
    addTearDown(() async {
      await enrollment.signOut();
      await db.close();
      await directory.delete(recursive: true);
    });
    await enrollment.create(
      companyName: 'Synthetic stale input',
      policy: CompanyContinuityPolicy.localContinuity,
      pin: '1234',
      recoveryPassphrase: 'synthetic authority recovery phrase',
      recoveryFile: File('${directory.path}/authority.wpca'),
    );
    var owner = await enrollment.signIn('1234');
    final user = await enrollment.createRestrictedUser(
      owner: owner,
      requestId: const Uuid().v4(),
      name: 'Casey',
      pin: '0123',
    );
    final firstRequest = const Uuid().v4();
    await enrollment.resetRestrictedUserPin(
      owner: owner,
      userId: user.userId,
      requestId: firstRequest,
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    final staleFile = File('${directory.path}/stale.sqlite');
    await db.customStatement(
      "VACUUM INTO '${staleFile.path.replaceAll("'", "''")}'",
    );
    final codec = BackupCodec();
    final encrypted = await codec.encrypt(
      BackupPayload(
        createdAt: DateTime.utc(2026, 10, 24),
        sourceDeviceId: owner.identity.deviceId,
        sqliteBytes: Uint8List.fromList(await staleFile.readAsBytes()),
        photos: {},
      ),
      'synthetic backup phrase',
    );
    final stale = await codec.decrypt(encrypted, 'synthetic backup phrase');
    await enrollment.resetRestrictedUserPin(
      owner: owner,
      userId: user.userId,
      requestId: const Uuid().v4(),
      expectedCredentialVersion: 2,
      pin: '6789',
    );
    final before = Map.of(store.states);
    final sql = await sqlSnapshot(db);
    await expectLater(
      BackupStore(supportDir: directory).replaceWithPayload(payload: stale),
      throwsA(isA<BackupFormatException>()),
    );
    expect(await sqlSnapshot(db), sql);
    bool unchanged(Map<String, ProtectedInstallationState> expected) =>
        store.states.length == expected.length &&
        expected.entries.every((entry) {
          final current = store.states[entry.key];
          return current?.revision == entry.value.revision &&
              base64Encode(current!.bytes) == base64Encode(entry.value.bytes);
        });
    expect(unchanged(before), isTrue);
    await enrollment.signOut();
    await db.close();
    db = AppDatabase.forTesting(NativeDatabase(file));
    installation = InstallationSecurity(
      store: store,
      namespace: installation.namespace,
    );
    await installation.start(db);
    enrollment = CompanyEnrollment(installation: installation, db: db);
    owner = await enrollment.signIn('1234');
    final reopened = Map.of(store.states);
    final slot = companyUserNamespace(installation.namespace);
    expect(reopened[slot]!.revision, before[slot]!.revision);
    expect(
      base64Encode(reopened[slot]!.bytes) == base64Encode(before[slot]!.bytes),
      isTrue,
    );
    final replay = await enrollment.resetRestrictedUserPin(
      owner: owner,
      userId: user.userId,
      requestId: firstRequest,
      expectedCredentialVersion: 1,
      pin: '4567',
    );
    expect(replay.credentialVersion, 2);
    expect(replay.isCurrent, isFalse);
    expect(
      (await enrollment.userLifecycleStatus(userId: user.userId))!
          .credentialVersion,
      3,
    );
    expect(await sqlSnapshot(db), sql);
    expect(unchanged(reopened), isTrue);
  });

  test('schema12 migration preserves exact existing rows and adds empty public user tables', () async {
    final directory = Directory.systemTemp.createTempSync(
      'user-history-migration-',
    );
    addTearDown(() => directory.deleteSync(recursive: true));
    final file = File('${directory.path}/shop.sqlite');
    final original = AppDatabase.forTesting(NativeDatabase(file));
    await original.customStatement(
      "INSERT INTO app_settings (key,value) VALUES ('migration-preserve','exact value')",
    );
    await original.close();
    final raw = sqlite.sqlite3.open(file.path);
    raw.execute('DROP TABLE company_user_events');
    raw.execute('DROP TABLE company_user_deliveries');
    raw.execute('DROP TABLE company_user_credential_grants');
    raw.execute('PRAGMA user_version = 12');
    final before = <String, List<Map<String, Object?>>>{};
    for (final row in raw.select(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )) {
      final name = row['name'] as String;
      before[name] = raw
          .select('SELECT * FROM "$name"')
          .map((r) => Map<String, Object?>.from(r))
          .toList();
    }
    raw.dispose();
    final db = AppDatabase.forTesting(NativeDatabase(file));
    addTearDown(db.close);
    expect(await db.select(db.companyUserEvents).get(), isEmpty);
    expect(await db.select(db.companyUserDeliveries).get(), isEmpty);
    for (final entry in before.entries) {
      expect(
        (await db.customSelect('SELECT * FROM "${entry.key}"').get())
            .map((r) => r.data)
            .toList(),
        entry.value,
        reason: entry.key,
      );
    }
    expect(
      (await db.customSelect('PRAGMA user_version').getSingle()).read<int>(
        'user_version',
      ),
      kAppSchemaVersion,
    );
  });

  test(
    'schema13 migration preserves existing rows and adds an empty grant table',
    () async {
      final directory = Directory.systemTemp.createTempSync('grant-migration-');
      addTearDown(() => directory.deleteSync(recursive: true));
      final file = File('${directory.path}/shop.sqlite');
      final original = AppDatabase.forTesting(NativeDatabase(file));
      await original.customStatement(
        "INSERT INTO app_settings (key,value) VALUES ('migration-grant','unchanged')",
      );
      await original.customStatement(
        "INSERT INTO company_user_events (company_id,user_id,sequence,request_id,public_head,previous_head,certificate_bytes,kind) VALUES ('company','user',1,'request','head','','immutable event','created')",
      );
      await original.customStatement(
        "INSERT INTO company_user_deliveries (company_id,user_id,public_head,source_device_id,peer_device_id,binding_commitment,receipt_bytes) VALUES ('company','user','head','source','recipient','binding','immutable receipt')",
      );
      await original.customStatement(
        "INSERT INTO company_jobs (job_id,company_id,shop_id,origin_generation,request_id,operation_commitment,command_commitment,operation_bytes,projection_bytes,receipt_key,receipt_bytes,audit_bytes,outgoing) VALUES ('job','company','shop','generation','request','op','command','immutable operation','projection','receipt','receipt bytes','audit',1)",
      );
      final events = await original.select(original.companyUserEvents).get();
      final deliveries = await original
          .select(original.companyUserDeliveries)
          .get();
      final jobs = await original.select(original.companyJobs).get();
      await original.close();
      final raw = sqlite.sqlite3.open(file.path);
      raw.execute('DROP TABLE company_user_credential_grants');
      raw.execute('PRAGMA user_version = 13');
      raw.dispose();
      final db = AppDatabase.forTesting(NativeDatabase(file));
      addTearDown(db.close);
      expect(await db.select(db.companyUserCredentialGrants).get(), isEmpty);
      expect(await db.select(db.companyUserEvents).get(), events);
      expect(await db.select(db.companyUserDeliveries).get(), deliveries);
      expect(await db.select(db.companyJobs).get(), jobs);
      expect(
        (await db
                .customSelect(
                  "SELECT value FROM app_settings WHERE key='migration-grant'",
                )
                .getSingle())
            .read<String>('value'),
        'unchanged',
      );
      expect(
        (await db.customSelect('PRAGMA user_version').getSingle()).read<int>(
          'user_version',
        ),
        14,
      );
    },
  );

  for (final table in [
    'company_user_events',
    'company_user_deliveries',
    'company_user_credential_grants',
  ]) {
    test(
      'missing schema13 $table is refused by live company schema gate',
      () async {
        final db = AppDatabase.forTesting(NativeDatabase.memory());
        addTearDown(db.close);
        await db.customStatement('DROP TABLE $table');
        await expectLater(
          requireCompanyJoinSchema(db),
          throwsA(isA<StateError>()),
        );
      },
    );
  }

  test('a grant row alone refuses legacy file handling', () async {
    final directory = Directory.systemTemp.createTempSync('grant-marker-');
    addTearDown(() => directory.deleteSync(recursive: true));
    final file = File('${directory.path}/shop.sqlite');
    final db = AppDatabase.forTesting(NativeDatabase(file));
    await db.customStatement(
      "INSERT INTO company_user_credential_grants (company_id,user_id,grant_key,grant_bytes) VALUES ('company','user','grant','public')",
    );
    expect(await hasCompanyStoreMarkers(db), isTrue);
    await db.close();
    final before = file.readAsBytesSync();
    expect(
      () => requireLegacyBusinessFile(file),
      throwsA(isA<BackupFormatException>()),
    );
    expect(file.readAsBytesSync(), before);
  });

  test('a grant row alone refuses company creation without mutation', () async {
    final directory = Directory.systemTemp.createTempSync(
      'grant-create-refusal-',
    );
    addTearDown(() => directory.deleteSync(recursive: true));
    final db = AppDatabase.forTesting(NativeDatabase.memory());
    addTearDown(db.close);
    final store = JoinActivationStore();
    final installation = InstallationSecurity(
      store: store,
      namespace: 'synthetic.grant-preflight',
    );
    await installation.start(db);
    await db.customStatement(
      "INSERT INTO company_user_credential_grants (company_id,user_id,grant_key,grant_bytes) VALUES ('company','user','grant','public')",
    );
    final beforeSql = await sqlSnapshot(db);
    final beforeProtected = Map.of(store.states);
    final recovery = File('${directory.path}/authority.wpca');
    await expectLater(
      CompanyBootstrap.preflightFreshShop(db),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final enrollment = CompanyEnrollment(installation: installation, db: db);
    await expectLater(
      enrollment.create(
        companyName: 'Synthetic',
        policy: CompanyContinuityPolicy.localContinuity,
        pin: '1234',
        recoveryPassphrase: 'synthetic authority recovery phrase',
        recoveryFile: recovery,
      ),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(await sqlSnapshot(db), beforeSql);
    expectJoinProtectedUnchanged(store, beforeProtected);
    expect(recovery.existsSync(), isFalse);
  });

  test('unknown newer database schema is refused before mutation', () async {
    final directory = Directory.systemTemp.createTempSync(
      'grant-newer-schema-',
    );
    addTearDown(() => directory.deleteSync(recursive: true));
    final file = File('${directory.path}/shop.sqlite');
    final original = AppDatabase.forTesting(NativeDatabase(file));
    await original.customSelect('SELECT 1').get();
    await original.close();
    final raw = sqlite.sqlite3.open(file.path);
    raw.execute('PRAGMA user_version = 15');
    raw.dispose();
    final before = file.readAsBytesSync();
    expect(
      () => requireLegacyBusinessFile(file),
      throwsA(isA<BackupFormatException>()),
    );
    expect(file.readAsBytesSync(), before);
    final db = AppDatabase.forTesting(NativeDatabase(file));
    await expectLater(
      db.customSelect('SELECT 1').get(),
      throwsA(isA<StateError>()),
    );
    await db.close();
    expect(file.readAsBytesSync(), before);
  });

  test(
    'extra grant column refuses live and raw company schema gates',
    () async {
      final directory = Directory.systemTemp.createTempSync(
        'grant-schema-extra-',
      );
      addTearDown(() => directory.deleteSync(recursive: true));
      final file = File('${directory.path}/shop.sqlite');
      final db = AppDatabase.forTesting(NativeDatabase(file));
      await db.customStatement(
        'ALTER TABLE company_user_credential_grants ADD COLUMN unexpected TEXT',
      );
      await expectLater(
        requireCompanyJoinSchema(db),
        throwsA(isA<StateError>()),
      );
      await db.close();
      final before = file.readAsBytesSync();
      expect(
        () => requireLegacyBusinessFile(file),
        throwsA(isA<BackupFormatException>()),
      );
      expect(file.readAsBytesSync(), before);
    },
  );

  test(
    'public user journal alone refuses legacy whole-shop file handling',
    () async {
      final directory = Directory.systemTemp.createTempSync(
        'user-history-marker-',
      );
      addTearDown(() => directory.deleteSync(recursive: true));
      final file = File('${directory.path}/shop.sqlite');
      final db = AppDatabase.forTesting(NativeDatabase(file));
      await db.customStatement(
        "INSERT INTO company_user_events (company_id,user_id,sequence,request_id,public_head,previous_head,certificate_bytes,kind) VALUES ('synthetic','synthetic',1,'synthetic','public','','public','created')",
      );
      expect(await hasCompanyStoreMarkers(db), isTrue);
      await db.close();
      final before = file.readAsBytesSync();
      expect(
        () => requireLegacyBusinessFile(file),
        throwsA(isA<BackupFormatException>()),
      );
      expect(file.readAsBytesSync(), before);
    },
  );
}

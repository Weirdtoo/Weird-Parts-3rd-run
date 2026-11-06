import 'dart:convert';
import 'dart:io';

import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:sqlite3/sqlite3.dart' as raw;
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/backup/backup_codec.dart';

import '../../tool/nearby_lan_validation.dart';
import '../../tool/nearby_lan_workspace.dart';
import '../../tool/native_nearby_test_crypto.dart';
import '../../tool/native_nearby_test_fixture.dart';
import 'schema10_native_test_fixture.dart';

void main() {
  late Directory temp;
  ValidationWorkspace? workspace;
  setUp(() {
    temp = Directory.systemTemp.createTempSync('native-fixture-unit-');
  });
  tearDown(() {
    workspace?.close();
    workspace = null;
    temp.deleteSync(recursive: true);
  });

  for (final history in [
    'company_job_lifecycles',
    'company_authority_facts',
    'company_user_events',
    'company_user_deliveries',
    'company_user_credential_grants',
  ]) {
    test(
      'schema10 projection refuses nonempty $history without changing schema or rows',
      () async {
        workspace = ValidationWorkspace.open(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        );
        final db = AppDatabase.forTesting(NativeDatabase.memory());
        addTearDown(db.close);
        await seedValidationShop(db, workspace!);
        final columns =
            (await db.customSelect('PRAGMA table_info("$history")').get())
                .map((row) => row.read<String>('name'))
                .toList();
        await db.customStatement(
          'INSERT INTO "$history" (${columns.map((name) => '"$name"').join(',')}) '
          'VALUES (${columns.map((_) => '?').join(',')})',
          [
            for (final name in columns)
              name == 'outgoing'
                  ? 0
                  : name == 'sequence'
                  ? 1
                  : 'synthetic-history',
          ],
        );
        Future<Map<String, Object?>> snapshot() async {
          final tables = await db
              .customSelect(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
              )
              .get();
          return {
            'version':
                (await db.customSelect('PRAGMA user_version').getSingle()).data,
            'rows': {
              for (final table in tables)
                table.read<String>('name'):
                    (await db
                            .customSelect(
                              'SELECT * FROM "${table.read<String>('name')}"',
                            )
                            .get())
                        .map((row) => row.data)
                        .toList(),
            },
          };
        }

        final before = await snapshot();
        await expectLater(
          projectSeededSchema10NativeFixture(db),
          throwsA(isA<TestFailure>()),
        );
        expect(await snapshot(), before);
        expect(
          (await db.customSelect('PRAGMA user_version').getSingle())
              .data
              .values
              .single,
          kAppSchemaVersion,
        );
        expect(
          await db
              .customSelect(
                "SELECT name FROM sqlite_master WHERE type = 'table'",
              )
              .get(),
          hasLength(39),
        );
      },
    );
  }

  for (final history in ['warehouse_locations', 'warehouse_counts']) {
    test(
      'schema10 projection refuses nonempty $history without changing schema or rows',
      () async {
        workspace = ValidationWorkspace.open(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        );
        final db = AppDatabase.forTesting(NativeDatabase.memory());
        addTearDown(db.close);
        await seedValidationShop(db, workspace!);
        final now = DateTime.utc(2026, 10, 20, 12);
        await db
            .into(db.warehouseLocations)
            .insert(
              WarehouseLocationsCompanion.insert(
                id: 'synthetic-location',
                originDeviceId: workspace!.deviceId,
                createdAt: now,
                modifiedAt: now,
                name: 'Synthetic location',
                nameKey: 'synthetic location',
              ),
            );
        if (history == 'warehouse_counts') {
          await db
              .into(db.warehouseCounts)
              .insert(
                WarehouseCountsCompanion.insert(
                  id: 'synthetic-count',
                  locationId: 'synthetic-location',
                  partId: 'unit-sender-part',
                  ordinal: 1,
                  quantity: 3.0,
                  uom: 'ea',
                  observedAt: now,
                  recordedAt: now,
                  originDeviceId: workspace!.deviceId,
                ),
              );
        }
        final beforeRows = await db
            .customSelect('SELECT * FROM "$history" ORDER BY id')
            .get();

        await expectLater(
          projectSeededSchema10NativeFixture(db),
          throwsA(isA<TestFailure>()),
        );

        expect(
          (await db.customSelect('PRAGMA user_version').getSingle()).read<int>(
            'user_version',
          ),
          kAppSchemaVersion,
        );
        expect(
          (await db.customSelect('SELECT * FROM "$history" ORDER BY id').get())
              .map((row) => row.data),
          beforeRows.map((row) => row.data),
        );
        expect(
          await db
              .customSelect(
                "SELECT name FROM sqlite_master WHERE type = 'table'",
              )
              .get(),
          hasLength(39),
        );
      },
    );
  }

  test(
    'resident refuses an absent fixture without creating a root or lock',
    () {
      expect(
        () => openExistingNativeFixture(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        ),
        throwsA(isA<NativeTestFailure>()),
      );
      expect(temp.listSync(), isEmpty);
    },
  );

  test('locked existing-only workspace cannot initialize an absent root', () {
    expect(
      () => ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
        requireExisting: true,
      ),
      throwsStateError,
    );
    expect(
      Directory(p.join(temp.path, 'wired-parts-lan-unit-sender')).existsSync(),
      false,
    );
  });

  test(
    'missing database and altered owner are rejected before storage opens',
    () {
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      workspace!.markInitialized();
      workspace!.close();
      expect(
        () => openExistingNativeFixture(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        ),
        throwsA(isA<NativeTestFailure>()),
      );
      File(p.join(workspace!.support.path, 'wired_parts.sqlite'))
          .writeAsStringSync('untouched');
      File(p.join(workspace!.root.path, 'validation-owner.json'))
          .writeAsStringSync(
            jsonEncode({
              'format': 1,
              'run': 'unit',
              'role': 'receiver',
              'root': workspace!.root.path,
              'initialized': true,
            }),
          );
      expect(
        () => openExistingNativeFixture(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        ),
        throwsA(isA<NativeTestFailure>()),
      );
      expect(
        File(p.join(workspace!.support.path, 'wired_parts.sqlite'))
            .readAsStringSync(),
        'untouched',
      );
    },
  );

  test(
    'capture retains tombstones and catches broken references and live edits',
    () async {
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      final db = AppDatabase.forTesting(NativeDatabase.memory());
      addTearDown(db.close);
      await seedSchema10NativeFixture(db, workspace!);
      expect(
        (await db.customSelect('PRAGMA user_version').getSingle())
            .data
            .values
            .single,
        10,
      );
      expect(
        await db
            .customSelect("SELECT name FROM sqlite_master WHERE type = 'table'")
            .get(),
        hasLength(32),
      );
      final baseline = await NativeFixtureSnapshot.capture(db, workspace!);
      expect(baseline.schemaVersion, 10);
      expect(baseline.domain.length, 30);
      expect(baseline.rowCount, 14);
      expect(baseline.referenceCount, 16);
      expect(baseline.referencesValid, true);
      expect(baseline.integrityValid, true);
      expect(baseline.assets.length, 1);
      expect(
        baseline.domain['jobs']!.where((r) => r['deleted_at'] != null).length,
        1,
      );
      await db.customStatement(
        'UPDATE job_lines SET notes = ?, revision = revision+1',
        ['synthetic-marker'],
      );
      final edited = await NativeFixtureSnapshot.capture(db, workspace!);
      expect(edited.digest, isNot(baseline.digest));
      expect(edited.profileDigest, baseline.profileDigest);
      await db.customStatement('UPDATE job_lines SET part_id = ?', [
        'missing-part',
      ]);
      expect(
        (await NativeFixtureSnapshot.capture(db, workspace!)).referencesValid,
        false,
      );
    },
  );

  for (final mutation in [
    'empty',
    'malformed',
    'schema',
    'missing-profile',
    'wrong-profile',
    'missing-table',
    'missing-history-table',
    'missing-company-jobs',
    'nonempty-company-name-table',
    'unknown-schema11',
    'extra-details-column',
    'missing-details-column',
    'missing-column',
  ]) {
    test('preflight rejects $mutation database without modifying its bytes', () async {
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      final file = File(p.join(workspace!.support.path, 'wired_parts.sqlite'));
      final db = AppDatabase.forTesting(NativeDatabase(file));
      await seedSchema10NativeFixture(db, workspace!);
      workspace!.markInitialized();
      await db.close();
      if (mutation == 'empty') {
        file.writeAsBytesSync([]);
      } else if (mutation == 'malformed') {
        file.writeAsStringSync('not a SQLite database');
      } else {
        final corrupt = raw.sqlite3.open(file.path);
        try {
          if (mutation == 'schema') {
            corrupt.execute('PRAGMA user_version = 1');
          } else if (mutation == 'missing-profile') {
            corrupt.execute('DELETE FROM device_profiles');
          } else if (mutation == 'missing-table') {
            corrupt.execute('DROP TABLE styles');
          } else if (mutation == 'missing-history-table') {
            corrupt.execute('DROP TABLE job_line_operations');
          } else if (mutation == 'missing-company-jobs') {
            corrupt.execute('DROP TABLE company_jobs');
          } else if (mutation == 'nonempty-company-name-table') {
            corrupt.execute(
              "INSERT INTO company_job_names (company_id, shop_id, job_id, origin_generation, request_id, operation_commitment, command_commitment, operation_bytes, receipt_key, receipt_bytes, audit_bytes, outgoing) VALUES ('c', 's', 'j', 'g', 'r', 'o', 'c', 'op', 'k', 'receipt', 'audit', 0)",
            );
          } else if (mutation == 'unknown-schema11') {
            corrupt.execute('PRAGMA user_version = 11');
          } else if (mutation == 'extra-details-column') {
            corrupt.execute(
              'ALTER TABLE company_job_details ADD COLUMN untrusted TEXT',
            );
          } else if (mutation == 'missing-details-column') {
            corrupt.execute(
              'ALTER TABLE company_job_detail_peer_acks DROP COLUMN ack_bytes',
            );
          } else if (mutation == 'missing-column') {
            corrupt.execute('ALTER TABLE job_lines DROP COLUMN notes');
          } else {
            corrupt.execute("UPDATE device_profiles SET id = 'other-device'");
          }
        } finally {
          corrupt.dispose();
        }
      }
      final before = file.readAsBytesSync();
      workspace!.close();
      expect(
        () => openExistingNativeFixture(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        ),
        throwsA(isA<NativeTestFailure>()),
      );
      expect(file.readAsBytesSync(), before);
      // Reacquisition proves the rejected preflight released its owned lock.
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
        requireExisting: true,
      );
    });
  }

  test(
    'preflight accepts the existing schema and exact device profile',
    () async {
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      final file = File(p.join(workspace!.support.path, 'wired_parts.sqlite'));
      final db = AppDatabase.forTesting(NativeDatabase(file));
      await seedSchema10NativeFixture(db, workspace!);
      workspace!.markInitialized();
      await db.close();
      final before = file.readAsBytesSync();
      workspace!.close();
      workspace = openExistingNativeFixture(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      expect(file.readAsBytesSync(), before);
      expect(workspace!.deviceId, 'lan-unit-sender');
    },
  );

  for (final entry in {
    2: 13,
    3: 20,
    4: 20,
    5: 21,
    6: 22,
    7: 25,
    8: 26,
    9: 28,
    10: 30,
  }.entries) {
    test(
      'frozen schema${entry.key} capture and preflight preserve declared proof and bytes',
      () async {
        workspace = ValidationWorkspace.open(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        );
        final file = File(
          p.join(workspace!.support.path, 'wired_parts.sqlite'),
        );
        final db = AppDatabase.forTesting(NativeDatabase(file));
        await seedSchema10NativeFixture(db, workspace!);
        for (final table in db.allTables) {
          final name = table.actualTableName;
          if (name == 'company_job_lifecycles' ||
              name == 'company_job_lifecycle_peer_acks') {
            continue;
          }
          if ((entry.key < 10 &&
                  {
                    'company_job_details',
                    'company_job_detail_peer_acks',
                  }.contains(name)) ||
              (entry.key < 9 &&
                  {
                    'company_job_names',
                    'company_job_name_peer_acks',
                  }.contains(name)) ||
              (entry.key < 8 && name == 'company_job_peer_acks') ||
              (entry.key < 7 &&
                  {
                    'company_membership_certificates',
                    'company_join_requests',
                    'company_join_events',
                  }.contains(name)) ||
              (entry.key < 6 && name == 'company_jobs') ||
              (entry.key < 5 && name == 'company_bootstrap_witnesses') ||
              (entry.key < 3 &&
                  (name.startsWith('job_line_') ||
                      name == 'company_authority_facts'))) {
            await db.customStatement('DROP TABLE "$name"');
          }
        }
        await db.customStatement('PRAGMA user_version = ${entry.key}');
        workspace!.markInitialized();
        await db.close();
        final before = file.readAsBytesSync();
        final frozen = AppDatabase.forTesting(
          NativeDatabase.opened(
            raw.sqlite3.open(file.path, mode: raw.OpenMode.readOnly),
            enableMigrations: false,
          ),
        );
        try {
          final captured = await NativeFixtureSnapshot.capture(
            frozen,
            workspace!,
          );
          expect(captured.schemaVersion, entry.key);
          expect(captured.domain.length, entry.value);
          expect(captured.rowCount, 14);
          expect(captured.referencesValid, isTrue);
        } finally {
          await frozen.close();
        }
        workspace!.close();
        workspace = openExistingNativeFixture(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        );
        expect(file.readAsBytesSync(), before);
      },
    );
  }

  for (final history in [
    'company_job_peer_acks',
    'company_job_details',
    'company_job_detail_peer_acks',
    'company_jobs',
    'company_membership_certificates',
    'company_join_requests',
    'company_join_events',
    'company_bootstrap_witnesses',
    'company_authority_facts',
    'job_line_baselines',
    'job_line_operations',
    'job_line_receipts',
    'job_line_audits',
    'job_line_outgoing',
    'job_line_conflicts',
  ]) {
    test('legacy capture and preflight refuse nonempty $history without writes', () async {
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      final file = File(p.join(workspace!.support.path, 'wired_parts.sqlite'));
      final db = AppDatabase.forTesting(NativeDatabase(file));
      await seedSchema10NativeFixture(db, workspace!);
      final columns =
          (await db.customSelect('PRAGMA table_info("$history")').get())
              .map((row) => row.read<String>('name'))
              .toList();
      await db.customStatement(
        'INSERT INTO "$history" (${columns.map((name) => '"$name"').join(',')}) '
        'VALUES (${columns.map((_) => '?').join(',')})',
        [
          for (final name in columns)
            name == 'admitted' || name == 'outgoing'
                ? 0
                : name == 'sequence'
                ? 1
                : 'synthetic-history',
        ],
      );
      await expectLater(
        NativeFixtureSnapshot.capture(db, workspace!),
        throwsA(isA<NativeTestFailure>()),
      );
      await expectLater(
        validationReceipt(db, workspace!),
        throwsA(isA<BackupFormatException>()),
      );
      expect(
        (await db
                .customSelect('SELECT count(*) AS n FROM "$history"')
                .getSingle())
            .read<int>('n'),
        1,
      );
      workspace!.markInitialized();
      await db.close();
      final before = file.readAsBytesSync();
      workspace!.close();
      expect(
        () => openExistingNativeFixture(
          run: 'unit',
          role: ValidationRole.sender,
          temporaryDirectory: temp,
        ),
        throwsA(isA<NativeTestFailure>()),
      );
      expect(file.readAsBytesSync(), before);
    });
  }

  for (final mutation in [
    'missing-company-jobs',
    'missing-company-join',
    'nonempty-company-name-table',
    'unknown-schema11',
    'extra-details-column',
    'missing-details-column',
  ]) {
    test('capture rejects $mutation without altering the source', () async {
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      final db = AppDatabase.forTesting(NativeDatabase.memory());
      addTearDown(db.close);
      await seedSchema10NativeFixture(db, workspace!);
      if (mutation == 'missing-company-jobs') {
        await db.customStatement('DROP TABLE company_jobs');
      } else if (mutation == 'missing-company-join') {
        await db.customStatement('DROP TABLE company_join_requests');
      } else if (mutation == 'nonempty-company-name-table') {
        await db.customStatement(
          "INSERT INTO company_job_names (company_id, shop_id, job_id, origin_generation, request_id, operation_commitment, command_commitment, operation_bytes, receipt_key, receipt_bytes, audit_bytes, outgoing) VALUES ('c', 's', 'j', 'g', 'r', 'o', 'c', 'op', 'k', 'receipt', 'audit', 0)",
        );
      } else if (mutation == 'extra-details-column') {
        await db.customStatement(
          'ALTER TABLE company_job_details ADD COLUMN untrusted TEXT',
        );
      } else if (mutation == 'missing-details-column') {
        await db.customStatement(
          'ALTER TABLE company_job_detail_peer_acks DROP COLUMN ack_bytes',
        );
      } else {
        await db.customStatement('PRAGMA user_version = 11');
      }
      final version = (await db.customSelect('PRAGMA user_version').getSingle())
          .read<int>('user_version');
      final names = await db
          .customSelect(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
          )
          .get();
      await expectLater(
        NativeFixtureSnapshot.capture(db, workspace!),
        throwsA(isA<NativeTestFailure>()),
      );
      expect(
        (await db.customSelect('PRAGMA user_version').getSingle()).read<int>(
          'user_version',
        ),
        version,
      );
      expect(
        (await db
                .customSelect(
                  "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
                )
                .get())
            .map((r) => r.data),
        names.map((r) => r.data),
      );
    });
  }
  test(
    'public settings digest excludes PIN while private comparisons retain it',
    () async {
      workspace = ValidationWorkspace.open(
        run: 'unit',
        role: ValidationRole.sender,
        temporaryDirectory: temp,
      );
      final db = AppDatabase.forTesting(NativeDatabase.memory());
      addTearDown(db.close);
      await seedSchema10NativeFixture(db, workspace!);
      final baseline = await NativeFixtureSnapshot.capture(db, workspace!);
      await db.settingsDao.setSetting(
        'editor_pin_hash',
        'synthetic-verifier-canary',
      );
      final changed = await NativeFixtureSnapshot.capture(db, workspace!);
      expect(changed.sharedSettingsDigest, baseline.sharedSettingsDigest);
      expect(
        changed.privateSharedSettingsDigest,
        isNot(baseline.privateSharedSettingsDigest),
      );
      expect(changed.privatePinDigest, isNot(baseline.privatePinDigest));
      expect(
        changed.completeSettingsDigest,
        isNot(baseline.completeSettingsDigest),
      );
    },
  );
}

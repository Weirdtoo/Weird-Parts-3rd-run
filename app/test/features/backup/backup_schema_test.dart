import 'dart:io';
import 'dart:typed_data';

import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:sqlite3/sqlite3.dart' as sqlite3;
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/data/sqlite_file.dart';
import 'package:wired_parts/features/backup/backup_codec.dart';
import 'package:wired_parts/features/backup/backup_store.dart';
import 'package:wired_parts/features/reset/local_data_reset.dart';

import '../../../tool/backup_recovery_scenario.dart';
import '../../../tool/nearby_lan_validation.dart';
import 'backup_test_support.dart';

void main() {
  for (final table in [
    'company_membership_certificates',
    'company_join_requests',
    'company_join_events',
    'company_job_peer_acks',
    'company_job_names',
    'company_job_name_peer_acks',
    'company_job_details',
    'company_job_detail_peer_acks',
    'company_job_lifecycles',
    'company_job_lifecycle_peer_acks',
    'company_user_events',
    'company_user_deliveries',
    'company_user_credential_grants',
  ]) {
    for (final malformed in ['missing', 'wrong columns']) {
      test(
        'current schema $malformed $table refuses backup before file mutation',
        () async {
          final dir = Directory.systemTemp.createTempSync('join-schema-file-');
          addTearDown(() => dir.deleteSync(recursive: true));
          final file = File(p.join(dir.path, kSqliteFileName));
          final db = AppDatabase.forTesting(NativeDatabase(file));
          await db.customSelect('SELECT 1').get();
          await db.close();
          final raw = sqlite3.sqlite3.open(file.path);
          raw.execute('DROP TABLE "$table"');
          if (malformed == 'wrong columns') {
            raw.execute('CREATE TABLE "$table" (wrong TEXT)');
          }
          raw.dispose();
          final before = file.readAsBytesSync();
          expect(
            () => requireLegacyBusinessFile(file),
            throwsA(isA<BackupFormatException>()),
          );
          expect(file.readAsBytesSync(), before);
        },
      );
    }
  }

  for (final malformed in ['missing', 'wrong columns', 'extra column']) {
    test(
      'schema14 $malformed credential grant table refuses restore before live mutation',
      () async {
        final temp = Directory.systemTemp.createTempSync(
          'grant-schema-restore-',
        );
        addTearDown(() => temp.deleteSync(recursive: true));
        final source = File(p.join(temp.path, 'source.sqlite'));
        final db = AppDatabase.forTesting(NativeDatabase(source));
        await db.customSelect('SELECT 1').get();
        await db.close();
        final original = source.readAsBytesSync();
        final raw = sqlite3.sqlite3.open(source.path);
        try {
          expect(raw.select('PRAGMA user_version').single.values.single, 14);
          if (malformed == 'extra column') {
            raw.execute(
              'ALTER TABLE company_user_credential_grants ADD COLUMN unexpected TEXT',
            );
          } else {
            raw.execute('DROP TABLE company_user_credential_grants');
            if (malformed == 'wrong columns') {
              raw.execute(
                'CREATE TABLE company_user_credential_grants (wrong TEXT)',
              );
            }
          }
        } finally {
          raw.dispose();
        }
        final malformedBytes = source.readAsBytesSync();
        final live = Directory(p.join(temp.path, 'live'))..createSync();
        final file = File(p.join(live.path, kSqliteFileName))
          ..writeAsBytesSync(original);
        final photos = Directory(p.join(live.path, 'part_photos'))
          ..createSync();
        final photo = File(p.join(photos.path, 'preserve.png'))
          ..writeAsBytesSync([7, 8, 9]);
        final marker = File(p.join(live.path, kRestoreSwapMarkerName))
          ..writeAsStringSync('leave this marker alone');
        await expectLater(
          BackupStore(
            supportDir: live,
            afterParkLive: () async => fail('Must not begin swap'),
          ).replaceWithPayload(
            payload: BackupPayload(
              createdAt: DateTime.utc(2026, 11, 4),
              sourceDeviceId: 'synthetic',
              sqliteBytes: malformedBytes,
              photos: const {},
            ),
            reset: LocalDataReset(supportDir: live, documentsDir: live),
          ),
          throwsA(
            isA<BackupFormatException>().having(
              (error) => error.message,
              'message',
              'Unsupported or incomplete company enrollment schema',
            ),
          ),
        );
        expect(source.readAsBytesSync(), malformedBytes);
        expect(file.readAsBytesSync(), original);
        expect(photo.readAsBytesSync(), [7, 8, 9]);
        expect(marker.readAsStringSync(), 'leave this marker alone');
        expect(
          Directory(p.join(live.path, kRestoreStagingName)).existsSync(),
          isFalse,
        );
      },
    );
  }

  test(
    'schema6 missing company Job journal refuses legacy file handling',
    () async {
      final dir = Directory.systemTemp.createTempSync('missing-company-jobs-');
      addTearDown(() => dir.deleteSync(recursive: true));
      final file = File(p.join(dir.path, kSqliteFileName));
      final db = AppDatabase.forTesting(NativeDatabase(file));
      await db.customSelect('SELECT 1 FROM company_jobs LIMIT 1').get();
      await db.close();
      final raw = sqlite3.sqlite3.open(file.path);
      raw.execute('DROP TABLE company_jobs');
      for (final table in [
        'company_membership_certificates',
        'company_join_requests',
        'company_join_events',
        'company_job_peer_acks',
        'company_job_names',
        'company_job_name_peer_acks',
        'company_job_details',
        'company_job_detail_peer_acks',
      ]) {
        raw.execute('DROP TABLE $table');
      }
      raw.dispose();
      expect(
        () => requireLegacyBusinessFile(file),
        throwsA(isA<BackupFormatException>()),
      );
    },
  );

  test('schema-4 empty-history backup remains admissible; schema-5 witness is required', () async {
    final dir = Directory.systemTemp.createTempSync('company-schema-gate-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final file = File(p.join(dir.path, kSqliteFileName));
    final db = AppDatabase.forTesting(NativeDatabase(file));
    await db
        .customSelect('SELECT 1 FROM company_bootstrap_witnesses LIMIT 1')
        .get();
    await db.close();

    requireLegacyBusinessFile(file);
    final old = sqlite3.sqlite3.open(file.path);
    old.execute('DROP TABLE company_bootstrap_witnesses');
    old.execute('DROP TABLE company_jobs');
    for (final table in [
      'company_membership_certificates',
      'company_join_requests',
      'company_join_events',
      'company_job_peer_acks',
      'company_job_names',
      'company_job_name_peer_acks',
      'company_job_details',
      'company_job_detail_peer_acks',
    ]) {
      old.execute('DROP TABLE $table');
    }
    old.execute('PRAGMA user_version = 4');
    old.dispose();
    requireLegacyBusinessFile(file);

    final malformed = sqlite3.sqlite3.open(file.path);
    malformed.execute('PRAGMA user_version = 5');
    malformed.dispose();
    expect(
      () => requireLegacyBusinessFile(file),
      throwsA(isA<BackupFormatException>()),
    );
  });

  test('unknown SQLite schemas reject before live recovery, directory creation or file changes', () async {
    final temp = Directory.systemTemp.createTempSync('backup-schema-reject-');
    addTearDown(() => temp.deleteSync(recursive: true));
    final sqlite = await sqliteBytesWithSetting(
      key: 'marker',
      value: 'preserve',
    );
    final live = Directory(p.join(temp.path, 'live'))..createSync();
    final file = File(p.join(live.path, kSqliteFileName))
      ..writeAsBytesSync(sqlite);
    final photos = Directory(p.join(live.path, 'part_photos'))..createSync();
    final photo = File(p.join(photos.path, 'preserve.png'))
      ..writeAsBytesSync([7, 8, 9]);
    final marker = File(p.join(live.path, kRestoreSwapMarkerName))
      ..writeAsStringSync('leave this marker alone');
    for (final version in [0, kAppSchemaVersion + 1]) {
      final unsupported = Uint8List.fromList(sqlite);
      ByteData.sublistView(unsupported).setUint32(60, version, Endian.big);
      final payload = BackupPayload(
        createdAt: DateTime.utc(2026, 10, 7),
        sourceDeviceId: 'synthetic',
        sqliteBytes: unsupported,
        photos: const {},
      );
      for (final destination in [
        live,
        Directory(p.join(temp.path, 'absent')),
      ]) {
        await expectLater(
          BackupStore(
            supportDir: destination,
            afterParkLive: () async => fail('Must not begin swap'),
          ).replaceWithPayload(
            payload: payload,
            reset: LocalDataReset(
              supportDir: destination,
              documentsDir: destination,
            ),
          ),
          throwsA(
            isA<BackupFormatException>().having(
              (e) => e.message,
              'message',
              'Unsupported backup database schema: $version',
            ),
          ),
        );
      }
      expect(file.readAsBytesSync(), sqlite);
      expect(photo.readAsBytesSync(), [7, 8, 9]);
      expect(marker.readAsStringSync(), 'leave this marker alone');
      expect(Directory(p.join(temp.path, 'absent')).existsSync(), isFalse);
      expect(
        Directory(p.join(live.path, kRestoreStagingName)).existsSync(),
        isFalse,
      );
    }
  });

  test('schema 1 migrates only in staging and preserves all fixture IDs and relationships', () async {
    final temp = Directory.systemTemp.createTempSync('backup-schema-one-');
    final scenario = RecoveryScenario.open(
      run: 'schema-one',
      action: RecoveryAction.exercise,
      temporaryDirectory: temp,
    );
    addTearDown(() {
      scenario.close();
      temp.deleteSync(recursive: true);
    });
    await scenario.seed();
    final source = scenario.openDatabase(scenario.source);
    await source.customStatement(
      "UPDATE brand_versions SET variance_name = '', is_main = 0",
    );
    final expected = await validationReceipt(source, scenario.source);
    await source.customStatement(
      'ALTER TABLE brand_versions DROP COLUMN variance_name',
    );
    await source.customStatement(
      'ALTER TABLE brand_versions DROP COLUMN is_main',
    );
    await source.customStatement('DROP TABLE company_jobs');
    for (final table in [
      'company_membership_certificates',
      'company_join_requests',
      'company_join_events',
      'company_job_peer_acks',
      'company_job_names',
      'company_job_name_peer_acks',
      'company_job_details',
      'company_job_detail_peer_acks',
    ]) {
      await source.customStatement('DROP TABLE $table');
    }
    await source.customStatement('DROP TABLE company_user_events');
    await source.customStatement('DROP TABLE company_user_deliveries');
    await source.customStatement('DROP TABLE company_user_credential_grants');
    await source.customStatement('PRAGMA user_version = 1');
    await source.close();
    final original = File(p.join(scenario.source.support.path, kSqliteFileName))
        .readAsBytesSync();
    expect(backupSqliteSchemaVersion(original), 1);
    final payload =
        await BackupStore(
          supportDir: scenario.source.support,
          photosDir: scenario.source.photos,
        ).collect(
          sourceDeviceId: scenario.source.deviceId,
          createdAt: DateTime.utc(2026, 10, 7),
          sqliteBytes: original,
        );
    await BackupStore(
      supportDir: scenario.receiver.support,
      photosDir: scenario.receiver.photos,
    ).replaceWithPayload(
      payload: payload,
      reset: LocalDataReset(
        supportDir: scenario.receiver.support,
        documentsDir: scenario.receiver.documents,
        photosDir: scenario.receiver.photos,
      ),
    );
    expect(
      File(p.join(scenario.source.support.path, kSqliteFileName))
          .readAsBytesSync(),
      original,
    );
    final restored = scenario.openDatabase(scenario.receiver);
    try {
      final actual = await validationReceipt(restored, scenario.receiver);
      expect(actual['content'], expected['content']);
      expect(actual['photos'], expected['photos']);
      final version = await restored
          .customSelect('PRAGMA user_version')
          .getSingle();
      expect(version.data.values.single, kAppSchemaVersion);
    } finally {
      await restored.close();
    }
  });
}

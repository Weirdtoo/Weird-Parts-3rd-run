import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/widgets.dart';
import 'package:wired_parts/app.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/backup/backup_codec.dart';
import 'package:wired_parts/features/pin/pin_service.dart';
import 'package:wired_parts/features/reset/local_data_reset.dart';
import 'package:wired_parts/features/warehouse/warehouse_repository.dart';

import '../../tool/backup_recovery_scenario.dart';

void expectWarehouseRecords(
  Map records, {
  required String prefix,
  required String deviceId,
  required double firstQuantity,
}) {
  final locations = records['warehouse_locations'] as List;
  final counts = records['warehouse_counts'] as List;
  expect(locations, hasLength(1), reason: 'Recovery must contain a warehouse');
  expect(
    locations.single,
    allOf(
      containsPair('id', '$prefix-warehouse'),
      containsPair('name', '$prefix warehouse'),
      containsPair('origin_device_id', deviceId),
      containsPair('revision', 1),
      containsPair('deleted_at', null),
    ),
  );
  expect(counts, hasLength(2), reason: 'Recovery must retain count history');
  final first = counts.singleWhere((row) => row['ordinal'] == 1) as Map;
  final latest = counts.singleWhere((row) => row['ordinal'] == 2) as Map;
  for (final row in [first, latest]) {
    expect(
      row,
      allOf(
        containsPair('location_id', '$prefix-warehouse'),
        containsPair('part_id', '$prefix-part'),
        containsPair('uom', 'box'),
        containsPair('origin_device_id', deviceId),
        containsPair('recorded_at', isA<int>()),
      ),
    );
  }
  expect(
    first,
    allOf(
      containsPair('id', '$prefix-count-first'),
      containsPair('prior_count_id', null),
      containsPair('quantity', firstQuantity),
      containsPair('note', '$prefix opening count'),
      containsPair(
        'observed_at',
        DateTime.utc(2026, 10, 7, 8).millisecondsSinceEpoch ~/ 1000,
      ),
    ),
  );
  expect(
    latest,
    allOf(
      containsPair('id', '$prefix-count-zero'),
      containsPair('prior_count_id', '$prefix-count-first'),
      containsPair('quantity', 0),
      containsPair('note', '$prefix counted empty\nVerified shelf'),
      containsPair(
        'observed_at',
        DateTime.utc(2026, 10, 7, 8, 15).millisecondsSinceEpoch ~/ 1000,
      ),
    ),
  );
}

Future<void> expectRestoredWarehouse(
  AppDatabase db, {
  required String prefix,
  required String localDeviceId,
}) async {
  final warehouse = WarehouseRepository(
    db,
    PinService(db.settingsDao),
    localDeviceId,
  );
  final stock = (await warehouse.loadLatestCounts('$prefix-warehouse')).single;
  expect(stock.part.id, '$prefix-part');
  expect(stock.count.id, '$prefix-count-zero');
  expect(stock.count.quantity, 0);
  expect(stock.count.uom, 'box');
  expect(stock.count.ordinal, 2);
  expect(stock.needsRecount, isFalse);
  final history = await warehouse.loadCountHistory(
    '$prefix-warehouse',
    '$prefix-part',
  );
  expect(history.map((row) => row.id), [
    '$prefix-count-zero',
    '$prefix-count-first',
  ]);
  expect(history.map((row) => row.quantity), [0, 12.5]);
}

void main() {
  test('restart refuses missing evidence without creating a shop', () {
    final temp = Directory.systemTemp.createTempSync('recovery-missing-');
    addTearDown(() => temp.deleteSync(recursive: true));
    expect(
      () => RecoveryScenario.open(
        run: 'missing',
        action: RecoveryAction.restart,
        temporaryDirectory: temp,
      ),
      throwsStateError,
    );
    expect(temp.listSync(), isEmpty);
  });

  test('an initialized shop without a manifest cannot restart or reseed', () {
    final temp = Directory.systemTemp.createTempSync('recovery-interrupted-');
    addTearDown(() => temp.deleteSync(recursive: true));
    final scenario = RecoveryScenario.open(
      run: 'interrupted',
      action: RecoveryAction.exercise,
      temporaryDirectory: temp,
    );
    scenario.source.markInitialized();
    scenario.receiver.markInitialized();
    scenario.close();
    expect(
      () => RecoveryScenario.open(
        run: 'interrupted',
        action: RecoveryAction.restart,
        temporaryDirectory: temp,
      ),
      throwsA(
        isA<StateError>().having(
          (e) => e.message,
          'message',
          'Restart requires recovery evidence',
        ),
      ),
    );
    expect(
      () => RecoveryScenario.open(
        run: 'interrupted',
        action: RecoveryAction.exercise,
        temporaryDirectory: temp,
      ),
      throwsStateError,
    );
  });

  testWidgets(
    'production callback rejects damaged archives and restores every domain relationship across reopen',
    (tester) async {
      final temp = Directory.systemTemp.createTempSync('recovery-behavior-');
      final scenario = RecoveryScenario.open(
        run: 'behavior',
        action: RecoveryAction.exercise,
        temporaryDirectory: temp,
        codec: BackupCodec(iterations: 1000),
      );
      addTearDown(() {
        scenario.close();
        temp.deleteSync(recursive: true);
      });
      late Map<String, Object?> source;
      await tester.runAsync(() async {
        await scenario.seed();
        source = await scenario.export();
      });
      final registry = source['records'] as Map;
      expect(registry.keys.toSet(), {
        'categories',
        'styles',
        'types',
        'devices',
        'brands',
        'suppliers',
        'parts',
        'warehouse_locations',
        'warehouse_counts',
        'part_devices',
        'brand_versions',
        'supplier_listings',
        'jobs',
        'job_lines',
        'order_splits',
        'company_jobs',
        'company_job_peer_acks',
        'company_job_names',
        'company_job_name_peer_acks',
        'company_job_lifecycles',
        'company_job_lifecycle_peer_acks',
        'company_job_details',
        'company_job_detail_peer_acks',
        'company_membership_certificates',
        'company_join_requests',
        'company_join_events',
        'company_bootstrap_witnesses',
        'company_authority_facts',
        'company_user_events',
        'company_user_deliveries',
        'company_user_credential_grants',
        'job_line_baselines',
        'job_line_operations',
        'job_line_receipts',
        'job_line_audits',
        'job_line_outgoing',
        'job_line_conflicts',
      });
      for (final table in [
        'company_jobs',
        'company_job_peer_acks',
        'company_job_names',
        'company_job_name_peer_acks',
        'company_job_lifecycles',
        'company_job_lifecycle_peer_acks',
        'company_job_details',
        'company_job_detail_peer_acks',
        'company_membership_certificates',
        'company_join_requests',
        'company_join_events',
        'company_bootstrap_witnesses',
        'company_authority_facts',
        'company_user_events',
        'company_user_deliveries',
        'company_user_credential_grants',
        'job_line_baselines',
        'job_line_operations',
        'job_line_receipts',
        'job_line_audits',
        'job_line_outgoing',
        'job_line_conflicts',
      ]) {
        expect(registry[table], isEmpty);
      }
      final prefix = '${scenario.source.run}-sender';
      expectWarehouseRecords(
        registry,
        prefix: prefix,
        deviceId: scenario.source.deviceId,
        firstQuantity: 12.5,
      );
      expect(
        (registry['parts'] as List).single,
        containsPair('id', '$prefix-part'),
      );
      expect(
        (registry['job_lines'] as List).single,
        allOf(
          containsPair('job_id', '$prefix-job'),
          containsPair('part_id', '$prefix-part'),
          containsPair('brand_version_id', '$prefix-brand-version'),
        ),
      );
      expect(
        (registry['order_splits'] as List).single,
        allOf(
          containsPair('job_line_id', '$prefix-line'),
          containsPair('supplier_id', '$prefix-supplier'),
        ),
      );
      expect(
        (registry['jobs'] as List).singleWhere(
          (row) => row['deleted_at'] != null,
        ),
        allOf(
          containsPair('id', '$prefix-deleted-job'),
          containsPair('revision', 7),
          containsPair('origin_device_id', scenario.source.deviceId),
        ),
      );
      final db = scenario.openDatabase(scenario.receiver);
      var liveDatabase = db;
      addTearDown(() => liveDatabase.close());
      await tester.runAsync(
        () => db.customStatement(
          'UPDATE device_profiles SET display_name = ?, created_at = ?',
          ['  Synthetic receiver name  ', 1700000123],
        ),
      );
      final receiverProfileBefore = await tester.runAsync(
        () =>
            db.customSelect('SELECT * FROM device_profiles ORDER BY id').get(),
      );
      final receiverPrefix = '${scenario.receiver.run}-receiver';
      final receiverBefore = await tester.runAsync(
        () => scenario.receipt(db, scenario.receiver),
      );
      expectWarehouseRecords(
        receiverBefore!['records'] as Map,
        prefix: receiverPrefix,
        deviceId: scenario.receiver.deviceId,
        firstQuantity: 4.25,
      );
      expect(
        (receiverBefore['records'] as Map)['warehouse_counts'],
        isNot(registry['warehouse_counts']),
      );
      expect(receiverProfileBefore!.single.data, {
        'id': scenario.receiver.deviceId,
        'display_name': '  Synthetic receiver name  ',
        'created_at': 1700000123,
      });
      var reopens = 0;
      await tester.pumpWidget(
        WiredPartsApp(
          db: db,
          pin: PinService(db.settingsDao),
          deviceId: scenario.receiver.deviceId,
          reset: LocalDataReset(
            supportDir: scenario.receiver.support,
            documentsDir: scenario.receiver.documents,
            photosDir: scenario.receiver.photos,
          ),
          reopenDatabase: () {
            reopens++;
            liveDatabase = scenario.openDatabase(scenario.receiver);
            return liveDatabase;
          },
        ),
      );
      await tester.pump();
      AppScope scope() => tester.widget<AppScope>(find.byType(AppScope));
      await tester.runAsync(
        () => scenario.exercise(
          scope: scope,
          settle: () => tester.pump(),
          sourceReceipt: source,
        ),
      );
      await tester.pump();
      expect(tester.takeException(), isNull);
      expect(scenario.readManifest()['state'], 'restored');
      expect(reopens, 1);
      final reports = scenario.receiver.receipts
          .listSync()
          .whereType<File>()
          .map((file) => jsonDecode(file.readAsStringSync()) as Map)
          .toList();
      expect(reports.map((row) => row['step']).toSet(), {
        'wrongPassword',
        'damagedArchive',
        'unsupportedSchema',
        'restore',
      });
      expect(reports.every((row) => row['validation'] == 'pass'), isTrue);
      for (final row in reports.where((row) => row['step'] != 'restore')) {
        expect(row['after']['deviceProfiles'], row['before']['deviceProfiles']);
        expect(row['after']['sqliteSha256'], row['before']['sqliteSha256']);
        expectWarehouseRecords(
          row['after']['records'] as Map,
          prefix: receiverPrefix,
          deviceId: scenario.receiver.deviceId,
          firstQuantity: 4.25,
        );
        for (final table in ['warehouse_locations', 'warehouse_counts']) {
          expect(
            row['after']['records'][table],
            row['before']['records'][table],
          );
        }
      }
      final restoreReport = reports.singleWhere(
        (row) => row['step'] == 'restore',
      );
      expectWarehouseRecords(
        restoreReport['after']['records'] as Map,
        prefix: prefix,
        deviceId: scenario.source.deviceId,
        firstQuantity: 12.5,
      );
      for (final table in ['warehouse_locations', 'warehouse_counts']) {
        expect(restoreReport['after']['records'][table], registry[table]);
      }
      await tester.runAsync(
        () => expectRestoredWarehouse(
          scope().db,
          prefix: prefix,
          localDeviceId: scenario.receiver.deviceId,
        ),
      );
      expect(restoreReport['after']['deviceProfiles'], [
        receiverProfileBefore.single.data,
      ]);
      expect(
        restoreReport['after']['deviceProfiles'],
        restoreReport['before']['deviceProfiles'],
      );
      expect(
        {for (final row in reports) row['step']: row['actualOutcome']},
        {
          'wrongPassword': 'rejected',
          'damagedArchive': 'rejected',
          'unsupportedSchema': 'rejected',
          'restore': 'restored',
        },
      );
      for (final file
          in scenario.receiver.receipts.listSync().whereType<File>()) {
        expect(file.readAsStringSync(), isNot(contains('editor_pin_hash')));
      }
      final live = scope().db;
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.runAsync(live.close);
      final reopened = scenario.openDatabase(scenario.receiver);
      liveDatabase = reopened;
      try {
        await tester.runAsync(() => scenario.restart(reopened));
        final reopenedReceipt = await tester.runAsync(
          () => scenario.receipt(reopened, scenario.receiver),
        );
        expectWarehouseRecords(
          reopenedReceipt!['records'] as Map,
          prefix: prefix,
          deviceId: scenario.source.deviceId,
          firstQuantity: 12.5,
        );
        for (final table in ['warehouse_locations', 'warehouse_counts']) {
          expect((reopenedReceipt['records'] as Map)[table], registry[table]);
        }
        await tester.runAsync(
          () => expectRestoredWarehouse(
            reopened,
            prefix: prefix,
            localDeviceId: scenario.receiver.deviceId,
          ),
        );
        final profileAfterRestart = await tester.runAsync(
          () => reopened
              .customSelect('SELECT * FROM device_profiles ORDER BY id')
              .get(),
        );
        expect(
          profileAfterRestart!.single.data,
          receiverProfileBefore.single.data,
        );
        await tester.runAsync(
          () => reopened.customStatement(
            'UPDATE device_profiles SET created_at = 1700000999',
          ),
        );
        await tester.runAsync(
          () => expectLater(scenario.restart(reopened), throwsStateError),
        );
        await tester.runAsync(
          () => reopened.customStatement(
            'UPDATE device_profiles SET created_at = 1700000123',
          ),
        );
        await tester.runAsync(
          () =>
              reopened.customStatement('UPDATE order_splits SET quantity = 99'),
        );
        await tester.runAsync(
          () => expectLater(scenario.restart(reopened), throwsStateError),
        );
      } finally {
        await tester.runAsync(reopened.close);
      }
      scenario.close();
      expect(
        () => RecoveryScenario.open(
          run: 'behavior',
          action: RecoveryAction.exercise,
          temporaryDirectory: temp,
        ),
        throwsStateError,
      );
      final archive = scenario.archive;
      final original = archive.readAsBytesSync();
      archive.writeAsBytesSync([1, 2, 3]);
      expect(scenario.readManifest, throwsStateError);
      archive.writeAsBytesSync(original);
    },
  );
}

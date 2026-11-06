import 'package:flutter_test/flutter_test.dart';
import 'package:wired_parts/data/app_database.dart';

import '../../tool/nearby_lan_validation.dart';
import '../../tool/nearby_lan_workspace.dart';

// Project only a newly seeded synthetic fixture for the strict legacy readers.
Future<void> seedSchema10NativeFixture(
  AppDatabase db,
  ValidationWorkspace workspace,
) async {
  await seedValidationShop(db, workspace);
  await projectSeededSchema10NativeFixture(db);
}

Future<void> projectSeededSchema10NativeFixture(AppDatabase db) async {
  await db.transaction(() async {
    expect(
      (await db.customSelect('PRAGMA user_version').getSingle())
          .data
          .values
          .single,
      kAppSchemaVersion,
    );
    expect(
      await db
          .customSelect("SELECT name FROM sqlite_master WHERE type = 'table'")
          .get(),
      hasLength(39),
    );
    for (final table in db.allTables.where(
      (table) =>
          table.actualTableName.startsWith('company_') ||
          table.actualTableName.startsWith('job_line_') ||
          table.actualTableName.startsWith('warehouse_'),
    )) {
      expect(
        await db
            .customSelect('SELECT 1 FROM "${table.actualTableName}" LIMIT 1')
            .get(),
        isEmpty,
      );
    }
    await db.customStatement('DROP TABLE company_job_lifecycle_peer_acks');
    await db.customStatement('DROP TABLE company_job_lifecycles');
    await db.customStatement('DROP TABLE warehouse_counts');
    await db.customStatement('DROP TABLE warehouse_locations');
    await db.customStatement('DROP TABLE company_user_events');
    await db.customStatement('DROP TABLE company_user_deliveries');
    await db.customStatement('DROP TABLE company_user_credential_grants');
    await db.customStatement('PRAGMA user_version = 10');
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
  });
}

import 'package:flutter_test/flutter_test.dart';
import 'package:sqlite3/sqlite3.dart' as sqlite;
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';

import 'company_job_name_test.dart' show NameFixture;

void main() {
  test('schema10 to11 adds lifecycle tables and preserves immutable signed creation and metadata', () async {
    final f = await NameFixture.create();
    try {
      await f.commands.renameJob(
        f.rename('Retained legacy name'),
        ownerSession: f.owner,
      );
      final creation = await f.db.select(f.db.companyJobs).get(),
          names = await f.db.select(f.db.companyJobNames).get(),
          jobs = await f.db.select(f.db.jobs).get();
      await f.enrollment.signOut();
      await f.db.close();
      final raw = sqlite.sqlite3.open('${f.root.path}/shop.sqlite');
      raw.execute('DROP TABLE company_job_lifecycles');
      raw.execute('DROP TABLE company_job_lifecycle_peer_acks');
      raw.execute('DROP TABLE warehouse_counts');
      raw.execute('DROP TABLE warehouse_locations');
      raw.execute('DROP TABLE company_user_events');
      raw.execute('DROP TABLE company_user_deliveries');
      raw.execute('DROP TABLE company_user_credential_grants');
      raw.execute('PRAGMA user_version = 10');
      raw.dispose();
      await f.reopen();
      expect(
        (await f.db.customSelect('PRAGMA user_version').getSingle()).read<int>(
          'user_version',
        ),
        kAppSchemaVersion,
      );
      expect(await f.db.select(f.db.companyJobs).get(), creation);
      expect(await f.db.select(f.db.companyJobNames).get(), names);
      expect(await f.db.select(f.db.jobs).get(), jobs);
      final view = (await f.commands.listJobViews(ownerSession: f.owner))
          .single;
      expect(view.displayName, 'Retained legacy name');
      expect(view.lifecycle.state, CompanyJobLifecycleState.live);
      expect(await f.db.select(f.db.companyJobLifecycles).get(), isEmpty);
    } finally {
      await f.close();
    }
  });
}

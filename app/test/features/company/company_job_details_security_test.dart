import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqlite3/sqlite3.dart' as sqlite;
import 'package:uuid/uuid.dart';
import 'package:drift/native.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';

import 'company_job_details_test.dart' show details;
import 'company_job_name_test.dart'
    show NameFixture, nameSnapshot, canonicalNameTest;

void main() {
  test('details refuses wrong scope baseline missing dependencies and field substitution without mutation', () async {
    final f = await NameFixture.create();
    try {
      final customer = await f.commands.patchJobDetails(
        details(f, const JobDetailsPatch(customer: SetField('Acme'))),
        ownerSession: f.owner,
      );
      final before = await nameSnapshot(f);
      final normal = details(f, const JobDetailsPatch(notes: SetField('Text')));
      for (final c in [
        PatchJobDetails(
          companyId: const Uuid().v4(),
          shopId: normal.shopId,
          jobId: normal.jobId,
          requestId: normal.requestId,
          creationDigest: normal.creationDigest,
          patch: normal.patch,
          observedHeads: normal.observedHeads,
        ),
        PatchJobDetails(
          companyId: normal.companyId,
          shopId: const Uuid().v4(),
          jobId: normal.jobId,
          requestId: normal.requestId,
          creationDigest: normal.creationDigest,
          patch: normal.patch,
          observedHeads: normal.observedHeads,
        ),
        PatchJobDetails(
          companyId: normal.companyId,
          shopId: normal.shopId,
          jobId: const Uuid().v4(),
          requestId: normal.requestId,
          creationDigest: normal.creationDigest,
          patch: normal.patch,
          observedHeads: normal.observedHeads,
        ),
        PatchJobDetails(
          companyId: normal.companyId,
          shopId: normal.shopId,
          jobId: normal.jobId,
          requestId: normal.requestId,
          creationDigest: 'f' * 64,
          patch: normal.patch,
          observedHeads: normal.observedHeads,
        ),
        details(
          f,
          const JobDetailsPatch(notes: SetField('Missing')),
          parents: {
            JobDetailField.notes: ['f' * 64],
          },
        ),
        details(
          f,
          const JobDetailsPatch(notes: SetField('Wrong field')),
          parents: {
            JobDetailField.notes: [customer.operationId],
          },
        ),
      ]) {
        await expectLater(
          f.commands.patchJobDetails(c, ownerSession: f.owner),
          throwsA(anything),
        );
        expect(await nameSnapshot(f), before);
      }
    } finally {
      await f.close();
    }
  });
  for (final dependency in [
    'creation seal',
    'creation signature',
    'parent seal',
    'parent signature',
  ]) {
    test(
      'details tampered $dependency refuses before protected intent',
      () async {
        final f = await NameFixture.create();
        try {
          final parent = await f.commands.patchJobDetails(
            details(f, const JobDetailsPatch(notes: SetField('Parent'))),
            ownerSession: f.owner,
          );
          final table = dependency.startsWith('creation')
              ? 'company_jobs'
              : 'company_job_details';
          final column = dependency.endsWith('seal')
              ? 'receipt_bytes'
              : 'operation_bytes';
          final row =
              (await f.db
                      .customSelect('SELECT $column AS bytes FROM $table')
                      .get())
                  .single;
          final value =
              jsonDecode(row.read<String>('bytes')) as Map<String, dynamic>;
          value[dependency.endsWith('seal') ? 'seal' : 'signature'] =
              base64Encode(List.filled(64, 0));
          await f.db.customStatement('UPDATE $table SET $column = ?', [
            canonicalNameTest(value),
          ]);
          final before = await nameSnapshot(f);
          await expectLater(
            f.commands.patchJobDetails(
              details(
                f,
                const JobDetailsPatch(notes: SetField('Child')),
                parents: {
                  JobDetailField.notes: [parent.operationId],
                },
              ),
              ownerSession: f.owner,
            ),
            throwsA(anything),
          );
          expect(await nameSnapshot(f), before);
        } finally {
          await f.close();
        }
      },
    );
  }
  for (final revocation in [
    'permission',
    'credential',
    'grant',
    'revocation.user',
    'revocation.device',
    'revocation.grant',
  ]) {
    test(
      'details stale or revoked $revocation refuses without mutation',
      () async {
        final f = await NameFixture.create();
        try {
          final state = f.store.states[f.security.namespace]!;
          final raw =
              jsonDecode(utf8.decode(state.bytes)) as Map<String, dynamic>;
          final facts = jsonDecode(
            (await f.db.select(f.db.companyAuthorityFacts).get())
                .single
                .signedBytes,
          ) as Map;
          final grant =
              ((facts['body'] as Map)['devices'] as List).single['grant']
                  as String;
          final actor = revocation.endsWith('grant')
              ? grant
              : revocation.endsWith('device')
              ? f.owner.identity.deviceId
              : f.owner.identity.userId;
          (raw['floors'] as Map)['$revocation.$actor'] =
              revocation.startsWith('revocation') ? 1 : 2;
          f.store.states[f.security.namespace] = ProtectedInstallationState(
            const Uuid().v4(),
            Uint8List.fromList(utf8.encode(jsonEncode(raw))),
          );
          final before = await nameSnapshot(f);
          await expectLater(
            f.commands.patchJobDetails(
              details(f, const JobDetailsPatch(notes: SetField('Denied'))),
              ownerSession: f.owner,
            ),
            throwsA(anything),
          );
          expect(await nameSnapshot(f), before);
        } finally {
          await f.close();
        }
      },
    );
  }
  test(
    'details rollback and lost reply reconcile own typed intent on restart',
    () async {
      final f = await NameFixture.create();
      try {
        await expectLater(
          CompanyJobCommands(
            enrollment: f.enrollment,
            beforeCommit: () async => throw StateError('interrupted'),
          ).patchJobDetails(
            details(f, const JobDetailsPatch(notes: SetField('Rollback'))),
            ownerSession: f.owner,
          ),
          throwsA(isA<StateError>()),
        );
        expect(await f.db.select(f.db.companyJobDetails).get(), isEmpty);
        final command = details(
          f,
          const JobDetailsPatch(notes: SetField('Committed')),
        );
        await expectLater(
          CompanyJobCommands(
            enrollment: f.enrollment,
            afterCommit: () async => throw StateError('lost reply'),
          ).patchJobDetails(command, ownerSession: f.owner),
          throwsA(isA<StateError>()),
        );
        final saved = (await f.db.select(f.db.companyJobDetails).get()).single;
        expect(await f.db.select(f.db.companyJobDetailPeerAcks).get(), isEmpty);
        await f.reopen();
        expect(f.security.readiness, InstallationReadiness.ready);
        expect(
          (await f.commands.patchJobDetails(
            command,
            ownerSession: f.owner,
          )).bytes,
          saved.receiptBytes,
        );
        expect(
          (await f.commands.listJobViews(ownerSession: f.owner))
              .single
              .details
              .notes
              .value,
          'Committed',
        );
      } finally {
        await f.close();
      }
    },
  );
  test(
    'schema9 migrates additively with exact creation and name bytes',
    () async {
      final f = await NameFixture.create();
      try {
        await f.commands.renameJob(
          f.rename('Retained name'),
          ownerSession: f.owner,
        );
        final creation = await f.db.select(f.db.companyJobs).get(),
            names = await f.db.select(f.db.companyJobNames).get(),
            jobs = await f.db.select(f.db.jobs).get();
        await f.enrollment.signOut();
        await f.db.close();
        final raw = sqlite.sqlite3.open('${f.root.path}/shop.sqlite');
        raw.execute('DROP TABLE company_job_details');
        raw.execute('DROP TABLE company_job_detail_peer_acks');
        raw.execute('DROP TABLE warehouse_counts');
        raw.execute('DROP TABLE warehouse_locations');
        raw.execute('DROP TABLE company_user_events');
        raw.execute('DROP TABLE company_user_deliveries');
        raw.execute('DROP TABLE company_user_credential_grants');
        raw.execute('PRAGMA user_version = 9');
        raw.dispose();
        f.db = AppDatabase.forTesting(
          NativeDatabase(File('${f.root.path}/shop.sqlite')),
        );
        f.security = InstallationSecurity(
          store: f.store,
          namespace: f.security.namespace,
        );
        await f.security.start(f.db);
        f.enrollment = CompanyEnrollment(db: f.db, installation: f.security);
        f.owner = await f.enrollment.signIn('1234');
        expect(
          (await f.db.customSelect('PRAGMA user_version').getSingle())
              .read<int>('user_version'),
          kAppSchemaVersion,
        );
        expect(await f.db.select(f.db.companyJobs).get(), creation);
        expect(await f.db.select(f.db.companyJobNames).get(), names);
        expect(await f.db.select(f.db.jobs).get(), jobs);
        await f.commands.patchJobDetails(
          details(f, const JobDetailsPatch(notes: SetField('After migration'))),
          ownerSession: f.owner,
        );
        expect(
          (await f.commands.listJobViews(ownerSession: f.owner))
              .single
              .details
              .notes
              .value,
          'After migration',
        );
      } finally {
        await f.close();
      }
    },
  );
  test(
    'details rejects oversize and nonfinite fields at typed boundary',
    () async {
      final f = await NameFixture.create();
      try {
        final before = await nameSnapshot(f);
        expect(
          () => details(f, JobDetailsPatch(notes: SetField('x' * 16385))),
          throwsA(isA<JobLineRefusal>()),
        );
        expect(
          () => details(f, JobDetailsPatch(customer: SetField('x' * 1025))),
          throwsA(isA<JobLineRefusal>()),
        );
        expect(
          () => details(f, const JobDetailsPatch()),
          throwsA(isA<JobLineRefusal>()),
        );
        expect(await nameSnapshot(f), before);
      } finally {
        await f.close();
      }
    },
  );
  test('creation name and details share request safely with separate receipt families', () async {
    final f = await NameFixture.create();
    try {
      final creation = (await f.db.select(f.db.companyJobs).get()).single;
      final request = f.createCommand.requestId;
      await f.commands.renameJob(
        f.rename('Renamed', request: request),
        ownerSession: f.owner,
      );
      final name = (await f.db.select(f.db.companyJobNames).get()).single;
      await f.commands.patchJobDetails(
        details(
          f,
          const JobDetailsPatch(notes: SetField('Details')),
          request: request,
        ),
        ownerSession: f.owner,
      );
      final detail = (await f.db.select(f.db.companyJobDetails).get()).single;
      expect(
        {creation.receiptKey, name.receiptKey, detail.receiptKey}.length,
        3,
      );
      expect(
        (await f.db.select(f.db.companyJobs).get()).single.operationBytes,
        creation.operationBytes,
      );
      expect(
        (await f.db.select(f.db.companyJobNames).get()).single.operationBytes,
        name.operationBytes,
      );
      final view = (await f.commands.listJobViews(ownerSession: f.owner))
          .single;
      expect(view.displayName, 'Renamed');
      expect(view.details.notes.value, 'Details');
    } finally {
      await f.close();
    }
  });
}

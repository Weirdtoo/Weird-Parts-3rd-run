import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hashes;

import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:sqlite3/sqlite3.dart' as sqlite;
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';

import 'company_job_test_support.dart';

void main() {
  test(
    'production name edit keeps immutable creation and exact retry',
    () async {
      final root = Directory.systemTemp.createTempSync('job-name-');
      final db = AppDatabase.forTesting(
        NativeDatabase(File('${root.path}/shop.sqlite')),
      );
      final security = InstallationSecurity(
        store: JobTestStore(),
        namespace: 'synthetic.names',
      );
      try {
        await security.start(db);
        final enrollment = CompanyEnrollment(db: db, installation: security);
        final identity = await enrollment.create(
          companyName: 'Synthetic names',
          policy: CompanyContinuityPolicy.localContinuity,
          pin: '1234',
          recoveryPassphrase: 'synthetic names authority',
          recoveryFile: File('${root.path}/authority.wpca'),
        );
        final owner = await enrollment.signIn('1234');
        final commands = CompanyJobCommands(enrollment: enrollment);
        final create = CreateJob(
          companyId: identity.companyId,
          shopId: identity.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          name: 'Baseline',
        );
        await commands.createJob(create, ownerSession: owner);
        final before = (await db.select(db.companyJobs).get()).single;
        final jobs = await db.select(db.jobs).get();
        final edit = RenameJob(
          companyId: identity.companyId,
          shopId: identity.shopId,
          jobId: create.jobId,
          requestId: create.requestId,
          creationDigest: hashes.sha256
              .convert(utf8.encode(before.operationBytes))
              .toString(),
          observedHeads: [],
          name: 'Edited',
        );
        await commands.renameJob(edit, ownerSession: owner);
        expect(
          (await commands.listJobViews(ownerSession: owner))
              .single
              .resolvedName,
          'Edited',
        );
        await commands.renameJob(edit, ownerSession: owner);
        expect(await db.select(db.companyJobNames).get(), hasLength(1));
        expect(
          (await db.select(db.companyJobNames).get()).single.receiptKey,
          isNot(before.receiptKey),
        );
        expect((await db.select(db.companyJobs).get()).single, before);
        expect(await db.select(db.jobs).get(), jobs);
      } finally {
        await db.close();
        await root.delete(recursive: true);
      }
    },
  );
  test('last agreed name survives concurrent edits and resolution', () async {
    final f = await NameFixture.create();
    try {
      final agreed = await f.commands.renameJob(
        f.rename('Agreed'),
        ownerSession: f.owner,
      );
      final heads = [agreed.operationId];
      await f.commands.renameJob(
        f.rename('A', parents: heads),
        ownerSession: f.owner,
      );
      await f.commands.renameJob(
        f.rename('B', parents: heads),
        ownerSession: f.owner,
      );
      final conflict = (await f.commands.listJobViews(ownerSession: f.owner))
          .single;
      expect(conflict.resolvedName, isNull);
      expect(conflict.lastAgreedName, 'Agreed');
      expect(conflict.candidates.map((c) => c.name).toSet(), {'A', 'B'});
      expect(
        conflict.candidates.every(
          (c) => c.originalUserId == f.owner.identity.userId,
        ),
        isTrue,
      );
      await f.commands.renameJob(
        f.rename('C', parents: conflict.nameHeads),
        ownerSession: f.owner,
      );
      await f.commands.renameJob(
        f.rename('D', parents: conflict.nameHeads),
        ownerSession: f.owner,
      );
      final competingResolutions = (await f.commands.listJobViews(
        ownerSession: f.owner,
      )).single;
      expect(competingResolutions.candidates.map((c) => c.name).toSet(), {
        'C',
        'D',
      });
      expect(competingResolutions.lastAgreedName, 'Agreed');
      final resolution = f.rename(
        'Chosen',
        parents: competingResolutions.nameHeads,
      );
      await f.commands.renameJob(resolution, ownerSession: f.owner);
      final resolved = (await f.commands.listJobViews(ownerSession: f.owner))
          .single;
      expect(resolved.resolvedName, 'Chosen');
      expect(resolved.nameHeads, hasLength(1));
      expect(await f.db.select(f.db.companyJobNames).get(), hasLength(6));
    } finally {
      await f.close();
    }
  });

  test('sequential stale and same-value edits retain history through restart and exact retry', () async {
    final f = await NameFixture.create();
    try {
      final first = await f.commands.renameJob(
        f.rename('One'),
        ownerSession: f.owner,
      );
      final second = await f.commands.renameJob(
        f.rename('Two', parents: [first.operationId]),
        ownerSession: f.owner,
      );
      var view = (await f.commands.listJobViews(ownerSession: f.owner)).single;
      expect(view.resolvedName, 'Two');
      expect(view.nameHeads, [second.operationId]);
      final same = f.rename('Two', parents: [first.operationId]);
      final saved = await f.commands.renameJob(same, ownerSession: f.owner);
      view = (await f.commands.listJobViews(ownerSession: f.owner)).single;
      expect(view.resolvedName, 'Two');
      expect(view.nameHeads, hasLength(2));
      final stale = f.rename('Stale', parents: [first.operationId]);
      await f.commands.renameJob(stale, ownerSession: f.owner);
      view = (await f.commands.listJobViews(ownerSession: f.owner)).single;
      expect(view.candidates.map((c) => c.name).toSet(), {'Two', 'Stale'});
      expect(view.nameHeads, hasLength(3));
      expect(view.lastAgreedName, 'One');
      await f.reopen();
      expect(
        (await f.commands.renameJob(same, ownerSession: f.owner)).bytes,
        saved.bytes,
      );
      expect(
        (await f.commands.listJobViews(ownerSession: f.owner)).single.nameHeads,
        view.nameHeads,
      );
      final before = await nameSnapshot(f);
      await expectLater(
        f.commands.renameJob(
          f.rename(
            'Collision',
            request: same.requestId,
            parents: same.observedHeads,
          ),
          ownerSession: f.owner,
        ),
        throwsA(isA<JobLineRefusal>()),
      );
      expect(await nameSnapshot(f), before);
    } finally {
      await f.close();
    }
  });

  test('wrong company shop Job full baseline and missing parents refuse without durable mutation', () async {
    final f = await NameFixture.create();
    try {
      final before = await nameSnapshot(f);
      for (final parents in [
        List.generate(33, (i) => i.toRadixString(16).padLeft(64, '0')),
        ['f' * 64, 'f' * 64],
      ]) {
        expect(
          () => f.rename('X', parents: parents),
          throwsA(isA<JobLineRefusal>()),
        );
      }
      for (final name in ['  ', 'x' * 101, 'a${'\u0301' * 4096}']) {
        expect(() => f.rename(name), throwsA(isA<JobLineRefusal>()));
      }
      expect(await nameSnapshot(f), before);
      final base = (await f.db.select(f.db.companyJobs).get()).single;
      for (final command in [
        f.rename('X', company: const Uuid().v4()),
        f.rename('X', shop: const Uuid().v4()),
        f.rename('X', job: const Uuid().v4()),
        f.rename('X', baseline: '0' * 64),
        f.rename('X', baseline: base.operationCommitment),
        f.rename('X', parents: ['f' * 64]),
      ]) {
        await expectLater(
          f.commands.renameJob(command, ownerSession: f.owner),
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
      'tampered $dependency refuses child before protected intent',
      () async {
        final f = await NameFixture.create();
        try {
          final parent = await f.commands.renameJob(
            f.rename('Parent'),
            ownerSession: f.owner,
          );
          final table = dependency.startsWith('creation')
              ? 'company_jobs'
              : 'company_job_names';
          final field = dependency.endsWith('seal')
              ? 'receipt_bytes'
              : 'operation_bytes';
          final row =
              (await f.db
                      .customSelect('SELECT $field AS bytes FROM $table')
                      .get())
                  .single;
          final value =
              jsonDecode(row.read<String>('bytes')) as Map<String, dynamic>;
          value[dependency.endsWith('seal') ? 'seal' : 'signature'] =
              base64Encode(List.filled(64, 0));
          await f.db.customStatement('UPDATE $table SET $field = ?', [
            canonicalNameTest(value),
          ]);
          final before = await nameSnapshot(f);
          await expectLater(
            f.commands.renameJob(
              f.rename('Child', parents: [parent.operationId]),
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
      'stale or revoked $revocation refuses name authoring with no mutation',
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
            f.commands.renameJob(f.rename('Denied'), ownerSession: f.owner),
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
    'lost reply and rollback reconcile name-specific intent on restart',
    () async {
      final f = await NameFixture.create();
      try {
        final rollback = f.rename('Rollback');
        await expectLater(
          CompanyJobCommands(
            enrollment: f.enrollment,
            beforeCommit: () async => throw StateError('interrupted'),
          ).renameJob(rollback, ownerSession: f.owner),
          throwsA(isA<StateError>()),
        );
        expect(await f.db.select(f.db.companyJobNames).get(), isEmpty);
        final request = f.rename('Committed');
        await expectLater(
          CompanyJobCommands(
            enrollment: f.enrollment,
            afterCommit: () async => throw StateError('reply lost'),
          ).renameJob(request, ownerSession: f.owner),
          throwsA(isA<StateError>()),
        );
        final saved = (await f.db.select(f.db.companyJobNames).get()).single;
        await f.reopen();
        expect(f.security.readiness, InstallationReadiness.ready);
        expect(
          (await f.commands.renameJob(request, ownerSession: f.owner)).bytes,
          saved.receiptBytes,
        );
        expect(
          (await f.commands.listJobViews(ownerSession: f.owner))
              .single
              .resolvedName,
          'Committed',
        );
      } finally {
        await f.close();
      }
    },
  );

  test(
    'schema8 migrates additively without changing signed creation',
    () async {
      final f = await NameFixture.create();
      try {
        final before = (await f.db.select(f.db.companyJobs).get()).single;
        final jobs = await f.db.select(f.db.jobs).get();
        await f.enrollment.signOut();
        await f.db.close();
        final raw = sqlite.sqlite3.open('${f.root.path}/shop.sqlite');
        raw.execute('DROP TABLE company_job_names');
        raw.execute('DROP TABLE company_job_name_peer_acks');
        raw.execute('DROP TABLE company_job_details');
        raw.execute('DROP TABLE company_job_detail_peer_acks');
        raw.execute('DROP TABLE warehouse_counts');
        raw.execute('DROP TABLE warehouse_locations');
        raw.execute('DROP TABLE company_user_events');
        raw.execute('DROP TABLE company_user_deliveries');
        raw.execute('DROP TABLE company_user_credential_grants');
        raw.execute('PRAGMA user_version = 8');
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
        expect((await f.db.select(f.db.companyJobs).get()).single, before);
        expect(await f.db.select(f.db.jobs).get(), jobs);
        await f.commands.renameJob(
          f.rename('After migration'),
          ownerSession: f.owner,
        );
        expect(
          (await f.commands.listJobViews(ownerSession: f.owner))
              .single
              .resolvedName,
          'After migration',
        );
      } finally {
        await f.close();
      }
    },
  );
}

class NameFixture {
  NameFixture(
    this.root,
    this.db,
    this.store,
    this.security,
    this.enrollment,
    this.owner,
    this.createCommand,
    this.creationDigest,
  );
  final Directory root;
  AppDatabase db;
  final JobTestStore store;
  InstallationSecurity security;
  CompanyEnrollment enrollment;
  OwnerSession owner;
  final CreateJob createCommand;
  final String creationDigest;
  CompanyJobCommands get commands => CompanyJobCommands(enrollment: enrollment);
  RenameJob rename(
    String name, {
    List<String> parents = const [],
    String? request,
    String? baseline,
    String? job,
    String? company,
    String? shop,
  }) => RenameJob(
    companyId: company ?? owner.identity.companyId,
    shopId: shop ?? owner.identity.shopId,
    jobId: job ?? createCommand.jobId,
    requestId: request ?? const Uuid().v4(),
    creationDigest: baseline ?? creationDigest,
    observedHeads: parents,
    name: name,
  );
  static Future<NameFixture> create({String? jobId}) async {
    final root = Directory.systemTemp.createTempSync('job-names-');
    final db = AppDatabase.forTesting(
      NativeDatabase(File('${root.path}/shop.sqlite')),
    );
    final store = JobTestStore();
    final security = InstallationSecurity(
      store: store,
      namespace: 'synthetic.job-names',
    );
    await security.start(db);
    final enrollment = CompanyEnrollment(db: db, installation: security);
    final identity = await enrollment.create(
      companyName: 'Synthetic names',
      policy: CompanyContinuityPolicy.localContinuity,
      pin: '1234',
      recoveryPassphrase: 'synthetic names authority',
      recoveryFile: File('${root.path}/authority.wpca'),
    );
    final owner = await enrollment.signIn('1234');
    final create = CreateJob(
      companyId: identity.companyId,
      shopId: identity.shopId,
      jobId: jobId ?? const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Baseline',
    );
    await CompanyJobCommands(enrollment: enrollment)
        .createJob(create, ownerSession: owner);
    final row = (await db.select(db.companyJobs).get()).single;
    return NameFixture(
      root,
      db,
      store,
      security,
      enrollment,
      owner,
      create,
      hashes.sha256.convert(utf8.encode(row.operationBytes)).toString(),
    );
  }

  Future<void> reopen() async {
    await enrollment.signOut();
    await db.close();
    db = AppDatabase.forTesting(
      NativeDatabase(File('${root.path}/shop.sqlite')),
    );
    security = InstallationSecurity(
      store: store,
      namespace: security.namespace,
    );
    await security.start(db);
    enrollment = CompanyEnrollment(db: db, installation: security);
    owner = await enrollment.signIn('1234');
  }

  Future<void> close() async {
    await db.close();
    await root.delete(recursive: true);
  }
}

String canonicalNameTest(Object? value) {
  Object? sorted(Object? v) {
    if (v is Map) {
      final keys = v.keys.cast<String>().toList()..sort();
      return {for (final k in keys) k: sorted(v[k])};
    }
    if (v is List) return v.map(sorted).toList();
    return v;
  }

  return jsonEncode(sorted(value));
}

Future<String> nameSnapshot(NameFixture f) async => hashes.sha256
    .convert(
      utf8.encode(
        canonicalNameTest({
          'tables': {
            for (final t in f.db.allTables)
              t.actualTableName:
                  (await f.db
                          .customSelect('SELECT * FROM "${t.actualTableName}"')
                          .get())
                      .map((r) => r.data)
                      .toList(),
          },
          'protected': {
            for (final entry in f.store.states.entries)
              entry.key: base64Encode(entry.value.bytes),
          },
        }),
      ),
    )
    .toString();

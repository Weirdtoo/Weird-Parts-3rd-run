import 'dart:io';
import 'dart:isolate';

import 'package:drift/drift.dart';
import 'package:drift/native.dart';
import 'package:path_provider/path_provider.dart';

import 'daos/jobs_dao.dart';
import 'daos/parts_dao.dart';
import 'daos/settings_dao.dart';
import 'daos/taxonomy_dao.dart';
import 'tables/app_settings.dart';
import 'tables/device_profile.dart';
import 'sqlite_file.dart';
import 'tables/jobs.dart';
import 'tables/company_jobs.dart';
import 'tables/company_membership.dart';
import 'tables/company_users.dart';
import 'tables/job_line_history.dart';
import 'tables/parts.dart';
import 'tables/taxonomy.dart';
import 'tables/warehouse.dart';

part 'app_database.g.dart';

const kAppSchemaVersion = 14;

@DriftDatabase(
  tables: [
    DeviceProfiles,
    AppSettings,
    Categories,
    Styles,
    Types,
    Devices,
    Brands,
    Suppliers,
    Parts,
    PartDevices,
    BrandVersions,
    SupplierListings,
    Jobs,
    CompanyJobs,
    CompanyJobPeerAcks,
    CompanyJobNames,
    CompanyJobNamePeerAcks,
    CompanyJobLifecycles,
    CompanyJobLifecyclePeerAcks,
    CompanyJobDetails,
    CompanyJobDetailPeerAcks,
    JobLines,
    OrderSplits,
    CompanyBootstrapWitnesses,
    CompanyAuthorityFacts,
    JobLineBaselines,
    JobLineOperations,
    JobLineReceipts,
    JobLineAudits,
    JobLineOutgoing,
    JobLineConflicts,
    CompanyMembershipCertificates,
    CompanyJoinRequests,
    CompanyJoinEvents,
    CompanyUserEvents,
    CompanyUserDeliveries,
    CompanyUserCredentialGrants,
    WarehouseLocations,
    WarehouseCounts,
  ],
  daos: [SettingsDao, TaxonomyDao, PartsDao, JobsDao],
)
class AppDatabase extends _$AppDatabase {
  AppDatabase() : this._(_DatabaseWorkerLifetime());

  AppDatabase._(_DatabaseWorkerLifetime lifetime)
    : _waitForWorkerExit = lifetime.waitForExit,
      super(_open(lifetime));

  AppDatabase.forTesting(
    QueryExecutor executor, {
    Future<void> Function()? waitForWorkerExit,
  }) : this._forTesting(executor, waitForWorkerExit);

  AppDatabase._forTesting(super.e, this._waitForWorkerExit);

  final Future<void> Function()? _waitForWorkerExit;
  Future<void>? _closeFuture;

  // Drift 2.31 has no public transaction-zone predicate. Its resolved engine
  // distinguishes the outer caller's transaction from this root connection.
  // ignore: invalid_use_of_internal_member
  bool get hasCallerTransaction => !identical(resolvedEngine, this);

  @override
  Future<void> close() {
    // Connections without an owned worker retain Drift's close semantics.
    if (_waitForWorkerExit == null) return super.close();
    return _closeFuture ??= _closeOwnedWorker().catchError((
      Object error,
      StackTrace stack,
    ) {
      _closeFuture = null;
      Error.throwWithStackTrace(error, stack);
    });
  }

  Future<void> _closeOwnedWorker() async {
    await super.close();
    // Drift's remote-close acknowledgment can precede SQLite disposal.
    // Engine teardown must also await the actual owned isolate exit.
    await _waitForWorkerExit?.call();
  }

  @override
  int get schemaVersion => kAppSchemaVersion;

  @override
  MigrationStrategy get migration => MigrationStrategy(
    onCreate: (m) => m.createAll(),
    onUpgrade: (m, from, to) async {
      if (from > to) {
        throw StateError('A newer database requires a compatible app');
      }
      if (from == 3) {
        for (final table in [
          'job_line_baselines',
          'job_line_operations',
          'job_line_receipts',
          'job_line_audits',
          'job_line_outgoing',
          'job_line_conflicts',
        ]) {
          if ((await customSelect(
            'SELECT 1 FROM $table LIMIT 1',
          ).get()).isNotEmpty) {
            throw StateError(
              'Unsigned experimental schema-3 history requires its original compatible recovery app',
            );
          }
        }
      }
      await transaction(() async {
        if (from < 14) {
          await m.createTable(companyUserCredentialGrants);
        }
        if (from < 13) {
          await m.createTable(companyUserEvents);
          await m.createTable(companyUserDeliveries);
        }
        if (from < 12) {
          await m.createTable(warehouseLocations);
          await m.createTable(warehouseCounts);
        }
        if (from < 11) {
          await m.createTable(companyJobLifecycles);
          await m.createTable(companyJobLifecyclePeerAcks);
        }
        if (from < 10) {
          await m.createTable(companyJobDetails);
          await m.createTable(companyJobDetailPeerAcks);
        }
        if (from < 9) {
          await m.createTable(companyJobNames);
          await m.createTable(companyJobNamePeerAcks);
        }
        if (from < 8) {
          await m.createTable(companyJobPeerAcks);
        }
        if (from < 7) {
          await m.createTable(companyMembershipCertificates);
          await m.createTable(companyJoinRequests);
          await m.createTable(companyJoinEvents);
        }
        if (from < 2) {
          await m.addColumn(brandVersions, brandVersions.varianceName);
          await m.addColumn(brandVersions, brandVersions.isMain);
        }
        if (from < 3) {
          await m.createTable(companyAuthorityFacts);
          await m.createTable(jobLineBaselines);
          await m.createTable(jobLineOperations);
          await m.createTable(jobLineReceipts);
          await m.createTable(jobLineAudits);
          await m.createTable(jobLineOutgoing);
          await m.createTable(jobLineConflicts);
        }
        if (from < 6) {
          await m.createTable(companyJobs);
        }
        if (from < 5) {
          await m.createTable(companyBootstrapWitnesses);
        }
      });
    },
  );
}

LazyDatabase _open(_DatabaseWorkerLifetime lifetime) {
  return LazyDatabase(() async {
    // Prefer Application Support over Documents: OneDrive-backed Documents
    // on Windows can fail SQLite open (SQLITE_CANTOPEN / code 14).
    final support = await getApplicationSupportDirectory();
    Directory? documents;
    try {
      documents = await getApplicationDocumentsDirectory();
    } on MissingPlatformDirectoryException {
      documents = null;
    }
    final file = resolveSqliteFile(
      supportDir: support,
      documentsDir: documents,
    );
    return NativeDatabase.createInBackground(
      file,
      readPool: 0,
      isolateSetup: _registerWorkerExit(lifetime.prepareExitSignal()),
    );
  });
}

// This factory captures only a SendPort, never the unsendable owner/ReceivePort.
void Function() _registerWorkerExit(SendPort port) =>
    () => Isolate.current.addOnExitListener(port);

class _DatabaseWorkerLifetime {
  Future<void>? _exited;

  SendPort prepareExitSignal() {
    final port = ReceivePort('Wired Parts database worker exit');
    _exited = port.first.then<void>((_) {}).whenComplete(port.close);
    return port.sendPort;
  }

  Future<void> waitForExit() async {
    // Never-opened LazyDatabase instances have no worker and no receive port.
    await _exited;
  }
}

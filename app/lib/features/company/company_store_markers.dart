import '../../data/app_database.dart';
import '../installation/installation_security.dart';

const priorCompanyMarkerTables = [
  'company_authority_facts',
  'job_line_baselines',
  'job_line_operations',
  'job_line_receipts',
  'job_line_audits',
  'job_line_outgoing',
  'job_line_conflicts',
];

const companyMarkerTables = [
  ...priorCompanyMarkerTables,
  'company_bootstrap_witnesses',
  'company_jobs',
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
];

const companyCredentialGrantTableColumns = <String, Set<String>>{
  'company_user_credential_grants': {
    'company_id',
    'user_id',
    'grant_key',
    'grant_bytes',
  },
};

const companyUserTableColumns = <String, Set<String>>{
  'company_user_events': {
    'company_id',
    'user_id',
    'sequence',
    'request_id',
    'public_head',
    'previous_head',
    'certificate_bytes',
    'kind',
  },
  'company_user_deliveries': {
    'company_id',
    'user_id',
    'public_head',
    'source_device_id',
    'peer_device_id',
    'binding_commitment',
    'receipt_bytes',
  },
};

const companySyncTableColumns = <String, Set<String>>{
  'company_job_peer_acks': {
    'company_id',
    'origin_generation',
    'request_id',
    'peer_device_id',
    'operation_digest',
    'ack_bytes',
  },
};

const companyNameTableColumns = <String, Set<String>>{
  'company_job_names': {
    'company_id',
    'shop_id',
    'job_id',
    'origin_generation',
    'request_id',
    'operation_commitment',
    'command_commitment',
    'operation_bytes',
    'receipt_key',
    'receipt_bytes',
    'audit_bytes',
    'outgoing',
  },
  'company_job_name_peer_acks': {
    'company_id',
    'origin_generation',
    'request_id',
    'peer_device_id',
    'operation_digest',
    'ack_bytes',
  },
};

const companyDetailsTableColumns = <String, Set<String>>{
  'company_job_details': {
    'company_id',
    'shop_id',
    'job_id',
    'origin_generation',
    'request_id',
    'operation_commitment',
    'command_commitment',
    'operation_bytes',
    'receipt_key',
    'receipt_bytes',
    'audit_bytes',
    'outgoing',
  },
  'company_job_detail_peer_acks': {
    'company_id',
    'origin_generation',
    'request_id',
    'peer_device_id',
    'operation_digest',
    'ack_bytes',
  },
};

const companyLifecycleTableColumns = <String, Set<String>>{
  'company_job_lifecycles': {
    'company_id',
    'shop_id',
    'job_id',
    'origin_generation',
    'request_id',
    'operation_commitment',
    'command_commitment',
    'operation_bytes',
    'receipt_key',
    'receipt_bytes',
    'audit_bytes',
    'outgoing',
  },
  'company_job_lifecycle_peer_acks': {
    'company_id',
    'origin_generation',
    'request_id',
    'peer_device_id',
    'operation_digest',
    'ack_bytes',
  },
};

const companyJoinTableColumns = <String, Set<String>>{
  'company_membership_certificates': {
    'grant_id',
    'company_id',
    'proof_commitment',
    'proof_bytes',
    'issuer_device_id',
    'issuer_sequence',
  },
  'company_join_requests': {
    'request_id',
    'side',
    'request_commitment',
    'request_bytes',
    'recipient_installation',
    'recipient_generation',
    'recipient_key',
    'certificate_commitment',
    'stage',
  },
  'company_join_events': {'request_id', 'ordinal', 'kind', 'evidence_bytes'},
};

bool companyJoinColumnsMatch(String table, Iterable<String> columns) {
  final expected = companyJoinTableColumns[table]!;
  final actual = columns.toSet();
  return actual.length == expected.length && actual.containsAll(expected);
}

Future<void> requireCompanyJoinSchema(AppDatabase db) async {
  final version = (await db.customSelect('PRAGMA user_version').getSingle())
      .read<int>('user_version');
  if (version > kAppSchemaVersion) {
    throw StateError('A newer company schema requires a compatible app');
  }
  if (version < 7) return;
  final expected = {
    ...companyJoinTableColumns,
    if (version >= 8) ...companySyncTableColumns,
    if (version >= 9) ...companyNameTableColumns,
    if (version >= 10) ...companyDetailsTableColumns,
    if (version >= 11) ...companyLifecycleTableColumns,
    if (version >= 13) ...companyUserTableColumns,
    if (version >= 14) ...companyCredentialGrantTableColumns,
  };
  for (final table in expected.keys) {
    final columns = await db.customSelect('PRAGMA table_info("$table")').get();
    final actual = columns.map((r) => r.read<String>('name')).toSet();
    if (actual.length != expected[table]!.length ||
        !actual.containsAll(expected[table]!)) {
      throw StateError('Unsupported or incomplete company enrollment schema');
    }
  }
}

/// Query failures are deliberately propagated: only a complete empty scan
/// proves that a shop can use legacy routes without company authority.
Future<bool> hasCompanyStoreMarkers(AppDatabase db) async {
  await requireCompanyJoinSchema(db);
  for (final table in companyMarkerTables) {
    if ((await db.customSelect('SELECT 1 FROM $table LIMIT 1').get())
        .isNotEmpty) {
      return true;
    }
  }
  return false;
}

/// Serialize every legacy business mutation with company activation. The
/// no-op update takes SQLite's write lock before checking the markers, and
/// keeps that lock through the caller's mutation in the same transaction.
Future<T> legacyBusinessWrite<T>(AppDatabase db, Future<T> Function() write) {
  return db.transaction(() async {
    await db.customStatement(
      'UPDATE app_settings SET value = value WHERE key = ?',
      [kInstallationBindingKey],
    );
    if (await hasCompanyStoreMarkers(db)) {
      throw StateError(
        'This shop belongs to a company. Legacy edits are unavailable.',
      );
    }
    return write();
  });
}

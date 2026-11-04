import 'dart:io';

import 'package:drift/drift.dart';

import '../../data/app_database.dart';
import '../installation/installation_security.dart';
import 'company_store_markers.dart';

final class CompanyBootstrapRefusal implements Exception {
  const CompanyBootstrapRefusal(this.message);
  final String message;

  @override
  String toString() => message;
}

/// Read-only preflight. Create repeats this check after obtaining its SQLite
/// write lock, before any protected or database mutation.
final class CompanyBootstrap {
  static Future<void> preflightFreshShop(
    AppDatabase db, {
    Directory? photosDirectory,
  }) async {
    await requireCompanyJoinSchema(db);
    for (final table in <String>[
      'categories',
      'styles',
      'types',
      'devices',
      'brands',
      'suppliers',
      'parts',
      'part_devices',
      'brand_versions',
      'supplier_listings',
      'jobs',
      'job_lines',
      'order_splits',
      'warehouse_locations',
      'warehouse_counts',
      ...companyMarkerTables,
    ]) {
      if ((await db.customSelect('SELECT 1 FROM $table LIMIT 1').get())
          .isNotEmpty) {
        throw const CompanyBootstrapRefusal(
          'Create Company requires a fresh empty shop',
        );
      }
    }
    final otherSettings = await db
        .customSelect(
          'SELECT 1 FROM app_settings WHERE key != ? LIMIT 1',
          variables: [Variable.withString(kInstallationBindingKey)],
        )
        .get();
    if (otherSettings.isNotEmpty) {
      throw const CompanyBootstrapRefusal(
        'Existing local settings require a separate legacy shop',
      );
    }
    if (photosDirectory != null && photosDirectory.existsSync()) {
      if (photosDirectory.listSync().isNotEmpty) {
        throw const CompanyBootstrapRefusal(
          'Existing photos require a separate legacy shop',
        );
      }
    }
  }
}

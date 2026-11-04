import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/widgets.dart';
import 'package:image/image.dart' as image;
import 'package:path/path.dart' as p;
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:wired_parts/app.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/backup/backup_store.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/pin/pin_service.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';

import 'nearby_lan_workspace.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  const run = String.fromEnvironment('LAN_VALIDATION_RUN');
  const roleName = String.fromEnvironment('LAN_VALIDATION_ROLE');
  final namespace = validationInstallationNamespace(
    run: run,
    roleName: roleName,
  );
  final role = ValidationRole.values.singleWhere((r) => r.name == roleName);
  final workspace = ValidationWorkspace.open(run: run, role: role);
  PathProviderPlatform.instance = workspace;
  final db = AppDatabase();
  try {
    if (!workspace.initialized) {
      await seedValidationShop(db, workspace);
      workspace.markInitialized();
    }
    final receipt = await validationReceipt(db, workspace);
    final path = p.join(
      workspace.receipts.path,
      '${DateTime.now().toUtc().microsecondsSinceEpoch}.json',
    );
    File(path).writeAsStringSync(
      const JsonEncoder.withIndent('  ').convert(receipt),
      flush: true,
    );
    debugPrint('Synthetic Nearby validation receipt: $path');
    debugPrint('Synthetic Nearby validation root: ${workspace.root.path}');
    debugPrint('Synthetic Nearby installation namespace: $namespace');
  } finally {
    await db.close();
  }
  runApp(await validationApplication(workspace));
}

String validationInstallationNamespace({
  required String run,
  required String roleName,
}) {
  if (!RegExp(r'^[a-z0-9][a-z0-9-]{0,47}$').hasMatch(run)) {
    throw ArgumentError(
      'Run must contain 1-48 lowercase letters, digits or hyphens',
    );
  }
  if (!ValidationRole.values.any((role) => role.name == roleName)) {
    throw ArgumentError('Role must be sender or receiver');
  }
  final digest = sha256.convert(utf8.encode(run)).toString().substring(0, 24);
  final namespace = 'synthetic.lan.$roleName.$digest';
  validateInstallationNamespace(namespace);
  companyCustodyNamespace(namespace);
  return namespace;
}

enum ValidationApplicationStage {
  database,
  protectedStore,
  localDevice,
  appConstruction,
}

Future<WiredPartsApp> validationApplication(
  ValidationWorkspace workspace, {
  NearbyController Function(String encounterAlias)? createCompanyJoinController,
  NativeInstallationSecureStore installationStore =
      const NativeInstallationSecureStore(),
  void Function(ValidationApplicationStage, InstallationReadiness?)?
  onStartupStage,
}) async {
  final namespace = validationInstallationNamespace(
    run: workspace.run,
    roleName: workspace.role.name,
  );
  PathProviderPlatform.instance = workspace;
  onStartupStage?.call(ValidationApplicationStage.database, null);
  final db = AppDatabase();
  try {
    onStartupStage?.call(ValidationApplicationStage.protectedStore, null);
    final installation = InstallationSecurity(
      store: installationStore,
      namespace: namespace,
    );
    await installation.start(db);
    onStartupStage?.call(
      ValidationApplicationStage.protectedStore,
      installation.readiness,
    );
    if (installation.readiness != InstallationReadiness.ready ||
        installation.identity == null) {
      throw StateError('Synthetic installation startup refused');
    }
    onStartupStage?.call(
      ValidationApplicationStage.localDevice,
      installation.readiness,
    );
    final deviceId = await db.settingsDao.ensureDeviceId();
    onStartupStage?.call(
      ValidationApplicationStage.appConstruction,
      installation.readiness,
    );
    return WiredPartsApp(
      db: db,
      pin: PinService(db.settingsDao),
      deviceId: deviceId,
      installation: installation,
      enableCompanyBootstrap: true,
      createCompanyJoinController: createCompanyJoinController,
    );
  } catch (_) {
    try {
      await db.close();
    } catch (_) {}
    rethrow;
  }
}

Future<void> seedValidationShop(
  AppDatabase db,
  ValidationWorkspace workspace,
) async {
  final prefix = '${workspace.run}-${workspace.role.name}';
  final device = workspace.deviceId;
  await db.transaction(() async {
    await db.settingsDao.keepLocalDeviceId(
      device,
      displayName: 'LAN ${workspace.role.name} ${workspace.run}',
    );
    await db.settingsDao.setSetting('lan_validation_fixture', prefix);
    await db.jobsDao.insertJob(
      id: '$prefix-job',
      name: 'Synthetic ${workspace.role.name} shop ${workspace.run}',
      deviceId: device,
    );
    await db.taxonomyDao.insertCategory(
      id: '$prefix-category',
      name: 'Synthetic category',
      deviceId: device,
    );
    await db.taxonomyDao.insertStyle(
      id: '$prefix-type',
      categoryId: '$prefix-category',
      name: 'Synthetic type',
      deviceId: device,
    );
    await db.taxonomyDao.insertType(
      id: '$prefix-variant',
      styleId: '$prefix-type',
      name: 'Synthetic variant',
      deviceId: device,
    );
    await db.partsDao.insertGeneralPart(
      id: '$prefix-part',
      name: 'Synthetic ${workspace.role.name} part',
      deviceId: device,
      categoryId: '$prefix-category',
      styleId: '$prefix-type',
      typeId: '$prefix-variant',
    );
    await db.customStatement(
      'UPDATE jobs SET job_number = ?, customer = ?, location = ?, notes = ? WHERE id = ?',
      [
        'LAN-42',
        'Synthetic customer',
        'Synthetic location',
        'Synthetic job notes',
        '$prefix-job',
      ],
    );
    await db.customStatement(
      'UPDATE parts SET description = ?, uom = ?, specs = ?, keywords = ? WHERE id = ?',
      [
        'Synthetic description',
        'box',
        'Synthetic specs',
        'synthetic keywords',
        '$prefix-part',
      ],
    );
    await db.jobsDao.insertJobLine(
      id: '$prefix-line',
      jobId: '$prefix-job',
      partId: '$prefix-part',
      brandVersionId: null,
      neededQty: 7,
      shopPullQty: 2,
      deviceId: device,
      customName: 'Synthetic line',
      customNotes: 'Synthetic custom notes',
      uom: 'box',
      notes: 'Synthetic line notes',
    );
    Future<void> related(
      String table,
      String suffix,
      Map<String, Object?> values,
    ) async {
      final row = <String, Object?>{
        'id': '$prefix-$suffix',
        'origin_device_id': device,
        'created_at': 1700000000,
        'modified_at': 1700000000,
        ...values,
      };
      await db.customStatement(
        'INSERT INTO "$table" (${row.keys.join(', ')}) VALUES (${List.filled(row.length, '?').join(', ')})',
        row.values.toList(),
      );
    }

    await related('jobs', 'deleted-job', {
      'name': 'Synthetic deleted job',
      'modified_at': 1700000060,
      'deleted_at': 1700000060,
      'revision': 7,
    });
    await related('devices', 'device', {'name': 'Synthetic compatible device'});
    await related('brands', 'brand', {'name': 'Synthetic brand'});
    await related('suppliers', 'supplier', {'name': 'Synthetic supplier'});
    await related('part_devices', 'part-device', {
      'part_id': '$prefix-part',
      'device_id': '$prefix-device',
    });
    await related('brand_versions', 'brand-version', {
      'part_id': '$prefix-part',
      'brand_id': '$prefix-brand',
      'mpn': 'SYN-42',
      'model': 'Synthetic model',
      'description': 'Synthetic brand description',
      'variance_name': 'Synthetic variance',
      'is_main': 1,
    });
    await related('supplier_listings', 'listing', {
      'brand_version_id': '$prefix-brand-version',
      'supplier_id': '$prefix-supplier',
      'sku': 'SYN-SKU',
      'description': 'Synthetic listing',
      'package_qty': 4.0,
      'last_price': 12.5,
      'notes': 'Synthetic supplier notes',
    });
    await db.customStatement(
      'UPDATE job_lines SET brand_version_id = ? WHERE id = ?',
      ['$prefix-brand-version', '$prefix-line'],
    );
    await related('order_splits', 'split', {
      'job_line_id': '$prefix-line',
      'supplier_id': '$prefix-supplier',
      'quantity': 5.0,
    });
    final photoName = '$prefix.png';
    final picture = image.Image(width: 8, height: 8);
    image.fill(
      picture,
      color: workspace.role == ValidationRole.sender
          ? image.ColorRgb8(23, 120, 201)
          : image.ColorRgb8(201, 80, 23),
    );
    workspace.photos.createSync();
    File(p.join(workspace.photos.path, photoName))
        .writeAsBytesSync(image.encodePng(picture), flush: true);
    await db.partsDao.setPhotoPath('$prefix-part', photoName);
  });
}

Future<Map<String, Object?>> validationReceipt(
  AppDatabase db,
  ValidationWorkspace workspace,
) async {
  return db.transaction(() async {
    await requireLegacyBusinessStore(db);
    final schemaVersion =
        (await db.customSelect('PRAGMA user_version').getSingle()).read<int>(
          'user_version',
        );
    final jobs = await db.jobsDao.listActiveJobs();
    final parts = await db.partsDao.listParts();
    final profiles = await db.select(db.deviceProfiles).get();
    final categories = await db.taxonomyDao.listCategories();
    final types = await db.taxonomyDao.listStyles();
    final variants = await db.taxonomyDao.listTypes();
    final photos = <Map<String, Object?>>[];
    if (workspace.photos.existsSync()) {
      for (final file in workspace.photos.listSync().whereType<File>()) {
        photos.add({
          'name': p.basename(file.path),
          'sha256': sha256.convert(file.readAsBytesSync()).toString(),
        });
      }
    }
    photos.sort((a, b) => (a['name'] as String).compareTo(b['name'] as String));
    final content = <String, Object?>{};
    for (final table in db.allTables) {
      final name = table.actualTableName;
      if (name == 'app_settings' || name == 'device_profiles') continue;
      if (schemaVersion < 14 && name == 'company_user_credential_grants') {
        continue;
      }
      if (schemaVersion < 12 &&
          const {'warehouse_locations', 'warehouse_counts'}.contains(name)) {
        continue;
      }
      final ordering = table.$primaryKey
          .map((column) => '"${column.$name}"')
          .join(', ');
      final rows = await db
          .customSelect('SELECT * FROM "$name" ORDER BY $ordering')
          .get();
      content[name] = rows.map((row) => row.data).toList();
    }
    return {
      'format': 2,
      'content': content,
      'observedAt': DateTime.now().toUtc().toIso8601String(),
      'run': workspace.run,
      'localRole': workspace.role.name,
      'root': workspace.root.path,
      'expectedLocalDeviceId': workspace.deviceId,
      'deviceIds': profiles.map((e) => e.id).toList(),
      'pinConfigured':
          await db.settingsDao.getSetting('editor_pin_hash') != null,
      'fixture': await db.settingsDao.getSetting('lan_validation_fixture'),
      'jobs': jobs.map((e) => {'id': e.id, 'name': e.name}).toList(),
      'parts': parts
          .map(
            (e) => {
              'id': e.id,
              'name': e.name,
              'categoryId': e.categoryId,
              'typeId': e.styleId,
              'variantId': e.typeId,
              'photo': e.photoPath,
            },
          )
          .toList(),
      'categoryIds': categories.map((e) => e.id).toList(),
      'typeIds': types.map((e) => e.id).toList(),
      'variantIds': variants.map((e) => e.id).toList(),
      'photos': photos,
    };
  });
}

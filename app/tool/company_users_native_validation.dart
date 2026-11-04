import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/app.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';
import 'package:wired_parts/features/nearby/nearby_discovery.dart';
import 'package:wired_parts/features/nearby/nearby_protocol.dart';

import 'nearby_lan_validation.dart'
    show
        validationApplication,
        validationInstallationNamespace,
        ValidationApplicationStage;
import 'nearby_lan_workspace.dart';
import 'company_user_network_diagnostic.dart';

const _enabled = bool.fromEnvironment('NATIVE_COMPANY_USER_VALIDATION');
const _run = String.fromEnvironment('LAN_VALIDATION_RUN');
const _roleName = String.fromEnvironment('LAN_VALIDATION_ROLE');
const _revision = String.fromEnvironment('COMPANY_USER_SOURCE_REVISION');
const _tree = String.fromEnvironment('COMPANY_USER_SOURCE_TREE');
const _disabledApiProbe = bool.fromEnvironment(
  'NATIVE_COMPANY_USER_DISABLED_API_PROBE',
);
const _networkDiagnostic = bool.fromEnvironment(
  'NATIVE_COMPANY_USER_NETWORK_DIAGNOSTIC',
);
const _disabledApiProbeRun = 'g2-users-20261024-disable-a';
const _disabledApiProbeUser = '8bca98b6-de9d-4816-ad4e-54290686f16c';
const _disabledApiProbePin = '0123';
const _syntheticPin = '1234';
const _syntheticRecoveryPhrase = 'Synthetic Goal 2 recovery authority 123';

ValidationWorkspace? _heldWorkspace;
AppDatabase? _openedDatabase;

Future<void> main() async {
  var stage = CompanyUserStartupStage.arguments;
  InstallationReadiness? readiness;
  InstallationSecurity? startedInstallation;
  CompanyUserTransportReceipts? acquiredTransport;
  final observedStore = ObservedCompanyUserNativeStore();
  late final ValidationRole role;
  try {
    role = _validateStartupArguments();
  } catch (_) {
    stderr.writeln('Company user validation startup failed.');
    stderr.writeln(
      const CompanyUserStartupFailure(
        CompanyUserStartupStage.arguments,
        null,
      ).summary,
    );
    exit(1);
  }
  late final WiredPartsApp readyApp;
  try {
    stage = CompanyUserStartupStage.binding;
    WidgetsFlutterBinding.ensureInitialized();
    stage = CompanyUserStartupStage.workspace;
    final namespace = validationInstallationNamespace(
      run: _run,
      roleName: _roleName,
    );
    if (!namespace.startsWith('synthetic.lan.$_roleName.')) {
      throw StateError('invalid synthetic installation namespace');
    }
    final workspace = ValidationWorkspace.open(
      run: _run,
      role: role,
      requireExisting: _disabledApiProbe,
    );
    _heldWorkspace = workspace;
    PathProviderPlatform.instance = workspace;

    final transport = CompanyUserTransportReceipts(
      directory: workspace.receipts,
      run: _run,
      role: _roleName,
      sourceRevision: _revision,
      sourceTree: _tree,
      processId: pid,
      localNetworkDiagnostic: _networkDiagnostic,
    );
    acquiredTransport = transport;
    final app = await validationApplication(
      workspace,
      installationStore: observedStore,
      createCompanyJoinController: transport.createController,
      onStartupStage: (current, observedReadiness) {
        stage = switch (current) {
          ValidationApplicationStage.database =>
            CompanyUserStartupStage.database,
          ValidationApplicationStage.protectedStore =>
            CompanyUserStartupStage.protectedStore,
          ValidationApplicationStage.localDevice =>
            CompanyUserStartupStage.localDevice,
          ValidationApplicationStage.appConstruction =>
            CompanyUserStartupStage.appConstruction,
        };
        readiness = observedReadiness;
      },
    );
    _openedDatabase = app.db;
    final installation = app.installation;
    startedInstallation = installation;
    if (installation == null || installation.identity == null) {
      throw StateError('installation setup unavailable');
    }

    stage = CompanyUserStartupStage.companyReadback;
    CompanyIdentity? createdCompany;
    if (role == ValidationRole.sender && !workspace.initialized) {
      final enrollment = CompanyEnrollment(
        installation: installation,
        db: app.db,
      );
      createdCompany = await enrollment.create(
        companyName: 'Synthetic Goal 2 company users $_run',
        policy: CompanyContinuityPolicy.localContinuity,
        pin: _syntheticPin,
        recoveryPassphrase: _syntheticRecoveryPhrase,
        recoveryFile: File(p.join(workspace.documents.path, 'authority.wpca')),
        photosDirectory: workspace.photos,
      );
    }

    if (!workspace.initialized) workspace.markInitialized();
    final enrollment = CompanyEnrollment(
      installation: installation,
      db: app.db,
    );
    final disabledApiProbe = await runCompanyUserDisabledApiProbe(
      enrollment: enrollment,
      enabled: _disabledApiProbe,
      validationEnabled: _enabled,
      initialized: workspace.initialized,
      run: _run,
      roleName: _roleName,
      expectedUserId: _disabledApiProbeUser,
      sourceRevision: _revision,
      sourceTree: _tree,
    );
    final choices = await enrollment.listCompanyUsers();
    final receiptCompany = createdCompany ?? await enrollment.readIdentity();
    final trust = await installation.readCompanyTrust(app.db);
    final protectedUser = trust == null
        ? {'present': false, 'available': false}
        : await readCompanyUserValidationProjection(
            enrollment,
            installation,
            run: _run,
            roleName: _roleName,
          );
    final identity = installation.identity!;
    final receipt = <String, Object?>{
      'kind': 'company-user-startup@1',
      'passed': false,
      'scope': 'startup measurement and synthetic preparation only',
      'pid': pid,
      'os': Platform.operatingSystem,
      'run': _run,
      'role': _roleName,
      'sourceRevision': _revision,
      'sourceTree': _tree,
      'installation': {
        'id': identity.id.value,
        'generation': identity.generation.value,
        'receivingStoreGeneration':
            installation.receivingStoreGeneration?.value,
        'publicKeySha256': sha256.convert(identity.publicKey).toString(),
      },
      'companyIdentity': receiptCompany == null
          ? null
          : {
              'companyId': receiptCompany.companyId,
              'shopId': receiptCompany.shopId,
              'userId': receiptCompany.userId,
              'deviceId': receiptCompany.deviceId,
              'name': receiptCompany.name,
              'packageId': receiptCompany.packageId,
            },
      'companyId': trust?.companyId.value,
      'userChoices': [
        for (final choice in choices)
          {
            'userId': choice.userId,
            'name': choice.name,
            'available': choice.available,
          },
      ],
      'secondaryProtectedRecord': protectedUser,
      'disabledApiProbe': ?disabledApiProbe,
      'appOwnsOrdinaryDatabaseExit': true,
      'normalQuitEvidence': 'external host process observation required',
      'transportMeasurements': {
        'passed': false,
        'localOnly': true,
        'file': p.basename(transport.filePath),
        'maxRecords': CompanyUserTransportReceipts.maxRecords,
        'maxRecordBytes': CompanyUserTransportReceipts.maxRecordBytes,
        'maxTotalBytes': CompanyUserTransportReceipts.maxTotalBytes,
        if (_networkDiagnostic && Platform.isMacOS)
          'localNetworkDiagnostic': {
            'maxAttempts': 1,
            'deadlineMillis': 10000,
            'maxEvents': 8,
            'scope': 'separate zero-payload app-context TCP diagnosis only',
          },
      },
    };
    stage = CompanyUserStartupStage.receiptWrite;
    final receiptId = '$pid-${DateTime.now().toUtc().microsecondsSinceEpoch}';
    final file = File(
      p.join(
        _heldWorkspace!.receipts.path,
        'company-user-startup-$receiptId.json',
      ),
    );
    file.createSync(exclusive: true);
    file.writeAsStringSync(
      const JsonEncoder.withIndent('  ').convert(receipt),
      flush: true,
    );
    debugPrint('Company user validation startup receipt written.');
    readyApp = app;
  } catch (_) {
    final failure = CompanyUserStartupFailure(
      stage,
      startedInstallation?.readiness ?? readiness,
      nativeFailure: observedStore.firstFailure,
    );
    await finishCompanyUserStartupFailure(
      failure: failure,
      workspace: _heldWorkspace,
      reporter: CompanyUserStartupFailureReporter(
        enabled: _enabled,
        run: _run,
        role: _roleName,
        sourceRevision: _revision,
        sourceTree: _tree,
        processId: pid,
      ),
      closeTransport: acquiredTransport?.close,
      closeDatabase: _openedDatabase?.close,
    );
    _openedDatabase = null;
    _heldWorkspace = null;
    stderr.writeln('Company user validation startup failed.');
    stderr.writeln(failure.summary);
    exit(1);
  }
  runApp(readyApp);
}

enum CompanyUserStartupStage {
  arguments,
  binding,
  workspace,
  database,
  protectedStore,
  localDevice,
  appConstruction,
  companyReadback,
  receiptWrite,
}

enum CompanyUserStartupCategory {
  stageFailed,
  installationUnsupported,
  installationUnavailable,
  installationRecoveryRequired,
  installationIdentityMissing,
}

enum CompanyUserNativeOperation { readState, compareAndSwapState }

enum CompanyUserNativeDomain { keychain, posix, platform }

enum CompanyUserNativeReason {
  interactionNotAllowed,
  missingEntitlement,
  notAvailable,
  authFailed,
  ioFailure,
  permissionDenied,
  busy,
  unknown,
}

final class CompanyUserNativeFailure {
  const CompanyUserNativeFailure(this.operation, this.domain, this.reason);
  final CompanyUserNativeOperation operation;
  final CompanyUserNativeDomain domain;
  final CompanyUserNativeReason reason;

  Map<String, String> toJson() => {
    'operation': operation.name,
    'domain': domain.name,
    'reason': reason.name,
  };
}

/// Observes existing native failures without changing calls, results or errors.
final class ObservedCompanyUserNativeStore
    extends NativeInstallationSecureStore {
  ObservedCompanyUserNativeStore({
    this._delegate = const NativeInstallationSecureStore(),
    bool? macOS,
  }) : _macOS = macOS ?? Platform.isMacOS;

  final NativeInstallationSecureStore _delegate;
  final bool _macOS;
  bool _observedFailure = false;
  CompanyUserNativeFailure? _firstFailure;
  CompanyUserNativeFailure? get firstFailure => _firstFailure;

  @override
  Future<ProtectedInstallationState?> readState(String namespace) async {
    try {
      return await _delegate.readState(namespace);
    } on PlatformException catch (error) {
      try {
        _observe(CompanyUserNativeOperation.readState, error);
      } catch (_) {}
      rethrow;
    }
  }

  @override
  Future<String> compareAndSwapState(
    String namespace, {
    required String? expectedRevision,
    required String nextRevision,
    required Uint8List bytes,
  }) async {
    try {
      return await _delegate.compareAndSwapState(
        namespace,
        expectedRevision: expectedRevision,
        nextRevision: nextRevision,
        bytes: bytes,
      );
    } on PlatformException catch (error) {
      try {
        _observe(CompanyUserNativeOperation.compareAndSwapState, error);
      } catch (_) {}
      rethrow;
    }
  }

  void _observe(CompanyUserNativeOperation operation, PlatformException error) {
    if (_observedFailure) {
      return;
    }
    _observedFailure = true;
    var failure = CompanyUserNativeFailure(
      operation,
      CompanyUserNativeDomain.platform,
      CompanyUserNativeReason.unknown,
    );
    try {
      failure = _classify(operation, error);
    } catch (_) {}
    _firstFailure = failure;
  }

  CompanyUserNativeFailure _classify(
    CompanyUserNativeOperation operation,
    PlatformException error,
  ) {
    final unknown = CompanyUserNativeFailure(
      operation,
      CompanyUserNativeDomain.platform,
      CompanyUserNativeReason.unknown,
    );
    final details = error.details;
    if (!_macOS ||
        error.code != 'installation_unavailable' ||
        details is! Map ||
        details.length != 1) {
      return unknown;
    }
    final key = details.keys.single;
    final value = details[key];
    if (value is! int || value < -2147483648 || value > 2147483647) {
      return unknown;
    }
    // Definitions, not observed causes: Apple's Security/base/SecBase.h and
    // xnu/bsd/sys/errno.h. Numeric values never leave this classifier.
    if (key == 'osStatus') {
      return CompanyUserNativeFailure(
        operation,
        CompanyUserNativeDomain.keychain,
        switch (value) {
          -25308 => CompanyUserNativeReason.interactionNotAllowed,
          -34018 => CompanyUserNativeReason.missingEntitlement,
          -25291 => CompanyUserNativeReason.notAvailable,
          -25293 => CompanyUserNativeReason.authFailed,
          -36 => CompanyUserNativeReason.ioFailure,
          _ => CompanyUserNativeReason.unknown,
        },
      );
    }
    if (key == 'errno') {
      return CompanyUserNativeFailure(
        operation,
        CompanyUserNativeDomain.posix,
        switch (value) {
          1 || 13 => CompanyUserNativeReason.permissionDenied,
          5 => CompanyUserNativeReason.ioFailure,
          16 => CompanyUserNativeReason.busy,
          _ => CompanyUserNativeReason.unknown,
        },
      );
    }
    return unknown;
  }
}

final class CompanyUserStartupFailure {
  const CompanyUserStartupFailure(
    this.stage,
    this.readiness, {
    this.nativeFailure,
  });
  final CompanyUserStartupStage stage;
  final InstallationReadiness? readiness;
  final CompanyUserNativeFailure? nativeFailure;

  CompanyUserStartupCategory get category => switch (readiness) {
    InstallationReadiness.unsupported =>
      CompanyUserStartupCategory.installationUnsupported,
    InstallationReadiness.unavailable =>
      CompanyUserStartupCategory.installationUnavailable,
    InstallationReadiness.needsRecovery =>
      CompanyUserStartupCategory.installationRecoveryRequired,
    InstallationReadiness.ready
        when stage == CompanyUserStartupStage.protectedStore =>
      CompanyUserStartupCategory.installationIdentityMissing,
    _ => CompanyUserStartupCategory.stageFailed,
  };

  String get summary =>
      'stage=${stage.name} category=${category.name} readiness=${readiness?.name ?? 'notObserved'}';
}

/// One fixed-shape failure record; never serializes an exception or store value.
final class CompanyUserStartupFailureReporter {
  CompanyUserStartupFailureReporter({
    required this.enabled,
    required this.run,
    required this.role,
    required this.sourceRevision,
    required this.sourceTree,
    required this.processId,
    DateTime? observation,
  }) : observation = (observation ?? DateTime.now()).toUtc();

  static const maxBytes = 1024;
  final bool enabled;
  final String run, role, sourceRevision, sourceTree;
  final int processId;
  final DateTime observation;
  bool _attempted = false;

  File publish(
    ValidationWorkspace workspace,
    CompanyUserStartupFailure failure,
  ) {
    if (_attempted) {
      throw StateError('Startup failure receipt already attempted');
    }
    _attempted = true;
    if (!enabled ||
        !RegExp(r'^g2-users-\d{8}-[a-z0-9][a-z0-9-]{0,29}$').hasMatch(run) ||
        run.length > 48 ||
        !{'sender', 'receiver'}.contains(role) ||
        workspace.run != run ||
        workspace.role.name != role ||
        !RegExp(r'^[a-f0-9]{40}$').hasMatch(sourceRevision) ||
        !RegExp(r'^[a-f0-9]{40}$').hasMatch(sourceTree) ||
        processId <= 0 ||
        processId > 2147483647) {
      throw StateError('Startup failure receipt refused');
    }
    final bytes = utf8.encode(
      jsonEncode({
        'kind': 'company-user-startup-failure@1',
        'passed': false,
        'run': run,
        'role': role,
        'sourceRevision': sourceRevision,
        'sourceTree': sourceTree,
        'pid': processId,
        'observedUtc': observation.toIso8601String(),
        'stage': failure.stage.name,
        'category': failure.category.name,
        'installationReadiness': failure.readiness?.name ?? 'notObserved',
        if (failure.nativeFailure case final native?)
          'nativeFailure': native.toJson(),
      }),
    );
    if (bytes.length > maxBytes) {
      throw StateError('Startup failure receipt refused');
    }
    workspace.requireOwnedReceipts();
    final file = File(
      p.join(
        workspace.receipts.path,
        'company-user-startup-failure-$processId-${observation.microsecondsSinceEpoch}.json',
      ),
    );
    if (FileSystemEntity.typeSync(file.path, followLinks: false) !=
        FileSystemEntityType.notFound) {
      throw StateError('Startup failure receipt target occupied');
    }
    file.createSync(exclusive: true);
    file.writeAsBytesSync(bytes, flush: true);
    return file;
  }
}

Future<bool> finishCompanyUserStartupFailure({
  required CompanyUserStartupFailure failure,
  required CompanyUserStartupFailureReporter reporter,
  ValidationWorkspace? workspace,
  Future<void> Function()? closeTransport,
  Future<void> Function()? closeDatabase,
}) async {
  var published = false;
  try {
    if (workspace != null) {
      reporter.publish(workspace, failure);
      published = true;
    }
  } catch (_) {
    // Publishing must never replace the original fixed failure classification.
  }
  try {
    try {
      await closeTransport?.call();
    } catch (_) {}
    try {
      await closeDatabase?.call();
    } catch (_) {}
  } finally {
    try {
      workspace?.close();
    } catch (_) {}
  }
  return published;
}

Future<Map<String, Object?>?> runCompanyUserDisabledApiProbe({
  required CompanyEnrollment enrollment,
  bool enabled = false,
  required bool validationEnabled,
  required bool initialized,
  required String run,
  required String roleName,
  required String expectedUserId,
  required String sourceRevision,
  required String sourceTree,
}) async {
  if (!enabled) return null;
  final namespace = enrollment.installation.namespace;
  if (!validationEnabled ||
      !initialized ||
      run != _disabledApiProbeRun ||
      !{'sender', 'receiver'}.contains(roleName) ||
      !RegExp(r'^[a-f0-9]{40}$').hasMatch(sourceRevision) ||
      !RegExp(r'^[a-f0-9]{40}$').hasMatch(sourceTree) ||
      !Uuid.isValidUUID(fromString: expectedUserId) ||
      namespace !=
          validationInstallationNamespace(run: run, roleName: roleName) ||
      enrollment.currentCompanySession != null) {
    throw StateError('Disabled API probe refused');
  }
  try {
    Future<Map<String, ProtectedInstallationState>> protectedState() async {
      final result = <String, ProtectedInstallationState>{};
      for (final slot in [
        namespace,
        companyCustodyNamespace(namespace),
        companyUserNamespace(namespace),
      ]) {
        final state = await enrollment.installation.store.readState(slot);
        if (state == null) throw StateError('Disabled API probe refused');
        result[slot] = state;
      }
      return result;
    }

    final beforeProtected = await protectedState();
    final beforeSql = await _disabledProbeSqlSnapshot(enrollment.db);
    if (await enrollment.readStatus() != CompanyBootstrapStatus.active) {
      throw StateError('Disabled API probe refused');
    }
    final lifecycle = await enrollment.userLifecycleStatus(
      userId: expectedUserId,
    );
    final additional = (await enrollment.listCompanyUsers()).skip(1).toList();
    final identity = await enrollment.readIdentity();
    if (identity == null ||
        lifecycle == null ||
        lifecycle.userId != expectedUserId ||
        !lifecycle.disabled ||
        additional.length != 1 ||
        additional.single.userId != expectedUserId ||
        !additional.single.disabled ||
        additional.single.available ||
        enrollment.currentCompanySession != null) {
      throw StateError('Disabled API probe refused');
    }

    var oldPinDenied = false;
    try {
      await enrollment.signInUser(expectedUserId, _disabledApiProbePin);
    } on CompanyBootstrapRefusal catch (error) {
      if (error.message != 'This company user is disabled') rethrow;
      oldPinDenied = true;
    }
    if (!oldPinDenied || enrollment.currentCompanySession != null) {
      throw StateError('Disabled API probe refused');
    }

    final command = CreateJob(
      companyId: identity.companyId,
      shopId: identity.shopId,
      jobId: const Uuid().v4(),
      requestId: const Uuid().v4(),
      name: 'Synthetic disabled-user authorization probe',
    );
    var commandDenied = false;
    try {
      await enrollment.issueCreateJobAssertion(command);
    } on CompanyBootstrapRefusal catch (error) {
      if (error.message != 'Administrator sign-in required') rethrow;
      commandDenied = true;
    }
    if (!commandDenied || enrollment.currentCompanySession != null) {
      throw StateError('Disabled API probe refused');
    }
    final afterProtected = await protectedState();
    for (final slot in beforeProtected.keys) {
      if (beforeProtected[slot]!.revision != afterProtected[slot]!.revision ||
          !_sameBytes(
            beforeProtected[slot]!.bytes,
            afterProtected[slot]!.bytes,
          )) {
        throw StateError('Disabled API probe refused');
      }
    }
    if (await _disabledProbeSqlSnapshot(enrollment.db) != beforeSql) {
      throw StateError('Disabled API probe refused');
    }
    return const {
      'passed': false,
      'oldPinDenied': true,
      'noSession': true,
      'commandAuthorizationDenied': true,
      'protectedStateUnchanged': true,
      'sqlUnchanged': true,
      'scope':
          'disabled login and unauthenticated Create Job authorization only',
    };
  } catch (_) {
    try {
      await enrollment.signOut();
    } catch (_) {}
    throw StateError('Disabled API probe refused');
  }
}

Future<String> _disabledProbeSqlSnapshot(AppDatabase db) async => jsonEncode({
  for (final table in db.allTables)
    table.actualTableName:
        (await db
                .customSelect('SELECT * FROM "${table.actualTableName}"')
                .get())
            .map((row) => jsonEncode(row.data))
            .toList()
          ..sort(),
});

/// A bounded local measurement sink, installed only by the guarded native target.
final class CompanyUserTransportReceipts {
  CompanyUserTransportReceipts({
    required Directory directory,
    required String run,
    required String role,
    required String sourceRevision,
    required String sourceTree,
    required int processId,
    bool localNetworkDiagnostic = false,
  }) : _metadata = Map.unmodifiable({
         'kind': 'company-user-transport@1',
         'passed': false,
         'localOnly': true,
         'os': Platform.operatingSystem,
         'run': run,
         'role': role,
         'pid': processId,
         'sourceRevision': sourceRevision,
         'sourceTree': sourceTree,
       }),
       _file = File(
         p.join(
           directory.path,
           'company-user-transport-$processId-${const Uuid().v4()}.jsonl',
         ),
       ) {
    if (!RegExp(r'^g2-users-\d{8}-[a-z0-9][a-z0-9-]{0,29}$').hasMatch(run) ||
        !{'sender', 'receiver'}.contains(role) ||
        !RegExp(r'^[a-f0-9]{40}$').hasMatch(sourceRevision) ||
        !RegExp(r'^[a-f0-9]{40}$').hasMatch(sourceTree) ||
        processId <= 0 ||
        processId > 2147483647) {
      throw ArgumentError('Invalid local transport measurement metadata');
    }
    _networkDiagnostic = localNetworkDiagnostic && Platform.isMacOS
        ? CompanyUserNetworkDiagnostic(enabled: true, run: run, record: _append)
        : null;
  }
  static const maxRecords = 128;
  static const maxRecordBytes = 1024;
  static const maxTotalBytes = maxRecords * maxRecordBytes;
  final Map<String, Object?> _metadata;
  final File _file;
  final List<List<int>> _records = [];
  int _bytes = 0;
  int _written = 0;
  bool _disabled = false;
  bool _closed = false;
  RandomAccessFile? _handle;
  Future<void>? _flushing;
  late final CompanyUserNetworkDiagnostic? _networkDiagnostic;
  String get filePath => _file.path;
  int get capturedCount => _records.length;

  NearbyController createController(String alias) {
    final diagnostic = _networkDiagnostic;
    if (diagnostic == null) {
      return NearbyController(
        deviceId: alias,
        deviceName: 'Nearby ${alias.substring(0, 6)}',
        discovery: LanNearbyDiscovery(),
        companyJoin: true,
        onTransportObservation: record,
      );
    }
    int? controller;
    return _DiagnosticNearbyController(
      alias: alias,
      observe: (event) {
        controller ??= event.controller;
        record(event);
      },
      cancel: () => diagnostic.cancelController(controller),
    );
  }

  void record(NearbyTransportObservation event) {
    _networkDiagnostic?.observe(event);
    _append(event.toJson());
  }

  void _append(Map<String, Object?> event) {
    if (_disabled || _closed || _records.length >= maxRecords) return;
    try {
      final bytes = utf8.encode('${jsonEncode({..._metadata, ...event})}\n');
      if (bytes.length > maxRecordBytes ||
          _bytes + bytes.length > maxTotalBytes) {
        return;
      }
      _records.add(bytes);
      _bytes += bytes.length;
      _scheduleFlush();
    } catch (_) {}
  }

  void _scheduleFlush() {
    if (_disabled || _flushing != null || _written == _records.length) return;
    _flushing =
        Future<void>(() async {
          try {
            if (_handle == null) {
              await _file.create(exclusive: true);
              if (await FileSystemEntity.type(_file.path, followLinks: false) !=
                  FileSystemEntityType.file) {
                throw const FileSystemException(
                  'Transport measurement file unavailable',
                );
              }
              _handle = await _file.open(mode: FileMode.writeOnlyAppend);
            }
            final end = _records.length;
            final bytes = [
              for (var index = _written; index < end; index++)
                ..._records[index],
            ];
            await _handle!.writeFrom(bytes);
            await _handle!.flush();
            _written = end;
          } catch (_) {
            _disabled = true;
            try {
              await _handle?.close();
            } catch (_) {}
            _handle = null;
          }
        }).whenComplete(() {
          _flushing = null;
          _scheduleFlush();
        });
  }

  Future<void> drain() async {
    while (_flushing != null) {
      await _flushing;
    }
  }

  Future<void> close() async {
    _closed = true;
    await _networkDiagnostic?.close();
    await drain();
    try {
      await _handle?.close();
    } catch (_) {}
    _handle = null;
  }
}

final class _DiagnosticNearbyController extends NearbyController {
  _DiagnosticNearbyController({
    required String alias,
    required NearbyTransportObserver observe,
    required this.cancel,
  }) : super(
         deviceId: alias,
         deviceName: 'Nearby ${alias.substring(0, 6)}',
         discovery: LanNearbyDiscovery(),
         companyJoin: true,
         onTransportObservation: observe,
       );
  final Future<void> Function() cancel;

  @override
  Future<void> stop({
    NearbyTransportStopReason reason = NearbyTransportStopReason.requested,
  }) {
    unawaited(cancel());
    return super.stop(reason: reason);
  }
}

ValidationRole _validateStartupArguments() {
  final runMatch = RegExp(r'^g2-users-(\d{8})-([a-z0-9][a-z0-9-]{0,29})$')
      .firstMatch(_run);
  final digits = runMatch?.group(1);
  final date = digits == null
      ? null
      : DateTime.tryParse(
          '${digits.substring(0, 4)}-${digits.substring(4, 6)}-${digits.substring(6, 8)}T00:00:00Z',
        );
  if (!_enabled ||
      date == null ||
      date.toUtc().toIso8601String().substring(0, 10).replaceAll('-', '') !=
          runMatch![1] ||
      _run.length > 48 ||
      (_disabledApiProbe && _run != _disabledApiProbeRun) ||
      !RegExp(r'^[a-f0-9]{40}$').hasMatch(_revision) ||
      !RegExp(r'^[a-f0-9]{40}$').hasMatch(_tree) ||
      !{'sender', 'receiver'}.contains(_roleName)) {
    throw StateError('company-user-validation-arguments-refused');
  }
  if ((_roleName == 'sender' && !Platform.isWindows) ||
      (_roleName == 'receiver' && !Platform.isMacOS)) {
    throw StateError('company-user-validation-host-refused');
  }
  return _roleName == 'sender'
      ? ValidationRole.sender
      : ValidationRole.receiver;
}

Future<Map<String, Object?>> readCompanyUserValidationProjection(
  CompanyEnrollment enrollment,
  InstallationSecurity installation, {
  required String run,
  required String roleName,
}) async {
  final namespace = validationInstallationNamespace(
    run: run,
    roleName: roleName,
  );
  if (!namespace.startsWith('synthetic.lan.$roleName.') ||
      namespace != installation.namespace) {
    return {'present': false, 'available': false};
  }
  final saved = <int, ProtectedInstallationState?>{};
  try {
    for (var slot = 1; slot <= kCompanyUserCapacity; slot++) {
      saved[slot] = await installation.store.readState(
        companyUserNamespace(namespace, slot: slot),
      );
    }
    final additional = (await enrollment.listCompanyUsers()).skip(1).toList();
    final occupied = saved.values
        .whereType<ProtectedInstallationState>()
        .length;
    if (additional.length != occupied ||
        additional.any((user) => user.userId.isEmpty)) {
      throw const FormatException('unavailable');
    }
    final users = <Map<String, Object?>>[];
    for (final choice in additional) {
      final lifecycle = await enrollment.userLifecycleStatus(
        userId: choice.userId,
      );
      if (lifecycle == null || lifecycle.disabled != choice.disabled) {
        throw const FormatException('unavailable');
      }
      users.add({
        'present': true,
        'byteLength': lifecycle.protectedByteLength,
        'available': choice.available,
        'disabled': lifecycle.disabled,
        'attemptsRemaining': lifecycle.attemptsRemaining,
        'disableReceiptSaved': lifecycle.disabled && lifecycle.confirmed,
        'awaitingCredential': lifecycle.awaitingCredential,
        'credentialReceiptSaved':
            !lifecycle.disabled &&
            lifecycle.credentialVersion > 1 &&
            lifecycle.confirmed,
        'certificatePublic': {
          'userId': choice.userId,
          'credentialVersion': lifecycle.credentialVersion,
          'permissionVersion': lifecycle.permissionVersion,
        },
      });
    }
    // Public IDs route the projection; locator order is only used for stable rereads.
    for (var slot = 1; slot <= kCompanyUserCapacity; slot++) {
      final latest = await installation.store.readState(
        companyUserNamespace(namespace, slot: slot),
      );
      final before = saved[slot];
      if ((before == null) != (latest == null) ||
          (before != null &&
              (latest!.revision != before.revision ||
                  !_sameBytes(latest.bytes, before.bytes)))) {
        throw const FormatException('unavailable');
      }
    }
    final sizes = saved.values
        .whereType<ProtectedInstallationState>()
        .map((state) => state.bytes.length)
        .toList();
    return {
      'present': users.isNotEmpty,
      'available':
          users.isNotEmpty && users.every((user) => user['available'] == true),
      'capacity': kCompanyUserCapacity,
      'byteLengths': sizes,
      'users': users,
      // Retain the existing single-user receipt fields for historical readers.
      if (users.length == 1) ...users.single,
      if (users.length == 1) 'byteLength': sizes.single,
    };
  } catch (_) {
    return {
      'present': saved.values.any((state) => state != null),
      'available': false,
    };
  }
}

bool _sameBytes(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) return false;
  }
  return true;
}

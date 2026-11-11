import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:drift/native.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:wired_parts/app.dart';
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/installation/installation_security.dart';

import '../../tool/company_users_native_validation.dart';
import '../../tool/nearby_lan_validation.dart';
import '../../tool/nearby_lan_workspace.dart';

final class _NativeDelegate extends NativeInstallationSecureStore {
  Object? failure;
  ProtectedInstallationState? state;
  String resultRevision = 'unchanged-public-revision';
  String? namespace, expectedRevision, nextRevision;
  Uint8List? bytes;
  int reads = 0, writes = 0;

  @override
  Future<ProtectedInstallationState?> readState(String namespace) async {
    reads++;
    this.namespace = namespace;
    if (failure case final error?) {
      throw error;
    }
    return state;
  }

  @override
  Future<String> compareAndSwapState(
    String namespace, {
    required String? expectedRevision,
    required String nextRevision,
    required Uint8List bytes,
  }) async {
    writes++;
    this.namespace = namespace;
    this.expectedRevision = expectedRevision;
    this.nextRevision = nextRevision;
    this.bytes = bytes;
    if (failure case final error?) {
      throw error;
    }
    return resultRevision;
  }
}

final class _ThrowingDetails extends MapBase<Object?, Object?> {
  @override
  Iterable<Object?> get keys => throw StateError('unexportable-test-value');
  @override
  Object? operator [](Object? key) =>
      throw StateError('unexportable-test-value');
  @override
  void operator []=(Object? key, Object? value) =>
      throw UnsupportedError('write');
  @override
  void clear() => throw UnsupportedError('clear');
  @override
  Object? remove(Object? key) => throw UnsupportedError('remove');
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('wired_parts/installation_security');

  test('only the designated ordinary run adds a Windows receiver', () {
    const run = 'g2-users-20261109-peer-member-win';
    bool allows(
      String operatingSystem,
      String roleName, {
      String validationRun = run,
      bool disabledApiProbe = false,
      bool networkDiagnostic = false,
    }) => companyUserValidationHostAllowed(
      operatingSystem: operatingSystem,
      roleName: roleName,
      run: validationRun,
      disabledApiProbe: disabledApiProbe,
      networkDiagnostic: networkDiagnostic,
    );

    expect(allows('windows', 'receiver'), isTrue);
    expect(
      allows('windows', 'receiver', validationRun: 'g2-users-20261109-other'),
      isFalse,
    );
    expect(allows('windows', 'receiver', disabledApiProbe: true), isFalse);
    expect(allows('windows', 'receiver', networkDiagnostic: true), isFalse);
    expect(allows('windows', 'sender', validationRun: 'existing'), isTrue);
    expect(allows('macos', 'receiver', validationRun: 'existing'), isTrue);
    expect(allows('macos', 'sender'), isFalse);
    expect(allows('linux', 'receiver'), isFalse);
    expect(allows('windows', 'owner'), isFalse);
  });

  ValidationWorkspace owned() {
    final temporary = Directory.systemTemp.createTempSync(
      'startup-receipt-test-',
    );
    final workspace = ValidationWorkspace.open(
      run: 'g2-users-20261026-startup-a',
      role: ValidationRole.receiver,
      temporaryDirectory: temporary,
    );
    workspace.markInitialized();
    addTearDown(() {
      workspace.close();
      expect(
        temporary.resolveSymbolicLinksSync(),
        startsWith(Directory.systemTemp.resolveSymbolicLinksSync()),
      );
      temporary.deleteSync(recursive: true);
    });
    return workspace;
  }

  CompanyUserStartupFailureReporter reporter({
    bool enabled = true,
    String run = 'g2-users-20261026-startup-a',
    String? revision,
  }) => CompanyUserStartupFailureReporter(
    enabled: enabled,
    run: run,
    role: 'receiver',
    sourceRevision: revision ?? 'a' * 40,
    sourceTree: 'b' * 40,
    processId: 123,
    observation: DateTime.utc(2026, 10, 26),
  );

  const unavailable = CompanyUserStartupFailure(
    CompanyUserStartupStage.protectedStore,
    InstallationReadiness.unavailable,
  );

  testWidgets(
    'unavailable native storage refuses before writing device identity',
    (tester) async {
      final previousPlatform = debugDefaultTargetPlatformOverride;
      final previousPaths = PathProviderPlatform.instance;
      final temporary = Directory.systemTemp.createTempSync(
        'startup-failure-test-',
      );
      final workspace = ValidationWorkspace.open(
        run: 'g2-users-20261026-startup-a',
        role: ValidationRole.receiver,
        temporaryDirectory: temporary,
      );
      final file = File(p.join(workspace.support.path, 'wired_parts.sqlite'));
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      var reads = 0;
      final observedStore = ObservedCompanyUserNativeStore(macOS: true);
      debugDefaultTargetPlatformOverride = TargetPlatform.windows;
      messenger.setMockMethodCallHandler(channel, (call) async {
        reads++;
        expect(call.method, 'readState');
        throw PlatformException(
          code: 'installation_unavailable',
          message: 'unexportable-test-value',
          details: {'osStatus': -25308},
        );
      });
      try {
        await tester.runAsync(() async {
          final seed = AppDatabase.forTesting(NativeDatabase(file));
          expect(
            await seed.customSelect('SELECT id FROM device_profiles').get(),
            isEmpty,
          );
          await seed.close();
        });
        workspace.markInitialized();
        final before = sha256.convert(file.readAsBytesSync()).toString();
        Object? failure;
        WiredPartsApp? returned;
        ValidationApplicationStage? stage;
        InstallationReadiness? readiness;
        await tester.runAsync(() async {
          try {
            returned = await validationApplication(
              workspace,
              installationStore: observedStore,
              onStartupStage: (current, observed) {
                stage = current;
                readiness = observed;
              },
            );
          } catch (error) {
            failure = error;
          } finally {
            await returned?.db.close();
          }
        });
        expect(reads, 1);
        expect(
          failure,
          isNotNull,
          reason: 'An unavailable protected store must refuse before ensureDeviceId',
        );
        expect(stage, ValidationApplicationStage.protectedStore);
        expect(readiness, InstallationReadiness.unavailable);
        expect(sha256.convert(file.readAsBytesSync()).toString(), before);
        final moved = file.renameSync('${file.path}.closed');
        moved.renameSync(file.path);
        expect(
          await finishCompanyUserStartupFailure(
            failure: CompanyUserStartupFailure(
              CompanyUserStartupStage.protectedStore,
              readiness,
              nativeFailure: observedStore.firstFailure,
            ),
            workspace: workspace,
            reporter: reporter(),
          ),
          isTrue,
        );
        final receiptFile = workspace.receipts
            .listSync()
            .whereType<File>()
            .single;
        final text = receiptFile.readAsStringSync();
        final receipt = jsonDecode(text) as Map;
        expect(receipt['nativeFailure'], {
          'operation': 'readState',
          'domain': 'keychain',
          'reason': 'interactionNotAllowed',
        });
        expect(receipt.keys.toSet(), {
          'kind',
          'passed',
          'run',
          'role',
          'sourceRevision',
          'sourceTree',
          'pid',
          'observedUtc',
          'stage',
          'category',
          'installationReadiness',
          'nativeFailure',
        });
        expect(receipt['kind'], 'company-user-startup-failure@1');
        expect(receipt['passed'], isFalse);
        expect(receipt['stage'], 'protectedStore');
        expect(receipt['category'], 'installationUnavailable');
        expect(receipt['installationReadiness'], 'unavailable');
        expect(receiptFile.lengthSync(), lessThanOrEqualTo(1024));
        for (final forbidden in [
          'unexportable-test-value',
          'osStatus',
          '-25308',
          file.path,
        ]) {
          expect(text, isNot(contains(forbidden)));
        }
        final reopened = ValidationWorkspace.open(
          run: workspace.run,
          role: workspace.role,
          temporaryDirectory: temporary,
        );
        reopened.close();
        expect(sha256.convert(file.readAsBytesSync()).toString(), before);
      } finally {
        messenger.setMockMethodCallHandler(channel, null);
        debugDefaultTargetPlatformOverride = previousPlatform;
        PathProviderPlatform.instance = previousPaths;
        workspace.close();
        expect(
          temporary.resolveSymbolicLinksSync(),
          startsWith(Directory.systemTemp.resolveSymbolicLinksSync()),
        );
        temporary.deleteSync(recursive: true);
      }
    },
  );

  testWidgets(
    'ready native startup preserves routing and creates no failure receipt',
    (tester) async {
      final workspace = owned();
      final previousPlatform = debugDefaultTargetPlatformOverride;
      final previousPaths = PathProviderPlatform.instance;
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      final states = <String, Map<String, Object?>>{};
      debugDefaultTargetPlatformOverride = TargetPlatform.windows;
      messenger.setMockMethodCallHandler(channel, (call) async {
        final args = call.arguments as Map;
        final namespace = args['namespace'] as String;
        if (call.method == 'readState') return states[namespace];
        if (call.method == 'compareAndSwapState') {
          states[namespace] = {
            'revision': args['nextRevision'],
            'bytes': args['bytes'],
          };
          return {'revision': args['nextRevision']};
        }
        throw UnsupportedError(call.method);
      });
      WiredPartsApp? app;
      ValidationApplicationStage? last;
      InstallationReadiness? readiness;
      try {
        app = await tester.runAsync(
          () => validationApplication(
            workspace,
            onStartupStage: (stage, observed) {
              last = stage;
              readiness = observed;
            },
          ),
        );
        expect(app!.installation!.readiness, InstallationReadiness.ready);
        expect(last, ValidationApplicationStage.appConstruction);
        expect(readiness, InstallationReadiness.ready);
        expect(workspace.receipts.listSync(), isEmpty);
        expect(
          await tester.runAsync(
            () async =>
                (await app!.db
                        .customSelect('SELECT id FROM device_profiles')
                        .get())
                    .length,
          ),
          1,
        );
      } finally {
        await tester.runAsync(() async {
          await app?.db.close();
        });
        messenger.setMockMethodCallHandler(channel, null);
        debugDefaultTargetPlatformOverride = previousPlatform;
        PathProviderPlatform.instance = previousPaths;
      }
    },
  );

  testWidgets('native CAS failure is classified before startup swallows it', (
    tester,
  ) async {
    final workspace = owned();
    final previousPlatform = debugDefaultTargetPlatformOverride;
    final previousPaths = PathProviderPlatform.instance;
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    final file = File(p.join(workspace.support.path, 'wired_parts.sqlite'));
    var reads = 0, writes = 0;
    final observed = ObservedCompanyUserNativeStore(macOS: true);
    debugDefaultTargetPlatformOverride = TargetPlatform.windows;
    PathProviderPlatform.instance = workspace;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'readState') {
        reads++;
        return null;
      }
      expect(call.method, 'compareAndSwapState');
      writes++;
      throw PlatformException(
        code: 'installation_unavailable',
        message: 'unexportable-test-value',
        details: {'osStatus': -34018},
      );
    });
    WiredPartsApp? returned;
    Object? failure;
    InstallationReadiness? readiness;
    try {
      await tester.runAsync(() async {
        final seed = AppDatabase();
        expect(
          await seed.customSelect('SELECT id FROM device_profiles').get(),
          isEmpty,
        );
        await seed.close();
      });
      final before = sha256.convert(file.readAsBytesSync()).toString();
      await tester.runAsync(() async {
        try {
          returned = await validationApplication(
            workspace,
            installationStore: observed,
            onStartupStage: (_, value) {
              readiness = value;
            },
          );
        } catch (error) {
          failure = error;
        } finally {
          await returned?.db.close();
        }
      });
      expect(failure, isNotNull);
      expect(reads, 1);
      expect(writes, 1);
      expect(readiness, InstallationReadiness.unavailable);
      expect(observed.firstFailure!.toJson(), {
        'operation': 'compareAndSwapState',
        'domain': 'keychain',
        'reason': 'missingEntitlement',
      });
      expect(sha256.convert(file.readAsBytesSync()).toString(), before);
      final moved = file.renameSync('${file.path}.closed');
      moved.renameSync(file.path);
      expect(
        await finishCompanyUserStartupFailure(
          failure: CompanyUserStartupFailure(
            CompanyUserStartupStage.protectedStore,
            readiness,
            nativeFailure: observed.firstFailure,
          ),
          workspace: workspace,
          reporter: reporter(),
        ),
        isTrue,
      );
      final text = workspace.receipts
          .listSync()
          .whereType<File>()
          .single
          .readAsStringSync();
      expect(text, isNot(contains('unexportable-test-value')));
      expect(text, isNot(contains('-34018')));
      expect(utf8.encode(text).length, lessThanOrEqualTo(1024));
    } finally {
      messenger.setMockMethodCallHandler(channel, null);
      debugDefaultTargetPlatformOverride = previousPlatform;
      PathProviderPlatform.instance = previousPaths;
    }
  });

  test('closed claim and invalid metadata cannot publish', () {
    final workspace = owned();
    for (final invalid in [
      reporter(enabled: false),
      reporter(run: 'invalid'),
      reporter(revision: 'private-value'),
    ]) {
      expect(() => invalid.publish(workspace, unavailable), throwsStateError);
    }
    expect(workspace.receipts.listSync(), isEmpty);
    workspace.close();
    expect(() => reporter().publish(workspace, unavailable), throwsStateError);
    expect(workspace.receipts.listSync(), isEmpty);
  });

  for (final directory in [false, true]) {
    test('occupied ${directory ? 'directory' : 'file'} target is preserved', () {
      final workspace = owned();
      final target = p.join(
        workspace.receipts.path,
        'company-user-startup-failure-123-${DateTime.utc(2026, 10, 26).microsecondsSinceEpoch}.json',
      );
      if (directory) {
        Directory(target).createSync();
      } else {
        File(target).writeAsStringSync('preserve-public-sentinel');
      }
      expect(
        () => reporter().publish(workspace, unavailable),
        throwsStateError,
      );
      if (directory) {
        expect(Directory(target).existsSync(), isTrue);
      } else {
        expect(File(target).readAsStringSync(), 'preserve-public-sentinel');
      }
    });
  }

  test('redirected receipts refuse without writing into target', () {
    final workspace = owned();
    final target = Directory(
      p.join(workspace.root.parent.path, 'redirect-target'),
    )..createSync();
    workspace.receipts.renameSync('${workspace.receipts.path}-original');
    final link = Link(workspace.receipts.path)..createSync(target.path);
    try {
      expect(
        () => reporter().publish(workspace, unavailable),
        throwsStateError,
      );
      expect(target.listSync(), isEmpty);
    } finally {
      link.deleteSync();
    }
  });

  test(
    'non-directory receipts and changed owner marker refuse publication',
    () {
      final workspace = owned();
      final marker = File(p.join(workspace.root.path, 'validation-owner.json'));
      final original = marker.readAsStringSync();
      marker.writeAsStringSync(
        jsonEncode({...jsonDecode(original) as Map, 'run': 'different'}),
      );
      expect(
        () => reporter().publish(workspace, unavailable),
        throwsStateError,
      );
      expect(workspace.receipts.listSync(), isEmpty);
      marker.writeAsStringSync(original);
      workspace.receipts.renameSync('${workspace.receipts.path}-original');
      final sentinel = File(workspace.receipts.path)
        ..writeAsStringSync('preserve');
      expect(
        () => reporter().publish(workspace, unavailable),
        throwsStateError,
      );
      expect(sentinel.readAsStringSync(), 'preserve');
    },
  );

  test(
    'publication and close errors preserve failure and release claim',
    () async {
      final workspace = owned();
      final closed = <String>[];
      expect(
        await finishCompanyUserStartupFailure(
          failure: unavailable,
          workspace: workspace,
          reporter: reporter(enabled: false),
          closeTransport: () async {
            closed.add('transport');
            throw StateError('unexportable');
          },
          closeDatabase: () async {
            closed.add('database');
            throw StateError('unexportable');
          },
        ),
        isFalse,
      );
      expect(closed, ['transport', 'database']);
      expect(
        unavailable.category,
        CompanyUserStartupCategory.installationUnavailable,
      );
      expect(workspace.receipts.listSync(), isEmpty);
      expect(() => workspace.requireOwnedReceipts(), throwsStateError);
      final reopened = ValidationWorkspace.open(
        run: workspace.run,
        role: workspace.role,
        temporaryDirectory: workspace.root.parent,
      );
      reopened.close();
    },
  );

  test(
    'native observer delegates successful arguments and results unchanged',
    () async {
      final delegate = _NativeDelegate()
        ..state = ProtectedInstallationState(
          'public-revision',
          Uint8List.fromList([1, 2]),
        );
      final store = ObservedCompanyUserNativeStore(
        delegate: delegate,
        macOS: true,
      );
      const namespace = 'synthetic.lan.receiver.test';
      expect(await store.readState(namespace), same(delegate.state));
      expect(delegate.namespace, same(namespace));
      final bytes = Uint8List.fromList([3, 4]);
      const expected = 'expected-public-revision',
          next = 'next-public-revision';
      expect(
        await store.compareAndSwapState(
          namespace,
          expectedRevision: expected,
          nextRevision: next,
          bytes: bytes,
        ),
        same(delegate.resultRevision),
      );
      expect(delegate.namespace, same(namespace));
      expect(delegate.expectedRevision, same(expected));
      expect(delegate.nextRevision, same(next));
      expect(delegate.bytes, same(bytes));
      expect(delegate.reads, 1);
      expect(delegate.writes, 1);
      expect(store.firstFailure, isNull);
    },
  );

  test(
    'native observer preserves exact exceptions and first failure',
    () async {
      final first = PlatformException(
        code: 'installation_unavailable',
        details: {'errno': 5},
      );
      final second = PlatformException(
        code: 'installation_unavailable',
        details: {'osStatus': -34018},
      );
      final delegate = _NativeDelegate()..failure = first;
      final store = ObservedCompanyUserNativeStore(
        delegate: delegate,
        macOS: true,
      );
      await expectLater(
        store.readState('synthetic.lan.receiver.test'),
        throwsA(same(first)),
      );
      final captured = store.firstFailure;
      expect(captured!.toJson(), {
        'operation': 'readState',
        'domain': 'posix',
        'reason': 'ioFailure',
      });
      delegate.failure = second;
      final bytes = Uint8List.fromList([1]);
      await expectLater(
        store.compareAndSwapState(
          'synthetic.lan.receiver.test',
          expectedRevision: null,
          nextRevision: 'public-revision',
          bytes: bytes,
        ),
        throwsA(same(second)),
      );
      expect(delegate.bytes, same(bytes));
      expect(delegate.writes, 1);
      expect(store.firstFailure, same(captured));
      final other = StateError('unchanged non-platform failure');
      final unobserved = ObservedCompanyUserNativeStore(
        delegate: _NativeDelegate()..failure = other,
        macOS: true,
      );
      await expectLater(
        unobserved.readState('synthetic.lan.receiver.test'),
        throwsA(same(other)),
      );
      expect(unobserved.firstFailure, isNull);
    },
  );

  test(
    'Mac native definitions remain domain-specific for both operations',
    () async {
      final cases = <(String, int, String, String)>[
        ('osStatus', -25308, 'keychain', 'interactionNotAllowed'),
        ('osStatus', -34018, 'keychain', 'missingEntitlement'),
        ('osStatus', -25291, 'keychain', 'notAvailable'),
        ('osStatus', -25293, 'keychain', 'authFailed'),
        ('osStatus', -36, 'keychain', 'ioFailure'),
        ('errno', 1, 'posix', 'permissionDenied'),
        ('errno', 13, 'posix', 'permissionDenied'),
        ('errno', 5, 'posix', 'ioFailure'),
        ('errno', 16, 'posix', 'busy'),
        ('osStatus', 13, 'keychain', 'unknown'),
        ('errno', -25308, 'posix', 'unknown'),
        ('osStatus', -99999, 'keychain', 'unknown'),
        ('errno', 99999, 'posix', 'unknown'),
      ];
      for (final operation in CompanyUserNativeOperation.values) {
        for (final entry in cases) {
          final error = PlatformException(
            code: 'installation_unavailable',
            message: 'unexportable-test-value',
            details: {entry.$1: entry.$2},
          );
          final delegate = _NativeDelegate()..failure = error;
          final store = ObservedCompanyUserNativeStore(
            delegate: delegate,
            macOS: true,
          );
          await expectLater(
            operation == CompanyUserNativeOperation.readState
                ? store.readState('synthetic.lan.receiver.test')
                : store.compareAndSwapState(
                    'synthetic.lan.receiver.test',
                    expectedRevision: null,
                    nextRevision: 'public-revision',
                    bytes: Uint8List(0),
                  ),
            throwsA(same(error)),
          );
          expect(store.firstFailure!.toJson(), {
            'operation': operation.name,
            'domain': entry.$3,
            'reason': entry.$4,
          });
        }
      }
    },
  );

  test('malformed details and observer errors stay unknown without replacing native error', () async {
    final details = <Object?>[
      null,
      'unexportable-test-value',
      {},
      {'osStatus': '-25308'},
      {'osStatus': true},
      {'osStatus': -25308.0},
      {'osStatus': -2147483649},
      {'errno': 2147483648},
      {'private': 'unexportable-test-value'},
      {'osStatus': -25308, 'private': 'unexportable-test-value'},
      {'osStatus': -25308, 'errno': 5},
      _ThrowingDetails(),
    ];
    for (final value in details) {
      final error = PlatformException(
        code: 'installation_unavailable',
        message: 'unexportable-test-value',
        details: value,
      );
      final store = ObservedCompanyUserNativeStore(
        delegate: _NativeDelegate()..failure = error,
        macOS: true,
      );
      await expectLater(
        store.readState('synthetic.lan.receiver.test'),
        throwsA(same(error)),
      );
      expect(store.firstFailure!.toJson(), {
        'operation': 'readState',
        'domain': 'platform',
        'reason': 'unknown',
      });
      final text = jsonEncode(store.firstFailure!.toJson());
      expect(text, isNot(contains('unexportable-test-value')));
      expect(text, isNot(contains('osStatus')));
    }
    for (final macOS in [false, true]) {
      final error = PlatformException(
        code: macOS ? 'unexpected-code' : 'installation_unavailable',
        details: {'osStatus': -25308},
      );
      final store = ObservedCompanyUserNativeStore(
        delegate: _NativeDelegate()..failure = error,
        macOS: macOS,
      );
      await expectLater(
        store.readState('synthetic.lan.receiver.test'),
        throwsA(same(error)),
      );
      expect(store.firstFailure!.domain, CompanyUserNativeDomain.platform);
      expect(store.firstFailure!.reason, CompanyUserNativeReason.unknown);
    }
  });

  test('fixed categories and one bounded attempt never expand error text', () {
    final workspace = owned();
    const expected = {
      InstallationReadiness.unsupported:
          CompanyUserStartupCategory.installationUnsupported,
      InstallationReadiness.unavailable:
          CompanyUserStartupCategory.installationUnavailable,
      InstallationReadiness.needsRecovery:
          CompanyUserStartupCategory.installationRecoveryRequired,
      InstallationReadiness.ready:
          CompanyUserStartupCategory.installationIdentityMissing,
    };
    for (final entry in expected.entries) {
      expect(
        CompanyUserStartupFailure(
          CompanyUserStartupStage.protectedStore,
          entry.key,
        ).category,
        entry.value,
      );
    }
    expect(
      const CompanyUserStartupFailure(
        CompanyUserStartupStage.receiptWrite,
        InstallationReadiness.ready,
      ).category,
      CompanyUserStartupCategory.stageFailed,
    );
    final once = reporter();
    final file = once.publish(workspace, unavailable);
    final before = file.readAsBytesSync();
    expect(() => once.publish(workspace, unavailable), throwsStateError);
    expect(file.readAsBytesSync(), before);
    expect(workspace.receipts.listSync(), hasLength(1));
  });
}

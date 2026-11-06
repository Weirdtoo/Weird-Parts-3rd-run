import 'dart:convert';
import 'dart:typed_data';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:drift/native.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:wired_parts/data/app_database.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/installation/installation_security.dart';

import 'company_join_test.dart'
    show JoinFixture, JoinActivationStore, canonicalJoinTest, joinChannels;

const _maximum = 9007199254740991;
const _domain = 'wiredpart.company.user.state@1:';

final class _SignedFixture {
  _SignedFixture(
    this.f,
    this.db,
    this.installation,
    this.store,
    this.enrollment,
    this.original,
    this.rootKey,
    this.privateMaterial,
  );
  final JoinFixture f;
  final AppDatabase db;
  final InstallationSecurity installation;
  final JoinActivationStore store;
  final CompanyEnrollment enrollment;
  final String original;
  final SimpleKeyPair rootKey;
  final List<Object?> privateMaterial;
  bool _joined = false;

  static Future<_SignedFixture> create(String name, {int authority = 1}) async {
    final f = await JoinFixture.create();
    addTearDown(f.closeAndCheckOwnerData);
    var db = f.aDb;
    var installation = f.a;
    var store = f.aStore;
    var enrollment = f.aEnrollment;
    var owner = f.owner;
    var source = File('${f.root.path}/a.wpca');
    var passphrase = 'synthetic durable authority phrase';
    for (var version = 2; version <= authority; version++) {
      final nextDb = AppDatabase.forTesting(
        NativeDatabase(File('${f.root.path}/authority-$version.sqlite')),
      );
      addTearDown(nextDb.close);
      store = JoinActivationStore();
      installation = InstallationSecurity(
        store: store,
        namespace: 'synthetic.codec-authority-$version',
      );
      await installation.start(nextDb);
      enrollment = CompanyEnrollment(installation: installation, db: nextDb);
      final destination = File('${f.root.path}/authority-$version.wpca');
      await enrollment.recover(
        policy: CompanyContinuityPolicy.localContinuity,
        sourceFile: source,
        sourcePassphrase: passphrase,
        newPin: '1234',
        newRecoveryPassphrase: 'synthetic codec authority phrase',
        newRecoveryFile: destination,
      );
      owner = await enrollment.signIn('1234');
      source = destination;
      passphrase = 'synthetic codec authority phrase';
      db = nextDb;
    }
    final user = await enrollment.createRestrictedUser(
      owner: owner,
      requestId: const Uuid().v4(),
      name: name,
      pin: '0123',
    );
    final custody = jsonDecode(
      utf8.decode(
        store.states[companyCustodyNamespace(installation.namespace)]!.bytes,
      ),
    ) as Map;
    return _SignedFixture(
      f,
      db,
      installation,
      store,
      enrollment,
      user.certificateBytes,
      await Ed25519().newKeyPairFromSeed(
        base64Decode(custody['rootSeed'] as String),
      ),
      [1, custody['pinSalt'], custody['pinVerifier']],
    );
  }

  Future<List<Object?>> certificate({
    int sequence = _maximum - 1,
    int credential = _maximum - 1,
    int status = 0,
    String? request,
    String? lastReset,
    String? previous,
  }) async {
    final original = jsonDecode(this.original) as Map;
    final b = original['body'] as Map;
    final operation = request ?? const Uuid().v4();
    final body = <Object?>[
      2,
      b['company'],
      b['shop'],
      b['authority'],
      b['facts'],
      b['user'],
      b['name'],
      [
        b['issuer'],
        b['device'],
        b['request'],
        b['authority'],
        b['facts'],
        original['signature'],
      ],
      sequence,
      credential,
      1,
      ['createJob'],
      status,
      operation,
      lastReset ?? operation,
      previous ?? 'f' * 64,
    ];
    return signBody(body);
  }

  Future<List<Object?>> signBody(List<Object?> body) async {
    final signature = await Ed25519().sign(
      utf8.encode('$_domain${canonicalJoinTest(body)}'),
      keyPair: rootKey,
    );
    return [body, base64Encode(signature.bytes)];
  }

  Map<String, Object?> record(
    List<Object?> certificate, {
    List<Object?>? credential,
    int attempts = 8,
    Object? delivery,
    Object? receipt,
    Object? projection,
  }) => {
    'v': 3,
    'c': certificate,
    'b': [
      installation.identity!.id.value,
      installation.identity!.generation.value,
      base64Encode(installation.identity!.publicKey),
      installation.receivingStoreGeneration!.value,
    ],
    'p': credential ?? privateMaterial,
    'a': attempts,
    'o': delivery,
    'r': receipt,
    'j': projection,
  };

  Future<CompanyUserStateRecord> decode(Map<String, Object?> record) =>
      CompanyUserStateRecord.decode(
        Uint8List.fromList(utf8.encode(canonicalJoinTest(record))),
        db: db,
        installation: installation,
      );

  Future<Map<String, Object?>> fullRecord(
    List<Object?> certificate, {
    bool received = false,
    bool confirmed = true,
  }) async {
    if (!_joined) {
      final (bc, ac) = await joinChannels();
      final a = CompanyJoin(enrollment: enrollment);
      final b = CompanyJoin(enrollment: f.bEnrollment);
      final request = await a.receiveJoinRequest(ac, await b.beginJoin(bc));
      await b.acceptProvision(
        await b.receiveProvision(
          bc,
          await a.approveJoin(
            ac,
            request,
            ownerSession: enrollment.currentSession!,
          ),
        ),
      );
      bc.close();
      ac.close();
      _joined = true;
    }
    Future<List<Object?>> binding(
      InstallationSecurity i,
      AppDatabase db,
    ) async {
      final m = await resolveCompanyMembership(db: db, installation: i);
      return [
        m.device['id'],
        m.device['installation'],
        m.device['generation'],
        m.device['key'],
        i.receivingStoreGeneration!.value,
        m.device['grant'],
      ];
    }

    final source = await binding(installation, db);
    final recipient = await binding(f.b, f.bDb);
    final request = (certificate[0] as List)[13];
    final target = [
      received ? 1 : 0,
      request,
      ...(received ? source : recipient),
    ];
    final result = record(
      certificate,
      delivery: target,
      projection: ['f' * 64, ((certificate[0] as List)[8] as int) - 1],
    );
    if (received) {
      result['b'] = [
        f.b.identity!.id.value,
        f.b.identity!.generation.value,
        base64Encode(f.b.identity!.publicKey),
        f.b.receivingStoreGeneration!.value,
      ];
    }
    if (confirmed) {
      final bRecord =
          jsonDecode(utf8.decode(f.bStore.states[f.b.namespace]!.bytes)) as Map;
      final key = await Ed25519().newKeyPairFromSeed(
        base64Decode(bRecord['seed'] as String),
      );
      final body = {
        'v': 1,
        'kind': 'company.user.state.receipt@1',
        'certificate': hashes.sha256
            .convert(utf8.encode(canonicalJoinTest(certificate)))
            .toString(),
        'request': request,
        'source': source,
        'recipient': recipient,
      };
      final signature = await Ed25519().sign(
        utf8.encode(
          'wiredpart.company.user.state.receipt@1:${canonicalJoinTest(body)}',
        ),
        keyPair: key,
      );
      result['r'] = base64Encode(signature.bytes);
    }
    return result;
  }
}

void main() {
  test(
    'integer discriminants refuse signed floating-point encodings',
    () async {
      final f = await _SignedFixture.create('Integer format');
      final packed = await f.certificate(sequence: 2, credential: 2);
      final wrongRecordTag = f.record(packed)..['v'] = 3.0;
      await expectLater(
        f.decode(wrongRecordTag),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      for (final index in [0, 10, 12]) {
        final body = List<Object?>.from(
          jsonDecode(canonicalJoinTest(packed[0])) as List,
        );
        body[index] = (body[index] as int).toDouble();
        await expectLater(
          f.decode(f.record(await f.signBody(body))),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
      }
      final wrongPinTag = f.record(packed)
        ..['p'] = [1.0, ...f.privateMaterial.skip(1)];
      await expectLater(
        f.decode(wrongPinTag),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
      final wrongDirection = await f.fullRecord(packed, confirmed: false);
      (wrongDirection['o'] as List)[0] = 0.0;
      await expectLater(
        f.decode(wrongDirection),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    },
  );
  test(
    'immediate projection predecessor must match the signed public head',
    () async {
      final f = await _SignedFixture.create('Projection predecessor');
      final packed = await f.certificate(sequence: 2, credential: 2);
      final contradicted = f.record(packed, projection: ['e' * 64, 1]);
      await expectLater(
        f.decode(contradicted),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    },
  );
  test(
    'active and awaiting states reserve a final terminal sequence',
    () async {
      final f = await _SignedFixture.create('Sequence ceiling');
      for (final awaiting in [false, true]) {
        final exhausted = f.record(
          await f.certificate(sequence: _maximum, credential: _maximum),
        );
        if (awaiting) exhausted['p'] = null;
        await expectLater(
          f.decode(exhausted),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
      }
    },
  );
  test(
    'terminal state requires a lifecycle step after its last credential reset',
    () async {
      final f = await _SignedFixture.create('Terminal sequence');
      final impossible = f.record(
        await f.certificate(status: 1, lastReset: const Uuid().v4()),
      )..['p'] = null;
      await expectLater(
        f.decode(impossible),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    },
  );
  test('signed proposed codec round-trips actual root provenance and binding without a write', () async {
    final f = await _SignedFixture.create('\\' * 64);
    final before = Map.of(f.f.aStore.states);
    final record = f.record(
      await f.certificate(),
      projection: ['f' * 64, _maximum - 2],
    );
    final decoded = await f.decode(record);
    expect(utf8.decode(decoded.encode()), canonicalJoinTest(record));
    expect(decoded.certificate.originalCertificateBytes, f.original);
    expect(decoded.status, CompanyUserStateStatus.active);
    expect(decoded.encode().length, lessThanOrEqualTo(kInstallationStateLimit));
    expect(f.f.aStore.states.keys, before.keys);
    for (final key in before.keys) {
      expect(f.f.aStore.states[key]!.revision, before[key]!.revision);
      expect(f.f.aStore.states[key]!.bytes, before[key]!.bytes);
    }
  });

  for (final shape in <String, String>{
    'backslash': '\\' * 64,
    'quote': '"' * 64,
    'multibyte': '😀' * 16,
    'separator': 'xx${'\u2028' * 20}yz',
  }.entries) {
    test(
      'actual signed ${shape.key} maximum-width current and later terminal shapes fit',
      () async {
        final f = await _SignedFixture.create(shape.value);
        final certificate = await f.certificate();
        final current = await f.fullRecord(certificate);
        var maximum = 0;
        for (final received in [false, true]) {
          for (final confirmed in [false, true]) {
            for (final mode in ['active', 'awaiting', 'disabled']) {
              final packed = mode == 'disabled'
                  ? await f.certificate(
                      sequence: _maximum,
                      status: 1,
                      credential: _maximum - 1,
                      lastReset: const Uuid().v4(),
                    )
                  : certificate;
              final raw = await f.fullRecord(
                packed,
                received: received,
                confirmed: confirmed,
              );
              if (mode != 'active') raw['p'] = null;
              final decoded = received
                  ? await CompanyUserStateRecord.decode(
                      Uint8List.fromList(utf8.encode(canonicalJoinTest(raw))),
                      db: f.f.bDb,
                      installation: f.f.b,
                    )
                  : await f.decode(raw);
              expect(utf8.decode(decoded.encode()), canonicalJoinTest(raw));
              expect(decoded.certificate.originalCertificateBytes, f.original);
              expect(
                decoded.status,
                mode == 'active'
                    ? CompanyUserStateStatus.active
                    : mode == 'awaiting'
                    ? CompanyUserStateStatus.awaitingCredential
                    : CompanyUserStateStatus.disabled,
              );
              expect(
                decoded.encode().length,
                lessThanOrEqualTo(kInstallationStateLimit),
              );
              if (decoded.encode().length > maximum) {
                maximum = decoded.encode().length;
              }
            }
          }
        }
        expect(current['r'], isNotNull);
        // The root-authority range is 1..17. Changing both authority fields
        // from one to two digits adds exactly two bytes. This is a structural
        // upper bound, not a claim that this altered signature is valid.
        final authorityWidthBound = Map<String, Object?>.from(
          jsonDecode(canonicalJoinTest(current)) as Map,
        );
        final widthBody = (authorityWidthBound['c'] as List)[0] as List;
        widthBody[3] = 17;
        (widthBody[7] as List)[3] = 17;
        final boundBytes = utf8
            .encode(canonicalJoinTest(authorityWidthBound))
            .length;
        expect(boundBytes, utf8.encode(canonicalJoinTest(current)).length + 2);
        expect(boundBytes, lessThanOrEqualTo(kInstallationStateLimit));
        stdout.writeln(
          'SIGNED_CODEC shape=${shape.key} max_record_bytes=$maximum authority=1 counter_digits=16 states=12',
        );
        stdout.writeln(
          'STRUCTURAL_CODEC shape=${shape.key} authority_width_bound_bytes=$boundBytes accepted_context=false',
        );
      },
    );
  }

  test('actual signed successor allows a second offline reset before ACK and terminal dominates replay', () async {
    final f = await _SignedFixture.create('Successor');
    final first = await f.certificate(sequence: 2, credential: 2);
    final prior = await f.decode(f.record(first));
    final second = await f.certificate(
      sequence: 3,
      credential: 3,
      previous: prior.certificate.publicHead,
    );
    final next = await f.decode(f.record(second));
    expect(
      next.validateSuccessor(prior),
      CompanyUserStateTransition.replacement,
    );
    final decremented = await f.decode(f.record(second, attempts: 6));
    expect(
      decremented.validateSuccessor(next),
      CompanyUserStateTransition.duplicate,
    );
    expect(
      () => next.validateSuccessor(decremented),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final terminal = await f.certificate(
      sequence: 4,
      credential: 3,
      status: 1,
      lastReset: next.certificate.lastPinResetRequest,
      previous: next.certificate.publicHead,
    );
    final terminalRaw = f.record(terminal, attempts: 6)..['p'] = null;
    final disabled = await f.decode(terminalRaw);
    expect(
      disabled.validateSuccessor(decremented),
      CompanyUserStateTransition.disabled,
    );
    final revival = await f.decode(
      f.record(
        await f.certificate(
          sequence: 5,
          credential: 5,
          previous: disabled.certificate.publicHead,
        ),
      ),
    );
    expect(
      () => revival.validateSuccessor(disabled),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    expect(
      () => prior.validateSuccessor(next),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final collision = await f.decode(
      f.record(
        await f.certificate(
          sequence: 3,
          credential: 3,
          previous: prior.certificate.publicHead,
        ),
      ),
    );
    expect(
      () => collision.validateSuccessor(next),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
  });

  test('real current floors apply to current epoch while original epoch-one provenance remains verifiable', () async {
    final previousProvider = Cryptography.instance;
    Cryptography.instance = DartCryptography.defaultInstance;
    addTearDown(() => Cryptography.instance = previousProvider);
    final f = await _SignedFixture.create('Floors');
    final packed = await f.certificate(sequence: 2, credential: 2);
    final trust = (await f.installation.readCompanyTrust(f.db))!;
    final user = (packed[0] as List)[5];
    final floors = {
      ...f.installation.knownSecurityFloors,
      'credential.$user': 2,
    };
    final saved = Map.of(floors);
    final certificate = await CompanyUserStateCertificate.verify(
      canonicalJoinTest(packed),
      db: f.db,
      trust: trust,
      floors: floors,
    );
    expect(certificate.originalCertificateBytes, f.original);
    expect(floors, saved);
    final beforeWarm = joinProofVerificationStatistics;
    await CompanyUserStateCertificate.verify(
      canonicalJoinTest(packed),
      db: f.db,
      trust: trust,
      floors: floors,
    );
    expect(
      joinProofVerificationStatistics.hits,
      greaterThanOrEqualTo(beforeWarm.hits + 2),
    );
    for (final extra in [
      {'credential.$user': 3},
      {'revocation.user.$user': 1},
      {'permission.$user': 2},
    ]) {
      await expectLater(
        CompanyUserStateCertificate.verify(
          canonicalJoinTest(packed),
          db: f.db,
          trust: trust,
          floors: {...floors, ...extra},
        ),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    }
  });

  test('strict signature shape context and secret boundaries refuse malformed inputs without writes', () async {
    final f = await _SignedFixture.create('Strict');
    final packed = await f.certificate();
    final raw = f.record(packed);
    final before = Map.of(f.store.states);
    final malformed = <Uint8List>[
      Uint8List.fromList(utf8.encode('${canonicalJoinTest(raw)} ')),
      Uint8List.fromList([255]),
      Uint8List(2049),
      Uint8List.fromList(
        utf8.encode(canonicalJoinTest({...raw, 'unknown': 'private-marker'})),
      ),
    ];
    for (final bytes in malformed) {
      Object? error;
      try {
        await CompanyUserStateRecord.decode(
          bytes,
          db: f.db,
          installation: f.installation,
        );
      } catch (e) {
        error = e;
      }
      expect(error, isA<CompanyBootstrapRefusal>());
      expect('$error'.contains('private-marker'), isFalse);
    }
    for (final mutation in <void Function(Map<String, Object?>)>[
      (r) => (r['b'] as List)[0] = const Uuid().v4(),
      (r) => r['a'] = 9,
      (r) => r['j'] = ['f' * 64, _maximum],
      (r) => r['p'] = [1, 'private-marker', 'private-marker'],
      (r) => (r['c'] as List)[1] = base64Encode(List<int>.filled(64, 0)),
      (r) => ((r['c'] as List)[0] as List).add(null),
    ]) {
      final changed = Map<String, Object?>.from(
        jsonDecode(canonicalJoinTest(raw)) as Map,
      );
      mutation(changed);
      await expectLater(
        f.decode(changed),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    }
    for (final mutate in <void Function(List<Object?>)>[
      (b) => b[0] = 3,
      (b) => b[2] = const Uuid().v4(),
      (b) => b[8] = _maximum + 1,
      (b) => b[9] = 1,
      (b) => b[10] = 2,
      (b) => b[11] = ['enrollDevice'],
      (b) => (b[7] as List)[5] = base64Encode(List<int>.filled(64, 0)),
    ]) {
      final body = List<Object?>.from(
        jsonDecode(canonicalJoinTest(packed[0])) as List,
      );
      mutate(body);
      await expectLater(
        f.decode(f.record(await f.signBody(body))),
        throwsA(isA<CompanyBootstrapRefusal>()),
      );
    }
    final wrongDomain = List<Object?>.from(packed);
    final wrongSignature = await Ed25519().sign(
      utf8.encode('$_domain${canonicalJoinTest({'state': packed[0]})}'),
      keyPair: f.rootKey,
    );
    wrongDomain[1] = base64Encode(wrongSignature.bytes);
    await expectLater(
      f.decode(f.record(wrongDomain)),
      throwsA(isA<CompanyBootstrapRefusal>()),
    );
    final public = canonicalJoinTest(packed);
    for (final private in f.privateMaterial.skip(1)) {
      expect(public.contains(private as String), isFalse);
    }
    expect(f.store.states.keys, before.keys);
    for (final key in before.keys) {
      expect(f.store.states[key]!.revision, before[key]!.revision);
      expect(f.store.states[key]!.bytes, before[key]!.bytes);
    }
  });

  test('real maximum authority lineage validates locally without claiming an unsupported Join', () async {
    final f = await _SignedFixture.create('\\' * 64, authority: 17);
    final packed = await f.certificate();
    final raw = f.record(packed, projection: ['f' * 64, _maximum - 2]);
    final decoded = await f.decode(raw);
    expect((packed[0] as List)[3], 17);
    expect(decoded.certificate.originalCertificateBytes, f.original);
    expect(decoded.encode().length, lessThanOrEqualTo(kInstallationStateLimit));
    stdout.writeln(
      'SIGNED_CODEC authority=17 max_record_bytes=${decoded.encode().length} certificate_bytes=${utf8.encode(decoded.certificate.certificateBytes).length} counter_digits=16',
    );
  }, timeout: const Timeout(Duration(minutes: 3)));
}

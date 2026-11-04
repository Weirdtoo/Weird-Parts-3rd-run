part of '../installation/installation_security.dart';

const _companyAttempts = 8;
const _companyPinProfile = 'argon2id-m19456-t2-p1-h32';

final class _CompanyCustody {
  _CompanyCustody._(this.values, this.revision);

  final Map<String, Object?> values;
  final String? revision;
  bool get isMember => values['v'] == 2;

  String get status => values['status'] as String;
  String get company => values['company'] as String;
  String get shop => values['shop'] as String;
  String get user => values['user'] as String;
  String get device => values['device'] as String;
  String get grant => values['grant'] as String;
  String get intent => values['intent'] as String;
  String get installation => values['installation'] as String;
  String get generation => values['generation'] as String;
  String get storeGeneration => values['store'] as String;
  String get name => values['name'] as String;
  String get packageId => values['package'] as String;
  int get authority => values['authority'] as int;
  String? get recoverySource => values['source'] as String?;
  String? get factsCommitment => values['facts'] as String?;
  String? get packageDigest => values['digest'] as String?;
  int get attempts => values['attempts'] as int;
  Uint8List get rootSeed => base64Decode(values['rootSeed'] as String);
  Uint8List? get recoverySeed => values['recoverySeed'] == null
      ? null
      : base64Decode(values['recoverySeed'] as String);

  Uint8List encode() {
    final bytes = Uint8List.fromList(utf8.encode(jsonEncode(values)));
    if (bytes.length > kInstallationStateLimit) {
      throw StateError('Protected company custody exceeds capacity');
    }
    return bytes;
  }

  _CompanyCustody change(Map<String, Object?> changes) =>
      _CompanyCustody.decode(
        Uint8List.fromList(utf8.encode(jsonEncode({...values, ...changes}))),
        revision: revision,
      );

  static _CompanyCustody decode(Uint8List bytes, {String? revision}) {
    if (bytes.length > kInstallationStateLimit) {
      throw const FormatException('Protected company custody exceeds capacity');
    }
    final raw = jsonDecode(utf8.decode(bytes));
    if (raw is! Map<String, dynamic>) {
      throw const FormatException('Invalid company custody');
    }
    const ownerKeys = <String>{
      'v',
      'status',
      'company',
      'shop',
      'user',
      'device',
      'grant',
      'intent',
      'installation',
      'generation',
      'store',
      'name',
      'package',
      'facts',
      'digest',
      'rootSeed',
      'recoverySeed',
      'pinSalt',
      'pinVerifier',
      'pinProfile',
      'attempts',
      'packageSalt',
      'packageNonce',
      'authority',
      'source',
    };
    const memberKeys = <String>{
      'v',
      'status',
      'company',
      'shop',
      'user',
      'device',
      'grant',
      'intent',
      'installation',
      'generation',
      'store',
      'name',
      'package',
      'facts',
      'pinSalt',
      'pinVerifier',
      'pinProfile',
      'attempts',
      'authority',
      'certificate',
      'activation',
    };
    final member = raw['v'] == 2;
    final keys = member
        ? memberKeys
        : {...ownerKeys, if (raw['v'] == 3) 'enrollment'};
    if (raw.keys.toSet().difference(keys).isNotEmpty ||
        keys.difference(raw.keys.toSet()).isNotEmpty ||
        ![1, 2, 3].contains(raw['v']) ||
        !['pending', 'active'].contains(raw['status']) ||
        raw['pinProfile'] != _companyPinProfile ||
        raw['authority'] is! int ||
        (raw['authority'] as int) < 1 ||
        (raw['authority'] as int) > 17 ||
        raw['attempts'] is! int ||
        (raw['attempts'] as int) < 0 ||
        (raw['attempts'] as int) > _companyAttempts ||
        raw['name'] is! String ||
        (raw['name'] as String).trim().isEmpty ||
        (raw['name'] as String).length > 100) {
      throw const FormatException('Unsupported company custody');
    }
    for (final key in <String>[
      'company',
      'shop',
      'user',
      'device',
      'grant',
      'intent',
      'installation',
      'generation',
      'store',
      'package',
    ]) {
      if (raw[key] is! String ||
          !Uuid.isValidUUID(fromString: raw[key] as String)) {
        throw const FormatException('Invalid company custody identity');
      }
    }
    for (final key in <String>['facts', 'digest']) {
      if (raw[key] != null &&
          (raw[key] is! String ||
              !RegExp(r'^[a-f0-9]{64}$').hasMatch(raw[key] as String))) {
        throw const FormatException('Invalid company custody commitment');
      }
    }
    if (raw['source'] != null &&
        (raw['source'] is! String ||
            !RegExp(r'^[a-f0-9]{64}$').hasMatch(raw['source'] as String))) {
      throw const FormatException('Invalid recovery source commitment');
    }
    for (final entry in <String, int>{
      if (!member) 'rootSeed': 32,
      'pinSalt': 16,
      'pinVerifier': 32,
      if (!member) 'packageSalt': 16,
      if (!member) 'packageNonce': 12,
    }.entries) {
      if (raw[entry.key] is! String ||
          base64Decode(raw[entry.key] as String).length != entry.value) {
        throw const FormatException('Invalid company custody key material');
      }
    }
    if (raw['recoverySeed'] != null &&
        (raw['recoverySeed'] is! String ||
            base64Decode(raw['recoverySeed'] as String).length != 32)) {
      throw const FormatException('Invalid recovery seed');
    }
    if (!member &&
        raw['status'] == 'active' &&
        (raw['recoverySeed'] != null ||
            raw['facts'] == null ||
            raw['digest'] == null)) {
      throw const FormatException('Incomplete active company custody');
    }
    if (member) {
      _joinHash(raw['certificate']);
      final activation = _joinObject(raw['activation'], {
        'before',
        'after',
        'path',
        'trust',
        'priorBinding',
      });
      for (final key in ['before', 'path', 'priorBinding']) {
        _joinHash(activation[key]);
      }
      if (activation['after'] != null) _joinHash(activation['after']);
      if (raw['status'] == 'active' && activation['after'] == null) {
        throw const FormatException('Unsealed member activation');
      }
      final trust = CompanyTrustAnchor.decode(activation['trust']);
      if (trust.companyId.value != raw['company'] ||
          trust.factsCommitment != raw['facts'] ||
          trust.authorityVersion != raw['authority']) {
        throw const FormatException('Member authority binding differs');
      }
    } else if (raw['v'] == 3) {
      _validateJoinIssuerPins(raw['enrollment']);
    }
    return _CompanyCustody._(Map<String, Object?>.from(raw), revision);
  }
}

Uint8List _secureRandom(int length) {
  final source = Random.secure();
  return Uint8List.fromList(
    List<int>.generate(length, (_) => source.nextInt(256)),
  );
}

Future<Uint8List> _deriveCompanySecret(String input, Uint8List salt) async =>
    Isolate.run(() async {
      final algorithm = Argon2id(
        parallelism: 1,
        memory: 19456,
        iterations: 2,
        hashLength: 32,
      );
      final key = await algorithm.deriveKey(
        secretKey: SecretKey(utf8.encode(input)),
        nonce: salt,
      );
      return Uint8List.fromList(await key.extractBytes());
    });

final class CompanyIdentity {
  const CompanyIdentity({
    required this.companyId,
    required this.shopId,
    required this.userId,
    required this.deviceId,
    required this.name,
    required this.packageId,
    this.isAuthorityOwner = true,
  });

  final String companyId;
  final String shopId;
  final String userId;
  final String deviceId;
  final String name;
  final String packageId;
  final bool isAuthorityOwner;
}

enum CompanyBootstrapStatus {
  unjoined,
  legacyUnsupported,
  pending,
  pendingRecovery,
  pendingJoin,
  active,
  needsRecovery,
}

enum CompanyContinuityPolicy { localContinuity, boundedAge }

sealed class CompanySession {
  CompanySession._(
    this._owner,
    this.identity,
    this.sessionId,
    this._authoritySnapshot,
    this._membershipSnapshot,
  ) : _clock = Stopwatch()..start();

  final CompanyEnrollment _owner;
  final CompanyIdentity identity;
  final String sessionId;
  final String _authoritySnapshot;
  final String _membershipSnapshot;
  final Stopwatch _clock;
  Duration _lastUse = Duration.zero;
  bool _revoked = false;
  int _inFlight = 0;
  Completer<void>? _idle;

  bool get isValid =>
      !_revoked &&
      identical(_owner._session, this) &&
      _clock.elapsed < const Duration(hours: 8) &&
      _clock.elapsed - _lastUse < const Duration(minutes: 15);

  Duration get timeUntilExpiry {
    final idle = const Duration(minutes: 15) - (_clock.elapsed - _lastUse);
    final absolute = const Duration(hours: 8) - _clock.elapsed;
    return idle < absolute ? idle : absolute;
  }

  void validateCommand({
    required String company,
    required String shop,
    required String user,
    required String device,
    required String installation,
    required String generation,
    required String session,
  }) {
    if (!isValid ||
        _membershipSnapshot != _owner.installation._membershipCommitment ||
        company != identity.companyId ||
        shop != identity.shopId ||
        user != identity.userId ||
        device != identity.deviceId ||
        installation != _owner.installation.identity?.id.value ||
        generation != _owner.installation.identity?.generation.value ||
        session != sessionId) {
      throw StateError('Local company session is unavailable');
    }
    _lastUse = _clock.elapsed;
  }

  void validateAuthority(CompanyTrustAnchor trust, Map<String, int> floors) {
    if (!isValid ||
        _membershipSnapshot != _owner.installation._membershipCommitment ||
        _authoritySnapshot !=
            _securityCanonical({
              'trust': _owner.installation._record?.companyTrust?.encode(),
              'floors': _owner.installation.knownSecurityFloors,
            }) ||
        _authoritySnapshot !=
            _securityCanonical({'trust': trust.encode(), 'floors': floors})) {
      throw StateError('Local administrator authority changed');
    }
  }

  void _clear() => _revoked = true;

  Future<void> requireCurrentAccount() => _owner._requireSessionAccount(this);

  Future<T> runLocalCommand<T>(Future<T> Function() operation) async {
    if (!isValid) {
      throw StateError('Local administrator session is unavailable');
    }
    _inFlight++;
    try {
      return await operation();
    } finally {
      _inFlight--;
      if (_inFlight == 0) {
        _idle?.complete();
        _idle = null;
      }
    }
  }

  Future<void> _waitForCommands() {
    if (_inFlight == 0) return Future<void>.value();
    return (_idle ??= Completer<void>()).future;
  }
}

final class OwnerSession extends CompanySession {
  OwnerSession._(
    super.owner,
    super.identity,
    super.sessionId,
    super.authoritySnapshot,
    super.membershipSnapshot,
  ) : super._();
}

final class RestrictedUserSession extends CompanySession {
  RestrictedUserSession._(
    super.owner,
    super.identity,
    super.sessionId,
    super.authoritySnapshot,
    super.membershipSnapshot,
    this._accountCommitment,
  ) : super._();
  final String _accountCommitment;
}

final class CompanyEnrollment {
  CompanyEnrollment({required this.installation, required this.db});

  final InstallationSecurity installation;
  final AppDatabase db;
  CompanySession? _session;
  int _authenticationEpoch = 0;
  String? _userProvisionOffer;

  CompanySession? get currentCompanySession =>
      _session?.isValid == true ? _session : null;
  OwnerSession? get currentSession => switch (currentCompanySession) {
    final OwnerSession owner => owner,
    _ => null,
  };

  Future<void> signOut() async {
    _authenticationEpoch++;
    _userProvisionOffer = null;
    installation._activeCompanyChannel?.close();
    final session = _session;
    session?._clear();
    await session?._waitForCommands();
    if (identical(_session, session)) _session = null;
  }

  Future<OwnerSession> signIn(String pin) async {
    final releasingPriorSession = signOut();
    final epoch = _authenticationEpoch;
    await releasingPriorSession;
    final custody = await _readCustody();
    if (custody == null || custody.status != 'active') {
      throw const CompanyBootstrapRefusal('Company is not active');
    }
    await _checkBinding(custody, requireActive: true);
    if (!await _verifyPin(custody, pin)) {
      throw const CompanyBootstrapRefusal('Administrator PIN refused');
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null || trust.companyId.value != custody.company) {
      throw const CompanyBootstrapRefusal('Company authority is unavailable');
    }
    final confirmedCustody = await _readCustody();
    if (confirmedCustody == null || confirmedCustody.status != 'active') {
      throw const CompanyBootstrapRefusal('Company authority is unavailable');
    }
    if (epoch != _authenticationEpoch) {
      throw const CompanyBootstrapRefusal(
        'Administrator sign-in was cancelled',
      );
    }
    final session = OwnerSession._(
      this,
      _identity(confirmedCustody),
      const Uuid().v4(),
      _securityCanonical({
        'trust': trust.encode(),
        'floors': installation.knownSecurityFloors,
      }),
      confirmedCustody.isMember
          ? confirmedCustody.values['certificate'] as String
          : trust.factsCommitment,
    );
    _session = session;
    return session;
  }

  Future<VerifiedJobLineSession> issueJobLineAssertion(
    JobLineCommand command,
  ) async {
    final session = currentSession;
    final custody = await _readCustody();
    if (session == null || custody == null || custody.status != 'active') {
      throw const CompanyBootstrapRefusal('Administrator sign-in required');
    }
    await _checkBinding(custody, requireActive: true);
    if (command.companyId != custody.company ||
        command.shopId != custody.shop) {
      throw const CompanyBootstrapRefusal('Command is outside this company');
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null || trust.companyId.value != custody.company) {
      throw const CompanyBootstrapRefusal('Company trust is unavailable');
    }
    session.validateAuthority(trust, installation.knownSecurityFloors);
    final facts =
        await (db.select(db.companyAuthorityFacts)..where(
              (t) =>
                  t.companyId.equals(custody.company) &
                  t.commitment.equals(trust.factsCommitment),
            ))
            .getSingle();
    final signed = jsonDecode(facts.signedBytes) as Map<String, dynamic>;
    final body = signed['body'] as Map<String, dynamic>;
    if (body['v'] != 2) {
      throw const CompanyBootstrapRefusal('Production facts version refused');
    }
    if (custody.isMember) {
      throw const CompanyBootstrapRefusal('Job line permission denied');
    }
    final device = (body['devices'] as List)
        .cast<Map<String, dynamic>>()
        .singleWhere((d) => d['id'] == custody.device);
    final user = (body['users'] as List)
        .cast<Map<String, dynamic>>()
        .singleWhere((u) => u['id'] == custody.user);
    final identity = installation.identity!;
    session.validateCommand(
      company: custody.company,
      shop: custody.shop,
      user: custody.user,
      device: custody.device,
      installation: identity.id.value,
      generation: identity.generation.value,
      session: session.sessionId,
    );
    final assertion = <String, Object?>{
      'v': 2,
      'company': custody.company,
      'shop': custody.shop,
      'line': command.lineId,
      'request': command.requestId,
      'command': command.commitment,
      'user': custody.user,
      'device': custody.device,
      'installation': identity.id.value,
      'generation': identity.generation.value,
      'grant': custody.grant,
      'credential': user['credential'],
      'permission': user['permission'],
      'authority': trust.authorityVersion,
      'facts': trust.factsCommitment,
      'session': session.sessionId,
    };
    if (device['grant'] != custody.grant ||
        device['installation'] != identity.id.value ||
        device['generation'] != identity.generation.value) {
      throw const CompanyBootstrapRefusal('Installation grant differs');
    }
    final canonical = _securityCanonical(assertion);
    final pair = await Ed25519().newKeyPairFromSeed(installation._record!.seed);
    final signature = await Ed25519().sign(
      utf8.encode('wiredpart.job.line.authorization@2:$canonical'),
      keyPair: pair,
    );
    final proof = Uint8List.fromList(
      utf8.encode(
        _securityCanonical({
          'body': assertion,
          'signature': base64Encode(signature.bytes),
        }),
      ),
    );
    return JobLineAuthorization(
      db: db,
      installation: installation,
    ).verify(command, proof);
  }

  Future<VerifiedCreateJobSession> issueCreateJobAssertion(
    CreateJob command,
  ) async {
    final session = currentCompanySession;
    final custody = await _readCustody();
    if (session == null || custody == null || custody.status != 'active') {
      throw const CompanyBootstrapRefusal('Administrator sign-in required');
    }
    await _checkBinding(custody, requireActive: true);
    if (session is RestrictedUserSession) {
      return _issueRestrictedCreateJob(command, session, custody);
    }
    if (command.companyId != custody.company ||
        command.shopId != custody.shop) {
      throw const CompanyBootstrapRefusal('Command is outside this company');
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null || trust.companyId.value != custody.company) {
      throw const CompanyBootstrapRefusal('Company trust is unavailable');
    }
    session.validateAuthority(trust, installation.knownSecurityFloors);
    final facts =
        await (db.select(db.companyAuthorityFacts)..where(
              (t) =>
                  t.companyId.equals(custody.company) &
                  t.commitment.equals(trust.factsCommitment),
            ))
            .getSingle();
    final signed = jsonDecode(facts.signedBytes) as Map<String, dynamic>;
    final body = signed['body'] as Map<String, dynamic>;
    if (body['v'] != 2) {
      throw const CompanyBootstrapRefusal('Production facts version refused');
    }
    final membership = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final device = membership.device;
    final user = membership.user;
    final identity = installation.identity!;
    session.validateCommand(
      company: custody.company,
      shop: custody.shop,
      user: custody.user,
      device: custody.device,
      installation: identity.id.value,
      generation: identity.generation.value,
      session: session.sessionId,
    );
    final assertion = <String, Object?>{
      'v': custody.isMember ? 3 : 2,
      if (custody.isMember) 'membership': membership.proofCommitment,
      'company': custody.company,
      'shop': custody.shop,
      'job': command.jobId,
      'request': command.requestId,
      'command': command.commitment,
      'user': custody.user,
      'device': custody.device,
      'installation': identity.id.value,
      'generation': identity.generation.value,
      'grant': custody.grant,
      'credential': user['credential'],
      'permission': user['permission'],
      'authority': trust.authorityVersion,
      'facts': trust.factsCommitment,
      'session': session.sessionId,
    };
    if (device['grant'] != custody.grant ||
        device['installation'] != identity.id.value ||
        device['generation'] != identity.generation.value) {
      throw const CompanyBootstrapRefusal('Installation grant differs');
    }
    final canonical = _securityCanonical(assertion);
    final pair = await Ed25519().newKeyPairFromSeed(installation._record!.seed);
    final signature = await Ed25519().sign(
      utf8.encode(
        '${custody.isMember ? 'wiredpart.job.create.authorization@2:' : 'wiredpart.job.create.authorization@1:'}$canonical',
      ),
      keyPair: pair,
    );
    final proof = Uint8List.fromList(
      utf8.encode(
        _securityCanonical({
          'body': assertion,
          'signature': base64Encode(signature.bytes),
          if (custody.isMember) 'membership': membership.certificateBytes,
        }),
      ),
    );
    return CreateJobAuthorization(
      db: db,
      installation: installation,
    ).verify(command, proof);
  }

  Future<VerifiedRenameJobSession> issueRenameJobAssertion(
    RenameJob command,
  ) async {
    final session = currentSession;
    final custody = await _readCustody();
    if (session == null || custody == null || custody.status != 'active') {
      throw const CompanyBootstrapRefusal('Administrator sign-in required');
    }
    await _checkBinding(custody, requireActive: true);
    if (command.companyId != custody.company ||
        command.shopId != custody.shop) {
      throw const CompanyBootstrapRefusal('Command is outside this company');
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null || trust.companyId.value != custody.company) {
      throw const CompanyBootstrapRefusal('Company trust is unavailable');
    }
    session.validateAuthority(trust, installation.knownSecurityFloors);
    final facts =
        await (db.select(db.companyAuthorityFacts)..where(
              (t) =>
                  t.companyId.equals(custody.company) &
                  t.commitment.equals(trust.factsCommitment),
            ))
            .getSingle();
    final signed = jsonDecode(facts.signedBytes) as Map<String, dynamic>;
    final body = signed['body'] as Map<String, dynamic>;
    if (body['v'] != 2) {
      throw const CompanyBootstrapRefusal('Production facts version refused');
    }
    final membership = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final device = membership.device;
    final user = membership.user;
    final identity = installation.identity!;
    session.validateCommand(
      company: custody.company,
      shop: custody.shop,
      user: custody.user,
      device: custody.device,
      installation: identity.id.value,
      generation: identity.generation.value,
      session: session.sessionId,
    );
    final assertion = <String, Object?>{
      'v': custody.isMember ? 3 : 2,
      if (custody.isMember) 'membership': membership.proofCommitment,
      'company': custody.company,
      'shop': custody.shop,
      'job': command.jobId,
      'request': command.requestId,
      'command': command.commitment,
      'user': custody.user,
      'device': custody.device,
      'installation': identity.id.value,
      'generation': identity.generation.value,
      'grant': custody.grant,
      'credential': user['credential'],
      'permission': user['permission'],
      'authority': trust.authorityVersion,
      'facts': trust.factsCommitment,
      'session': session.sessionId,
    };
    if (device['grant'] != custody.grant ||
        device['installation'] != identity.id.value ||
        device['generation'] != identity.generation.value) {
      throw const CompanyBootstrapRefusal('Installation grant differs');
    }
    final canonical = _securityCanonical(assertion);
    final pair = await Ed25519().newKeyPairFromSeed(installation._record!.seed);
    final signature = await Ed25519().sign(
      utf8.encode(
        '${custody.isMember ? 'wiredpart.job.name.authorization@2:' : 'wiredpart.job.name.authorization@1:'}$canonical',
      ),
      keyPair: pair,
    );
    final proof = Uint8List.fromList(
      utf8.encode(
        _securityCanonical({
          'body': assertion,
          'signature': base64Encode(signature.bytes),
          if (custody.isMember) 'membership': membership.certificateBytes,
        }),
      ),
    );
    return RenameJobAuthorization(
      db: db,
      installation: installation,
    ).verify(command, proof);
  }

  Future<VerifiedJobLifecycleSession> issueJobLifecycleAssertion(
    SetJobLifecycle command,
  ) async {
    final session = currentSession;
    final custody = await _readCustody();
    if (session == null || custody == null || custody.status != 'active') {
      throw const CompanyBootstrapRefusal('Administrator sign-in required');
    }
    await _checkBinding(custody, requireActive: true);
    if (command.companyId != custody.company ||
        command.shopId != custody.shop) {
      throw const CompanyBootstrapRefusal('Command is outside this company');
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null || trust.companyId.value != custody.company) {
      throw const CompanyBootstrapRefusal('Company trust is unavailable');
    }
    session.validateAuthority(trust, installation.knownSecurityFloors);
    final facts =
        await (db.select(db.companyAuthorityFacts)..where(
              (t) =>
                  t.companyId.equals(custody.company) &
                  t.commitment.equals(trust.factsCommitment),
            ))
            .getSingle();
    final signed = jsonDecode(facts.signedBytes) as Map<String, dynamic>;
    final body = signed['body'] as Map<String, dynamic>;
    if (body['v'] != 2) {
      throw const CompanyBootstrapRefusal('Production facts version refused');
    }
    final membership = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final device = membership.device;
    final user = membership.user;
    final identity = installation.identity!;
    session.validateCommand(
      company: custody.company,
      shop: custody.shop,
      user: custody.user,
      device: custody.device,
      installation: identity.id.value,
      generation: identity.generation.value,
      session: session.sessionId,
    );
    final assertion = <String, Object?>{
      'v': custody.isMember ? 3 : 2,
      if (custody.isMember) 'membership': membership.proofCommitment,
      'company': custody.company,
      'shop': custody.shop,
      'job': command.jobId,
      'request': command.requestId,
      'command': command.commitment,
      'user': custody.user,
      'device': custody.device,
      'installation': identity.id.value,
      'generation': identity.generation.value,
      'grant': custody.grant,
      'credential': user['credential'],
      'permission': user['permission'],
      'authority': trust.authorityVersion,
      'facts': trust.factsCommitment,
      'session': session.sessionId,
    };
    if (device['grant'] != custody.grant ||
        device['installation'] != identity.id.value ||
        device['generation'] != identity.generation.value) {
      throw const CompanyBootstrapRefusal('Installation grant differs');
    }
    final canonical = _securityCanonical(assertion);
    final pair = await Ed25519().newKeyPairFromSeed(installation._record!.seed);
    final signature = await Ed25519().sign(
      utf8.encode(
        '${custody.isMember ? 'wiredpart.job.lifecycle.authorization@2:' : 'wiredpart.job.lifecycle.authorization@1:'}$canonical',
      ),
      keyPair: pair,
    );
    final proof = Uint8List.fromList(
      utf8.encode(
        _securityCanonical({
          'body': assertion,
          'signature': base64Encode(signature.bytes),
          if (custody.isMember) 'membership': membership.certificateBytes,
        }),
      ),
    );
    return JobLifecycleAuthorization(
      db: db,
      installation: installation,
    ).verify(command, proof);
  }

  Future<VerifiedJobDetailsSession> issueJobDetailsAssertion(
    PatchJobDetails command,
  ) async {
    final session = currentSession;
    final custody = await _readCustody();
    if (session == null || custody == null || custody.status != 'active') {
      throw const CompanyBootstrapRefusal('Administrator sign-in required');
    }
    await _checkBinding(custody, requireActive: true);
    if (command.companyId != custody.company ||
        command.shopId != custody.shop) {
      throw const CompanyBootstrapRefusal('Command is outside this company');
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null || trust.companyId.value != custody.company) {
      throw const CompanyBootstrapRefusal('Company trust is unavailable');
    }
    session.validateAuthority(trust, installation.knownSecurityFloors);
    final facts =
        await (db.select(db.companyAuthorityFacts)..where(
              (t) =>
                  t.companyId.equals(custody.company) &
                  t.commitment.equals(trust.factsCommitment),
            ))
            .getSingle();
    final signed = jsonDecode(facts.signedBytes) as Map<String, dynamic>;
    final body = signed['body'] as Map<String, dynamic>;
    if (body['v'] != 2) {
      throw const CompanyBootstrapRefusal('Production facts version refused');
    }
    final membership = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final device = membership.device;
    final user = membership.user;
    final identity = installation.identity!;
    session.validateCommand(
      company: custody.company,
      shop: custody.shop,
      user: custody.user,
      device: custody.device,
      installation: identity.id.value,
      generation: identity.generation.value,
      session: session.sessionId,
    );
    final assertion = <String, Object?>{
      'v': custody.isMember ? 3 : 2,
      if (custody.isMember) 'membership': membership.proofCommitment,
      'company': custody.company,
      'shop': custody.shop,
      'job': command.jobId,
      'request': command.requestId,
      'command': command.commitment,
      'user': custody.user,
      'device': custody.device,
      'installation': identity.id.value,
      'generation': identity.generation.value,
      'grant': custody.grant,
      'credential': user['credential'],
      'permission': user['permission'],
      'authority': trust.authorityVersion,
      'facts': trust.factsCommitment,
      'session': session.sessionId,
    };
    if (device['grant'] != custody.grant ||
        device['installation'] != identity.id.value ||
        device['generation'] != identity.generation.value) {
      throw const CompanyBootstrapRefusal('Installation grant differs');
    }
    final canonical = _securityCanonical(assertion);
    final pair = await Ed25519().newKeyPairFromSeed(installation._record!.seed);
    final signature = await Ed25519().sign(
      utf8.encode(
        '${custody.isMember ? 'wiredpart.job.details.authorization@2:' : 'wiredpart.job.details.authorization@1:'}$canonical',
      ),
      keyPair: pair,
    );
    final proof = Uint8List.fromList(
      utf8.encode(
        _securityCanonical({
          'body': assertion,
          'signature': base64Encode(signature.bytes),
          if (custody.isMember) 'membership': membership.certificateBytes,
        }),
      ),
    );
    return JobDetailsAuthorization(
      db: db,
      installation: installation,
    ).verify(command, proof);
  }

  String get _namespace => companyCustodyNamespace(installation.namespace);

  Future<_CompanyCustody?> _readCustody() async {
    final state = await installation.store.readState(_namespace);
    return state == null
        ? null
        : _CompanyCustody.decode(state.bytes, revision: state.revision);
  }

  Future<_CompanyCustody> _writeCustody(_CompanyCustody next) async {
    final revision = const Uuid().v4();
    final bytes = next.encode();
    await installation.store.compareAndSwapState(
      _namespace,
      expectedRevision: next.revision,
      nextRevision: revision,
      bytes: bytes,
    );
    return _CompanyCustody.decode(bytes, revision: revision);
  }

  Future<CompanyIdentity?> readIdentity() async {
    final custody = await _readCustody();
    if (custody == null) return null;
    await _checkBinding(custody, requireActive: true);
    return _identity(custody);
  }

  Future<CompanyBootstrapStatus> readStatus() async {
    try {
      if (installation.readiness == InstallationReadiness.unsupported) {
        if (await hasCompanyStoreMarkers(db) ||
            await db.settingsDao.getSetting(kInstallationBindingKey) != null) {
          return CompanyBootstrapStatus.needsRecovery;
        }
        return CompanyBootstrapStatus.legacyUnsupported;
      }
      final custody = await _readCustody();
      if (custody == null) {
        if (await hasCompanyStoreMarkers(db) ||
            installation._record?.companyTrust != null) {
          return CompanyBootstrapStatus.needsRecovery;
        }
        return switch (installation.readiness) {
          InstallationReadiness.ready => CompanyBootstrapStatus.unjoined,
          InstallationReadiness.unsupported =>
            CompanyBootstrapStatus.legacyUnsupported,
          _ => CompanyBootstrapStatus.needsRecovery,
        };
      }
      if (custody.isMember && custody.status == 'pending') {
        return CompanyBootstrapStatus.pendingJoin;
      }
      await _checkBinding(custody, requireActive: custody.status == 'active');
      return custody.status == 'active'
          ? CompanyBootstrapStatus.active
          : custody.recoverySource == null
          ? CompanyBootstrapStatus.pending
          : CompanyBootstrapStatus.pendingRecovery;
    } catch (_) {
      return CompanyBootstrapStatus.needsRecovery;
    }
  }

  CompanyIdentity _identity(_CompanyCustody custody) => CompanyIdentity(
    companyId: custody.company,
    shopId: custody.shop,
    userId: custody.user,
    deviceId: custody.device,
    name: custody.name,
    packageId: custody.packageId,
    isAuthorityOwner: !custody.isMember,
  );

  Future<void> _checkBinding(
    _CompanyCustody custody, {
    required bool requireActive,
  }) async {
    await installation.reconcile(db);
    await _checkCurrentBinding(custody, requireActive: requireActive);
  }

  Future<void> _checkCurrentBinding(
    _CompanyCustody custody, {
    required bool requireActive,
  }) async {
    final pendingContinuation = !requireActive && custody.status == 'pending';
    if (installation.readiness != InstallationReadiness.ready &&
        !pendingContinuation) {
      throw const CompanyBootstrapRefusal('Installation needs recovery');
    }
    final record = installation._record;
    if (record == null) {
      throw const CompanyBootstrapRefusal('Installation key is missing');
    }
    final identity = record.identity;
    final actualPublic = await (await Ed25519().newKeyPairFromSeed(record.seed))
        .extractPublicKey();
    final binding = await db.settingsDao.getSetting(kInstallationBindingKey);
    final pendingOldBinding = jsonEncode({
      'v': 1,
      'id': identity.id.value,
      'generation': identity.generation.value,
      'key': identity.keyReference,
      'public': base64Encode(identity.publicKey),
      'store': record.storeGeneration.value,
    });
    if (custody.installation != identity.id.value ||
        custody.generation != identity.generation.value ||
        custody.storeGeneration != record.storeGeneration.value ||
        base64Encode(actualPublic.bytes) != base64Encode(identity.publicKey) ||
        !(binding == record.binding ||
            (pendingContinuation &&
                binding == pendingOldBinding &&
                record.companyTrust?.companyId.value == custody.company &&
                record.storePathFingerprint == await _companyStorePath(db))) ||
        (requireActive && custody.status != 'active') ||
        (requireActive &&
            (record.companyTrust?.companyId.value != custody.company ||
                record.companyTrust?.factsCommitment !=
                    custody.factsCommitment))) {
      throw const CompanyBootstrapRefusal('Company custody needs recovery');
    }
  }

  Future<CompanyIdentity> create({
    required String companyName,
    required CompanyContinuityPolicy policy,
    required String pin,
    required String recoveryPassphrase,
    required File recoveryFile,
    Directory? photosDirectory,
  }) async {
    if (policy != CompanyContinuityPolicy.localContinuity) {
      throw const CompanyBootstrapRefusal(
        'Company continuity policy is unsupported',
      );
    }
    final name = companyName.trim();
    final pinPattern = installation.namespace.startsWith('synthetic.')
        ? RegExp(r'^\d{4,12}$')
        : RegExp(r'^\d{8,12}$');
    if (name.isEmpty ||
        name.length > 100 ||
        !pinPattern.hasMatch(pin) ||
        recoveryPassphrase.length < 16 ||
        recoveryPassphrase.length > 1024) {
      throw const CompanyBootstrapRefusal(
        'Invalid company name or credentials',
      );
    }
    var custody = await _readCustody();
    if (custody == null) {
      await CompanyBootstrap.preflightFreshShop(
        db,
        photosDirectory: photosDirectory,
      );
      await installation.reconcile(db);
      if (installation.readiness != InstallationReadiness.ready ||
          installation._record?.companyTrust != null) {
        throw const CompanyBootstrapRefusal('Installation is not unjoined');
      }
      final identity = installation.identity!;
      final store = installation.receivingStoreGeneration!;
      final device = await db.settingsDao.ensureDeviceId();
      final pinSalt = _secureRandom(16);
      final pinVerifier = await _deriveCompanySecret(pin, pinSalt);
      final rootPair = await Ed25519().newKeyPair();
      final recoveryPair = await Ed25519().newKeyPair();
      final ids = List<String>.generate(5, (_) => const Uuid().v4());
      custody = _CompanyCustody.decode(
        Uint8List.fromList(
          utf8.encode(
            jsonEncode({
              'v': 1,
              'status': 'pending',
              'company': ids[0],
              'shop': ids[1],
              'user': ids[2],
              'grant': ids[3],
              'intent': ids[4],
              'device': device,
              'installation': identity.id.value,
              'generation': identity.generation.value,
              'store': store.value,
              'name': name,
              'package': const Uuid().v4(),
              'authority': 1,
              'source': null,
              'facts': null,
              'digest': null,
              'rootSeed': base64Encode(await rootPair.extractPrivateKeyBytes()),
              'recoverySeed': base64Encode(
                await recoveryPair.extractPrivateKeyBytes(),
              ),
              'pinSalt': base64Encode(pinSalt),
              'pinVerifier': base64Encode(pinVerifier),
              'pinProfile': _companyPinProfile,
              'attempts': _companyAttempts,
              'packageSalt': base64Encode(_secureRandom(16)),
              'packageNonce': base64Encode(_secureRandom(12)),
            }),
          ),
        ),
      );
      await db.transaction(() async {
        await db.customStatement(
          'UPDATE app_settings SET value = value WHERE key = ?',
          [kInstallationBindingKey],
        );
        await CompanyBootstrap.preflightFreshShop(
          db,
          photosDirectory: photosDirectory,
        );
        await _checkBinding(custody!, requireActive: false);
        if (installation.readiness != InstallationReadiness.ready ||
            installation._record?.companyTrust != null) {
          throw const CompanyBootstrapRefusal(
            'Installation changed before company admission',
          );
        }
        custody = await _writeCustody(custody!);
        await _writeFacts(custody!, photosDirectory: photosDirectory);
      });
    } else {
      if (custody.recoverySource != null || custody.authority != 1) {
        throw const CompanyBootstrapRefusal(
          'Pending authority recovery must resume through Recover',
        );
      }
      await _checkBinding(custody, requireActive: false);
      if (custody.name != name) {
        throw const CompanyBootstrapRefusal('Pending company name differs');
      }
      if (!await _verifyPin(custody, pin)) {
        throw const CompanyBootstrapRefusal('Administrator PIN refused');
      }
      custody = (await _readCustody())!;
      if (custody.status == 'active') return _identity(custody);
      await _writeFacts(custody, photosDirectory: photosDirectory);
    }
    custody = (await _readCustody())!;
    custody = await _writeRecoveryPackage(
      custody!,
      recoveryPassphrase,
      recoveryFile,
    );
    await _activate(custody!);
    return _identity((await _readCustody())!);
  }

  /// Recover authority into a fresh empty store and a fresh installation key.
  /// The package is an offline checkpoint, not proof of unseen later changes.
  Future<CompanyIdentity> recover({
    required CompanyContinuityPolicy policy,
    required File sourceFile,
    required String sourcePassphrase,
    required String newPin,
    required String newRecoveryPassphrase,
    required File newRecoveryFile,
    Directory? photosDirectory,
  }) async {
    final pinPattern = installation.namespace.startsWith('synthetic.')
        ? RegExp(r'^\d{4,12}$')
        : RegExp(r'^\d{8,12}$');
    if (policy != CompanyContinuityPolicy.localContinuity ||
        !pinPattern.hasMatch(newPin) ||
        sourcePassphrase.isEmpty ||
        sourcePassphrase.length > 1024 ||
        newRecoveryPassphrase.length < 16 ||
        newRecoveryPassphrase.length > 1024 ||
        !sourceFile.isAbsolute ||
        !newRecoveryFile.isAbsolute ||
        p.equals(sourceFile.path, newRecoveryFile.path) ||
        FileSystemEntity.typeSync(sourceFile.path, followLinks: false) ==
            FileSystemEntityType.link) {
      throw const CompanyBootstrapRefusal('Invalid recovery request');
    }
    final sourceLength = await sourceFile.length();
    if (sourceLength == 0 || sourceLength > 65536) {
      throw const CompanyBootstrapRefusal('Recovery package exceeds capacity');
    }
    final bytes = await sourceFile.readAsBytes();
    final source = await _verifyRecoverySource(
      Uint8List.fromList(bytes),
      sourcePassphrase,
    );
    if (source.body['authority'] == 17) {
      throw const CompanyBootstrapRefusal('Recovery lineage capacity reached');
    }
    var custody = await _readCustody();
    if (custody == null) {
      await CompanyBootstrap.preflightFreshShop(
        db,
        photosDirectory: photosDirectory,
      );
      await installation.reconcile(db);
      if (installation.readiness != InstallationReadiness.ready ||
          installation._record?.companyTrust != null) {
        throw const CompanyBootstrapRefusal(
          'Recovery needs a fresh unjoined installation',
        );
      }
      final installed = installation.identity!;
      final oldDevice = (source.body['devices'] as List).single as Map;
      if (installed.id.value == oldDevice['installation'] ||
          base64Encode(installed.publicKey) == oldDevice['key'] ||
          (installation
                      .knownSecurityFloors['authority.${source.body['company']}'] ??
                  0) >=
              (source.body['authority'] as int) + 1) {
        throw const CompanyBootstrapRefusal('Recovery authority is not newer');
      }
      _requireRecoveryFloors(source.floors);
      final root = await Ed25519().newKeyPair();
      final recovery = await Ed25519().newKeyPair();
      final salt = _secureRandom(16);
      final verifier = await _deriveCompanySecret(newPin, salt);
      custody = _CompanyCustody.decode(
        Uint8List.fromList(
          utf8.encode(
            jsonEncode({
              'v': 1,
              'status': 'pending',
              'company': source.body['company'],
              'shop': source.body['shop'],
              'user': (source.body['users'] as List).single['id'],
              'device': await db.settingsDao.ensureDeviceId(),
              'grant': const Uuid().v4(),
              'intent': const Uuid().v4(),
              'installation': installed.id.value,
              'generation': installed.generation.value,
              'store': installation.receivingStoreGeneration!.value,
              'name': source.body['name'],
              'package': const Uuid().v4(),
              'authority': (source.body['authority'] as int) + 1,
              'source': source.digest,
              'facts': null,
              'digest': null,
              'rootSeed': base64Encode(await root.extractPrivateKeyBytes()),
              'recoverySeed': base64Encode(
                await recovery.extractPrivateKeyBytes(),
              ),
              'pinSalt': base64Encode(salt),
              'pinVerifier': base64Encode(verifier),
              'pinProfile': _companyPinProfile,
              'attempts': _companyAttempts,
              'packageSalt': base64Encode(_secureRandom(16)),
              'packageNonce': base64Encode(_secureRandom(12)),
            }),
          ),
        ),
      );
      await db.transaction(() async {
        await db.customStatement(
          'UPDATE app_settings SET value = value WHERE key = ?',
          [kInstallationBindingKey],
        );
        await CompanyBootstrap.preflightFreshShop(
          db,
          photosDirectory: photosDirectory,
        );
        await _checkBinding(custody!, requireActive: false);
        if (installation.readiness != InstallationReadiness.ready ||
            installation._record?.companyTrust != null) {
          throw const CompanyBootstrapRefusal(
            'Installation changed before recovery admission',
          );
        }
        custody = await _writeCustody(custody!);
        await _writeRecoveryFacts(
          custody!,
          source,
          photosDirectory: photosDirectory,
        );
      });
    } else {
      await _checkBinding(custody, requireActive: custody.status == 'active');
      if (custody.recoverySource != source.digest ||
          custody.company != source.body['company'] ||
          custody.authority != (source.body['authority'] as int) + 1) {
        throw const CompanyBootstrapRefusal('Recovery continuation differs');
      }
      if (installation._record?.companyTrust == null) {
        _requireRecoveryFloors(source.floors);
      }
      if (!await _verifyPin(custody, newPin)) {
        throw const CompanyBootstrapRefusal('Administrator PIN refused');
      }
      custody = (await _readCustody())!;
      if (custody.status == 'active') return _identity(custody);
      await _writeRecoveryFacts(
        custody,
        source,
        photosDirectory: photosDirectory,
      );
    }
    custody = (await _readCustody())!;
    custody = await _writeRecoveryPackage(
      custody!,
      newRecoveryPassphrase,
      newRecoveryFile,
    );
    await _activate(custody!);
    return _identity((await _readCustody())!);
  }

  void _requireRecoveryFloors(Map<String, int> checkpoint) {
    for (final known in installation.knownSecurityFloors.entries) {
      if (known.value > (checkpoint[known.key] ?? 0)) {
        throw const CompanyBootstrapRefusal(
          'Recovery checkpoint is below a known security floor',
        );
      }
    }
  }

  Future<void> _writeRecoveryFacts(
    _CompanyCustody custody,
    _VerifiedRecovery source, {
    Directory? photosDirectory,
  }) async {
    final existing = await (db.select(
      db.companyBootstrapWitnesses,
    )..where((t) => t.companyId.equals(custody.company))).getSingleOrNull();
    if (existing != null) {
      if (existing.bootstrapId != custody.intent ||
          existing.packageId != custody.packageId ||
          (custody.factsCommitment != null &&
              existing.factsCommitment != custody.factsCommitment)) {
        throw const CompanyBootstrapRefusal('Recovery witness differs');
      }
      if (custody.factsCommitment == null) {
        await _writeCustody(
          custody.change({'facts': existing.factsCommitment}),
        );
      }
      return;
    }
    final oldSigned = source.payload['facts'] as String;
    final oldCommitment = hashes.sha256
        .convert(utf8.encode(_securityCanonical(source.body)))
        .toString();
    final rootPair = await Ed25519().newKeyPairFromSeed(custody.rootSeed);
    final recoveryPair = await Ed25519().newKeyPairFromSeed(
      custody.recoverySeed!,
    );
    final root = await rootPair.extractPublicKey();
    final recovery = await recoveryPair.extractPublicKey();
    final oldUser = (source.body['users'] as List).single as Map;
    final oldRecoverySeed = base64Decode(
      source.payload['recoverySeed'] as String,
    );
    final oldRecoveryPair = await Ed25519().newKeyPairFromSeed(oldRecoverySeed);
    final installed = installation.identity!;
    final userCredential = (oldUser['credential'] as int) + 1;
    final userPermission = oldUser['permission'] as int;
    final floors = <String, int>{...source.floors};
    for (final item in installation.knownSecurityFloors.entries) {
      if (item.value > (floors[item.key] ?? 0)) floors[item.key] = item.value;
    }
    floors['authority.${custody.company}'] = custody.authority;
    floors['grant.${custody.grant}'] = 1;
    floors['credential.${custody.user}'] = userCredential;
    floors['permission.${custody.user}'] = userPermission;
    final manifest = <String, Object?>{
      'v': 1,
      'previous': oldCommitment,
      'previousRoot': source.payload['root'],
      'company': custody.company,
      'shop': custody.shop,
      'user': custody.user,
      'authority': custody.authority,
      'root': base64Encode(root.bytes),
      'recovery': base64Encode(recovery.bytes),
      'package': custody.packageId,
      'installation': installed.id.value,
      'generation': installed.generation.value,
      'device': custody.device,
      'grant': custody.grant,
      'credential': userCredential,
      'permission': userPermission,
      'floors': floors,
    };
    final rotation = await Ed25519().sign(
      utf8.encode(
        'wiredpart.company.recovery.rotate@1:${_securityCanonical(manifest)}',
      ),
      keyPair: oldRecoveryPair,
    );
    final body = <String, Object?>{
      'v': 2,
      'company': custody.company,
      'shop': custody.shop,
      'name': custody.name,
      'authority': custody.authority,
      'policy': 'localContinuity',
      'recovery': {
        'v': 1,
        'key': base64Encode(recovery.bytes),
        'package': custody.packageId,
      },
      'devices': [
        {
          'id': custody.device,
          'installation': installed.id.value,
          'generation': installed.generation.value,
          'key': base64Encode(installed.publicKey),
          'grant': custody.grant,
          'version': 1,
          'revoked': false,
          'shops': [custody.shop],
          'capabilities': List<String>.from(
            (source.body['devices'] as List).single['capabilities'] as List,
          ),
        },
      ],
      'users': [
        {
          'id': custody.user,
          'credential': userCredential,
          'permission': userPermission,
          'revoked': false,
          'shops': [custody.shop],
          'capabilities': List<String>.from(oldUser['capabilities'] as List),
        },
      ],
      'entities': <Object>[],
      'rotation': {
        'manifest': manifest,
        'signature': base64Encode(rotation.bytes),
      },
    };
    final commitment = hashes.sha256
        .convert(utf8.encode(_securityCanonical(body)))
        .toString();
    final signature = await Ed25519().sign(
      utf8.encode('wiredpart.company.facts@2:${_securityCanonical(body)}'),
      keyPair: rootPair,
    );
    final lineage = [
      ...(source.payload['lineage'] as List).cast<String>(),
      oldSigned,
    ];
    await db.transaction(() async {
      await db.customStatement(
        'UPDATE app_settings SET value = value WHERE key = ?',
        [kInstallationBindingKey],
      );
      await CompanyBootstrap.preflightFreshShop(
        db,
        photosDirectory: photosDirectory,
      );
      for (final item in lineage) {
        final prior = (jsonDecode(item)['body'] as Map<String, dynamic>);
        final priorCommitment = hashes.sha256
            .convert(utf8.encode(_securityCanonical(prior)))
            .toString();
        await db
            .into(db.companyAuthorityFacts)
            .insert(
              CompanyAuthorityFactsCompanion.insert(
                companyId: custody.company,
                commitment: priorCommitment,
                signedBytes: item,
              ),
            );
      }
      await db
          .into(db.companyAuthorityFacts)
          .insert(
            CompanyAuthorityFactsCompanion.insert(
              companyId: custody.company,
              commitment: commitment,
              signedBytes: _securityCanonical({
                'body': body,
                'signature': base64Encode(signature.bytes),
              }),
            ),
          );
      await db
          .into(db.companyBootstrapWitnesses)
          .insert(
            CompanyBootstrapWitnessesCompanion.insert(
              companyId: custody.company,
              bootstrapId: custody.intent,
              factsCommitment: commitment,
              packageId: custody.packageId,
              status: 'pending',
            ),
          );
    });
    await _writeCustody(custody.change({'facts': commitment}));
  }

  Future<void> _writeFacts(
    _CompanyCustody custody, {
    Directory? photosDirectory,
  }) async {
    if (custody.recoverySource != null || custody.authority != 1) {
      throw const CompanyBootstrapRefusal(
        'First company facts require a Create intent',
      );
    }
    final existing = await (db.select(
      db.companyBootstrapWitnesses,
    )..where((t) => t.companyId.equals(custody.company))).getSingleOrNull();
    if (existing != null) {
      if (existing.bootstrapId != custody.intent ||
          existing.packageId != custody.packageId ||
          (custody.factsCommitment != null &&
              existing.factsCommitment != custody.factsCommitment)) {
        throw const CompanyBootstrapRefusal('Bootstrap witness differs');
      }
      if (custody.factsCommitment == null) {
        await _writeCustody(
          custody.change({'facts': existing.factsCommitment}),
        );
      }
      return;
    }
    final rootPair = await Ed25519().newKeyPairFromSeed(custody.rootSeed);
    final recoveryPair = await Ed25519().newKeyPairFromSeed(
      custody.recoverySeed!,
    );
    final recovery = await recoveryPair.extractPublicKey();
    final identity = installation.identity!;
    final body = <String, Object?>{
      'v': 2,
      'company': custody.company,
      'shop': custody.shop,
      'name': custody.name,
      'authority': 1,
      'policy': 'localContinuity',
      'recovery': {
        'v': 1,
        'key': base64Encode(recovery.bytes),
        'package': custody.packageId,
      },
      'devices': [
        {
          'id': custody.device,
          'installation': identity.id.value,
          'generation': identity.generation.value,
          'key': base64Encode(identity.publicKey),
          'grant': custody.grant,
          'version': 1,
          'revoked': false,
          'shops': [custody.shop],
          'capabilities': [
            'patchJobLine',
            'deleteJobLine',
            'enrollDevice',
            'createJob',
            'renameJob',
            'editJobDetails',
            'manageJobLifecycle',
          ],
        },
      ],
      'users': [
        {
          'id': custody.user,
          'credential': 1,
          'permission': 1,
          'revoked': false,
          'shops': [custody.shop],
          'capabilities': [
            'patchJobLine',
            'deleteJobLine',
            'enrollDevice',
            'createJob',
            'renameJob',
            'editJobDetails',
            'manageJobLifecycle',
          ],
        },
      ],
      'entities': <Object>[],
    };
    final canonical = _securityCanonical(body);
    final commitment = hashes.sha256.convert(utf8.encode(canonical)).toString();
    final signature = await Ed25519().sign(
      utf8.encode('wiredpart.company.facts@2:$canonical'),
      keyPair: rootPair,
    );
    final signed = _securityCanonical({
      'body': body,
      'signature': base64Encode(signature.bytes),
    });
    await db.transaction(() async {
      await db.customStatement(
        'UPDATE app_settings SET value = value WHERE key = ?',
        [kInstallationBindingKey],
      );
      await CompanyBootstrap.preflightFreshShop(
        db,
        photosDirectory: photosDirectory,
      );
      await db
          .into(db.companyAuthorityFacts)
          .insert(
            CompanyAuthorityFactsCompanion.insert(
              companyId: custody.company,
              commitment: commitment,
              signedBytes: signed,
            ),
          );
      await db
          .into(db.companyBootstrapWitnesses)
          .insert(
            CompanyBootstrapWitnessesCompanion.insert(
              companyId: custody.company,
              bootstrapId: custody.intent,
              factsCommitment: commitment,
              packageId: custody.packageId,
              status: 'pending',
            ),
          );
    });
    await _writeCustody(custody.change({'facts': commitment}));
  }

  Future<bool> _verifyPin(_CompanyCustody expected, String pin) async {
    final current = await _readCustody();
    if (current == null ||
        current.company != expected.company ||
        current.intent != expected.intent ||
        current.attempts == 0) {
      return false;
    }
    await _writeCustody(current.change({'attempts': current.attempts - 1}));
    final pinPattern = installation.namespace.startsWith('synthetic.')
        ? RegExp(r'^\d{4,12}$')
        : RegExp(r'^\d{8,12}$');
    if (!pinPattern.hasMatch(pin)) return false;
    final actual = await _deriveCompanySecret(
      pin,
      base64Decode(current.values['pinSalt'] as String),
    );
    final wanted = base64Decode(current.values['pinVerifier'] as String);
    var mismatch = actual.length ^ wanted.length;
    for (var i = 0; i < wanted.length; i++) {
      mismatch |= wanted[i] ^ actual[i];
    }
    if (mismatch != 0) return false;
    final after = await _readCustody();
    if (after == null ||
        after.company != current.company ||
        after.intent != current.intent) {
      throw const CompanyBootstrapRefusal('Company custody changed');
    }
    await _writeCustody(after.change({'attempts': _companyAttempts}));
    return true;
  }

  Future<_CompanyCustody> _writeRecoveryPackage(
    _CompanyCustody custody,
    String passphrase,
    File destination,
  ) async {
    if (custody.recoverySeed == null || custody.factsCommitment == null) {
      throw const CompanyBootstrapRefusal('Recovery material is incomplete');
    }
    final fact =
        await (db.select(db.companyAuthorityFacts)..where(
              (t) =>
                  t.companyId.equals(custody.company) &
                  t.commitment.equals(custody.factsCommitment!),
            ))
            .getSingleOrNull();
    if (fact == null) {
      throw const CompanyBootstrapRefusal('Signed company facts are missing');
    }
    final older = await (db.select(
      db.companyAuthorityFacts,
    )..where((t) => t.companyId.equals(custody.company))).get();
    if (older.length > 17) {
      throw const CompanyBootstrapRefusal('Recovery lineage capacity reached');
    }
    final lineage =
        older
            .where((row) => row.commitment != custody.factsCommitment)
            .map((row) => row.signedBytes)
            .toList()
          ..sort((a, b) {
            final left = (jsonDecode(a)['body'] as Map)['authority'] as int;
            final right = (jsonDecode(b)['body'] as Map)['authority'] as int;
            return left.compareTo(right);
          });
    final factBody = (jsonDecode(fact.signedBytes)['body'] as Map);
    final user = (factBody['users'] as List).single as Map;
    final floors = <String, int>{
      ...installation.knownSecurityFloors,
      if (factBody['rotation'] is Map)
        ...(((factBody['rotation'] as Map)['manifest'] as Map)['floors'] as Map)
            .cast<String, int>(),
      'authority.${custody.company}': custody.authority,
      'grant.${custody.grant}': 1,
      'credential.${custody.user}': user['credential'] as int,
      'permission.${custody.user}': user['permission'] as int,
    };
    final root = await (await Ed25519().newKeyPairFromSeed(custody.rootSeed))
        .extractPublicKey();
    final header = <String, Object?>{
      'v': 1,
      'company': custody.company,
      'package': custody.packageId,
      'kdf': _companyPinProfile,
      'salt': custody.values['packageSalt'],
      'nonce': custody.values['packageNonce'],
    };
    final headerBytes = utf8.encode(_securityCanonical(header));
    final payload = <String, Object?>{
      'v': 1,
      'company': custody.company,
      'shop': custody.shop,
      'user': custody.user,
      'package': custody.packageId,
      'authority': custody.authority,
      'root': base64Encode(root.bytes),
      'recoverySeed': base64Encode(custody.recoverySeed!),
      'facts': fact.signedBytes,
      'lineage': lineage,
      'floors': floors,
    };
    final key = SecretKey(
      await _deriveCompanySecret(
        passphrase,
        base64Decode(custody.values['packageSalt'] as String),
      ),
    );
    final box = await AesGcm.with256bits().encrypt(
      utf8.encode(_securityCanonical(payload)),
      secretKey: key,
      nonce: base64Decode(custody.values['packageNonce'] as String),
      aad: headerBytes,
    );
    final fileBytes = Uint8List.fromList(
      utf8.encode(
        _securityCanonical({
          'header': header,
          'cipher': base64Encode(box.cipherText),
          'mac': base64Encode(box.mac.bytes),
        }),
      ),
    );
    if (fileBytes.length > 65536) {
      throw const CompanyBootstrapRefusal('Recovery package exceeds capacity');
    }
    final digest = hashes.sha256.convert(fileBytes).toString();
    if (custody.packageDigest != null && custody.packageDigest != digest) {
      throw const CompanyBootstrapRefusal('Recovery package retry differs');
    }
    if (!destination.isAbsolute ||
        FileSystemEntity.typeSync(destination.path, followLinks: false) ==
            FileSystemEntityType.link) {
      throw const CompanyBootstrapRefusal('Recovery destination is unsafe');
    }
    if (destination.existsSync()) {
      throw const CompanyBootstrapRefusal(
        'Recovery destination already exists; choose a fresh destination',
      );
    }
    if (custody.packageDigest == null) {
      custody = await _writeCustody(custody.change({'digest': digest}));
    }
    if (installation.store is! RecoveryFilePublisher) {
      throw const CompanyBootstrapRefusal(
        'Secure recovery file publication is unavailable',
      );
    }
    final publisher = installation.store as RecoveryFilePublisher;
    try {
      await publisher.writeRecoveryFileExclusive(destination.path, fileBytes);
    } on FileSystemException {
      throw const CompanyBootstrapRefusal(
        'Recovery destination appeared during export; choose a fresh destination',
      );
    }
    // A complete but unconfirmed write also remains pending. Retrying with a
    // fresh destination repeats the native durability barrier for this payload.
    final written = await destination.readAsBytes();
    if (hashes.sha256.convert(written).toString() != digest) {
      throw const CompanyBootstrapRefusal('Recovery package write differs');
    }
    final roundTrip = await _decryptRecoveryPackage(
      Uint8List.fromList(written),
      passphrase,
    );
    if (roundTrip['company'] != custody.company ||
        roundTrip['package'] != custody.packageId ||
        roundTrip['recoverySeed'] != base64Encode(custody.recoverySeed!) ||
        roundTrip['facts'] != fact.signedBytes) {
      throw const CompanyBootstrapRefusal('Recovery round trip differs');
    }
    if (custody.packageDigest == null) {
      custody = await _writeCustody(custody.change({'digest': digest}));
    }
    return custody;
  }

  Future<void> _activate(_CompanyCustody custody) async {
    if (custody.packageDigest == null || custody.factsCommitment == null) {
      throw const CompanyBootstrapRefusal('Bootstrap is incomplete');
    }
    final fact =
        await (db.select(db.companyAuthorityFacts)..where(
              (t) =>
                  t.companyId.equals(custody.company) &
                  t.commitment.equals(custody.factsCommitment!),
            ))
            .getSingleOrNull();
    final witness = await (db.select(
      db.companyBootstrapWitnesses,
    )..where((t) => t.companyId.equals(custody.company))).getSingleOrNull();
    if (fact == null ||
        witness == null ||
        witness.bootstrapId != custody.intent ||
        witness.factsCommitment != custody.factsCommitment ||
        witness.packageId != custody.packageId) {
      throw const CompanyBootstrapRefusal('Bootstrap evidence differs');
    }
    final signed = jsonDecode(fact.signedBytes) as Map<String, dynamic>;
    final body = signed['body'] as Map<String, dynamic>;
    final user = (body['users'] as List).single as Map;
    final rotatedFloors = body['rotation'] is Map
        ? (((body['rotation'] as Map)['manifest'] as Map)['floors'] as Map)
              .cast<String, int>()
        : <String, int>{};
    final rootPair = await Ed25519().newKeyPairFromSeed(custody.rootSeed);
    final root = await rootPair.extractPublicKey();
    final signature = Signature(
      base64Decode(signed['signature'] as String),
      publicKey: root,
    );
    if (hashes.sha256
                .convert(utf8.encode(_securityCanonical(body)))
                .toString() !=
            custody.factsCommitment ||
        !await Ed25519().verify(
          utf8.encode('wiredpart.company.facts@2:${_securityCanonical(body)}'),
          signature: signature,
        )) {
      throw const CompanyBootstrapRefusal('Company authority proof failed');
    }
    final persisted = await installation.store.readState(
      installation.namespace,
    );
    if (persisted == null) {
      throw const CompanyBootstrapRefusal('Installation key is missing');
    }
    final current = _InstallationRecord.decode(persisted.bytes);
    if (current.identity.id.value != custody.installation ||
        current.identity.generation.value != custody.generation ||
        current.storeGeneration.value != custody.storeGeneration ||
        current.floors.entries.any(
          (known) =>
              known.value >
              (rotatedFloors[known.key] ??
                  (custody.recoverySource == null ? known.value : 0)),
        )) {
      throw const CompanyBootstrapRefusal(
        'Installation identity or security floor differs',
      );
    }
    await db.transaction(() async {
      await (db.update(
        db.companyBootstrapWitnesses,
      )..where((t) => t.companyId.equals(custody.company))).write(
        CompanyBootstrapWitnessesCompanion(
          packageDigest: Value(custody.packageDigest),
          status: const Value('active'),
        ),
      );
    });
    final trust = CompanyTrustAnchor(
      companyId: CompanyId(custody.company),
      rootKey: Uint8List.fromList(root.bytes),
      authorityVersion: custody.authority,
      factsCommitment: custody.factsCommitment!,
      policy: 'localContinuity',
    );
    if (current.companyTrust == null) {
      installation._persisted = persisted;
      final next = _InstallationRecord(
        current.identity,
        current.seed,
        InstallationActivation.active,
        current.storeGeneration,
        {
          ...current.floors,
          ...rotatedFloors,
          'authority.${custody.company}': custody.authority,
          'grant.${custody.grant}': 1,
          'credential.${custody.user}': user['credential'] as int,
          'permission.${custody.user}': user['permission'] as int,
        },
        companyTrust: trust,
        storePathFingerprint: await _companyStorePath(db),
      );
      await installation._write(next, expectedRevision: persisted.revision);
    } else if (jsonEncode(current.companyTrust!.encode()) !=
        jsonEncode(trust.encode())) {
      throw const CompanyBootstrapRefusal('Company authority differs');
    }
    await db.settingsDao.setSetting(
      kInstallationBindingKey,
      installation._record!.binding,
    );
    if (custody.status != 'active') {
      await _writeCustody(
        custody.change({'status': 'active', 'recoverySeed': null}),
      );
    }
    await installation.reconcile(db);
    if (installation.readiness != InstallationReadiness.ready) {
      throw const CompanyBootstrapRefusal('Company activation needs recovery');
    }
  }
}

Future<Map<String, Object?>> _decryptRecoveryPackage(
  Uint8List bytes,
  String passphrase,
) async {
  if (bytes.length > 65536 ||
      bytes.isEmpty ||
      passphrase.isEmpty ||
      passphrase.length > 1024) {
    throw const CompanyBootstrapRefusal('Invalid recovery package');
  }
  final wrapper = jsonDecode(utf8.decode(bytes));
  if (wrapper is! Map<String, dynamic> ||
      wrapper.keys.toSet().difference({'header', 'cipher', 'mac'}).isNotEmpty ||
      wrapper.length != 3) {
    throw const CompanyBootstrapRefusal('Invalid recovery package');
  }
  final header = wrapper['header'];
  if (header is! Map<String, dynamic> ||
      header['v'] != 1 ||
      header['kdf'] != _companyPinProfile ||
      header['salt'] is! String ||
      header['nonce'] is! String ||
      base64Decode(header['salt'] as String).length != 16 ||
      base64Decode(header['nonce'] as String).length != 12) {
    throw const CompanyBootstrapRefusal('Unsupported recovery package');
  }
  final key = SecretKey(
    await _deriveCompanySecret(
      passphrase,
      base64Decode(header['salt'] as String),
    ),
  );
  try {
    final plain = await AesGcm.with256bits().decrypt(
      SecretBox(
        base64Decode(wrapper['cipher'] as String),
        nonce: base64Decode(header['nonce'] as String),
        mac: Mac(base64Decode(wrapper['mac'] as String)),
      ),
      secretKey: key,
      aad: utf8.encode(_securityCanonical(header)),
    );
    final payload = jsonDecode(utf8.decode(plain));
    if (payload is! Map<String, dynamic> ||
        payload['v'] != 1 ||
        payload['company'] != header['company'] ||
        payload['package'] != header['package']) {
      throw const CompanyBootstrapRefusal('Recovery payload differs');
    }
    return Map<String, Object?>.from(payload);
  } catch (_) {
    throw const CompanyBootstrapRefusal('Wrong passphrase or damaged package');
  }
}

final class _VerifiedRecovery {
  const _VerifiedRecovery(this.payload, this.body, this.floors, this.digest);
  final Map<String, Object?> payload;
  final Map<String, dynamic> body;
  final Map<String, int> floors;
  final String digest;
}

Map<String, int> _strictCompanyFloors(Object? raw) {
  if (raw is! Map || raw.length > 128) {
    throw const CompanyBootstrapRefusal('Invalid security floor map');
  }
  final result = <String, int>{};
  for (final item in raw.entries) {
    if (item.key is! String ||
        (item.key as String).isEmpty ||
        item.value is! int ||
        (item.value as int) < 0) {
      throw const CompanyBootstrapRefusal('Invalid security floor');
    }
    result[item.key as String] = item.value as int;
  }
  return Map.unmodifiable(result);
}

Future<_VerifiedRecovery> _verifyRecoverySource(
  Uint8List bytes,
  String passphrase,
) async {
  final payload = await _decryptRecoveryPackage(bytes, passphrase);
  const keys = <String>{
    'v',
    'company',
    'shop',
    'user',
    'package',
    'authority',
    'root',
    'recoverySeed',
    'facts',
    'lineage',
    'floors',
  };
  if (payload.keys.toSet().difference(keys).isNotEmpty ||
      keys.difference(payload.keys.toSet()).isNotEmpty ||
      payload['v'] != 1 ||
      payload['root'] is! String ||
      payload['recoverySeed'] is! String ||
      payload['facts'] is! String ||
      payload['lineage'] is! List ||
      payload['floors'] is! Map ||
      payload['authority'] is! int) {
    throw const CompanyBootstrapRefusal('Invalid recovery checkpoint');
  }
  final root = base64Decode(payload['root'] as String);
  final recoverySeed = base64Decode(payload['recoverySeed'] as String);
  if (root.length != 32 || recoverySeed.length != 32) {
    throw const CompanyBootstrapRefusal('Invalid recovery key material');
  }
  final rawLineage = payload['lineage'] as List;
  if (rawLineage.any((item) => item is! String) ||
      rawLineage.length != (payload['authority'] as int) - 1) {
    throw const CompanyBootstrapRefusal('Recovery lineage differs');
  }
  final body = await _verifyFactLineage(
    current: payload['facts'] as String,
    currentRoot: root,
    lineage: rawLineage.cast<String>(),
  );
  _requireRecoverableFirstOwner(body);
  final recovery = body['recovery'] as Map;
  final recoveryPublic = await (await Ed25519().newKeyPairFromSeed(
    recoverySeed,
  )).extractPublicKey();
  if (payload['company'] != body['company'] ||
      payload['shop'] != body['shop'] ||
      payload['user'] != (body['users'] as List).single['id'] ||
      payload['package'] != recovery['package'] ||
      payload['authority'] != body['authority'] ||
      base64Encode(recoveryPublic.bytes) != recovery['key']) {
    throw const CompanyBootstrapRefusal('Recovery checkpoint identity differs');
  }
  final floors = _strictCompanyFloors(payload['floors']);
  final company = body['company'] as String;
  final user = (body['users'] as List).single as Map;
  final device = (body['devices'] as List).single as Map;
  if (device['revoked'] == true &&
      (floors['revocation.device.${device['id']}'] ?? 0) == 0 &&
      (floors['revocation.grant.${device['grant']}'] ?? 0) == 0) {
    throw const CompanyBootstrapRefusal(
      'Revoked source device lacks a signed revocation floor',
    );
  }
  if ((floors['authority.$company'] ?? 0) != (body['authority'] as int) ||
      (floors['credential.${user['id']}'] ?? 0) !=
          (user['credential'] as int) ||
      (floors['permission.${user['id']}'] ?? 0) !=
          (user['permission'] as int) ||
      (floors['grant.${device['grant']}'] ?? 0) != (device['version'] as int) ||
      (floors['revocation.user.${user['id']}'] ?? 0) > 0) {
    throw const CompanyBootstrapRefusal(
      'Recovery floors differ from authorized actor',
    );
  }
  if (body['rotation'] is Map) {
    final signedFloors = _strictCompanyFloors(
      ((body['rotation'] as Map)['manifest'] as Map)['floors'],
    );
    for (final item in signedFloors.entries) {
      if ((floors[item.key] ?? 0) < item.value) {
        throw const CompanyBootstrapRefusal(
          'Recovery package omits signed floor',
        );
      }
    }
  }
  return _VerifiedRecovery(
    payload,
    body,
    Map.unmodifiable(floors),
    hashes.sha256.convert(bytes).toString(),
  );
}

/// Recovery currently supports the exact first-owner profile issued by
/// Create. In particular, it must never turn a signed revoked or reduced
/// administrator into the full administrator issued by rotation.
void _requireRecoverableFirstOwner(Map<String, dynamic> body) {
  bool keys(Map value, Set<String> expected) =>
      value.keys.toSet().containsAll(expected) &&
      expected.containsAll(value.keys);
  bool id(Object? value) =>
      value is String && Uuid.isValidUUID(fromString: value);
  bool key(Object? value) {
    if (value is! String) return false;
    try {
      return base64Decode(value).length == 32;
    } on FormatException {
      return false;
    }
  }

  bool scope(Object? value, Object? shop) =>
      value is List && value.length == 1 && value.single == shop;
  const capabilities = {'patchJobLine', 'deleteJobLine', 'enrollDevice'};
  bool grants(Object? value) =>
      value is List &&
      value.toSet().length == value.length &&
      ((value.length == capabilities.length &&
              value.toSet().containsAll(capabilities)) ||
          (value.length == capabilities.length + 1 &&
              value.toSet().containsAll({...capabilities, 'createJob'})) ||
          (value.length == capabilities.length + 2 &&
              value.toSet().containsAll({
                ...capabilities,
                'createJob',
                'renameJob',
              })) ||
          (value.length == capabilities.length + 3 &&
              value.toSet().containsAll({
                ...capabilities,
                'createJob',
                'renameJob',
                'editJobDetails',
              })) ||
          (value.length == capabilities.length + 4 &&
              value.toSet().containsAll({
                ...capabilities,
                'createJob',
                'renameJob',
                'editJobDetails',
                'manageJobLifecycle',
              })));
  bool entities(Object? value) {
    if (value is! List || value.length > 128) return false;
    final seen = <String>{};
    for (final item in value) {
      if (item is! Map || !id(item['id']) || item['shop'] != body['shop']) {
        return false;
      }
      final kind = item['kind'];
      if (kind == 'job') {
        if (!keys(item, {'kind', 'id', 'shop'})) return false;
      } else if (kind == 'jobLine') {
        if (!keys(item, {'kind', 'id', 'shop', 'baseline'}) ||
            item['baseline'] is! String ||
            !RegExp(r'^[a-f0-9]{64}$').hasMatch(item['baseline'] as String)) {
          return false;
        }
      } else {
        return false;
      }
      if (!seen.add('$kind:${item['id']}')) return false;
    }
    return true;
  }

  final recovery = body['recovery'];
  final users = body['users'];
  final devices = body['devices'];
  if (recovery is! Map ||
      !keys(recovery, {'v', 'key', 'package'}) ||
      recovery['v'] != 1 ||
      !key(recovery['key']) ||
      !id(recovery['package']) ||
      !entities(body['entities']) ||
      users is! List ||
      users.length != 1 ||
      users.single is! Map ||
      devices is! List ||
      devices.length != 1 ||
      devices.single is! Map) {
    throw const CompanyBootstrapRefusal('Unsupported recovery actor semantics');
  }
  final user = users.single as Map;
  final device = devices.single as Map;
  if (!keys(user, {
        'id',
        'credential',
        'permission',
        'revoked',
        'shops',
        'capabilities',
      }) ||
      !id(user['id']) ||
      user['credential'] is! int ||
      (user['credential'] as int) < 1 ||
      user['permission'] is! int ||
      (user['permission'] as int) < 1 ||
      user['revoked'] != false ||
      !scope(user['shops'], body['shop']) ||
      !grants(user['capabilities']) ||
      !keys(device, {
        'id',
        'installation',
        'generation',
        'key',
        'grant',
        'version',
        'revoked',
        'shops',
        'capabilities',
      }) ||
      !id(device['id']) ||
      !id(device['installation']) ||
      !id(device['generation']) ||
      !key(device['key']) ||
      !id(device['grant']) ||
      device['version'] is! int ||
      (device['version'] as int) < 1 ||
      device['revoked'] is! bool ||
      !scope(device['shops'], body['shop']) ||
      !grants(device['capabilities']) ||
      _securityCanonical((device['capabilities'] as List).toList()..sort()) !=
          _securityCanonical((user['capabilities'] as List).toList()..sort())) {
    throw const CompanyBootstrapRefusal('Unsupported recovery actor semantics');
  }
}

Future<Map<String, dynamic>> _verifyFactLineage({
  required String current,
  required Uint8List currentRoot,
  required List<String> lineage,
}) async {
  if (lineage.length > 16 || utf8.encode(current).length > 32768) {
    throw const CompanyBootstrapRefusal('Recovery lineage exceeds capacity');
  }
  final older = <String, String>{};
  for (final item in lineage) {
    if (utf8.encode(item).length > 32768) {
      throw const CompanyBootstrapRefusal('Recovery lineage exceeds capacity');
    }
    final parsed = jsonDecode(item);
    if (parsed is! Map<String, dynamic> || parsed['body'] is! Map) {
      throw const CompanyBootstrapRefusal('Invalid recovery lineage');
    }
    final commitment = hashes.sha256
        .convert(utf8.encode(_securityCanonical(parsed['body'])))
        .toString();
    if (older.containsKey(commitment)) {
      throw const CompanyBootstrapRefusal('Duplicate recovery lineage');
    }
    older[commitment] = item;
  }
  final seen = <String>{};
  Future<Map<String, dynamic>> verifyOne(
    String encoded,
    Uint8List root,
    int depth,
  ) async {
    if (depth > 16) {
      throw const CompanyBootstrapRefusal('Recovery lineage capacity reached');
    }
    final signed = jsonDecode(encoded);
    if (signed is! Map<String, dynamic> ||
        signed.keys.toSet().difference({'body', 'signature'}).isNotEmpty ||
        signed.length != 2 ||
        signed['body'] is! Map<String, dynamic> ||
        signed['signature'] is! String) {
      throw const CompanyBootstrapRefusal('Invalid signed company facts');
    }
    final body = signed['body'] as Map<String, dynamic>;
    final authority = body['authority'];
    final commitment = hashes.sha256
        .convert(utf8.encode(_securityCanonical(body)))
        .toString();
    if (!seen.add(commitment) ||
        body['v'] != 2 ||
        authority is! int ||
        authority < 1 ||
        authority > 17 ||
        body['policy'] != 'localContinuity' ||
        body['company'] is! String ||
        body['shop'] is! String ||
        body['users'] is! List ||
        (body['users'] as List).length != 1 ||
        body['devices'] is! List ||
        (body['devices'] as List).length != 1 ||
        body['recovery'] is! Map<String, dynamic>) {
      throw const CompanyBootstrapRefusal('Invalid company authority chain');
    }
    final expectedKeys = <String>{
      'v',
      'company',
      'shop',
      'name',
      'authority',
      'policy',
      'recovery',
      'devices',
      'users',
      'entities',
      if (authority > 1) 'rotation',
    };
    if (body.keys.toSet().difference(expectedKeys).isNotEmpty ||
        expectedKeys.difference(body.keys.toSet()).isNotEmpty ||
        !Uuid.isValidUUID(fromString: body['company'] as String) ||
        !Uuid.isValidUUID(fromString: body['shop'] as String) ||
        body['name'] is! String ||
        (body['name'] as String).trim().isEmpty ||
        (body['name'] as String).length > 100 ||
        body['entities'] is! List) {
      throw const CompanyBootstrapRefusal('Unsupported company fact semantics');
    }
    final signature = base64Decode(signed['signature'] as String);
    if (signature.length != 64 ||
        !await Ed25519().verify(
          utf8.encode('wiredpart.company.facts@2:${_securityCanonical(body)}'),
          signature: Signature(
            signature,
            publicKey: SimplePublicKey(root, type: KeyPairType.ed25519),
          ),
        )) {
      throw const CompanyBootstrapRefusal('Company authority signature failed');
    }
    _requireRecoverableFirstOwner(body);
    if (authority == 1) {
      return body;
    }
    final rotation = body['rotation'];
    if (rotation is! Map<String, dynamic> ||
        rotation.keys.toSet().difference({
          'manifest',
          'signature',
        }).isNotEmpty ||
        rotation.length != 2 ||
        rotation['manifest'] is! Map<String, dynamic> ||
        rotation['signature'] is! String) {
      throw const CompanyBootstrapRefusal('Missing recovery rotation');
    }
    final manifest = rotation['manifest'] as Map<String, dynamic>;
    const keys = <String>{
      'v',
      'previous',
      'previousRoot',
      'company',
      'shop',
      'user',
      'authority',
      'root',
      'recovery',
      'package',
      'installation',
      'generation',
      'device',
      'grant',
      'credential',
      'permission',
      'floors',
    };
    if (manifest.keys.toSet().difference(keys).isNotEmpty ||
        keys.difference(manifest.keys.toSet()).isNotEmpty ||
        manifest['v'] != 1 ||
        manifest['authority'] != authority ||
        manifest['root'] != base64Encode(root) ||
        manifest['company'] != body['company'] ||
        manifest['shop'] != body['shop'] ||
        manifest['recovery'] != (body['recovery'] as Map)['key'] ||
        manifest['package'] != (body['recovery'] as Map)['package']) {
      throw const CompanyBootstrapRefusal('Recovery rotation scope differs');
    }
    final devices = body['devices'] as List;
    final device = devices.single as Map;
    final user = (body['users'] as List).single as Map;
    if (manifest['installation'] != device['installation'] ||
        manifest['generation'] != device['generation'] ||
        manifest['device'] != device['id'] ||
        manifest['grant'] != device['grant'] ||
        manifest['user'] != user['id'] ||
        manifest['credential'] != user['credential'] ||
        manifest['permission'] != user['permission']) {
      throw const CompanyBootstrapRefusal('Recovery rotation actor differs');
    }
    final signedFloors = _strictCompanyFloors(manifest['floors']);
    final requiredFloors = <String, int>{
      'authority.${body['company']}': authority,
      'credential.${user['id']}': user['credential'] as int,
      'permission.${user['id']}': user['permission'] as int,
      'grant.${device['grant']}': device['version'] as int,
    };
    for (final item in requiredFloors.entries) {
      if ((signedFloors[item.key] ?? 0) < item.value) {
        throw const CompanyBootstrapRefusal(
          'Recovery rotation lowers a signed floor',
        );
      }
    }
    final predecessor = older[manifest['previous']];
    if (predecessor == null) {
      throw const CompanyBootstrapRefusal('Recovery predecessor missing');
    }
    final priorRoot = base64Decode(manifest['previousRoot'] as String);
    if (priorRoot.length != 32) {
      throw const CompanyBootstrapRefusal('Invalid previous authority key');
    }
    final prior = await verifyOne(predecessor, priorRoot, depth + 1);
    if (prior['company'] != body['company'] ||
        prior['shop'] != body['shop'] ||
        (prior['users'] as List).single['id'] != user['id'] ||
        prior['authority'] != authority - 1 ||
        _securityCanonical(
              ((prior['users'] as List).single['capabilities'] as List).toList()
                ..sort(),
            ) !=
            _securityCanonical(
              (user['capabilities'] as List).toList()..sort(),
            ) ||
        _securityCanonical(
              ((prior['devices'] as List).single['capabilities'] as List)
                  .toList()
                ..sort(),
            ) !=
            _securityCanonical(
              (device['capabilities'] as List).toList()..sort(),
            )) {
      throw const CompanyBootstrapRefusal(
        'Recovery identity continuity failed',
      );
    }
    if (prior['rotation'] is Map) {
      final priorFloors = _strictCompanyFloors(
        (((prior['rotation'] as Map)['manifest']) as Map)['floors'],
      );
      for (final item in priorFloors.entries) {
        if ((signedFloors[item.key] ?? 0) < item.value) {
          throw const CompanyBootstrapRefusal(
            'Recovery lineage lowers a signed floor',
          );
        }
      }
    }
    final priorRecovery = prior['recovery'] as Map;
    final recoveryKey = base64Decode(priorRecovery['key'] as String);
    final proof = base64Decode(rotation['signature'] as String);
    if (recoveryKey.length != 32 ||
        proof.length != 64 ||
        !await Ed25519().verify(
          utf8.encode(
            'wiredpart.company.recovery.rotate@1:${_securityCanonical(manifest)}',
          ),
          signature: Signature(
            proof,
            publicKey: SimplePublicKey(recoveryKey, type: KeyPairType.ed25519),
          ),
        )) {
      throw const CompanyBootstrapRefusal('Recovery rotation signature failed');
    }
    return body;
  }

  final verified = await verifyOne(current, currentRoot, 0);
  if (seen.length != lineage.length + 1) {
    throw const CompanyBootstrapRefusal('Unreferenced recovery lineage');
  }
  return verified;
}

Future<bool> _companyCustodyReady(
  InstallationSecurity installation,
  AppDatabase db,
  _InstallationRecord record,
) async {
  final trust = record.companyTrust!;
  final facts =
      await (db.select(db.companyAuthorityFacts)..where(
            (t) =>
                t.companyId.equals(trust.companyId.value) &
                t.commitment.equals(trust.factsCommitment),
          ))
          .getSingleOrNull();
  if (facts == null) return false;
  final signed = jsonDecode(facts.signedBytes);
  if (signed is! Map<String, dynamic> ||
      signed['body'] is! Map<String, dynamic>) {
    return false;
  }
  final body = signed['body'] as Map<String, dynamic>;
  if (body['v'] == 1 && installation.namespace != 'production') {
    // Existing synthetic v1 command fixtures predate the production issuer.
    return true;
  }
  if (body['v'] != 2 ||
      body['company'] != trust.companyId.value ||
      body['authority'] != trust.authorityVersion ||
      body['policy'] != trust.policy ||
      hashes.sha256.convert(utf8.encode(_securityCanonical(body))).toString() !=
          trust.factsCommitment) {
    return false;
  }
  final allFacts = await (db.select(
    db.companyAuthorityFacts,
  )..where((t) => t.companyId.equals(trust.companyId.value))).get();
  try {
    await _verifyFactLineage(
      current: facts.signedBytes,
      currentRoot: trust.rootKey,
      lineage: allFacts
          .where((row) => row.commitment != trust.factsCommitment)
          .map((row) => row.signedBytes)
          .toList(),
    );
  } catch (_) {
    return false;
  }
  final key = SimplePublicKey(trust.rootKey, type: KeyPairType.ed25519);
  final encodedSignature = signed['signature'];
  if (encodedSignature is! String ||
      !await Ed25519().verify(
        utf8.encode('wiredpart.company.facts@2:${_securityCanonical(body)}'),
        signature: Signature(base64Decode(encodedSignature), publicKey: key),
      )) {
    return false;
  }
  final protected = await installation.store.readState(
    companyCustodyNamespace(installation.namespace),
  );
  if (protected == null) return false;
  final custody = _CompanyCustody.decode(protected.bytes);
  if (custody.isMember) {
    return _memberCustodyReady(installation, db, record, custody);
  }
  installation._membershipCommitment = trust.factsCommitment;
  final custodyRoot = await (await Ed25519().newKeyPairFromSeed(
    custody.rootSeed,
  )).extractPublicKey();
  final witness = await (db.select(
    db.companyBootstrapWitnesses,
  )..where((t) => t.companyId.equals(custody.company))).getSingleOrNull();
  return custody.status == 'active' &&
      custody.company == trust.companyId.value &&
      base64Encode(custodyRoot.bytes) == base64Encode(trust.rootKey) &&
      custody.installation == record.identity.id.value &&
      custody.generation == record.identity.generation.value &&
      custody.storeGeneration == record.storeGeneration.value &&
      custody.factsCommitment == trust.factsCommitment &&
      witness != null &&
      witness.bootstrapId == custody.intent &&
      witness.status == 'active' &&
      witness.factsCommitment == trust.factsCommitment &&
      witness.packageId == custody.packageId &&
      witness.packageDigest == custody.packageDigest;
}

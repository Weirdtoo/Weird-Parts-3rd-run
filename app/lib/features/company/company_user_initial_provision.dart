part of '../installation/installation_security.dart';

const _initialProfile = 'company.user.initial-provision@2';
const _initialPrefix = 'company.user.initial-provision.';
const _initialDomain = 'wiredpart.company.user.initial-provision.';
const _initialCapacity = 128;
const _initialFields = {
  'v',
  'profile',
  'collection',
  'capacity',
  'request',
  'company',
  'shop',
  'authority',
  'facts',
  'user',
  'creation',
  'head',
  'sequence',
  'credential',
  'permission',
  'capabilities',
  'source',
  'recipient',
};

final class _InitialUserScope {
  _InitialUserScope._(this.bytes);
  final String bytes;
  Map<String, Object?> get fields =>
      Map<String, Object?>.from(jsonDecode(bytes) as Map);
  String get request => fields['request'] as String;
  String get user => fields['user'] as String;
  String get head => fields['head'] as String;
  int get sequence => fields['sequence'] as int;
  List<Object?> get source => List<Object?>.from(fields['source'] as List);
  List<Object?> get recipient =>
      List<Object?>.from(fields['recipient'] as List);
  String get lookup => _joinDigest({
    'v': 2,
    'purpose': '${_initialPrefix}authorization.lookup@2',
    'company': fields['company'],
    'issuerInstallation': source[1],
    'issuerGeneration': source[2],
    'request': request,
  });
  static _InitialUserScope parse(Object? value) {
    final f = _joinObject(value, _initialFields);
    if (f['v'] != 2 ||
        f['profile'] != _initialProfile ||
        f['collection'] != kCompanyUserProfile ||
        f['capacity'] != kCompanyUserCapacity ||
        f['capacity'] is! int ||
        f['permission'] != 1 ||
        f['permission'] is! int ||
        _securityCanonical(f['capabilities']) != '["createJob"]') {
      throw const CompanyBootstrapRefusal('Unsupported initial user profile');
    }
    for (final k in ['request', 'company', 'shop', 'user']) {
      _joinId(f, k);
    }
    for (final k in ['facts', 'creation', 'head']) {
      _joinHash(f[k]);
    }
    for (final k in ['authority', 'sequence', 'credential']) {
      _joinVersion(f[k]);
    }
    if (f['v'] is! int ||
        f['sequence'] != f['credential'] ||
        (f['sequence'] as int) > 17) {
      throw const CompanyBootstrapRefusal(
        'Initial user history exceeds profile',
      );
    }
    for (final k in ['source', 'recipient']) {
      final b = _stateTuple(f[k], 6);
      for (final i in [0, 1, 2, 4, 5]) {
        _stateId(b[i]);
      }
      _userBase64(b[3], 32);
    }
    return _InitialUserScope._(_securityCanonical(f));
  }

  static _InitialUserScope body(
    Object? value,
    String kind, [
    Set<String> extra = const {},
  ]) {
    final b = _joinObject(value, {..._initialFields, 'kind', ...extra});
    if (b['kind'] != '$_initialPrefix$kind@2') {
      throw const CompanyBootstrapRefusal('Initial user message kind differs');
    }
    return parse({for (final k in _initialFields) k: b[k]});
  }

  Map<String, Object?> message(String kind) => {
    ...fields,
    'kind': '$_initialPrefix$kind@2',
  };
}

sealed class _InitialUserTransfer {
  const _InitialUserTransfer(this.peer);
  final VerifiedPeerMembership peer;
}

final class _InitialUserOffer extends _InitialUserTransfer {
  const _InitialUserOffer(super.peer, this.scope, this.owner);
  final _InitialUserScope scope;
  final OwnerSession owner;
}

final class _InitialUserConsent extends _InitialUserTransfer {
  const _InitialUserConsent(super.peer, this.scope);
  final _InitialUserScope scope;
}

final class _InitialUserProbe extends _InitialUserTransfer {
  const _InitialUserProbe(
    super.peer,
    this.owner,
    this.user,
    this.revision,
    this.head,
    this.signed,
  );
  final OwnerSession owner;
  final String user, head;
  final String? revision;
  final Map<String, Object?> signed;
}

final class _InitialAuthorization {
  _InitialAuthorization(this.scope, this.signed);
  final _InitialUserScope scope;
  final Map<String, Object?> signed;
  String get bytes => _securityCanonical(signed);
  String get commitment => _joinDigest(signed);
  String get receiptKey => _joinDigest({
    'v': 2,
    'purpose': '${_initialPrefix}installed@2',
    'authorization': commitment,
    'request': scope.request,
    'source': scope.source,
    'recipient': scope.recipient,
  });
  Map<String, Object?> get receiptBody => {
    for (final k in [
      'v',
      'profile',
      'request',
      'company',
      'shop',
      'authority',
      'facts',
      'user',
      'creation',
      'head',
      'sequence',
      'credential',
      'permission',
      'source',
      'recipient',
    ])
      k: scope.fields[k],
    'kind': '${_initialPrefix}installed@2',
    'authorization': commitment,
    'installed': true,
  };
}

enum _InitialRecipientState { absent, installed, publicOnly }

bool _initialProtectedMatches(
  _UserAccount expected,
  ProtectedInstallationState? saved,
) =>
    saved != null &&
    saved.revision == expected.revision &&
    base64Encode(saved.bytes) == base64Encode(expected.encode());

final class _InitialCredential {
  const _InitialCredential(
    this.authorization,
    this.origin,
    this.states,
    this.pin,
  );
  final _InitialAuthorization authorization;
  final String origin;
  final List<CompanyUserStateCertificate> states;
  final List<Object?> pin;
}

extension CompanyUserInitialProvision on CompanyEnrollment {
  void _initialLiveFence(
    VerifiedPeerMembership peer,
    CompanySession session,
    _InitialUserTransfer? transfer,
  ) {
    if (!identical(currentCompanySession, session) ||
        !identical(_initialUserTransfer, transfer)) {
      throw const CompanyBootstrapRefusal(
        'Initial user session or consent changed',
      );
    }
    peer._held.permit.requireLive();
    session.validateAuthority(
      installation._record!.companyTrust!,
      installation.knownSecurityFloors,
    );
    peer._held.channel._requireLive();
  }

  Future<void> _initialWriterLock() async {
    await db.customStatement(
      'UPDATE app_settings SET value = value WHERE key = ?',
      [kInstallationBindingKey],
    );
  }

  Future<Map<String, Object?>> _initialRootSign(
    OwnerSession owner,
    Map<String, Object?> body,
    String domain,
  ) async {
    final custody = await _requireUserAdministrator(owner);
    final pair = await Ed25519().newKeyPairFromSeed(custody.rootSeed);
    if (base64Encode((await pair.extractPublicKey()).bytes) !=
        base64Encode(installation._record!.companyTrust!.rootKey)) {
      throw const CompanyBootstrapRefusal(
        'Initial user signing authority differs',
      );
    }
    final signature = await Ed25519().sign(
      utf8.encode('$domain${_securityCanonical(body)}'),
      keyPair: pair,
    );
    await _requireUserAdministrator(owner);
    return {'body': body, 'signature': base64Encode(signature.bytes)};
  }

  Future<void> _initialScopePeer(
    _InitialUserScope scope,
    VerifiedPeerMembership peer, {
    required bool issuer,
  }) async {
    await _requireUserSyncPeer(peer);
    final f = scope.fields;
    final trust = installation._record!.companyTrust!;
    if (f['company'] != trust.companyId.value ||
        f['shop'] != currentCompanySession!.identity.shopId ||
        f['authority'] != trust.authorityVersion ||
        f['facts'] != trust.factsCommitment) {
      throw const CompanyBootstrapRefusal(
        'Initial user authority scope differs',
      );
    }
    final local = await _lifecycleLocalBinding();
    final remote = issuer ? scope.recipient : scope.source;
    if (_securityCanonical(local) !=
            _securityCanonical(issuer ? scope.source : scope.recipient) ||
        _securityCanonical(remote) !=
            _securityCanonical(
              _userPeerBinding(
                peer._held.peer._membership,
                remote[4] as String,
              ),
            )) {
      throw const CompanyBootstrapRefusal(
        'Initial user recipient binding differs',
      );
    }
    final authority = await _membershipAuthority(db, trust);
    if (scope.source[0] !=
        ((authority['devices'] as List).single as Map)['id']) {
      throw const CompanyBootstrapRefusal(
        'Initial user issuer is not authority Owner',
      );
    }
    await _requireUserSyncPeer(peer);
  }

  Future<void> _initialCurrent(
    OwnerSession owner,
    VerifiedPeerMembership peer,
    _InitialUserScope scope, {
    String? revision,
  }) async {
    await _requireUserAdministrator(owner);
    await _initialScopePeer(scope, peer, issuer: true);
    final account = await _readUserAccount(
      userId: scope.user,
      reconcile: false,
    );
    if (account == null ||
        account.isDisabled ||
        account.values['p'] == null ||
        (revision != null && revision != account.revision)) {
      throw const CompanyBootstrapRefusal('Initial user credential changed');
    }
    final user = await _checkUserAccount(account);
    if (user.commitment != scope.head ||
        user.user['credential'] != scope.fields['credential'] ||
        user.user['permission'] != scope.fields['permission']) {
      throw const CompanyBootstrapRefusal('Initial user public head changed');
    }
    final origin = account.isCurrentState
        ? (await _currentUserState(account)).originalCertificateBytes
        : account.certificate;
    if (_joinDigest(_decodeUserJson(origin)) != scope.fields['creation']) {
      throw const CompanyBootstrapRefusal('Initial user creation differs');
    }
    await _requireUserAdministrator(owner);
    await _requireUserSyncPeer(peer);
  }

  Future<_InitialAuthorization> _verifyInitialAuthorization(
    Object? value,
  ) async {
    final signed = _joinObject(value, {'body', 'signature'});
    final scope = _InitialUserScope.body(signed['body'], 'authorization', {
      'requestCommitment',
    });
    _joinHash((signed['body'] as Map)['requestCommitment']);
    final trust = installation._record!.companyTrust!;
    if (scope.fields['company'] != trust.companyId.value ||
        scope.fields['authority'] != trust.authorityVersion ||
        scope.fields['facts'] != trust.factsCommitment) {
      throw const CompanyBootstrapRefusal(
        'Initial authorization authority differs',
      );
    }
    await _joinVerify(
      Map<String, Object?>.from(signed['body'] as Map),
      signed['signature'],
      base64Encode(trust.rootKey),
      '${_initialDomain}authorization@2:',
    );
    return _InitialAuthorization(scope, signed);
  }

  Future<List<_InitialAuthorization>> _initialAuthorizations() async {
    final company = installation._record!.companyTrust!.companyId.value;
    final rows = await db
        .customSelect(
          'SELECT user_id,grant_key,grant_bytes FROM company_user_credential_grants WHERE company_id = ?',
          variables: [Variable(company)],
        )
        .get();
    final result = <_InitialAuthorization>[];
    for (final row in rows) {
      final bytes = row.read<String>('grant_bytes');
      final signed = _joinObject(_decodeUserJson(bytes), {'body', 'signature'});
      if (_securityCanonical(signed) != bytes || signed['body'] is! Map) {
        throw const CompanyBootstrapRefusal(
          'Malformed company credential authorization',
        );
      }
      final kind = (signed['body'] as Map)['kind'];
      if (kind == 'company.user.credential.grant@1') {
        final body = _joinObject(signed['body'], {
          'v',
          'kind',
          'purpose',
          'company',
          'shop',
          'user',
          'creation',
          'source',
          'recipient',
        });
        if (body['v'] != 1 ||
            body['v'] is! int ||
            body['purpose'] != 'existing-credential-updates' ||
            body['company'] != company ||
            body['user'] != row.read<String>('user_id') ||
            _joinDigest(body) != row.read<String>('grant_key')) {
          throw const CompanyBootstrapRefusal(
            'Legacy credential grant binding differs',
          );
        }
        for (final k in ['company', 'shop', 'user']) {
          _joinId(body, k);
        }
        _joinHash(body['creation']);
        for (final k in ['source', 'recipient']) {
          final binding = _stateTuple(body[k], 6);
          for (final i in [0, 1, 2, 4, 5]) {
            _stateId(binding[i]);
          }
          _userBase64(binding[3], 32);
        }
        await _joinVerify(
          body,
          signed['signature'],
          base64Encode(installation._record!.companyTrust!.rootKey),
          _credentialGrantDomain,
        );
        continue;
      }
      if (kind != '${_initialPrefix}authorization@2') {
        throw const CompanyBootstrapRefusal(
          'Unsupported company credential authorization',
        );
      }
      final auth = await _verifyInitialAuthorization(signed);
      if (auth.bytes != bytes ||
          auth.scope.lookup != row.read<String>('grant_key') ||
          auth.scope.user != row.read<String>('user_id')) {
        throw const CompanyBootstrapRefusal(
          'Initial authorization record differs',
        );
      }
      result.add(auth);
    }
    return result;
  }

  Future<void> _saveInitialAuthorization(_InitialAuthorization auth) async {
    final scope = auth.scope;
    final existing = await db
        .customSelect(
          'SELECT user_id,grant_bytes FROM company_user_credential_grants WHERE company_id = ? AND grant_key = ?',
          variables: [
            Variable(scope.fields['company'] as String),
            Variable(scope.lookup),
          ],
        )
        .get();
    if (existing.isNotEmpty) {
      if (existing.length != 1 ||
          existing.single.read<String>('user_id') != scope.user ||
          existing.single.read<String>('grant_bytes') != auth.bytes) {
        throw const CompanyBootstrapRefusal(
          'Initial user logical request collision',
        );
      }
      return;
    }
    final authorizations = await _initialAuthorizations();
    if (authorizations
            .where(
              (a) =>
                  a.scope.source[1] == scope.source[1] &&
                  a.scope.source[2] == scope.source[2],
            )
            .length >=
        _initialCapacity) {
      throw const CompanyBootstrapRefusal(
        'Initial user authorization capacity reached',
      );
    }
    await db.customStatement(
      'INSERT INTO company_user_credential_grants (company_id,user_id,grant_key,grant_bytes) VALUES (?,?,?,?)',
      [scope.fields['company'], scope.user, scope.lookup, auth.bytes],
    );
  }

  Future<Map<String, Object?>> _initialCapability(
    VerifiedPeerMembership peer,
    List<Object?> local,
    List<Object?> remote,
  ) async => _signJoin(installation, {
    'v': 2,
    'kind': '${_initialPrefix}capability@2',
    'profile': _initialProfile,
    'collection': kCompanyUserProfile,
    'capacity': kCompanyUserCapacity,
    'channel': peer._held.channel._keys.id,
    'nonce': base64Encode(_secureRandom(32)),
    'source': local,
    'recipient': remote,
  }, '${_initialDomain}capability@2:');

  Future<void> _verifyInitialCapability(
    Object? value,
    VerifiedPeerMembership peer,
    List<Object?> remote,
    List<Object?> local,
  ) async {
    final signed = _joinObject(value, {'body', 'signature'});
    final body = _joinObject(signed['body'], {
      'v',
      'kind',
      'profile',
      'collection',
      'capacity',
      'channel',
      'nonce',
      'source',
      'recipient',
    });
    _userBase64(body['nonce'], 32);
    if (body['v'] != 2 ||
        body['v'] is! int ||
        body['kind'] != '${_initialPrefix}capability@2' ||
        body['profile'] != _initialProfile ||
        body['collection'] != kCompanyUserProfile ||
        body['capacity'] != kCompanyUserCapacity ||
        body['capacity'] is! int ||
        body['channel'] != peer._held.channel._keys.id ||
        _securityCanonical(body['source']) != _securityCanonical(remote) ||
        _securityCanonical(body['recipient']) != _securityCanonical(local)) {
      throw const CompanyBootstrapRefusal(
        'Initial provisioning negotiation refused',
      );
    }
    await _joinVerify(
      body,
      signed['signature'],
      remote[3],
      '${_initialDomain}capability@2:',
    );
  }

  Future<Map<String, Object?>> _prepareInitialUserInvitation(
    OwnerSession owner,
    VerifiedPeerMembership peer,
    _UserAccount account,
    List<Object?> target,
    String request,
  ) async {
    await _requireUserAdministrator(owner);
    await _requireUserSyncPeer(peer);
    final user = await _checkUserAccount(account);
    final state = account.isCurrentState
        ? await _currentUserState(account)
        : null;
    final source = await _lifecycleLocalBinding();
    final f = {
      'v': 2,
      'profile': _initialProfile,
      'collection': kCompanyUserProfile,
      'capacity': kCompanyUserCapacity,
      'request': request,
      'company': owner.identity.companyId,
      'shop': owner.identity.shopId,
      'authority': installation._record!.companyTrust!.authorityVersion,
      'facts': installation._record!.companyTrust!.factsCommitment,
      'user': user.user['id'],
      'creation': _joinDigest(
        _decodeUserJson(state?.originalCertificateBytes ?? account.certificate),
      ),
      'head': user.commitment,
      'sequence': state?.sequence ?? 1,
      'credential': user.user['credential'],
      'permission': user.user['permission'],
      'capabilities': ['createJob'],
      'source': source,
      'recipient': target,
    };
    final scope = _InitialUserScope.parse(f);
    final channel = await _userSyncChannel(peer);
    final invitation = await _signJoin(
      installation,
      scope.message('invite'),
      '${_initialDomain}invite@2:',
    );
    final cap = await _initialCapability(peer, scope.source, scope.recipient);
    final wire = await _sealJoin(
      channel,
      'user-provision-invite',
      scope.request,
      scope.recipient[3] as String,
      {
        'v': 2,
        'kind': '${_initialPrefix}invitation-envelope@2',
        'profile': _initialProfile,
        'capability': cap,
        'invitation': invitation,
      },
    );
    await _initialCurrent(owner, peer, scope, revision: account.revision);
    _initialUserTransfer = _InitialUserOffer(peer, scope, owner);
    return wire;
  }

  Map<String, Object?> _initialMembershipProjection(
    Map<String, Object?> device,
  ) => {
    'device': device['id'],
    'installation': device['installation'],
    'generation': device['generation'],
    'key': device['key'],
    'grant': device['grant'],
  };

  Future<Map<String, Object?>> _prepareInitialUserProbe(
    OwnerSession owner,
    VerifiedPeerMembership peer,
    _UserAccount account, {
    String? requestId,
  }) async {
    if (requestId != null) _stateId(requestId);
    await _requireUserAdministrator(owner);
    await _requireUserSyncPeer(peer);
    final user = await _checkUserAccount(account);
    final source = await _lifecycleLocalBinding();
    final previous = (await _initialAuthorizations())
        .where(
          (a) =>
              a.scope.user == user.user['id'] &&
              a.scope.head == user.commitment &&
              a.scope.recipient[0] == peer.deviceId &&
              _securityCanonical(a.scope.source) == _securityCanonical(source),
        )
        .toList();
    final body = {
      'v': 2,
      'kind': '${_initialPrefix}negotiation.probe@2',
      'profile': _initialProfile,
      'collection': kCompanyUserProfile,
      'capacity': kCompanyUserCapacity,
      'request':
          requestId ??
          (previous.isEmpty ? const Uuid().v4() : previous.last.scope.request),
      'channel': peer._held.channel._keys.id,
      'nonce': base64Encode(_secureRandom(32)),
      'source': source,
      'recipient': _initialMembershipProjection(
        peer._held.peer._membership.device,
      ),
    };
    final signed = await _signJoin(
      installation,
      body,
      '${_initialDomain}negotiation.probe@2:',
    );
    final channel = await _userSyncChannel(peer);
    final wire = await _sealJoin(
      channel,
      'user-initial-provision-probe@2',
      body['request'] as String,
      peer._held.peer._membership.device['key'] as String,
      signed,
    );
    await _requireUserAdministrator(owner);
    await _requireUserSyncPeer(peer);
    final current = await _readUserAccount(
      userId: user.user['id'] as String,
      reconcile: false,
    );
    if (current?.revision != account.revision) {
      throw const CompanyBootstrapRefusal('Selected initial user changed');
    }
    _initialUserTransfer = _InitialUserProbe(
      peer,
      owner,
      user.user['id'] as String,
      account.revision,
      user.commitment,
      signed,
    );
    return wire;
  }

  Future<Map<String, Object?>> receiveUserProvisionNegotiation(
    Map<String, Object?> wire, {
    required VerifiedPeerMembership peer,
  }) async {
    await _requireUserSyncPeer(peer);
    final kind = wire['kind'];
    if (kind != 'user-initial-provision-probe@2' &&
        kind != 'user-initial-provision-response@2') {
      throw const CompanyBootstrapRefusal(
        'Unsupported initial user negotiation',
      );
    }
    final channel = await _userSyncChannel(peer);
    final signed = _joinObject(
      await _openUserEnvelope(
        channel,
        kind as String,
        wire,
        recipient: base64Encode(installation.identity!.publicKey),
      ),
      {'body', 'signature'},
    );
    final probe = kind == 'user-initial-provision-probe@2';
    final body = _joinObject(signed['body'], {
      'v',
      'kind',
      'profile',
      'collection',
      'capacity',
      'request',
      'channel',
      'nonce',
      'source',
      'recipient',
      if (!probe) 'probe',
    });
    _joinId(body, 'request');
    _userBase64(body['nonce'], 32);
    if (body['v'] != 2 ||
        body['v'] is! int ||
        body['profile'] != _initialProfile ||
        body['collection'] != kCompanyUserProfile ||
        body['capacity'] != kCompanyUserCapacity ||
        body['capacity'] is! int ||
        body['kind'] !=
            '${_initialPrefix}negotiation.${probe ? 'probe' : 'response'}@2' ||
        body['channel'] != peer._held.channel._keys.id) {
      throw const CompanyBootstrapRefusal(
        'Initial user negotiation binding differs',
      );
    }
    await _joinVerify(
      body,
      signed['signature'],
      peer._held.peer._membership.device['key'],
      '${_initialDomain}negotiation.${probe ? 'probe' : 'response'}@2:',
    );
    final local = await _lifecycleLocalBinding();
    final remote = _stateTuple(body['source'], 6);
    _stateId(remote[4]);
    if (_securityCanonical(remote) !=
        _securityCanonical(
          _userPeerBinding(peer._held.peer._membership, remote[4] as String),
        )) {
      throw const CompanyBootstrapRefusal('Negotiated peer membership differs');
    }
    if (probe) {
      final trust = installation._record!.companyTrust!;
      final authority = await _membershipAuthority(db, trust);
      if (remote[0] != ((authority['devices'] as List).single as Map)['id'] ||
          _securityCanonical(
                _joinObject(body['recipient'], {
                  'device',
                  'installation',
                  'generation',
                  'key',
                  'grant',
                }),
              ) !=
              _securityCanonical(
                _initialMembershipProjection(
                  (await resolveCompanyMembership(
                    db: db,
                    installation: installation,
                  )).device,
                ),
              )) {
        throw const CompanyBootstrapRefusal(
          'Probe requires the retained issuing root',
        );
      }
      final response = await _signJoin(installation, {
        'v': 2,
        'kind': '${_initialPrefix}negotiation.response@2',
        'profile': _initialProfile,
        'collection': kCompanyUserProfile,
        'capacity': kCompanyUserCapacity,
        'request': body['request'],
        'channel': body['channel'],
        'probe': _joinDigest(signed),
        'nonce': base64Encode(_secureRandom(32)),
        'source': local,
        'recipient': remote,
      }, '${_initialDomain}negotiation.response@2:');
      await _requireUserSyncPeer(peer);
      if (_securityCanonical(await _lifecycleLocalBinding()) !=
          _securityCanonical(local)) {
        throw const CompanyBootstrapRefusal(
          'Recipient changed during negotiation',
        );
      }
      return _sealJoin(
        channel,
        'user-initial-provision-response@2',
        body['request'] as String,
        remote[3] as String,
        response,
      );
    }
    final held = _initialUserTransfer;
    if (held is! _InitialUserProbe ||
        !identical(held.peer, peer) ||
        body['probe'] != _joinDigest(held.signed) ||
        body['request'] != (held.signed['body'] as Map)['request'] ||
        _securityCanonical(body['recipient']) != _securityCanonical(local)) {
      throw const CompanyBootstrapRefusal('No matching initial user probe');
    }
    await _requireUserAdministrator(held.owner);
    final account = await _readUserAccount(userId: held.user, reconcile: false);
    if (account == null ||
        account.revision != held.revision ||
        (await _checkUserAccount(account)).commitment != held.head) {
      throw const CompanyBootstrapRefusal(
        'Initial user changed during negotiation',
      );
    }
    final prior = (await _initialAuthorizations()).where(
      (a) =>
          a.scope.lookup ==
          _joinDigest({
            'v': 2,
            'purpose': '${_initialPrefix}authorization.lookup@2',
            'company': held.owner.identity.companyId,
            'issuerInstallation': local[1],
            'issuerGeneration': local[2],
            'request': body['request'],
          }),
    );
    if (prior.any(
      (a) =>
          _securityCanonical(a.scope.recipient) != _securityCanonical(remote),
    )) {
      throw const CompanyBootstrapRefusal(
        'Recipient store changed for this request',
      );
    }
    return _prepareInitialUserInvitation(
      held.owner,
      peer,
      account,
      remote,
      body['request'] as String,
    );
  }

  Future<UserProvisionInvitation> _receiveInitialUserInvitation(
    Map<String, Object?> opened,
    VerifiedPeerMembership peer,
  ) async {
    final body = _joinObject(opened, {
      'v',
      'kind',
      'profile',
      'capability',
      'invitation',
    });
    if (body['v'] != 2 ||
        body['v'] is! int ||
        body['profile'] != _initialProfile ||
        body['kind'] != '${_initialPrefix}invitation-envelope@2') {
      throw const CompanyBootstrapRefusal('Unsupported initial invitation');
    }
    final signed = _joinObject(body['invitation'], {'body', 'signature'});
    final scope = _InitialUserScope.body(signed['body'], 'invite');
    await _initialScopePeer(scope, peer, issuer: false);
    await _verifyInitialCapability(
      body['capability'],
      peer,
      scope.source,
      scope.recipient,
    );
    await _joinVerify(
      Map<String, Object?>.from(signed['body'] as Map),
      signed['signature'],
      scope.source[3],
      '${_initialDomain}invite@2:',
    );
    await _initialScopePeer(scope, peer, issuer: false);
    return UserProvisionInvitation._(
      scope.request,
      scope.user,
      scope.user,
      peer,
      scope,
    );
  }

  Future<Map<String, Object?>> _acceptInitialUserInvitation(
    UserProvisionInvitation invitation,
  ) async {
    final scope = invitation._initial!;
    final peer = invitation._peer;
    await _initialScopePeer(scope, peer, issuer: false);
    final accounts = await _readUserAccounts(reconcile: false);
    if (accounts.select(scope.user) == null) {
      accounts.freeSlot;
    }
    final signed = await _signJoin(
      installation,
      scope.message('request'),
      '${_initialDomain}request@2:',
    );
    final channel = await _userSyncChannel(peer);
    final wire = await _sealJoin(
      channel,
      'user-initial-provision-request@2',
      scope.request,
      scope.source[3] as String,
      {
        'v': 2,
        'kind': '${_initialPrefix}request-envelope@2',
        'profile': _initialProfile,
        'channel': channel._keys.id,
        'nonce': base64Encode(_secureRandom(32)),
        'requestProof': signed,
      },
    );
    await _initialScopePeer(scope, peer, issuer: false);
    _initialUserTransfer = _InitialUserConsent(peer, scope);
    return wire;
  }

  Future<VerifiedUserProvisionRequest> _receiveInitialUserRequest(
    Map<String, Object?> wire,
    VerifiedPeerMembership peer,
  ) async {
    final held = _initialUserTransfer;
    if (held is! _InitialUserOffer || !identical(held.peer, peer)) {
      throw const CompanyBootstrapRefusal(
        'No negotiated initial user invitation',
      );
    }
    await _initialCurrent(held.owner, peer, held.scope);
    final channel = await _userSyncChannel(peer);
    final body = _joinObject(
      await _openUserEnvelope(
        channel,
        'user-initial-provision-request@2',
        wire,
        recipient: base64Encode(installation.identity!.publicKey),
      ),
      {'v', 'kind', 'profile', 'channel', 'nonce', 'requestProof'},
    );
    _userBase64(body['nonce'], 32);
    if (body['v'] != 2 ||
        body['v'] is! int ||
        body['kind'] != '${_initialPrefix}request-envelope@2' ||
        body['profile'] != _initialProfile ||
        body['channel'] != channel._keys.id) {
      throw const CompanyBootstrapRefusal(
        'Initial user request channel differs',
      );
    }
    final signed = _joinObject(body['requestProof'], {'body', 'signature'});
    final scope = _InitialUserScope.body(signed['body'], 'request');
    if (scope.bytes != held.scope.bytes || wire['request'] != scope.request) {
      throw const CompanyBootstrapRefusal('Initial user request changed');
    }
    await _joinVerify(
      Map<String, Object?>.from(signed['body'] as Map),
      signed['signature'],
      scope.recipient[3],
      '${_initialDomain}request@2:',
    );
    await _initialCurrent(held.owner, peer, scope);
    return VerifiedUserProvisionRequest._(_securityCanonical(signed), peer);
  }

  Future<void> _requireInitialAuthorization(_InitialAuthorization auth) async {
    final rows = await db
        .customSelect(
          'SELECT user_id,grant_bytes FROM company_user_credential_grants WHERE company_id = ? AND grant_key = ?',
          variables: [
            Variable(auth.scope.fields['company'] as String),
            Variable(auth.scope.lookup),
          ],
        )
        .get();
    if (rows.length != 1 ||
        rows.single.read<String>('user_id') != auth.scope.user ||
        rows.single.read<String>('grant_bytes') != auth.bytes) {
      throw const CompanyBootstrapRefusal(
        'Initial authorization changed or missing',
      );
    }
  }

  Future<Map<String, Object?>> _prepareInitialUserProvision(
    OwnerSession owner,
    VerifiedPeerMembership peer,
    VerifiedUserProvisionRequest request,
  ) async {
    await requireCompanyJoinSchema(db);
    final held = _initialUserTransfer;
    if (held is! _InitialUserOffer ||
        !identical(held.peer, peer) ||
        !identical(held.owner, owner) ||
        !identical(request._peer, peer)) {
      throw const CompanyBootstrapRefusal('Initial user Owner intent differs');
    }
    final scope = _InitialUserScope.body(request._body, 'request');
    if (scope.bytes != held.scope.bytes) {
      throw const CompanyBootstrapRefusal('Initial user intent changed');
    }
    await _joinVerify(
      request._body,
      request._signed['signature'],
      scope.recipient[3],
      '${_initialDomain}request@2:',
    );
    return owner.runLocalCommand(() async {
      await _initialCurrent(owner, peer, scope);
      final account = (await _readUserAccount(
        userId: scope.user,
        reconcile: false,
      ))!;
      final auth = await _verifyInitialAuthorization(
        await _initialRootSign(owner, {
          ...scope.message('authorization'),
          'requestCommitment': _joinDigest(request._signed),
        }, '${_initialDomain}authorization@2:'),
      );
      await db.transaction(() async {
        await _initialWriterLock();
        await _initialCurrent(owner, peer, scope, revision: account.revision);
        await _saveInitialAuthorization(auth);
        await _initialCurrent(owner, peer, scope, revision: account.revision);
      });
      final origin = account.isCurrentState
          ? (await _currentUserState(account)).originalCertificateBytes
          : account.certificate;
      final states = account.isCurrentState
          ? (await (db.select(db.companyUserEvents)
                      ..where(
                        (t) =>
                            t.companyId.equals(owner.identity.companyId) &
                            t.userId.equals(scope.user) &
                            t.sequence.isBiggerThanValue(1),
                      )
                      ..orderBy([(t) => OrderingTerm.asc(t.sequence)]))
                    .get())
                .map((r) => r.certificateBytes)
                .toList()
          : <String>[];
      if (states.length != scope.sequence - 1 || states.length > 16) {
        throw const CompanyBootstrapRefusal('Initial user history unavailable');
      }
      final secret = await _initialRootSign(owner, {
        'v': 2,
        'kind': '${_initialPrefix}private@2',
        'profile': _initialProfile,
        'authorization': auth.commitment,
        'request': scope.request,
        'user': scope.user,
        'head': scope.head,
        'sequence': scope.sequence,
        'credentialVersion': scope.fields['credential'],
        'permission': scope.fields['permission'],
        'source': scope.source,
        'recipient': scope.recipient,
        'credential': account.values['p'],
      }, '${_initialDomain}private@2:');
      final channel = await _userSyncChannel(peer);
      final box = await _sealJoin(
        channel,
        'user-initial-provision-bundle@2',
        scope.request,
        scope.recipient[3] as String,
        {
          'v': 2,
          'kind': '${_initialPrefix}bundle@2',
          'profile': _initialProfile,
          'authorization': auth.signed,
          'origin': origin,
          'states': states,
          'privateIssuance': secret,
        },
      );
      final issuance = await _signJoin(installation, {
        'v': 2,
        'kind': '${_initialPrefix}issuance@2',
        'profile': _initialProfile,
        'authorization': auth.commitment,
        'request': scope.request,
        'head': scope.head,
        'source': scope.source,
        'recipient': scope.recipient,
        'channel': channel._keys.id,
        'box': _joinDigest(box),
      }, '${_initialDomain}issuance@2:');
      await _requireInitialAuthorization(auth);
      await _initialCurrent(owner, peer, scope, revision: account.revision);
      if (!identical(_initialUserTransfer, held)) {
        throw const CompanyBootstrapRefusal('Initial user selection changed');
      }
      final beforeReturn = await installation.store.readState(
        companyUserNamespace(installation.namespace, slot: account.slot),
      );
      if (!_initialProtectedMatches(account, beforeReturn)) {
        throw const CompanyBootstrapRefusal(
          'Initial user changed before private wire return',
        );
      }
      _initialLiveFence(peer, owner, held);
      return {'box': box, 'issuance': issuance};
    });
  }

  Future<_InitialCredential> _validateInitialCredential(
    Map<String, Object?> bundle,
    _InitialAuthorization auth,
  ) async {
    final scope = auth.scope;
    final trust = installation._record!.companyTrust!;
    final origin = bundle['origin'];
    if (origin is! String ||
        _joinDigest(_decodeUserJson(origin)) != scope.fields['creation']) {
      throw const CompanyBootstrapRefusal(
        'Initial user creation proof differs',
      );
    }
    final historical = _historicalUserFloors(
      installation.knownSecurityFloors,
      scope.user,
    );
    final creation = await _resolveUserAuthority(db, trust, historical, origin);
    if (creation.user['id'] != scope.user) {
      throw const CompanyBootstrapRefusal(
        'Initial user creation identity differs',
      );
    }
    final rawStates = bundle['states'];
    if (rawStates is! List ||
        rawStates.length != scope.sequence - 1 ||
        rawStates.length > 16) {
      throw const CompanyBootstrapRefusal(
        'Initial user history length differs',
      );
    }
    final states = <CompanyUserStateCertificate>[];
    for (final raw in rawStates) {
      if (raw is! String) {
        throw const CompanyBootstrapRefusal(
          'Initial user history encoding differs',
        );
      }
      final state = await CompanyUserStateCertificate.verify(
        raw,
        db: db,
        trust: trust,
        floors: states.length == rawStates.length - 1
            ? installation.knownSecurityFloors
            : historical,
      );
      if (state.originalCertificateBytes != origin ||
          state.disabled ||
          state.userId != scope.user ||
          state.sequence != states.length + 2) {
        throw const CompanyBootstrapRefusal(
          'Initial user history identity differs',
        );
      }
      if (states.isEmpty) {
        if (state.previousPublicHead != scope.fields['creation']) {
          throw const CompanyBootstrapRefusal(
            'Initial user origin chain differs',
          );
        }
      } else {
        state.validateSuccessor(states.last);
      }
      states.add(state);
    }
    final selected = await _resolveUserAuthority(
      db,
      trust,
      installation.knownSecurityFloors,
      states.isEmpty ? origin : states.last.certificateBytes,
    );
    if (selected.commitment != scope.head ||
        selected.user['credential'] != scope.fields['credential'] ||
        selected.user['permission'] != scope.fields['permission']) {
      throw const CompanyBootstrapRefusal('Initial user target state differs');
    }
    final signed = _joinObject(bundle['privateIssuance'], {
      'body',
      'signature',
    });
    final secret = _joinObject(signed['body'], {
      'v',
      'kind',
      'profile',
      'authorization',
      'request',
      'user',
      'head',
      'sequence',
      'credentialVersion',
      'permission',
      'source',
      'recipient',
      'credential',
    });
    final expected = {
      'v': 2,
      'kind': '${_initialPrefix}private@2',
      'profile': _initialProfile,
      'authorization': auth.commitment,
      'request': scope.request,
      'user': scope.user,
      'head': scope.head,
      'sequence': scope.sequence,
      'credentialVersion': scope.fields['credential'],
      'permission': scope.fields['permission'],
      'source': scope.source,
      'recipient': scope.recipient,
      'credential': secret['credential'],
    };
    if (_securityCanonical(secret) != _securityCanonical(expected)) {
      throw const CompanyBootstrapRefusal(
        'Initial private credential binding differs',
      );
    }
    await _joinVerify(
      secret,
      signed['signature'],
      base64Encode(trust.rootKey),
      '${_initialDomain}private@2:',
    );
    final pin = _stateTuple(secret['credential'], 3);
    if (pin[0] != 1 || pin[0] is! int) {
      throw const CompanyBootstrapRefusal(
        'Initial private credential profile differs',
      );
    }
    _userBase64(pin[1], 16);
    _userBase64(pin[2], 32);
    return _InitialCredential(
      auth,
      origin,
      List.unmodifiable(states),
      List.unmodifiable(pin),
    );
  }

  Future<Map<String, Object?>?> _readInitialReceipt(
    _InitialAuthorization auth,
  ) async {
    final rows =
        await (db.select(db.companyUserDeliveries)..where(
              (t) =>
                  t.companyId.equals(auth.scope.fields['company'] as String) &
                  t.userId.equals(auth.scope.user) &
                  t.publicHead.equals(auth.scope.head) &
                  t.bindingCommitment.equals(auth.receiptKey),
            ))
            .get();
    if (rows.isEmpty) return null;
    if (rows.length != 1) {
      throw const CompanyBootstrapRefusal('Initial receipt identity collision');
    }
    final signed = _joinObject(_decodeUserJson(rows.single.receiptBytes), {
      'body',
      'signature',
    });
    if (_securityCanonical(signed) != rows.single.receiptBytes ||
        _securityCanonical(signed['body']) !=
            _securityCanonical(auth.receiptBody) ||
        rows.single.sourceDeviceId != auth.scope.source[0] ||
        rows.single.peerDeviceId != auth.scope.recipient[0]) {
      throw const CompanyBootstrapRefusal('Initial installed receipt differs');
    }
    await _joinVerify(
      auth.receiptBody,
      signed['signature'],
      auth.scope.recipient[3],
      '${_initialDomain}installed@2:',
    );
    return signed;
  }

  Future<_InitialRecipientState> _classifyInitialRecipient(
    _InitialCredential credential,
  ) async {
    final auth = credential.authorization;
    final scope = auth.scope;
    final accounts = await _readUserAccounts(reconcile: false);
    final account = accounts.select(scope.user);
    var installedCurrent = false;
    if (account != null) {
      if (account.isDisabled ||
          (account.isCurrentState && account.values['j'] != null)) {
        throw const CompanyBootstrapRefusal(
          'Finish the existing user recovery first',
        );
      }
      final current = await _checkUserAccount(account);
      if (current.commitment != scope.head ||
          current.user['credential'] != scope.fields['credential']) {
        throw const CompanyBootstrapRefusal(
          'Existing user public state differs',
        );
      }
      if (account.values['p'] != null) {
        if (_securityCanonical(account.values['p']) !=
            _securityCanonical(credential.pin)) {
          throw const CompanyBootstrapRefusal(
            'Existing credential conflicts at this version',
          );
        }
        installedCurrent = true;
      }
    }
    final all = await _initialAuthorizations();
    for (final old in all.where(
      (a) =>
          a.scope.user == scope.user &&
          _securityCanonical(a.scope.recipient) ==
              _securityCanonical(scope.recipient),
    )) {
      if (old.scope.lookup == scope.lookup && old.bytes != auth.bytes) {
        throw const CompanyBootstrapRefusal(
          'Initial user logical request collision',
        );
      }
      final receipt = await _readInitialReceipt(old);
      if (receipt == null && old.scope.lookup != scope.lookup) {
        var superseded = false;
        if (installedCurrent &&
            old.scope.sequence < scope.sequence &&
            old.scope.fields['creation'] == scope.fields['creation'] &&
            _securityCanonical(old.scope.source) ==
                _securityCanonical(scope.source)) {
          final ancestor =
              await (db.select(db.companyUserEvents)..where(
                    (t) =>
                        t.companyId.equals(scope.fields['company'] as String) &
                        t.userId.equals(scope.user) &
                        t.sequence.equals(old.scope.sequence),
                  ))
                  .getSingleOrNull();
          superseded = ancestor?.publicHead == old.scope.head;
        }
        if (!superseded) {
          throw const CompanyBootstrapRefusal(
            'Another initial user request is pending',
          );
        }
      }
      if (receipt != null &&
          old.scope.head == scope.head &&
          account?.values['p'] == null) {
        throw const CompanyBootstrapRefusal(
          'Installed receipt has no protected credential',
        );
      }
    }
    final creationRequest =
        ((jsonDecode(credential.origin) as Map)['body'] as Map)['request'];
    if (accounts.creationRequests[creationRequest] case final other?) {
      if (other != scope.user) {
        throw const CompanyBootstrapRefusal(
          'Initial user creation request collision',
        );
      }
    }
    if (account == null) {
      accounts.freeSlot;
      return _InitialRecipientState.absent;
    }
    if (installedCurrent) {
      return _InitialRecipientState.installed;
    }
    final outgoing = account.values['o'];
    if (!account.isCurrentState ||
        outgoing is! List ||
        outgoing[0] != 1 ||
        outgoing[1] != (await _currentUserState(account)).requestId ||
        _securityCanonical(outgoing.skip(2).toList()) !=
            _securityCanonical(scope.source)) {
      throw const CompanyBootstrapRefusal(
        'Unproved partial user state. Finish authorized Owner Sync before retrying provisioning',
      );
    }
    return _InitialRecipientState.publicOnly;
  }

  Future<void> _requireInitialRecipient(
    _InitialUserConsent consent,
    _InitialAuthorization auth,
  ) async {
    if (!identical(_initialUserTransfer, consent)) {
      throw const CompanyBootstrapRefusal('Initial user consent changed');
    }
    await _initialScopePeer(consent.scope, consent.peer, issuer: false);
    await _requireInitialAuthorization(auth);
  }

  Future<void> _installInitialCredential(
    _InitialCredential credential,
    _InitialUserConsent consent,
    _InitialRecipientState classification,
  ) async {
    final scope = consent.scope;
    final auth = credential.authorization;
    if (classification == _InitialRecipientState.installed) return;
    var accounts = await _readUserAccounts(reconcile: false);
    var account = accounts.select(scope.user);
    final slot = account?.slot ?? accounts.freeSlot;
    Future<void> requireCurrent() => _requireInitialRecipient(consent, auth);
    if (classification == _InitialRecipientState.absent &&
        credential.states.isEmpty) {
      await _writeUserAccount(
        _UserAccount._(
          {
            'v': 2,
            'd': null,
            'c': credential.origin,
            'b': _userBinding(),
            'p': credential.pin,
            'a': _companyAttempts,
            'o': null,
            'r': null,
          },
          null,
          slot: slot,
        ),
        requireCurrent: requireCurrent,
      );
      return;
    }
    if (classification == _InitialRecipientState.absent) {
      for (final state in credential.states) {
        await requireCurrent();
        accounts = await _readUserAccounts(reconcile: false);
        account = accounts.select(scope.user);
        final priorSequence = account == null
            ? 1
            : (await _currentUserState(account)).sequence;
        if (state.sequence != priorSequence + 1) {
          throw const CompanyBootstrapRefusal(
            'Initial user staged prefix changed',
          );
        }
        final next = _UserAccount._(
          {
            'v': 3,
            'c': _decodeUserJson(state.certificateBytes),
            'b': _userBinding(),
            'p': null,
            'a': account?.attempts ?? _companyAttempts,
            'o': null,
            'r': null,
            'j': [state.previousPublicHead, priorSequence],
          },
          account?.revision,
          slot: slot,
        );
        account = await _reconcileUserPinState(
          await _writeUserAccount(next, requireCurrent: requireCurrent),
        );
      }
    }
    await requireCurrent();
    account = await _readUserAccount(userId: scope.user, reconcile: false);
    if (account == null ||
        account.values['p'] != null ||
        (await _checkUserAccount(account)).commitment != scope.head) {
      throw const CompanyBootstrapRefusal(
        'Initial user changed before credential installation',
      );
    }
    final expected = account;
    await _writeUserAccount(
      account.change({'p': credential.pin}),
      requireCurrent: () async {
        await requireCurrent();
        if (classification == _InitialRecipientState.publicOnly &&
            await _classifyInitialRecipient(credential) !=
                _InitialRecipientState.publicOnly) {
          throw const CompanyBootstrapRefusal(
            'Inbound user provenance changed before private CAS',
          );
        }
        await _requireInitialAuthorization(auth);
        final saved = await installation.store.readState(
          companyUserNamespace(installation.namespace, slot: expected.slot),
        );
        if (!_initialProtectedMatches(expected, saved)) {
          throw const CompanyBootstrapRefusal(
            'Initial user revision changed before private CAS',
          );
        }
        _initialLiveFence(consent.peer, consent.peer._held.owner, consent);
      },
    );
  }

  Future<_UserAccount> _requireInitialInstalled(
    _InitialCredential credential,
    _InitialUserConsent consent,
  ) async {
    await _requireInitialRecipient(consent, credential.authorization);
    final account = await _readUserAccount(
      userId: consent.scope.user,
      reconcile: false,
    );
    if (account == null ||
        account.isDisabled ||
        account.values['j'] != null ||
        _securityCanonical(account.values['p']) !=
            _securityCanonical(credential.pin) ||
        (await _checkUserAccount(account)).commitment != consent.scope.head) {
      throw const CompanyBootstrapRefusal(
        'Exact initial credential is not durably installed',
      );
    }
    return account;
  }

  Future<void> _saveInitialReceipt(
    _InitialAuthorization auth,
    Map<String, Object?> signed,
  ) async {
    if (await _readInitialReceipt(auth) case final existing?) {
      if (_securityCanonical(existing) != _securityCanonical(signed)) {
        throw const CompanyBootstrapRefusal(
          'Initial installed receipt collision',
        );
      }
      return;
    }
    await db
        .into(db.companyUserDeliveries)
        .insert(
          CompanyUserDeliveriesCompanion.insert(
            companyId: auth.scope.fields['company'] as String,
            userId: auth.scope.user,
            publicHead: auth.scope.head,
            sourceDeviceId: auth.scope.source[0] as String,
            peerDeviceId: auth.scope.recipient[0] as String,
            bindingCommitment: auth.receiptKey,
            receiptBytes: _securityCanonical(signed),
          ),
        );
  }

  Future<Map<String, Object?>> _acceptInitialUserProvision(
    Map<String, Object?> wire,
    VerifiedPeerMembership peer,
  ) async {
    await requireCompanyJoinSchema(db);
    final consent = _initialUserTransfer;
    if (consent is! _InitialUserConsent || !identical(consent.peer, peer)) {
      throw const CompanyBootstrapRefusal(
        'Confirm the exact initial user first',
      );
    }
    final scope = consent.scope;
    await _initialScopePeer(scope, peer, issuer: false);
    if (utf8.encode(_securityCanonical(wire)).length > 65536) {
      throw const CompanyBootstrapRefusal(
        'Initial user envelope capacity reached',
      );
    }
    final outer = _joinObject(wire, {'box', 'issuance'});
    final signed = _joinObject(outer['issuance'], {'body', 'signature'});
    final issuance = _joinObject(signed['body'], {
      'v',
      'kind',
      'profile',
      'authorization',
      'request',
      'head',
      'source',
      'recipient',
      'channel',
      'box',
    });
    final box = Map<String, Object?>.from(outer['box'] as Map);
    final channel = await _userSyncChannel(peer);
    final expected = {
      'v': 2,
      'kind': '${_initialPrefix}issuance@2',
      'profile': _initialProfile,
      'authorization': issuance['authorization'],
      'request': scope.request,
      'head': scope.head,
      'source': scope.source,
      'recipient': scope.recipient,
      'channel': channel._keys.id,
      'box': _joinDigest(box),
    };
    _joinHash(issuance['authorization']);
    if (_securityCanonical(issuance) != _securityCanonical(expected)) {
      throw const CompanyBootstrapRefusal(
        'Initial user issuance binding differs',
      );
    }
    await _joinVerify(
      issuance,
      signed['signature'],
      scope.source[3],
      '${_initialDomain}issuance@2:',
    );
    final bundle = _joinObject(
      await _openUserEnvelope(
        channel,
        'user-initial-provision-bundle@2',
        box,
        recipient: scope.recipient[3] as String,
      ),
      {
        'v',
        'kind',
        'profile',
        'authorization',
        'origin',
        'states',
        'privateIssuance',
      },
    );
    if (bundle['v'] != 2 ||
        bundle['v'] is! int ||
        bundle['profile'] != _initialProfile ||
        bundle['kind'] != '${_initialPrefix}bundle@2' ||
        box['request'] != scope.request) {
      throw const CompanyBootstrapRefusal(
        'Initial user bundle profile differs',
      );
    }
    final auth = await _verifyInitialAuthorization(bundle['authorization']);
    final request = await _signJoin(
      installation,
      scope.message('request'),
      '${_initialDomain}request@2:',
    );
    if (auth.scope.bytes != scope.bytes ||
        auth.commitment != issuance['authorization'] ||
        (auth.signed['body'] as Map)['requestCommitment'] !=
            _joinDigest(request)) {
      throw const CompanyBootstrapRefusal(
        'Initial user authorization request differs',
      );
    }
    final credential = await _validateInitialCredential(bundle, auth);
    final initialAccount = await _readUserAccount(
      userId: scope.user,
      reconcile: false,
    );
    final classification = await _classifyInitialRecipient(credential);
    final session = currentCompanySession!;
    return session.runLocalCommand(() async {
      await db.transaction(() async {
        await _initialWriterLock();
        await _initialScopePeer(scope, peer, issuer: false);
        if (!identical(_initialUserTransfer, consent) ||
            await _classifyInitialRecipient(credential) != classification ||
            (await _readUserAccount(
                  userId: scope.user,
                  reconcile: false,
                ))?.revision !=
                initialAccount?.revision) {
          throw const CompanyBootstrapRefusal(
            'Initial recipient provenance changed',
          );
        }
        await _saveInitialAuthorization(auth);
        await _initialScopePeer(scope, peer, issuer: false);
      });
      await _installInitialCredential(credential, consent, classification);
      final installed = await _requireInitialInstalled(credential, consent);
      final ack = await _signJoin(
        installation,
        auth.receiptBody,
        '${_initialDomain}installed@2:',
      );
      if ((await _requireInitialInstalled(credential, consent)).revision !=
          installed.revision) {
        throw const CompanyBootstrapRefusal(
          'Initial user changed during ACK signing',
        );
      }
      await db.transaction(() async {
        await _initialWriterLock();
        if ((await _requireInitialInstalled(credential, consent)).revision !=
            installed.revision) {
          throw const CompanyBootstrapRefusal(
            'Initial user changed before ACK storage',
          );
        }
        await _saveInitialReceipt(auth, ack);
        await _requireInitialInstalled(credential, consent);
        final beforeCommit = await installation.store.readState(
          companyUserNamespace(installation.namespace, slot: installed.slot),
        );
        if (!_initialProtectedMatches(installed, beforeCommit)) {
          throw const CompanyBootstrapRefusal(
            'Initial user changed before ACK commit',
          );
        }
        _initialLiveFence(peer, session, consent);
      });
      final result = await _sealJoin(
        channel,
        'user-provision-ack',
        scope.request,
        scope.source[3] as String,
        ack,
      );
      await _requireInitialInstalled(credential, consent);
      final beforeReturn = await installation.store.readState(
        companyUserNamespace(installation.namespace, slot: installed.slot),
      );
      if (!_initialProtectedMatches(installed, beforeReturn)) {
        throw const CompanyBootstrapRefusal(
          'Initial user changed before installed ACK return',
        );
      }
      _initialLiveFence(peer, session, consent);
      return result;
    });
  }

  Future<void> _acceptInitialUserReceipt(
    Map<String, Object?> signed,
    VerifiedPeerMembership peer,
    String userId,
  ) async {
    final body = _joinObject(signed['body'], {
      'v',
      'kind',
      'profile',
      'authorization',
      'request',
      'company',
      'shop',
      'authority',
      'facts',
      'user',
      'creation',
      'head',
      'sequence',
      'credential',
      'permission',
      'source',
      'recipient',
      'installed',
    });
    final authorizations = await _initialAuthorizations();
    final matched = authorizations
        .where((a) => a.commitment == body['authorization'])
        .toList();
    if (matched.length != 1 ||
        matched.single.scope.user != userId ||
        _securityCanonical(body) !=
            _securityCanonical(matched.single.receiptBody)) {
      throw const CompanyBootstrapRefusal(
        'No exact initial authorization for receipt',
      );
    }
    final auth = matched.single;
    final owner = currentSession;
    final transfer = _initialUserTransfer;
    if (owner == null) {
      throw const CompanyBootstrapRefusal(
        'Authority Owner required to confirm provisioning',
      );
    }
    await _joinVerify(
      body,
      signed['signature'],
      auth.scope.recipient[3],
      '${_initialDomain}installed@2:',
    );
    await _initialCurrent(owner, peer, auth.scope);
    await owner.runLocalCommand(() async {
      await db.transaction(() async {
        await _initialWriterLock();
        await _requireInitialAuthorization(auth);
        await _initialCurrent(owner, peer, auth.scope);
        final expected = await _readUserAccount(
          userId: userId,
          reconcile: false,
        );
        if (expected == null ||
            (await _checkUserAccount(expected)).commitment != auth.scope.head) {
          throw const CompanyBootstrapRefusal(
            'Initial recipient grant target changed',
          );
        }
        final grant = await _initialRootSign(owner, {
          'v': 1,
          'kind': 'company.user.credential.grant@1',
          'purpose': 'existing-credential-updates',
          'company': auth.scope.fields['company'],
          'shop': auth.scope.fields['shop'],
          'user': userId,
          'creation': auth.scope.fields['creation'],
          'source': auth.scope.source,
          'recipient': auth.scope.recipient,
        }, _credentialGrantDomain);
        await _requireInitialAuthorization(auth);
        await _initialCurrent(owner, peer, auth.scope);
        final key = _joinDigest(grant['body']);
        final rows = await db
            .customSelect(
              'SELECT grant_bytes FROM company_user_credential_grants WHERE company_id = ? AND user_id = ? AND grant_key = ?',
              variables: [
                Variable(owner.identity.companyId),
                Variable(userId),
                Variable(key),
              ],
            )
            .get();
        final bytes = _securityCanonical(grant);
        if (rows.length > 1 ||
            (rows.isNotEmpty &&
                rows.single.read<String>('grant_bytes') != bytes)) {
          throw const CompanyBootstrapRefusal(
            'Initial recipient update grant collision',
          );
        }
        await _saveInitialReceipt(auth, signed);
        if (rows.isEmpty) {
          await db.customStatement(
            'INSERT INTO company_user_credential_grants (company_id,user_id,grant_key,grant_bytes) VALUES (?,?,?,?)',
            [owner.identity.companyId, userId, key, bytes],
          );
        }
        await _initialCurrent(owner, peer, auth.scope);
        final beforeCommit = await installation.store.readState(
          companyUserNamespace(installation.namespace, slot: expected.slot),
        );
        if (!_initialProtectedMatches(expected, beforeCommit)) {
          throw const CompanyBootstrapRefusal(
            'Initial user changed before recipient grant commit',
          );
        }
        _initialLiveFence(peer, owner, transfer);
      });
    });
    _userProvisionConfirmation = _UserProvisionConfirmation(
      peer,
      userId,
      auth.scope.head,
      _securityCanonical(auth.scope.source),
      _securityCanonical(auth.scope.recipient),
    );
  }
}

part of '../installation/installation_security.dart';

const _userAuthorityDomain = 'wiredpart.company.user.authority@1:';
const _userNameByteLimit = 64;

/// Current release capacity; storage locators are never company user identities.
const kCompanyUserCapacity = 2;
const kCompanyUserProfile = 'company.users.collection@1';

String companyUserNamespace(String baseNamespace, {int slot = 1}) {
  validateInstallationNamespace(baseNamespace);
  if (baseNamespace.endsWith('.company-custody') ||
      RegExp(r'\.company-user-[1-9][0-9]*$').hasMatch(baseNamespace)) {
    throw ArgumentError.value(baseNamespace, 'baseNamespace');
  }
  if (slot < 1 || slot > kCompanyUserCapacity) {
    throw ArgumentError.value(slot, 'slot');
  }
  final result = '$baseNamespace.company-user-$slot';
  validateInstallationNamespace(result);
  return result;
}

final class CompanyUserChoice {
  CompanyUserChoice._(
    this.userId,
    this.name,
    this.capabilities,
    this.available, [
    this.disabled = false,
  ]);
  final String userId;
  final String name;
  final List<String> capabilities;
  final bool available;
  final bool disabled;
}

final class CompanyUserReceipt {
  CompanyUserReceipt._(this.certificateBytes, this._body);
  final String certificateBytes;
  final Map<String, Object?> _body;
  String get userId => _body['user'] as String;
  String get name => _body['name'] as String;
  String get commitment => _joinDigest(jsonDecode(certificateBytes));
}

final class ResolvedCompanyUserAuthority {
  ResolvedCompanyUserAuthority._(this.certificateBytes, this._body);
  final String certificateBytes;
  final Map<String, Object?> _body;
  String get commitment => _joinDigest(jsonDecode(certificateBytes));
  Map<String, Object?> get user => {
    'id': _body['user'],
    'credential': _body['credential'],
    'permission': _body['permission'],
    'revoked': false,
    'shops': [_body['shop']],
    'capabilities': ['createJob'],
  };
}

final class VerifiedUserProvisionRequest {
  VerifiedUserProvisionRequest._(this._signedBytes, this._peer);
  final String _signedBytes;
  final VerifiedPeerMembership _peer;
  Map<String, Object?> get _signed =>
      Map<String, Object?>.from(jsonDecode(_signedBytes) as Map);
  Map<String, Object?> get _body =>
      Map<String, Object?>.from(_signed['body'] as Map);
  String get requestId => _body['request'] as String;
  String get userId => _body['user'] as String;
}

final class UserProvisionInvitation {
  UserProvisionInvitation._(this.requestId, this.userId, this.name, this._peer);
  final String requestId;
  final String userId;
  final String name;
  final VerifiedPeerMembership _peer;
}

final class CompanyUserProvisionStatus {
  CompanyUserProvisionStatus._(
    this.userId,
    this.targetDeviceId,
    this.confirmed, [
    this.disabled = false,
  ]);
  final String userId;
  final String? targetDeviceId;
  final bool confirmed;
  final bool disabled;
}

void _validateUserName(String name) {
  if (name.isEmpty ||
      name != name.trim() ||
      utf8.encode(name).length > _userNameByteLimit ||
      name.runes.any((r) => r < 32 || (r >= 127 && r <= 159))) {
    throw const CompanyBootstrapRefusal(
      'User name must contain 1 to 64 UTF-8 bytes without controls',
    );
  }
}

Future<ResolvedCompanyUserAuthority> resolveCompanyUserAuthority({
  required AppDatabase db,
  required InstallationSecurity installation,
  required String certificateBytes,
}) async {
  final trust = await installation.readCompanyTrust(db);
  if (trust == null) {
    throw const CompanyBootstrapRefusal('Company authority unavailable');
  }
  return _resolveActiveUserAuthority(
    db,
    installation,
    trust,
    installation.knownSecurityFloors,
    certificateBytes,
  );
}

Future<ResolvedCompanyUserAuthority> _resolveUserAuthority(
  AppDatabase db,
  CompanyTrustAnchor trust,
  Map<String, int> floors,
  String certificateBytes,
) async {
  if (_decodeUserJson(certificateBytes) is List) {
    final state = await CompanyUserStateCertificate.verify(
      certificateBytes,
      db: db,
      trust: trust,
      floors: floors,
    );
    final original = Map<String, Object?>.from(
      (jsonDecode(state.originalCertificateBytes) as Map)['body'] as Map,
    );
    return ResolvedCompanyUserAuthority._(certificateBytes, {
      ...original,
      'credential': state.credentialVersion,
    });
  }
  if (utf8.encode(certificateBytes).length > 1024) {
    throw const CompanyBootstrapRefusal('User certificate exceeds capacity');
  }
  final signed = _joinObject(jsonDecode(certificateBytes), {
    'body',
    'signature',
  });
  if (_securityCanonical(signed) != certificateBytes) {
    throw const CompanyBootstrapRefusal('Noncanonical user certificate');
  }
  final body = _joinObject(signed['body'], {
    'v',
    'kind',
    'company',
    'shop',
    'authority',
    'facts',
    'user',
    'name',
    'credential',
    'permission',
    'capabilities',
    'request',
    'issuer',
    'device',
  });
  if (body['v'] != 1 ||
      body['kind'] != 'company.user.authority@1' ||
      body['company'] != trust.companyId.value ||
      body['authority'] != trust.authorityVersion ||
      body['facts'] != trust.factsCommitment ||
      body['credential'] != 1 ||
      body['permission'] != 1 ||
      _securityCanonical(body['capabilities']) != '["createJob"]') {
    throw const CompanyBootstrapRefusal('User authority or version differs');
  }
  for (final key in [
    'company',
    'shop',
    'user',
    'request',
    'issuer',
    'device',
  ]) {
    _joinId(body, key);
  }
  _validateUserName(_joinString(body, 'name', maximum: _userNameByteLimit));
  final authority = await _membershipAuthority(db, trust);
  final issuer = Map<String, Object?>.from(
    (authority['users'] as List).single as Map,
  );
  final device = Map<String, Object?>.from(
    (authority['devices'] as List).single as Map,
  );
  if (body['shop'] != authority['shop'] ||
      body['issuer'] != issuer['id'] ||
      body['device'] != device['id'] ||
      body['user'] == issuer['id'] ||
      !(issuer['capabilities'] as List).contains('enrollDevice') ||
      !(device['capabilities'] as List).contains('enrollDevice')) {
    throw const CompanyBootstrapRefusal(
      'User issuer is not the authority owner',
    );
  }
  _memberFloors(issuer, device, trust, floors);
  final resolved = ResolvedCompanyUserAuthority._(certificateBytes, body);
  _memberFloors(resolved.user, device, trust, floors);
  await _joinVerify(
    body,
    signed['signature'],
    base64Encode(trust.rootKey),
    _userAuthorityDomain,
  );
  return resolved;
}

final class _UserAccount {
  _UserAccount._(this.values, this.revision, {required this.slot});
  final Map<String, Object?> values;
  final String? revision;
  final int slot;
  bool get isCurrentState => values['v'] == 3;
  String get certificate =>
      isCurrentState ? _securityCanonical(values['c']) : values['c'] as String;
  List<Object?> get binding => (values['b'] as List).cast<Object?>();
  List<Object?> get credential => (values['p'] as List).cast<Object?>();
  _UserDisable? get disable =>
      values['d'] == null ? null : _UserDisable.decode(values['d']);
  bool get isDisabled => isCurrentState
      ? ((values['c'] as List)[0] as List)[12] == 1
      : disable != null;
  int get attempts => values['a'] as int;
  String get identityCommitment => _joinDigest({
    'locator': slot,
    'c': certificate,
    'b': binding,
    'p': values['p'],
    if (disable != null) 'd': disable!.identity,
  });
  _UserAccount change(Map<String, Object?> changes) => _UserAccount.decode(
    Uint8List.fromList(
      utf8.encode(_securityCanonical({...values, ...changes})),
    ),
    revision: revision,
    slot: slot,
  );
  Uint8List encode() {
    final bytes = Uint8List.fromList(utf8.encode(_securityCanonical(values)));
    if (bytes.length > kInstallationStateLimit) {
      throw const CompanyBootstrapRefusal(
        'Protected user account capacity reached',
      );
    }
    return bytes;
  }

  static _UserAccount decode(
    Uint8List bytes, {
    String? revision,
    required int slot,
  }) {
    if (bytes.length > kInstallationStateLimit) {
      throw const CompanyBootstrapRefusal(
        'Protected user account capacity reached',
      );
    }
    final text = _decodeUserUtf8(bytes);
    final decoded = _decodeUserJson(text);
    if (decoded is Map && decoded['v'] == 3 && decoded['v'] is int) {
      final value = _joinObject(decoded, {
        'v',
        'c',
        'b',
        'p',
        'a',
        'o',
        'r',
        'j',
      });
      if (_securityCanonical(value) != text ||
          value['a'] is! int ||
          (value['a'] as int) < 0 ||
          (value['a'] as int) > _companyAttempts) {
        throw const CompanyBootstrapRefusal('Invalid protected current user');
      }
      _stateTuple(value['c'], 2);
      _stateTuple(value['b'], 4);
      if (value['p'] != null) _stateTuple(value['p'], 3);
      return _UserAccount._(value, revision, slot: slot);
    }
    final value = _joinObject(decoded, {
      'v',
      'c',
      'b',
      'p',
      'a',
      'o',
      'r',
      if (decoded is Map && decoded['v'] == 2) 'd',
    });
    if (_securityCanonical(value) != text ||
        (value['v'] != 1 && value['v'] != 2) ||
        value['c'] is! String ||
        value['b'] is! List ||
        (value['b'] as List).length != 4 ||
        (value['d'] == null
            ? value['p'] is! List || (value['p'] as List).length != 3
            : value['p'] != null) ||
        value['a'] is! int ||
        (value['a'] as int) < 0 ||
        (value['a'] as int) > _companyAttempts) {
      throw const CompanyBootstrapRefusal('Unsupported protected user account');
    }
    final binding = (value['b'] as List).cast<Object?>();
    if (_decodeUserJson(value['c'] as String) is! Map) {
      throw const CompanyBootstrapRefusal(
        'Current user state requires its compatible protected record',
      );
    }
    for (final index in [0, 1, 3]) {
      if (binding[index] is! String ||
          !Uuid.isValidUUID(fromString: binding[index] as String)) {
        throw const CompanyBootstrapRefusal(
          'Invalid user installation binding',
        );
      }
    }
    _userBase64(binding[2], 32);
    if (value['d'] != null) {
      _UserDisable.decode(value['d']);
    } else {
      final pin = (value['p'] as List).cast<Object?>();
      if (pin[0] != 1) {
        throw const CompanyBootstrapRefusal('Unsupported user PIN profile');
      }
      _userBase64(pin[1], 16);
      _userBase64(pin[2], 32);
    }
    final outgoing = value['o'];
    if (outgoing != null) {
      if (outgoing is! List ||
          outgoing.length != 8 ||
          (outgoing[0] != 0 && outgoing[0] != 1)) {
        throw const CompanyBootstrapRefusal(
          'Unsupported user provisioning state',
        );
      }
      for (final i in [1, 2, 3, 4, 6, 7]) {
        if (outgoing[i] is! String ||
            !Uuid.isValidUUID(fromString: outgoing[i] as String)) {
          throw const CompanyBootstrapRefusal(
            'Invalid user provisioning identity',
          );
        }
      }
      _userBase64(outgoing[5], 32);
    }
    if (value['r'] != null) _userBase64(value['r'], 64);
    if (value['r'] != null && outgoing == null) {
      throw const CompanyBootstrapRefusal(
        'User receipt has no provisioning identity',
      );
    }
    return _UserAccount._(value, revision, slot: slot);
  }
}

final class _UserAccounts {
  _UserAccounts(this.byUserId, this.creationRequests);
  final Map<String, _UserAccount> byUserId;
  final Map<String, String> creationRequests;

  _UserAccount? select(String userId) => byUserId[userId];

  int get freeSlot {
    final occupied = byUserId.values.map((account) => account.slot).toSet();
    for (var slot = 1; slot <= kCompanyUserCapacity; slot++) {
      if (!occupied.contains(slot)) return slot;
    }
    throw const CompanyBootstrapRefusal('Company user capacity reached');
  }
}

void _userBase64(Object? value, int length) {
  if (value is! String || value.length > 88) {
    throw const CompanyBootstrapRefusal('Invalid protected user field');
  }
  final Uint8List bytes;
  try {
    bytes = base64Decode(value);
  } catch (_) {
    throw const CompanyBootstrapRefusal('Invalid protected user field');
  }
  if (bytes.length != length || base64Encode(bytes) != value) {
    throw const CompanyBootstrapRefusal('Invalid protected user field');
  }
}

String _decodeUserUtf8(Uint8List bytes) {
  try {
    return utf8.decode(bytes);
  } catch (_) {
    throw const CompanyBootstrapRefusal('Malformed protected user data');
  }
}

Object? _decodeUserJson(String text) {
  try {
    return jsonDecode(text);
  } catch (_) {
    throw const CompanyBootstrapRefusal('Malformed protected user data');
  }
}

// Routing only. The selected account and supplied certificate still require
// their existing signature, current-state and installation checks.
String _userCertificateUserId(String certificate) {
  final decoded = _decodeUserJson(certificate);
  final Object? id;
  if (decoded is List) {
    id = _stateTuple(_stateTuple(decoded, 2)[0], 16)[5];
  } else {
    final signed = _joinObject(decoded, {'body', 'signature'});
    final body = signed['body'];
    if (body is! Map) {
      throw const CompanyBootstrapRefusal('User certificate differs');
    }
    id = body['user'];
  }
  _stateId(id);
  return id as String;
}

Future<Map<String, Object?>> _openUserEnvelope(
  NearbyJoinChannel channel,
  String kind,
  Map<String, Object?> wire, {
  required String recipient,
}) async {
  try {
    return await _openJoin(channel, kind, wire, recipient: recipient);
  } on CompanyBootstrapRefusal {
    rethrow;
  } catch (_) {
    throw const CompanyBootstrapRefusal('Protected user message refused');
  }
}

extension CompanyUsers on CompanyEnrollment {
  Future<CompanyUserProvisionStatus?> userProvisionStatus(
    OwnerSession owner, {
    required String userId,
  }) async {
    await _requireUserAdministrator(owner);
    final account = await _readUserAccount(userId: userId);
    if (account == null) return null;
    final user = await _checkUserAccount(account, requireActive: false);
    final outgoing = account.values['o'];
    final disable = account.disable;
    return CompanyUserProvisionStatus._(
      user.user['id'] as String,
      disable != null
          ? (disable.target?[1] as String?)
          : (outgoing is List ? outgoing[2] as String : null),
      disable != null ? disable.receipt != null : account.values['r'] != null,
      account.isDisabled,
    );
  }

  Future<Map<String, Object?>> prepareUserProvisionInvitation({
    required OwnerSession owner,
    required VerifiedPeerMembership peer,
    required String userId,
  }) async {
    await _requireUserAdministrator(owner);
    await _requireUserPeer(peer);
    final account = await _readUserAccount(userId: userId);
    if (account == null) {
      throw const CompanyBootstrapRefusal('Create one additional user first');
    }
    if (account.isCurrentState) {
      throw const CompanyBootstrapRefusal(
        'Use the compatible retained-peer Sync Now flow for the current user PIN state',
      );
    }
    await _checkUserAccount(account);
    final outgoing = account.values['o'];
    if (outgoing is List &&
        (outgoing[0] != 0 || outgoing[2] != peer.deviceId)) {
      throw const CompanyBootstrapRefusal(
        'Additional user is bound to another recipient',
      );
    }
    final request = outgoing is List
        ? outgoing[1] as String
        : const Uuid().v4();
    final channel = await _userChannel(peer);
    final wire = await _sealJoin(
      channel,
      'user-provision-invite',
      request,
      peer._held.peer._membership.device['key'] as String,
      {
        'v': 1,
        'kind': 'company.user.provision.invite@1',
        'profile': kCompanyUserProfile,
        'capacity': kCompanyUserCapacity,
        'request': request,
        'certificate': account.certificate,
        'sender': owner.identity.deviceId,
        'recipient': peer.deviceId,
      },
    );
    await _requireUserAdministrator(owner);
    await _requireUserPeer(peer);
    return wire;
  }

  Future<UserProvisionInvitation> receiveUserProvisionInvitation(
    Map<String, Object?> wire, {
    required VerifiedPeerMembership peer,
  }) async {
    final channel = await _userChannel(peer);
    final body = _joinObject(
      await _openUserEnvelope(
        channel,
        'user-provision-invite',
        wire,
        recipient: base64Encode(installation.identity!.publicKey),
      ),
      {
        'v',
        'kind',
        'profile',
        'capacity',
        'request',
        'certificate',
        'sender',
        'recipient',
      },
    );
    _joinId(body, 'request');
    if (body['v'] != 1 ||
        body['kind'] != 'company.user.provision.invite@1' ||
        body['profile'] != kCompanyUserProfile ||
        body['capacity'] is! int ||
        body['capacity'] != kCompanyUserCapacity ||
        body['recipient'] != currentSession!.identity.deviceId ||
        body['sender'] != peer.deviceId ||
        body['certificate'] is! String) {
      throw const CompanyBootstrapRefusal('User invitation binding differs');
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null) {
      throw const CompanyBootstrapRefusal('Company unavailable');
    }
    final user = await _resolveUserAuthority(
      db,
      trust,
      installation.knownSecurityFloors,
      body['certificate'] as String,
    );
    final existing = await _readUserAccount(userId: user.user['id'] as String);
    if (existing != null) await _checkUserAccount(existing);
    if (user._body['device'] != peer.deviceId) {
      throw const CompanyBootstrapRefusal(
        'Only the authority owner may provision this user',
      );
    }
    await _requireUserPeer(peer);
    return UserProvisionInvitation._(
      body['request'] as String,
      user.user['id'] as String,
      user._body['name'] as String,
      peer,
    );
  }

  Future<Map<String, Object?>> acceptUserProvisionInvitation(
    UserProvisionInvitation invitation,
  ) => prepareUserProvisionRequest(
    peer: invitation._peer,
    requestId: invitation.requestId,
    userId: invitation.userId,
  );

  Future<void> _requireSessionAccount(CompanySession session) async {
    if (session is! RestrictedUserSession) return;
    final account = await _readUserAccount(userId: session.identity.userId);
    final trust = installation._record?.companyTrust;
    if (account == null ||
        trust == null ||
        account.identityCommitment != session._accountCommitment ||
        _securityCanonical(account.binding) !=
            _securityCanonical(_userBinding())) {
      session._clear();
      throw const CompanyBootstrapRefusal('Selected user account changed');
    }
    if (account.isDisabled) {
      session._clear();
      throw const CompanyBootstrapRefusal('This company user is disabled');
    }
    final user = await _resolveActiveUserAuthority(
      db,
      installation,
      trust,
      installation.knownSecurityFloors,
      account.certificate,
    );
    if (user.user['id'] != session.identity.userId) {
      throw const CompanyBootstrapRefusal('Selected user identity changed');
    }
    session.validateAuthority(trust, installation.knownSecurityFloors);
  }

  Future<void> _requireUserPeer(VerifiedPeerMembership peer) async {
    if (!identical(peer._owner.enrollment, this)) {
      throw const CompanyBootstrapRefusal(
        'User provisioning belongs to another installation',
      );
    }
    try {
      await peer.requireCurrent();
    } on NearbyException {
      throw const CompanyBootstrapRefusal(
        'Authenticated user provisioning peer is no longer current',
      );
    }
    if (!identical(currentSession, peer._held.owner)) {
      throw const CompanyBootstrapRefusal(
        'Current enrolled owner sign-in required',
      );
    }
  }

  List<Object?> _userPeerBinding(
    ResolvedCompanyMembership member,
    String store,
  ) => [
    member.device['id'],
    member.device['installation'],
    member.device['generation'],
    member.device['key'],
    store,
    member.device['grant'],
  ];

  Future<NearbyJoinChannel> _userChannel(VerifiedPeerMembership peer) async {
    await _requireUserPeer(peer);
    final channel = peer._held.channel;
    Future<SecretKey> derive(SecretKey key, String direction) =>
        Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
          secretKey: key,
          nonce: utf8.encode(channel._keys.id),
          info: utf8.encode('wiredpart-v2/company-user-provision@1/$direction'),
        );
    final result = NearbyJoinChannel._(
      channel._pair,
      channel._keys,
      await derive(channel._send, channel._keys.sendDirection),
      await derive(channel._receive, channel._keys.receiveDirection),
    );
    await _requireUserPeer(peer);
    return result;
  }

  Future<Map<String, Object?>> prepareUserProvisionRequest({
    required VerifiedPeerMembership peer,
    required String requestId,
    required String userId,
  }) async {
    _joinId({'id': requestId}, 'id');
    _joinId({'id': userId}, 'id');
    await _requireUserPeer(peer);
    final accounts = await _readUserAccounts();
    if (accounts.select(userId) == null &&
        accounts.byUserId.length >= kCompanyUserCapacity) {
      throw const CompanyBootstrapRefusal('Company user capacity reached');
    }
    final trust = installation._record!.companyTrust!;
    final local = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final body = <String, Object?>{
      'v': 1,
      'kind': 'company.user.provision.request@1',
      'profile': kCompanyUserProfile,
      'capacity': kCompanyUserCapacity,
      'company': trust.companyId.value,
      'shop': currentSession!.identity.shopId,
      'authority': trust.authorityVersion,
      'facts': trust.factsCommitment,
      'request': requestId,
      'user': userId,
      'channel': peer._held.channel._keys.id,
      'recipient': _userPeerBinding(
        local,
        installation.receivingStoreGeneration!.value,
      ),
      'sender': peer.deviceId,
    };
    final signed = await _signJoin(
      installation,
      body,
      'wiredpart.company.user.provision.request@1:',
    );
    await _requireUserPeer(peer);
    _userProvisionOffer = _securityCanonical(body);
    return signed;
  }

  Future<VerifiedUserProvisionRequest> receiveUserProvisionRequest(
    Map<String, Object?> wire, {
    required VerifiedPeerMembership peer,
  }) async {
    final snapshot = _securityCanonical(wire);
    if (utf8.encode(snapshot).length > 2048) {
      throw const CompanyBootstrapRefusal('User request capacity reached');
    }
    final signed = _joinObject(jsonDecode(snapshot), {'body', 'signature'});
    await _requireUserPeer(peer);
    final body = _joinObject(signed['body'], {
      'v',
      'kind',
      'profile',
      'capacity',
      'company',
      'shop',
      'authority',
      'facts',
      'request',
      'user',
      'channel',
      'recipient',
      'sender',
    });
    final trust = installation._record!.companyTrust!;
    _joinId(body, 'request');
    _joinId(body, 'user');
    final binding = body['recipient'];
    if (binding is! List ||
        binding.length != 6 ||
        binding[4] is! String ||
        !Uuid.isValidUUID(fromString: binding[4] as String) ||
        body['v'] != 1 ||
        body['kind'] != 'company.user.provision.request@1' ||
        body['profile'] != kCompanyUserProfile ||
        body['capacity'] is! int ||
        body['capacity'] != kCompanyUserCapacity ||
        body['company'] != trust.companyId.value ||
        body['shop'] != currentSession!.identity.shopId ||
        body['authority'] != trust.authorityVersion ||
        body['facts'] != trust.factsCommitment ||
        body['channel'] != peer._held.channel._keys.id ||
        body['sender'] != currentSession!.identity.deviceId ||
        _securityCanonical(binding) !=
            _securityCanonical(
              _userPeerBinding(
                peer._held.peer._membership,
                binding[4] as String,
              ),
            )) {
      throw const CompanyBootstrapRefusal('User recipient request differs');
    }
    await _joinVerify(
      body,
      signed['signature'],
      peer._held.peer._membership.device['key'],
      'wiredpart.company.user.provision.request@1:',
    );
    await _requireUserPeer(peer);
    return VerifiedUserProvisionRequest._(snapshot, peer);
  }

  Future<Map<String, Object?>> prepareUserProvision({
    required OwnerSession owner,
    required VerifiedPeerMembership peer,
    required VerifiedUserProvisionRequest request,
  }) async {
    if (!identical(request._peer, peer)) {
      throw const CompanyBootstrapRefusal(
        'User request belongs to another channel',
      );
    }
    await _requireUserPeer(peer);
    await _requireUserAdministrator(owner);
    return owner.runLocalCommand(() async {
      final verifiedRequest = await receiveUserProvisionRequest(
        request._signed,
        peer: peer,
      );
      var account = await _readUserAccount(userId: verifiedRequest.userId);
      if (account == null) {
        throw const CompanyBootstrapRefusal('No additional user to provision');
      }
      if (account.isCurrentState) {
        throw const CompanyBootstrapRefusal(
          'Use the compatible retained-peer Sync Now flow for the current user PIN state',
        );
      }
      final user = await _checkUserAccount(account);
      if (user.user['id'] != verifiedRequest.userId) {
        throw const CompanyBootstrapRefusal('Requested user differs');
      }
      final target = List<Object?>.from(
        verifiedRequest._body['recipient'] as List,
      );
      final outgoing = [0, verifiedRequest.requestId, ...target];
      if (account.values['o'] != null &&
          _securityCanonical(account.values['o']) !=
              _securityCanonical(outgoing)) {
        throw const CompanyBootstrapRefusal(
          'User provisioning target or request is immutable',
        );
      }
      _preflightUserCapacity(account);
      await _requireUserAdministrator(owner);
      await _requireUserPeer(peer);
      if (account.values['o'] == null) {
        account = await _writeUserAccount(
          account.change({'o': outgoing}),
          requireCurrent: () async {
            await _requireUserAdministrator(owner);
            await _requireUserPeer(peer);
          },
        );
      }
      final local = await resolveCompanyMembership(
        db: db,
        installation: installation,
      );
      final source = _userPeerBinding(
        local,
        installation.receivingStoreGeneration!.value,
      );
      final channel = await _userChannel(peer);
      final payload = <String, Object?>{
        'v': 1,
        'kind': 'company.user.provision@1',
        'certificate': account.certificate,
        'credential': account.credential,
        'request': verifiedRequest.requestId,
        'sender': source,
        'recipient': target,
      };
      final box = await _sealJoin(
        channel,
        'user-provision',
        verifiedRequest.requestId,
        target[3] as String,
        payload,
      );
      final trust = installation._record!.companyTrust!;
      final issuance = await _signJoin(installation, {
        'v': 1,
        'kind': 'company.user.provision.issuance@1',
        'profile': kCompanyUserProfile,
        'capacity': kCompanyUserCapacity,
        'company': trust.companyId.value,
        'shop': owner.identity.shopId,
        'authority': trust.authorityVersion,
        'facts': trust.factsCommitment,
        'request': verifiedRequest.requestId,
        'certificate': user.commitment,
        'sender': source,
        'recipient': target,
        'channel': channel._keys.id,
        'box': _joinDigest(box),
      }, 'wiredpart.company.user.provision.issuance@1:');
      await _requireUserAdministrator(owner);
      await _requireUserPeer(peer);
      final latest = await _readUserAccount(userId: verifiedRequest.userId);
      if (latest?.identityCommitment != account.identityCommitment ||
          _securityCanonical(latest?.values['o']) !=
              _securityCanonical(outgoing)) {
        throw const CompanyBootstrapRefusal(
          'User provisioning account changed',
        );
      }
      await _checkUserAccount(latest!);
      await _requireUserAdministrator(owner);
      await _requireUserPeer(peer);
      return {'box': box, 'issuance': issuance};
    });
  }

  Future<Map<String, Object?>> _userReceiptBody(_UserAccount account) async {
    final transfer = account.values['o'] as List;
    final local = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final localBinding = _userPeerBinding(
      local,
      installation.receivingStoreGeneration!.value,
    );
    final remote = transfer.sublist(2);
    return {
      'v': 1,
      'kind': 'company.user.provision.receipt@1',
      'certificate': _joinDigest(jsonDecode(account.certificate)),
      'request': transfer[1],
      'sender': transfer[0] == 0 ? localBinding : remote,
      'recipient': transfer[0] == 0 ? remote : localBinding,
    };
  }

  Future<Map<String, Object?>> acceptUserProvision(
    Map<String, Object?> wire, {
    required VerifiedPeerMembership peer,
  }) async {
    final snapshot = _securityCanonical(wire);
    if (utf8.encode(snapshot).length > 8192) {
      throw const CompanyBootstrapRefusal('User envelope capacity reached');
    }
    final value = _joinObject(jsonDecode(snapshot), {'box', 'issuance'});
    await _requireUserPeer(peer);
    final box = Map<String, Object?>.from(value['box'] as Map);
    final signed = _joinObject(value['issuance'], {'body', 'signature'});
    final issuance = _joinObject(signed['body'], {
      'v',
      'kind',
      'profile',
      'capacity',
      'company',
      'shop',
      'authority',
      'facts',
      'request',
      'certificate',
      'sender',
      'recipient',
      'channel',
      'box',
    });
    final trust = installation._record!.companyTrust!;
    final local = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final target = _userPeerBinding(
      local,
      installation.receivingStoreGeneration!.value,
    );
    final source = issuance['sender'];
    if (source is! List ||
        source.length != 6 ||
        source[4] is! String ||
        !Uuid.isValidUUID(fromString: source[4] as String) ||
        issuance['v'] != 1 ||
        issuance['kind'] != 'company.user.provision.issuance@1' ||
        issuance['profile'] != kCompanyUserProfile ||
        issuance['capacity'] is! int ||
        issuance['capacity'] != kCompanyUserCapacity ||
        issuance['company'] != trust.companyId.value ||
        issuance['shop'] != currentSession!.identity.shopId ||
        issuance['authority'] != trust.authorityVersion ||
        issuance['facts'] != trust.factsCommitment ||
        issuance['channel'] != peer._held.channel._keys.id ||
        issuance['box'] != _joinDigest(box) ||
        _securityCanonical(issuance['recipient']) !=
            _securityCanonical(target) ||
        _securityCanonical(source) !=
            _securityCanonical(
              _userPeerBinding(
                peer._held.peer._membership,
                source[4] as String,
              ),
            )) {
      throw const CompanyBootstrapRefusal('User provisioning binding differs');
    }
    _joinId(issuance, 'request');
    final authority = await _membershipAuthority(db, trust);
    final rootDevice = (authority['devices'] as List).single as Map;
    if (source[0] != rootDevice['id']) {
      throw const CompanyBootstrapRefusal(
        'User provisioning issuer is not the authority owner',
      );
    }
    await _joinVerify(
      issuance,
      signed['signature'],
      source[3],
      'wiredpart.company.user.provision.issuance@1:',
    );
    final channel = await _userChannel(peer);
    final payload = _joinObject(
      await _openUserEnvelope(
        channel,
        'user-provision',
        box,
        recipient: target[3] as String,
      ),
      {
        'v',
        'kind',
        'certificate',
        'credential',
        'request',
        'sender',
        'recipient',
      },
    );
    if (payload['v'] != 1 ||
        payload['kind'] != 'company.user.provision@1' ||
        payload['request'] != issuance['request'] ||
        _securityCanonical(payload['sender']) != _securityCanonical(source) ||
        _securityCanonical(payload['recipient']) !=
            _securityCanonical(target) ||
        payload['certificate'] is! String ||
        _joinDigest(jsonDecode(payload['certificate'] as String)) !=
            issuance['certificate']) {
      throw const CompanyBootstrapRefusal('User provisioning contents differ');
    }
    final offerSnapshot = _userProvisionOffer;
    final offer = offerSnapshot == null
        ? null
        : Map<String, Object?>.from(jsonDecode(offerSnapshot) as Map);
    final selected =
        (jsonDecode(payload['certificate'] as String) as Map)['body'] as Map;
    if (offer == null ||
        offer['request'] != issuance['request'] ||
        offer['user'] != selected['user'] ||
        offer['channel'] != channel._keys.id ||
        offer['sender'] != peer.deviceId ||
        _securityCanonical(offer['recipient']) != _securityCanonical(target)) {
      throw const CompanyBootstrapRefusal(
        'Confirm this user provisioning request first',
      );
    }
    final accounts = await _readUserAccounts();
    var existing = accounts.select(selected['user'] as String);
    final creationRequest = selected['request'] as String;
    if (accounts.creationRequests[creationRequest] case final other?) {
      if (other != selected['user']) {
        throw const CompanyBootstrapRefusal('User creation request collision');
      }
    }
    var account = _UserAccount.decode(
      Uint8List.fromList(
        utf8.encode(
          _securityCanonical({
            'v': 2,
            'd': null,
            'c': payload['certificate'],
            'b': _userBinding(),
            'p': payload['credential'],
            'a': _companyAttempts,
            'o': [1, issuance['request'], ...source],
            'r': null,
          }),
        ),
      ),
      slot: existing?.slot ?? accounts.freeSlot,
    );
    await _checkUserAccount(account);
    _preflightUserCapacity(account);
    if (existing != null) {
      await _checkUserAccount(existing);
      if (existing.identityCommitment != account.identityCommitment ||
          _securityCanonical(existing.values['o']) !=
              _securityCanonical(account.values['o'])) {
        throw const CompanyBootstrapRefusal(
          'Conflicting or stale user provisioning',
        );
      }
      account = existing;
    }
    final receiptBody = await _userReceiptBody(account);
    final receipt = await _signJoin(
      installation,
      receiptBody,
      'wiredpart.company.user.provision.receipt@1:',
    );
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: selected['user'] as String);
    if (existing == null && latest != null) {
      throw const CompanyBootstrapRefusal(
        'User account changed during provisioning',
      );
    }
    if (existing != null) {
      if (latest == null ||
          latest.identityCommitment != account.identityCommitment ||
          _securityCanonical(latest.values['o']) !=
              _securityCanonical(account.values['o'])) {
        throw const CompanyBootstrapRefusal(
          'User account changed during provisioning',
        );
      }
      account = latest;
    }
    await _checkUserAccount(account);
    await _requireUserPeer(peer);
    if (offerSnapshot != _userProvisionOffer) {
      throw const CompanyBootstrapRefusal('User provisioning consent changed');
    }
    if (account.values['r'] != receipt['signature']) {
      account = await _writeUserAccount(
        account.change({'r': receipt['signature']}),
        requireCurrent: () async {
          await _requireUserPeer(peer);
          if (offerSnapshot != _userProvisionOffer) {
            throw const CompanyBootstrapRefusal(
              'User provisioning consent changed',
            );
          }
        },
      );
    }
    return _sealJoin(
      channel,
      'user-provision-ack',
      issuance['request'] as String,
      source[3] as String,
      receipt,
    );
  }

  Future<void> acceptUserProvisionReceipt(
    Map<String, Object?> wire, {
    required VerifiedPeerMembership peer,
    required String userId,
  }) async {
    await _requireUserPeer(peer);
    final channel = await _userChannel(peer);
    final signed = _joinObject(
      await _openUserEnvelope(
        channel,
        'user-provision-ack',
        wire,
        recipient: base64Encode(installation.identity!.publicKey),
      ),
      {'body', 'signature'},
    );
    var account = await _readUserAccount(userId: userId);
    if (account == null ||
        account.values['o'] is! List ||
        (account.values['o'] as List)[0] != 0) {
      throw const CompanyBootstrapRefusal('User provisioning is not pending');
    }
    await _checkUserAccount(account);
    final receiptBody = await _userReceiptBody(account);
    if (_securityCanonical(signed['body']) != _securityCanonical(receiptBody) ||
        (account.values['o'] as List)[2] != peer.deviceId) {
      throw const CompanyBootstrapRefusal('User receipt target differs');
    }
    await _joinVerify(
      receiptBody,
      signed['signature'],
      peer._held.peer._membership.device['key'],
      'wiredpart.company.user.provision.receipt@1:',
    );
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: userId);
    if (latest == null ||
        latest.identityCommitment != account.identityCommitment ||
        _securityCanonical(latest.values['o']) !=
            _securityCanonical(account.values['o'])) {
      throw const CompanyBootstrapRefusal('User provisioning state changed');
    }
    account = latest;
    await _checkUserAccount(account);
    await _requireUserPeer(peer);
    if (account.values['r'] != signed['signature']) {
      await _writeUserAccount(
        account.change({'r': signed['signature']}),
        requireCurrent: () async {
          await _requireUserPeer(peer);
        },
      );
    }
  }

  Future<_UserAccounts> _readUserAccounts({bool reconcile = true}) async {
    try {
      final accounts = <String, _UserAccount>{};
      final requests = <String, String>{};
      for (var slot = 1; slot <= kCompanyUserCapacity; slot++) {
        final state = await installation.store.readState(
          companyUserNamespace(installation.namespace, slot: slot),
        );
        if (state == null) continue;
        final account = _UserAccount.decode(
          state.bytes,
          revision: state.revision,
          slot: slot,
        );
        final authority = await _checkUserAccount(
          account,
          requireActive: false,
          requireJournal: false,
        );
        final user = authority.user['id'] as String;
        final request = authority._body['request'] as String;
        if (accounts.containsKey(user) || requests.containsKey(request)) {
          throw const CompanyBootstrapRefusal(
            'Protected user identity or creation request collision',
          );
        }
        accounts[user] = account;
        requests[request] = user;
      }
      if (reconcile) {
        for (final user in accounts.keys.toList()) {
          final account = accounts[user]!;
          if (account.isCurrentState) {
            accounts[user] = await _reconcileUserPinState(account);
          }
        }
      }
      return _UserAccounts(
        Map.unmodifiable(accounts),
        Map.unmodifiable(requests),
      );
    } on CompanyBootstrapRefusal {
      rethrow;
    } catch (_) {
      throw const CompanyBootstrapRefusal('Protected user account unavailable');
    }
  }

  Future<_UserAccount?> _readUserAccount({
    required String userId,
    bool reconcile = true,
  }) async => (await _readUserAccounts(reconcile: reconcile)).select(userId);

  List<Object?> _userBinding() => [
    installation.identity!.id.value,
    installation.identity!.generation.value,
    base64Encode(installation.identity!.publicKey),
    installation.receivingStoreGeneration!.value,
  ];

  Future<ResolvedCompanyUserAuthority> _checkUserAccount(
    _UserAccount account, {
    bool requireActive = true,
    bool requireJournal = true,
  }) async {
    final custody = await _readCustody();
    if (custody == null) {
      throw const CompanyBootstrapRefusal('Company is unavailable');
    }
    final heldCommand =
        db.hasCallerTransaction && installation._record?.pendingCommand != null;
    final trust = await _userStateTrust();
    if (heldCommand) {
      await _checkCurrentBinding(custody, requireActive: true);
    } else {
      await _checkBinding(custody, requireActive: true);
    }
    if (_securityCanonical(account.binding) !=
        _securityCanonical(_userBinding())) {
      throw const CompanyBootstrapRefusal(
        'User unavailable on this installation',
      );
    }
    if (account.isCurrentState) {
      await CompanyUserStateRecord._decode(
        account.encode(),
        db: db,
        installation: installation,
        heldTrust: trust,
      );
      if (requireJournal) await _requireUserJournal(account);
    }
    final user = await _resolveUserAuthority(
      db,
      trust,
      installation.knownSecurityFloors,
      account.certificate,
    );
    await _verifyUserDisable(account, user, trust);
    if (requireActive && account.isDisabled) {
      throw const CompanyBootstrapRefusal('This company user is disabled');
    }
    return user;
  }

  void _preflightUserCapacity(_UserAccount account) {
    const id = 'ffffffff-ffff-4fff-bfff-ffffffffffff';
    final worst = account.change({
      'o': [0, id, id, id, id, base64Encode(List<int>.filled(32, 255)), id, id],
      'r': base64Encode(List<int>.filled(64, 255)),
    });
    worst.encode();
    if (account.isCurrentState) return;
    worst.change({
      'v': 2,
      'p': null,
      'd': [
        1,
        id,
        base64Encode(List<int>.filled(64, 255)),
        [0, id, id, id, base64Encode(List<int>.filled(32, 255)), id, id],
        base64Encode(List<int>.filled(64, 255)),
      ],
    }).encode();
  }

  Future<_UserAccount> _writeUserAccount(
    _UserAccount next, {
    required Future<void> Function() requireCurrent,
  }) async {
    final accounts = await _readUserAccounts(reconcile: false);
    final authority = await _checkUserAccount(
      next,
      requireActive: false,
      requireJournal: false,
    );
    final userId = authority.user['id'] as String;
    final creationRequest = authority._body['request'] as String;
    final selected = accounts.select(userId);
    final requestOwner = accounts.creationRequests[creationRequest];
    if ((selected != null && selected.slot != next.slot) ||
        (requestOwner != null && requestOwner != userId) ||
        accounts.byUserId.entries.any(
          (entry) => entry.key != userId && entry.value.slot == next.slot,
        )) {
      throw const CompanyBootstrapRefusal(
        'Protected user locator or creation request changed',
      );
    }
    final bytes = next.encode();
    final revision = const Uuid().v4();
    final namespace = companyUserNamespace(
      installation.namespace,
      slot: next.slot,
    );
    await requireCurrent();
    try {
      await installation.store.compareAndSwapState(
        namespace,
        expectedRevision: next.revision,
        nextRevision: revision,
        bytes: bytes,
      );
    } catch (_) {
      final saved = await installation.store.readState(namespace);
      if (saved == null ||
          saved.revision != revision ||
          base64Encode(saved.bytes) != base64Encode(bytes)) {
        rethrow;
      }
    }
    return _UserAccount.decode(bytes, revision: revision, slot: next.slot);
  }

  Future<_CompanyCustody> _requireUserAdministrator(OwnerSession owner) async {
    final custody = await _readCustody();
    if (!identical(currentSession, owner) ||
        custody == null ||
        custody.isMember) {
      throw const CompanyBootstrapRefusal(
        'Current authority owner sign-in required',
      );
    }
    await _checkBinding(custody, requireActive: true);
    final membership = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final trust = installation._record!.companyTrust!;
    owner.validateAuthority(trust, installation.knownSecurityFloors);
    owner.validateCommand(
      company: custody.company,
      shop: custody.shop,
      user: custody.user,
      device: custody.device,
      installation: custody.installation,
      generation: custody.generation,
      session: owner.sessionId,
    );
    if (!(membership.user['capabilities'] as List).contains('enrollDevice') ||
        !(membership.device['capabilities'] as List).contains('enrollDevice')) {
      throw const CompanyBootstrapRefusal(
        'User administration permission denied',
      );
    }
    return custody;
  }

  Future<List<CompanyUserChoice>> listCompanyUsers() async {
    final custody = await _readCustody();
    if (custody == null) return const [];
    await _checkBinding(custody, requireActive: true);
    final membership = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final result = [
      CompanyUserChoice._(
        custody.user,
        'Owner',
        List<String>.unmodifiable(
          (membership.user['capabilities'] as List).cast<String>(),
        ),
        true,
      ),
    ];
    try {
      final accounts = await _readUserAccounts();
      for (final account in accounts.byUserId.values) {
        final user = await _checkUserAccount(account, requireActive: false);
        result.add(
          CompanyUserChoice._(
            user.user['id'] as String,
            user._body['name'] as String,
            const ['createJob'],
            !account.isDisabled && account.values['p'] != null,
            account.isDisabled,
          ),
        );
      }
    } catch (_) {
      result.add(
        CompanyUserChoice._(
          '',
          'Additional user unavailable. Provisioning required.',
          const [],
          false,
        ),
      );
    }
    return List.unmodifiable(result);
  }

  Future<CompanyUserReceipt> createRestrictedUser({
    required OwnerSession owner,
    required String requestId,
    required String name,
    required String pin,
  }) async {
    _joinId({'id': requestId}, 'id');
    _validateUserName(name);
    final pattern = installation.namespace.startsWith('synthetic.')
        ? RegExp(r'^\d{4,12}$')
        : RegExp(r'^\d{8,12}$');
    if (!pattern.hasMatch(pin)) {
      throw const CompanyBootstrapRefusal('User PIN refused');
    }
    await _requireUserAdministrator(owner);
    return owner.runLocalCommand(() async {
      final custody = await _requireUserAdministrator(owner);
      final accounts = await _readUserAccounts();
      final existingId = accounts.creationRequests[requestId];
      final existing = existingId == null ? null : accounts.select(existingId);
      if (existing != null) {
        final authority = await _checkUserAccount(existing);
        if (authority._body['request'] != requestId ||
            authority._body['name'] != name ||
            !await _userPinMatches(existing, pin)) {
          throw const CompanyBootstrapRefusal(
            'Additional user capacity or immutable request differs',
          );
        }
        await _requireUserAdministrator(owner);
        final latest = await _readUserAccount(userId: existingId!);
        if (latest?.identityCommitment != existing.identityCommitment) {
          throw const CompanyBootstrapRefusal('User account changed');
        }
        return CompanyUserReceipt._(existing.certificate, authority._body);
      }
      final slot = accounts.freeSlot;
      final trust = installation._record!.companyTrust!;
      final body = <String, Object?>{
        'v': 1,
        'kind': 'company.user.authority@1',
        'company': custody.company,
        'shop': custody.shop,
        'authority': trust.authorityVersion,
        'facts': trust.factsCommitment,
        'user': const Uuid().v4(),
        'name': name,
        'credential': 1,
        'permission': 1,
        'capabilities': ['createJob'],
        'request': requestId,
        'issuer': custody.user,
        'device': custody.device,
      };
      final salt = _secureRandom(16);
      var account = _UserAccount._(
        {
          'v': 2,
          'd': null,
          'c': _securityCanonical({
            'body': body,
            'signature': base64Encode(List<int>.filled(64, 255)),
          }),
          'b': _userBinding(),
          'p': [1, base64Encode(salt), base64Encode(List<int>.filled(32, 255))],
          'a': _companyAttempts,
          'o': null,
          'r': null,
        },
        null,
        slot: slot,
      );
      _preflightUserCapacity(account);
      final verifier = await _deriveCompanySecret(pin, salt);
      await _requireUserAdministrator(owner);
      final signature = await Ed25519().sign(
        utf8.encode('$_userAuthorityDomain${_securityCanonical(body)}'),
        keyPair: await Ed25519().newKeyPairFromSeed(custody.rootSeed),
      );
      account = account.change({
        'c': _securityCanonical({
          'body': body,
          'signature': base64Encode(signature.bytes),
        }),
        'p': [1, base64Encode(salt), base64Encode(verifier)],
      });
      await _requireUserAdministrator(owner);
      await _checkUserAccount(account);
      await _requireUserAdministrator(owner);
      await _writeUserAccount(
        account,
        requireCurrent: () async {
          await _requireUserAdministrator(owner);
        },
      );
      return CompanyUserReceipt._(account.certificate, body);
    });
  }

  Future<bool> _userPinMatches(_UserAccount account, String pin) async {
    final actual = await _deriveCompanySecret(
      pin,
      base64Decode(account.credential[1] as String),
    );
    final wanted = base64Decode(account.credential[2] as String);
    var mismatch = actual.length ^ wanted.length;
    for (var i = 0; i < wanted.length; i++) {
      mismatch |= wanted[i] ^ actual[i];
    }
    return mismatch == 0;
  }

  Future<CompanySession> signInUser(String userId, String pin) async {
    final releasing = signOut();
    final epoch = _authenticationEpoch;
    await releasing;
    final custody = await _readCustody();
    if (epoch != _authenticationEpoch) {
      throw const CompanyBootstrapRefusal('User sign-in was cancelled');
    }
    if (custody?.user == userId) return signIn(pin);
    var account = await _readUserAccount(userId: userId);
    if (account == null) {
      throw const CompanyBootstrapRefusal('User is not available locally');
    }
    final user = await _checkUserAccount(account);
    if (user.user['id'] != userId ||
        account.attempts == 0 ||
        account.values['p'] == null) {
      throw const CompanyBootstrapRefusal('User PIN refused');
    }
    account = await _writeUserAccount(
      account.change({'a': account.attempts - 1}),
      requireCurrent: () async {
        if (epoch != _authenticationEpoch) {
          throw const CompanyBootstrapRefusal('User sign-in was cancelled');
        }
      },
    );
    final pattern = installation.namespace.startsWith('synthetic.')
        ? RegExp(r'^\d{4,12}$')
        : RegExp(r'^\d{8,12}$');
    if (!pattern.hasMatch(pin) || !await _userPinMatches(account, pin)) {
      throw const CompanyBootstrapRefusal('User PIN refused');
    }
    final latest = await _readUserAccount(userId: userId);
    if (latest == null ||
        latest.identityCommitment != account.identityCommitment ||
        epoch != _authenticationEpoch) {
      throw const CompanyBootstrapRefusal('User sign-in was cancelled');
    }
    await _checkUserAccount(latest);
    account = await _writeUserAccount(
      latest.change({'a': _companyAttempts}),
      requireCurrent: () async {
        if (epoch != _authenticationEpoch) {
          throw const CompanyBootstrapRefusal('User sign-in was cancelled');
        }
      },
    );
    await _checkUserAccount(account);
    if (epoch != _authenticationEpoch) {
      throw const CompanyBootstrapRefusal('User sign-in was cancelled');
    }
    final current = (await _readCustody())!;
    final selected = await _readUserAccount(userId: userId);
    if (selected == null ||
        selected.isDisabled ||
        selected.identityCommitment != account.identityCommitment) {
      throw const CompanyBootstrapRefusal(
        'User lifecycle changed during sign-in',
      );
    }
    if (epoch != _authenticationEpoch) {
      throw const CompanyBootstrapRefusal('User sign-in was cancelled');
    }
    final trust = installation._record!.companyTrust!;
    final session = RestrictedUserSession._(
      this,
      CompanyIdentity(
        companyId: current.company,
        shopId: current.shop,
        userId: userId,
        deviceId: current.device,
        name: current.name,
        packageId: current.packageId,
        isAuthorityOwner: false,
      ),
      const Uuid().v4(),
      _securityCanonical({
        'trust': trust.encode(),
        'floors': installation.knownSecurityFloors,
      }),
      installation._membershipCommitment!,
      account.identityCommitment,
    );
    _session = session;
    return session;
  }

  Future<VerifiedCreateJobSession> _issueRestrictedCreateJob(
    CreateJob command,
    RestrictedUserSession session,
    _CompanyCustody custody,
  ) async {
    final account = await _readUserAccount(userId: session.identity.userId);
    if (account == null ||
        session._accountCommitment != account.identityCommitment) {
      throw const CompanyBootstrapRefusal('User account is unavailable');
    }
    final user = await _checkUserAccount(account);
    final membership = await resolveCompanyMembership(
      db: db,
      installation: installation,
    );
    final trust = installation._record!.companyTrust!;
    session.validateAuthority(trust, installation.knownSecurityFloors);
    session.validateCommand(
      company: command.companyId,
      shop: command.shopId,
      user: user.user['id'] as String,
      device: custody.device,
      installation: custody.installation,
      generation: custody.generation,
      session: session.sessionId,
    );
    if (!(membership.device['capabilities'] as List).contains('createJob')) {
      throw const CompanyBootstrapRefusal(
        'Device Create Job permission denied',
      );
    }
    final body = <String, Object?>{
      'v': 4,
      'deviceProof': custody.isMember ? 3 : 2,
      if (custody.isMember) 'membership': membership.proofCommitment,
      'userAuthority': user.commitment,
      'company': custody.company,
      'shop': custody.shop,
      'job': command.jobId,
      'request': command.requestId,
      'command': command.commitment,
      'user': session.identity.userId,
      'device': custody.device,
      'installation': custody.installation,
      'generation': custody.generation,
      'grant': custody.grant,
      'credential': user.user['credential'],
      'permission': 1,
      'authority': trust.authorityVersion,
      'facts': trust.factsCommitment,
      'session': session.sessionId,
    };
    final signature = await _signJoin(
      installation,
      body,
      'wiredpart.job.create.authorization@3:',
    );
    final proof = <String, Object?>{
      ...signature,
      'userAuthority': account.certificate,
      if (custody.isMember) 'membership': membership.certificateBytes,
    };
    final latest = await _readUserAccount(userId: session.identity.userId);
    if (latest?.identityCommitment != account.identityCommitment) {
      throw const CompanyBootstrapRefusal('User account changed');
    }
    await _checkUserAccount(latest!);
    session.validateAuthority(trust, installation.knownSecurityFloors);
    final verified =
        await CreateJobAuthorization(db: db, installation: installation).verify(
          command,
          Uint8List.fromList(utf8.encode(_securityCanonical(proof))),
        );
    await session.requireCurrentAccount();
    return verified;
  }
}

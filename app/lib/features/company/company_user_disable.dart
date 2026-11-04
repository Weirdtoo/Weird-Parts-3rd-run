part of '../installation/installation_security.dart';

const _userDisableDomain = 'wiredpart.company.user.disable@1:';
const _userDisableReceiptDomain = 'wiredpart.company.user.disable.receipt@1:';

final class _UserDisable {
  _UserDisable._(this.request, this.signature, this.target, this.receipt);
  final String request;
  final String signature;
  final List<Object?>? target;
  final String? receipt;
  List<Object?> get identity => [1, request, signature];
  List<Object?> get encoded => [...identity, target, receipt];

  static _UserDisable decode(Object? raw) {
    if (raw is! List || raw.length != 5 || raw[0] != 1) {
      throw const CompanyBootstrapRefusal('Unsupported user disable state');
    }
    _joinId({'id': raw[1]}, 'id');
    _userBase64(raw[2], 64);
    final target = raw[3];
    if (target != null) {
      if (target is! List ||
          target.length != 7 ||
          (target[0] != 0 && target[0] != 1)) {
        throw const CompanyBootstrapRefusal('Invalid disable recipient');
      }
      for (final index in [1, 2, 3, 5, 6]) {
        _joinId({'id': target[index]}, 'id');
      }
      _userBase64(target[4], 32);
    }
    if (raw[4] != null) _userBase64(raw[4], 64);
    if (raw[4] != null && target == null) {
      throw const CompanyBootstrapRefusal('Disable receipt has no target');
    }
    return _UserDisable._(
      raw[1] as String,
      raw[2] as String,
      target == null ? null : List<Object?>.unmodifiable(target as List),
      raw[4] as String?,
    );
  }
}

Map<String, Object?> _userDisableBody(
  ResolvedCompanyUserAuthority user,
  String request,
) => {
  'v': 1,
  'kind': 'company.user.disable@1',
  'company': user._body['company'],
  'authority': user._body['authority'],
  'facts': user._body['facts'],
  'user': user.user['id'],
  'certificate': user.commitment,
  'sequence': 1,
  'request': request,
};

Future<void> _verifyUserDisable(
  _UserAccount account,
  ResolvedCompanyUserAuthority user,
  CompanyTrustAnchor trust,
) async {
  final disable = account.disable;
  if (disable == null) return;
  await _joinVerify(
    _userDisableBody(user, disable.request),
    disable.signature,
    base64Encode(trust.rootKey),
    _userDisableDomain,
  );
}

Future<ResolvedCompanyUserAuthority> _resolveActiveUserAuthority(
  AppDatabase db,
  InstallationSecurity installation,
  CompanyTrustAnchor trust,
  Map<String, int> floors,
  String certificateBytes,
) async {
  final enrollment = CompanyEnrollment(installation: installation, db: db);
  final userId = _userCertificateUserId(certificateBytes);
  final account = await enrollment._readUserAccount(userId: userId);
  if (account == null ||
      account.certificate != certificateBytes ||
      _securityCanonical(account.binding) !=
          _securityCanonical([
            installation.identity!.id.value,
            installation.identity!.generation.value,
            base64Encode(installation.identity!.publicKey),
            installation.receivingStoreGeneration!.value,
          ])) {
    throw const CompanyBootstrapRefusal('Current user account unavailable');
  }
  final user = await _resolveUserAuthority(db, trust, floors, certificateBytes);
  await _verifyUserDisable(account, user, trust);
  if (account.isDisabled) {
    throw const CompanyBootstrapRefusal('This company user is disabled');
  }
  final latest = await enrollment._readUserAccount(userId: userId);
  if (latest == null ||
      latest.isDisabled ||
      latest.identityCommitment != account.identityCommitment) {
    throw const CompanyBootstrapRefusal('Current user lifecycle changed');
  }
  return user;
}

final class CompanyUserDisableReceipt {
  CompanyUserDisableReceipt._(this.userId, this.requestId, this.proofBytes);
  final String userId;
  final String requestId;
  final String proofBytes;
}

final class CompanyUserLifecycleStatus {
  CompanyUserLifecycleStatus._(
    this.userId,
    this.name,
    this.disabled,
    this.attemptsRemaining,
    this.targetDeviceId,
    this.confirmed,
    this.credentialVersion,
    this.permissionVersion,
    this.protectedByteLength,
    this.awaitingCredential,
  );
  final String userId;
  final String name;
  final bool disabled;
  final int attemptsRemaining;
  final String? targetDeviceId;
  final bool confirmed;
  final int credentialVersion;
  final int permissionVersion;
  final int protectedByteLength;
  final bool awaitingCredential;
}

final class VerifiedUserLifecycleTarget {
  VerifiedUserLifecycleTarget._(this._bytes, this._peer);
  final String _bytes;
  final VerifiedPeerMembership _peer;
  String get userId =>
      ((jsonDecode(_bytes) as Map)['body'] as Map)['user'] as String;
  List<Object?> get _binding => List<Object?>.from(
    ((jsonDecode(_bytes) as Map)['body'] as Map)['binding'] as List,
  );
  List<Object?>? get _checkpoint {
    final value = ((jsonDecode(_bytes) as Map)['body'] as Map)['checkpoint'];
    return value == null ? null : List<Object?>.from(value as List);
  }
}

extension CompanyUserDisable on CompanyEnrollment {
  Future<CompanyUserLifecycleStatus?> userLifecycleStatus({
    required String userId,
  }) async {
    final account = await _readUserAccount(userId: userId);
    if (account == null) return null;
    final user = await _checkUserAccount(account, requireActive: false);
    final disable = account.disable;
    return CompanyUserLifecycleStatus._(
      user.user['id'] as String,
      user._body['name'] as String,
      account.isDisabled,
      account.attempts,
      account.isCurrentState
          ? ((account.values['o'] as List?)?[2] as String?)
          : (disable?.target?[1] as String?),
      account.isCurrentState
          ? account.values['r'] != null
          : disable?.receipt != null,
      user.user['credential'] as int,
      user.user['permission'] as int,
      account.encode().length,
      account.values['p'] == null && !account.isDisabled,
    );
  }

  Future<bool> isCompanyUserDisabled(String userId) async {
    final state = await userLifecycleStatus(userId: userId);
    return state?.userId == userId && state!.disabled;
  }

  Future<CompanyUserDisableReceipt> disableRestrictedUser({
    required OwnerSession owner,
    required String userId,
    required String requestId,
  }) async {
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User disable requires its own transaction',
      );
    }
    _joinId({'id': requestId}, 'id');
    _joinId({'id': userId}, 'id');
    await _requireUserAdministrator(owner);
    return owner.runLocalCommand(() async {
      final custody = await _requireUserAdministrator(owner);
      final account = await _readUserAccount(userId: userId);
      if (account == null) {
        throw const CompanyBootstrapRefusal('User account unavailable');
      }
      final user = await _checkUserAccount(account, requireActive: false);
      if (user.user['id'] != userId) {
        throw const CompanyBootstrapRefusal('User identity differs');
      }
      if (account.isCurrentState) {
        return _disableCurrentUser(owner, account, requestId);
      }
      if (account.isDisabled) {
        if (account.disable!.request != requestId) {
          throw const CompanyBootstrapRefusal(
            'Terminal disable request differs',
          );
        }
        await _requireUserAdministrator(owner);
        return CompanyUserDisableReceipt._(
          userId,
          requestId,
          _securityCanonical({
            'body': _userDisableBody(user, requestId),
            'signature': account.disable!.signature,
          }),
        );
      }
      _preflightUserCapacity(account);
      final placeholder = base64Encode(List<int>.filled(64, 255));
      final oldTarget = account.values['o'] as List?;
      final target = oldTarget == null
          ? null
          : <Object?>[0, ...oldTarget.skip(2)];
      var next = account.change({
        'v': 2,
        'p': null,
        'd': [1, requestId, placeholder, target, null],
      });
      next.encode();
      final signature = await Ed25519().sign(
        utf8.encode(
          '$_userDisableDomain${_securityCanonical(_userDisableBody(user, requestId))}',
        ),
        keyPair: await Ed25519().newKeyPairFromSeed(custody.rootSeed),
      );
      await _requireUserAdministrator(owner);
      final latest = await _readUserAccount(userId: userId);
      if (latest == null ||
          latest.identityCommitment != account.identityCommitment ||
          latest.isDisabled) {
        throw const CompanyBootstrapRefusal(
          'User account changed during disable',
        );
      }
      await _checkUserAccount(latest);
      await _requireUserAdministrator(owner);
      final latestOutgoing = latest.values['o'] as List?;
      final latestTarget = latestOutgoing == null
          ? null
          : <Object?>[0, ...latestOutgoing.skip(2)];
      next = latest.change({
        'v': 2,
        'p': null,
        'd': [1, requestId, base64Encode(signature.bytes), latestTarget, null],
      });
      await _writeUserAccount(
        next,
        requireCurrent: () async {
          await _requireUserAdministrator(owner);
        },
      );
      return CompanyUserDisableReceipt._(
        userId,
        requestId,
        _securityCanonical({
          'body': _userDisableBody(user, requestId),
          'signature': base64Encode(signature.bytes),
        }),
      );
    });
  }

  Future<List<Object?>> _lifecycleLocalBinding() async {
    final custody = await _readCustody();
    if (custody == null) {
      throw const CompanyBootstrapRefusal('Company unavailable');
    }
    return _userPeerBinding(
      await resolveCompanyMembership(db: db, installation: installation),
      installation.receivingStoreGeneration!.value,
    );
  }

  Future<Map<String, Object?>> createUserLifecycleOffer(
    VerifiedPeerMembership peer, {
    required String userId,
  }) async {
    await _requireUserPeer(peer);
    final body = <String, Object?>{
      'v': 1,
      'kind': 'company.user.lifecycle.offer@2',
      'profile': kCompanyUserProfile,
      'capacity': kCompanyUserCapacity,
      'channel': peer._held.channel._keys.id,
      'request': const Uuid().v4(),
      'user': userId,
      'binding': await _lifecycleLocalBinding(),
      'checkpoint': await _userCheckpoint(userId),
    };
    final signed = await _signJoin(
      installation,
      body,
      'wiredpart.company.user.lifecycle.offer@2:',
    );
    await _requireUserPeer(peer);
    return signed;
  }

  Future<VerifiedUserLifecycleTarget> verifyUserLifecycleOffer(
    Map<String, Object?> signed,
    VerifiedPeerMembership peer,
  ) async {
    final bytes = _securityCanonical(signed);
    final snapshot = _joinObject(_decodeUserJson(bytes), {'body', 'signature'});
    final body = _joinObject(snapshot['body'], {
      'v',
      'kind',
      'profile',
      'capacity',
      'channel',
      'request',
      'user',
      'binding',
      'checkpoint',
    });
    await _requireUserPeer(peer);
    _joinId(body, 'request');
    _joinId(body, 'user');
    final binding = body['binding'];
    final member = peer._held.peer._membership;
    if (body['v'] != 1 ||
        body['kind'] != 'company.user.lifecycle.offer@2' ||
        body['profile'] != kCompanyUserProfile ||
        body['capacity'] is! int ||
        body['capacity'] != kCompanyUserCapacity ||
        body['channel'] != peer._held.channel._keys.id ||
        binding is! List ||
        binding.length != 6 ||
        _securityCanonical(binding) !=
            _securityCanonical(
              _userPeerBinding(
                member,
                _joinString({'store': binding[4]}, 'store', maximum: 36),
              ),
            )) {
      throw const CompanyBootstrapRefusal('Lifecycle target differs');
    }
    _joinId({'id': binding[4]}, 'id');
    if (body['checkpoint'] != null) {
      final checkpoint = _stateTuple(body['checkpoint'], 3);
      if (checkpoint[0] != body['user']) {
        throw const CompanyBootstrapRefusal('Lifecycle user differs');
      }
      _stateId(checkpoint[0]);
      _joinVersion(checkpoint[1]);
      _joinHash(checkpoint[2]);
    }
    await _joinVerify(
      body,
      snapshot['signature'],
      member.device['key'],
      'wiredpart.company.user.lifecycle.offer@2:',
    );
    await _requireUserPeer(peer);
    return VerifiedUserLifecycleTarget._(bytes, peer);
  }

  Future<Map<String, Object?>?> prepareUserDisablePolicy(
    VerifiedPeerMembership peer,
    VerifiedUserLifecycleTarget target,
  ) async {
    await _requireUserPeer(peer);
    if (!identical(target._peer, peer)) {
      throw const CompanyBootstrapRefusal(
        'Lifecycle target belongs to another peer',
      );
    }
    var account = await _readUserAccount(userId: target.userId);
    if (account?.isCurrentState == true) {
      return _prepareUserPinPolicy(peer, target);
    }
    if (account == null || !account.isDisabled) return null;
    await _checkUserAccount(account, requireActive: false);
    var disable = account.disable!;
    if (disable.target != null && disable.target![0] == 1) return null;
    final outgoing = <Object?>[0, ...target._binding];
    if (disable.target != null &&
        _securityCanonical(disable.target) != _securityCanonical(outgoing)) {
      throw const CompanyBootstrapRefusal('Disable recipient changed');
    }
    if (disable.target == null) {
      account = await _writeUserAccount(
        account.change({
          'd': [...disable.identity, outgoing, null],
        }),
        requireCurrent: () async {
          await _requireUserPeer(peer);
        },
      );
      disable = account.disable!;
    }
    final body = <String, Object?>{
      'v': 1,
      'certificate': account.certificate,
      'disable': disable.identity,
      'source': await _lifecycleLocalBinding(),
      'recipient': target._binding,
    };
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: target.userId);
    if (latest?.identityCommitment != account.identityCommitment ||
        _securityCanonical(latest?.disable?.target) !=
            _securityCanonical(outgoing)) {
      throw const CompanyBootstrapRefusal('User lifecycle changed');
    }
    await _checkUserAccount(latest!, requireActive: false);
    await _requireUserPeer(peer);
    return body;
  }

  Future<Map<String, Object?>> _disableReceiptBody(_UserAccount account) async {
    final user = await _checkUserAccount(account, requireActive: false);
    final disable = account.disable!;
    final target = disable.target;
    if (target == null) {
      throw const CompanyBootstrapRefusal('Disable has no target');
    }
    final local = await _lifecycleLocalBinding();
    return {
      'v': 1,
      'kind': 'company.user.disable.receipt@1',
      'decision': _joinDigest(_userDisableBody(user, disable.request)),
      'request': disable.request,
      'source': target[0] == 0 ? local : target.skip(1).toList(),
      'recipient': target[0] == 0 ? target.skip(1).toList() : local,
    };
  }

  Future<Map<String, Object?>?> acceptUserDisablePolicy(
    Map<String, Object?>? policy,
    VerifiedPeerMembership peer,
    VerifiedUserLifecycleTarget source,
  ) async {
    if (policy == null) return null;
    if (policy['kind'] == 'company.user.state.policy@1') {
      return _acceptUserPinPolicy(policy, peer, source);
    }
    final bytes = _securityCanonical(policy);
    final body = _joinObject(_decodeUserJson(bytes), {
      'v',
      'certificate',
      'disable',
      'source',
      'recipient',
    });
    await _requireUserPeer(peer);
    if (!identical(source._peer, peer) ||
        body['v'] != 1 ||
        body['certificate'] is! String ||
        _securityCanonical(body['source']) !=
            _securityCanonical(source._binding) ||
        _securityCanonical(body['recipient']) !=
            _securityCanonical(await _lifecycleLocalBinding())) {
      throw const CompanyBootstrapRefusal('Disable policy binding differs');
    }
    final identity = body['disable'];
    if (identity is! List || identity.length != 3) {
      throw const CompanyBootstrapRefusal('Unsupported disable policy');
    }
    final accounts = await _readUserAccounts();
    final existing = accounts.select(source.userId);
    if (_userCertificateUserId(body['certificate'] as String) !=
        source.userId) {
      throw const CompanyBootstrapRefusal('Disable user differs');
    }
    final target = <Object?>[1, ...source._binding];
    var account = _UserAccount._(
      {
        'v': 2,
        'c': body['certificate'],
        'b': _userBinding(),
        'p': null,
        'a': existing?.attempts ?? _companyAttempts,
        'o': existing?.values['o'],
        'r': existing?.values['r'],
        'd': [...identity, target, null],
      },
      existing?.revision,
      slot: existing?.slot ?? accounts.freeSlot,
    );
    account = _UserAccount.decode(
      account.encode(),
      revision: account.revision,
      slot: account.slot,
    );
    await _checkUserAccount(account, requireActive: false);
    _preflightUserCapacity(account);
    if (existing != null) {
      await _checkUserAccount(existing, requireActive: false);
      if (existing.certificate != account.certificate ||
          (existing.isDisabled &&
              (existing.identityCommitment != account.identityCommitment ||
                  _securityCanonical(existing.disable!.target) !=
                      _securityCanonical(target)))) {
        throw const CompanyBootstrapRefusal('Conflicting terminal user policy');
      }
    }
    final receipt = await _signJoin(
      installation,
      await _disableReceiptBody(account),
      _userDisableReceiptDomain,
    );
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: source.userId);
    if ((existing == null && latest != null) ||
        (existing != null &&
            (latest?.identityCommitment != existing.identityCommitment ||
                _securityCanonical(latest?.values['o']) !=
                    _securityCanonical(existing.values['o']) ||
                _securityCanonical(latest?.disable?.target) !=
                    _securityCanonical(existing.disable?.target)))) {
      throw const CompanyBootstrapRefusal(
        'User changed during disable receipt',
      );
    }
    if (latest != null) {
      account = account.change({
        'a': latest.attempts,
        'o': latest.values['o'],
        'r': latest.values['r'],
      });
    }
    account = account.change({
      'd': [...identity, target, receipt['signature']],
    });
    await _requireUserPeer(peer);
    if (latest == null ||
        _securityCanonical(account.values) !=
            _securityCanonical(latest.values)) {
      await _writeUserAccount(
        _UserAccount.decode(
          account.encode(),
          revision: latest?.revision,
          slot: account.slot,
        ),
        requireCurrent: () async {
          await _requireUserPeer(peer);
        },
      );
    }
    return receipt;
  }

  Future<void> acceptUserDisableReceipt(
    Map<String, Object?>? signed,
    VerifiedPeerMembership peer, {
    required String userId,
  }) async {
    if (signed == null) return;
    if ((signed['body'] as Map?)?['kind'] == 'company.user.state.receipt@1') {
      return _acceptUserPinReceipt(signed, peer, userId: userId);
    }
    final snapshot = _joinObject(_decodeUserJson(_securityCanonical(signed)), {
      'body',
      'signature',
    });
    await _requireUserPeer(peer);
    final account = await _readUserAccount(userId: userId);
    if (account == null ||
        account.isCurrentState ||
        !account.isDisabled ||
        account.disable!.target?[0] != 0) {
      throw const CompanyBootstrapRefusal('Disable delivery is not pending');
    }
    final expected = await _disableReceiptBody(account);
    if (_securityCanonical(snapshot['body']) != _securityCanonical(expected) ||
        account.disable!.target![1] != peer.deviceId) {
      throw const CompanyBootstrapRefusal('Disable receipt binding differs');
    }
    await _joinVerify(
      expected,
      snapshot['signature'],
      peer._held.peer._membership.device['key'],
      _userDisableReceiptDomain,
    );
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: userId);
    if (latest?.identityCommitment != account.identityCommitment ||
        _securityCanonical(latest?.disable?.target) !=
            _securityCanonical(account.disable!.target)) {
      throw const CompanyBootstrapRefusal('Disable state changed');
    }
    await _checkUserAccount(latest!, requireActive: false);
    await _requireUserPeer(peer);
    if (latest.disable!.receipt != snapshot['signature']) {
      await _writeUserAccount(
        latest.change({
          'd': [
            ...latest.disable!.identity,
            latest.disable!.target,
            snapshot['signature'],
          ],
        }),
        requireCurrent: () async {
          await _requireUserPeer(peer);
        },
      );
    }
  }
}

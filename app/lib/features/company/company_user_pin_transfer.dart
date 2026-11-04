part of '../installation/installation_security.dart';

const _userPinIssuanceDomain = 'wiredpart.company.user.pin.issuance@1:';
const _userPinSuffixLimit = 16;

extension CompanyUserPinTransfer on CompanyEnrollment {
  Future<List<Object?>?> _userCheckpoint(String userId) async {
    final account = await _readUserAccount(userId: userId);
    if (account == null) return null;
    await _checkUserAccount(account, requireActive: false);
    final user = await _resolveUserAuthority(
      db,
      installation._record!.companyTrust!,
      installation.knownSecurityFloors,
      account.certificate,
    );
    if (!account.isCurrentState) return [user.user['id'], 1, user.commitment];
    final state = await _currentUserState(account);
    return [state.userId, state.sequence, state.publicHead];
  }

  Future<Map<String, Object?>?> _prepareUserPinPolicy(
    VerifiedPeerMembership peer,
    VerifiedUserLifecycleTarget target,
  ) async {
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User policy requires its own transaction',
      );
    }
    await _requireUserPeer(peer);
    if (!identical(target._peer, peer)) {
      throw const CompanyBootstrapRefusal('User policy target differs');
    }
    var account = await _readUserAccount(userId: target.userId);
    if (account == null || !account.isCurrentState) return null;
    await _checkUserAccount(account, requireActive: false);
    final current = await _currentUserState(account);
    final sourceBinding = await _lifecycleLocalBinding();
    final checkpoint = target._checkpoint;
    final originHead = _joinDigest(
      jsonDecode(current.originalCertificateBytes),
    );
    var from = 1;
    var fromHead = originHead;
    if (checkpoint != null) {
      if (checkpoint[0] != current.userId) {
        throw const CompanyBootstrapRefusal('Peer user identity differs');
      }
      from = checkpoint[1] as int;
      fromHead = checkpoint[2] as String;
    }
    if (from > current.sequence) return null;
    final known = from == 1
        ? current.originalCertificateBytes
        : (await (db.select(db.companyUserEvents)..where(
                    (t) =>
                        t.companyId.equals(
                          peer._held.owner.identity.companyId,
                        ) &
                        t.userId.equals(current.userId) &
                        t.sequence.equals(from),
                  ))
                  .getSingleOrNull())
              ?.certificateBytes;
    if (known == null || _joinDigest(_decodeUserJson(known)) != fromHead) {
      throw const CompanyBootstrapRefusal('Peer user checkpoint conflicts');
    }
    final suffix =
        await (db.select(db.companyUserEvents)
              ..where(
                (t) =>
                    t.companyId.equals(peer._held.owner.identity.companyId) &
                    t.userId.equals(current.userId) &
                    t.sequence.isBiggerThanValue(from),
              )
              ..orderBy([(t) => OrderingTerm.asc(t.sequence)])
              ..limit(_userPinSuffixLimit))
            .get();
    final selected = suffix.isEmpty
        ? current
        : await CompanyUserStateCertificate.verify(
            suffix.last.certificateBytes,
            db: db,
            trust: installation._record!.companyTrust!,
            floors: _historicalUserFloors(
              installation.knownSecurityFloors,
              current.userId,
            ),
          );
    final complete = selected.sequence == current.sequence;
    final binding = <Object?>[0, current.requestId, ...target._binding];
    if (complete &&
        _securityCanonical(account.values['o']) !=
            _securityCanonical(binding)) {
      final latest = await _readUserAccount(userId: target.userId);
      if (latest?.identityCommitment != account.identityCommitment) {
        throw const CompanyBootstrapRefusal('User policy changed');
      }
      await _requireUserPeer(peer);
      account = await _writeUserAccount(
        latest!.change({'o': binding, 'r': null}),
        requireCurrent: () async {
          await _requireUserPeer(peer);
        },
      );
    }
    Map<String, Object?>? secret;
    final custody = await _readCustody();
    if (complete &&
        !current.disabled &&
        account.values['p'] != null &&
        custody?.isMember == false) {
      await _requireUserAdministrator(peer._held.owner);
      final channel = await _userChannel(peer);
      final body = <String, Object?>{
        'v': 1,
        'certificate': current.publicHead,
        'request': current.requestId,
        'credential': account.values['p'],
        'source': sourceBinding,
        'recipient': target._binding,
        'channel': channel._keys.id,
      };
      final signature = await Ed25519().sign(
        utf8.encode('$_userPinIssuanceDomain${_securityCanonical(body)}'),
        keyPair: await Ed25519().newKeyPairFromSeed(custody!.rootSeed),
      );
      secret = await _sealJoin(
        channel,
        'user-pin-state',
        current.requestId,
        target._binding[3] as String,
        {'body': body, 'signature': base64Encode(signature.bytes)},
      );
    }
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: target.userId);
    if (latest?.identityCommitment != account.identityCommitment) {
      throw const CompanyBootstrapRefusal(
        'User policy changed before delivery',
      );
    }
    await _checkUserAccount(latest!, requireActive: false);
    await _requireUserPeer(peer);
    return {
      'v': 1,
      'kind': 'company.user.state.policy@1',
      'state': selected.certificateBytes,
      'events': suffix.map((r) => r.certificateBytes).toList(),
      'source': sourceBinding,
      'recipient': target._binding,
      'secret': secret,
      'more': !complete,
    };
  }

  Map<String, Object?> _pinReceiptBody(
    CompanyUserStateCertificate state,
    List<Object?> source,
    List<Object?> recipient,
  ) => {
    'v': 1,
    'kind': 'company.user.state.receipt@1',
    'certificate': state.publicHead,
    'request': state.requestId,
    'source': source,
    'recipient': recipient,
  };

  Future<Map<String, Object?>> _acceptUserPinPolicy(
    Map<String, Object?> policy,
    VerifiedPeerMembership peer,
    VerifiedUserLifecycleTarget source,
  ) async {
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User policy requires its own transaction',
      );
    }
    final body = _joinObject(_decodeUserJson(_securityCanonical(policy)), {
      'v',
      'kind',
      'state',
      'events',
      'source',
      'recipient',
      'secret',
      'more',
    });
    await _requireUserPeer(peer);
    final local = await _lifecycleLocalBinding();
    if (!identical(source._peer, peer) ||
        body['v'] is! int ||
        body['v'] != 1 ||
        body['kind'] != 'company.user.state.policy@1' ||
        body['more'] is! bool ||
        _securityCanonical(body['source']) !=
            _securityCanonical(source._binding) ||
        _securityCanonical(body['recipient']) != _securityCanonical(local) ||
        body['events'] is! List ||
        (body['events'] as List).length > _userPinSuffixLimit) {
      throw const CompanyBootstrapRefusal('User policy binding refused');
    }
    final trust = installation._record!.companyTrust!;
    final target = await CompanyUserStateCertificate.verify(
      body['state'] as String,
      db: db,
      trust: trust,
      floors: installation.knownSecurityFloors,
    );
    if (target.userId != source.userId) {
      throw const CompanyBootstrapRefusal('User policy identity differs');
    }
    var account = await _readUserAccount(userId: target.userId);
    if (account?.isDisabled == true &&
        (account?.isCurrentState != true ||
            account!.certificate != target.certificateBytes)) {
      throw const CompanyBootstrapRefusal(
        'Terminal user cannot receive active policy',
      );
    }
    final certificates = <CompanyUserStateCertificate>[];
    for (final encoded in body['events'] as List) {
      if (encoded is! String) {
        throw const CompanyBootstrapRefusal('User suffix encoding refused');
      }
      certificates.add(
        await CompanyUserStateCertificate.verify(
          encoded,
          db: db,
          trust: trust,
          floors: installation.knownSecurityFloors,
        ),
      );
    }
    if (certificates.isNotEmpty &&
        certificates.last.certificateBytes != target.certificateBytes) {
      throw const CompanyBootstrapRefusal('User suffix target differs');
    }
    for (final state in certificates) {
      final collision = await _knownUserRequest(
        trust.companyId.value,
        state.userId,
        state.requestId,
      );
      if (collision != null &&
          collision.certificateBytes != state.certificateBytes) {
        throw const CompanyBootstrapRefusal(
          'User policy request identity collision',
        );
      }
      if (account != null && account.isCurrentState) {
        final current = await _currentUserState(account);
        if (state.sequence <= current.sequence) {
          final admitted =
              await (db.select(db.companyUserEvents)..where(
                    (t) =>
                        t.companyId.equals(trust.companyId.value) &
                        t.userId.equals(state.userId) &
                        t.sequence.equals(state.sequence),
                  ))
                  .getSingleOrNull();
          if (admitted?.certificateBytes != state.certificateBytes) {
            throw const CompanyBootstrapRefusal(
              'User epoch collision or replay',
            );
          }
          continue;
        }
        state.validateSuccessor(current);
      } else {
        if (state.sequence != 2 ||
            (account != null &&
                account.certificate != state.originalCertificateBytes) ||
            state.previousPublicHead !=
                _joinDigest(jsonDecode(state.originalCertificateBytes))) {
          throw const CompanyBootstrapRefusal(
            'User origin or missing suffix differs',
          );
        }
      }
      final old = account;
      final pending = _UserAccount._(
        {
          'v': 3,
          'c': _decodeUserJson(state.certificateBytes),
          'b': _userBinding(),
          'p': null,
          'a': state.disabled
              ? (account?.attempts ?? _companyAttempts)
              : _companyAttempts,
          'o': [1, state.requestId, ...source._binding],
          'r': null,
          'j': [state.previousPublicHead, state.sequence - 1],
        },
        account?.revision,
        slot:
            account?.slot ??
            (await _readUserAccounts(reconcile: false)).freeSlot,
      );
      await CompanyUserStateRecord.decode(
        pending.encode(),
        db: db,
        installation: installation,
      );
      await _requireUserPeer(peer);
      final latest = await _readUserAccount(userId: target.userId);
      if ((old == null && latest != null) ||
          (old != null &&
              latest?.identityCommitment != old.identityCommitment)) {
        throw const CompanyBootstrapRefusal(
          'User changed during policy admission',
        );
      }
      await _requireUserPeer(peer);
      account = await _reconcileUserPinState(
        await _writeUserAccount(
          _UserAccount.decode(
            (state.disabled && latest != null
                    ? pending.change({'a': latest.attempts})
                    : pending)
                .encode(),
            revision: latest?.revision,
            slot: pending.slot,
          ),
          requireCurrent: () async {
            await _requireUserPeer(peer);
          },
        ),
      );
    }
    account = await _readUserAccount(userId: target.userId);
    if (account == null ||
        !account.isCurrentState ||
        account.certificate != target.certificateBytes) {
      throw const CompanyBootstrapRefusal('Current user policy not installed');
    }
    // The public replacement is durable before decrypting any replacement material.
    if (body['secret'] != null && !target.disabled) {
      final channel = await _userChannel(peer);
      final signed = _joinObject(
        await _openUserEnvelope(
          channel,
          'user-pin-state',
          Map<String, Object?>.from(body['secret'] as Map),
          recipient: base64Encode(installation.identity!.publicKey),
        ),
        {'body', 'signature'},
      );
      final issuance = _joinObject(signed['body'], {
        'v',
        'certificate',
        'request',
        'credential',
        'source',
        'recipient',
        'channel',
      });
      if (issuance['v'] is! int ||
          issuance['v'] != 1 ||
          issuance['certificate'] != target.publicHead ||
          issuance['request'] != target.requestId ||
          issuance['channel'] != channel._keys.id ||
          _securityCanonical(issuance['source']) !=
              _securityCanonical(source._binding) ||
          _securityCanonical(issuance['recipient']) !=
              _securityCanonical(local)) {
        throw const CompanyBootstrapRefusal('Private user issuance differs');
      }
      await _joinVerify(
        issuance,
        signed['signature'],
        base64Encode(trust.rootKey),
        _userPinIssuanceDomain,
      );
      final latest = await _readUserAccount(userId: target.userId);
      if (latest?.identityCommitment != account.identityCommitment) {
        throw const CompanyBootstrapRefusal(
          'User changed during private issuance',
        );
      }
      if (latest!.values['p'] != null &&
          _securityCanonical(latest.values['p']) !=
              _securityCanonical(issuance['credential'])) {
        throw const CompanyBootstrapRefusal('Private user epoch collision');
      }
      final next = latest.change({'p': issuance['credential']});
      await CompanyUserStateRecord.decode(
        next.encode(),
        db: db,
        installation: installation,
      );
      await _requireUserPeer(peer);
      if (latest.values['p'] == null) {
        account = await _writeUserAccount(
          next,
          requireCurrent: () async {
            await _requireUserPeer(peer);
          },
        );
      }
    }
    final receipt = await _signJoin(
      installation,
      _pinReceiptBody(target, source._binding, local),
      _userStateReceiptDomain,
    );
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: target.userId);
    if (latest?.certificate != target.certificateBytes) {
      throw const CompanyBootstrapRefusal('User changed before policy receipt');
    }
    if (_securityCanonical(latest!.values['o']) ==
            _securityCanonical([1, target.requestId, ...source._binding]) &&
        latest.values['r'] != receipt['signature']) {
      await _writeUserAccount(
        latest.change({'r': receipt['signature']}),
        requireCurrent: () async {
          await _requireUserPeer(peer);
        },
      );
    }
    await _saveUserPinDelivery(target, receipt);
    return receipt;
  }

  Future<void> _saveUserPinDelivery(
    CompanyUserStateCertificate state,
    Map<String, Object?> receipt,
  ) async {
    final body = receipt['body'] as Map;
    final source = (body['source'] as List)[0] as String;
    final recipient = (body['recipient'] as List)[0] as String;
    final binding = _joinDigest({
      'source': body['source'],
      'recipient': body['recipient'],
    });
    final existing =
        await (db.select(db.companyUserDeliveries)..where(
              (t) =>
                  t.companyId.equals(
                    installation._record!.companyTrust!.companyId.value,
                  ) &
                  t.userId.equals(state.userId) &
                  t.publicHead.equals(state.publicHead) &
                  t.bindingCommitment.equals(binding),
            ))
            .getSingleOrNull();
    final bytes = _securityCanonical(receipt);
    if (existing != null) {
      if (existing.receiptBytes != bytes) {
        throw const CompanyBootstrapRefusal('User delivery receipt collision');
      }
      return;
    }
    await db
        .into(db.companyUserDeliveries)
        .insert(
          CompanyUserDeliveriesCompanion.insert(
            companyId: installation._record!.companyTrust!.companyId.value,
            userId: state.userId,
            publicHead: state.publicHead,
            sourceDeviceId: source,
            peerDeviceId: recipient,
            bindingCommitment: binding,
            receiptBytes: bytes,
          ),
        );
  }

  Future<void> _acceptUserPinReceipt(
    Map<String, Object?> signed,
    VerifiedPeerMembership peer, {
    required String userId,
  }) async {
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User receipt requires its own transaction',
      );
    }
    final snapshot = _joinObject(_decodeUserJson(_securityCanonical(signed)), {
      'body',
      'signature',
    });
    final receipt = _joinObject(snapshot['body'], {
      'v',
      'kind',
      'certificate',
      'request',
      'source',
      'recipient',
    });
    await _requireUserPeer(peer);
    final account = await _readUserAccount(userId: userId);
    if (account == null) {
      throw const CompanyBootstrapRefusal('Current user account unavailable');
    }
    final currentUser = await _checkUserAccount(account, requireActive: false);
    final rows =
        await (db.select(db.companyUserEvents)..where(
              (t) =>
                  t.companyId.equals(
                    installation._record!.companyTrust!.companyId.value,
                  ) &
                  t.publicHead.equals(receipt['certificate'] as String) &
                  t.userId.equals(currentUser.user['id'] as String),
            ))
            .get();
    if (rows.length != 1 || rows.single.requestId != receipt['request']) {
      throw const CompanyBootstrapRefusal(
        'User receipt has no admitted operation',
      );
    }
    final state = await CompanyUserStateCertificate.verify(
      rows.single.certificateBytes,
      db: db,
      trust: installation._record!.companyTrust!,
      floors: _historicalUserFloors(
        installation.knownSecurityFloors,
        currentUser.user['id'] as String,
      ),
    );
    final recipient = _stateTuple(receipt['recipient'], 6);
    final member = peer._held.peer._membership;
    if (_securityCanonical(receipt['source']) !=
            _securityCanonical(await _lifecycleLocalBinding()) ||
        _securityCanonical(recipient) !=
            _securityCanonical(
              _userPeerBinding(member, recipient[4] as String),
            ) ||
        receipt['v'] is! int ||
        receipt['v'] != 1 ||
        receipt['kind'] != 'company.user.state.receipt@1') {
      throw const CompanyBootstrapRefusal('User receipt peer differs');
    }
    await _joinVerify(
      receipt,
      snapshot['signature'],
      member.device['key'],
      _userStateReceiptDomain,
    );
    await _requireUserPeer(peer);
    final latest = await _readUserAccount(userId: userId);
    if (latest == null) {
      throw const CompanyBootstrapRefusal('Current user account unavailable');
    }
    final latestUser = await _checkUserAccount(latest, requireActive: false);
    if (latestUser.user['id'] != state.userId) {
      throw const CompanyBootstrapRefusal('Current user identity differs');
    }
    await _requireUserPeer(peer);
    await _saveUserPinDelivery(state, snapshot);
    if (latest.certificate == state.certificateBytes &&
        _securityCanonical(latest.values['o']) ==
            _securityCanonical([0, state.requestId, ...recipient]) &&
        latest.values['r'] != snapshot['signature']) {
      await _requireUserPeer(peer);
      await _writeUserAccount(
        latest.change({'r': snapshot['signature']}),
        requireCurrent: () async {
          await _requireUserPeer(peer);
        },
      );
    }
  }
}

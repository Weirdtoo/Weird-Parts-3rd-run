part of '../installation/installation_security.dart';

final class CompanyUserPinResetReceipt {
  CompanyUserPinResetReceipt._(
    this.userId,
    this.requestId,
    this.credentialVersion,
    this.certificateBytes,
    this.isCurrent,
  );
  final String userId;
  final String requestId;
  final int credentialVersion;
  final String certificateBytes;
  final bool isCurrent;
}

Map<String, int> _historicalUserFloors(Map<String, int> floors, String user) =>
    Map<String, int>.from(floors)..remove('credential.$user');

extension CompanyUserPinRecovery on CompanyEnrollment {
  Future<CompanyUserEvent?> _knownUserRequest(
    String company,
    String user,
    String request,
  ) =>
      (db.select(db.companyUserEvents)..where(
            (t) =>
                t.companyId.equals(company) &
                t.userId.equals(user) &
                t.requestId.equals(request),
          ))
          .getSingleOrNull();
  Future<CompanyTrustAnchor> _userStateTrust() async {
    final cached = installation._record;
    if (db.hasCallerTransaction && cached?.pendingCommand != null) {
      final current = await installation.store.readState(
        installation.namespace,
      );
      final held = installation._persisted;
      if (current == null ||
          held == null ||
          current.revision != held.revision ||
          base64Encode(current.bytes) != base64Encode(held.bytes) ||
          cached!.companyTrust == null) {
        throw const CompanyBootstrapRefusal('Held user authority changed');
      }
      return cached.companyTrust!;
    }
    final trust = await installation.readCompanyTrust(db);
    if (trust == null) {
      throw const CompanyBootstrapRefusal('Company authority unavailable');
    }
    return trust;
  }

  Future<bool> isCompanyUserOperationHeld(String userId, int credential) async {
    final account = await _readUserAccount(userId: userId);
    if (account == null) {
      throw const CompanyBootstrapRefusal('Current user account unavailable');
    }
    final user = await _checkUserAccount(account, requireActive: false);
    if (user.user['id'] != userId) {
      throw const CompanyBootstrapRefusal('Current user identity differs');
    }
    return account.isDisabled || (user.user['credential'] as int) > credential;
  }

  Future<CompanyUserDisableReceipt> _disableCurrentUser(
    OwnerSession owner,
    _UserAccount account,
    String request,
  ) async {
    final custody = await _requireUserAdministrator(owner);
    final current = await _currentUserState(account);
    if (current.disabled) {
      if (current.requestId != request) {
        throw const CompanyBootstrapRefusal('Terminal disable request differs');
      }
      await _requireUserAdministrator(owner);
      return CompanyUserDisableReceipt._(
        current.userId,
        request,
        current.certificateBytes,
      );
    }
    final spent = await _knownUserRequest(
      custody.company,
      current.userId,
      request,
    );
    if (spent != null) {
      throw const CompanyBootstrapRefusal(
        'User request identity is already spent',
      );
    }
    final body = List<Object?>.from(current._body);
    body[8] = current.sequence + 1;
    body[12] = 1;
    body[13] = request;
    body[15] = current.publicHead;
    var next = account.change({
      'c': [body, base64Encode(List<int>.filled(64, 255))],
      'p': null,
      'o': null,
      'r': null,
      'j': [current.publicHead, current.sequence],
    });
    _preflightUserCapacity(next);
    final signature = await Ed25519().sign(
      utf8.encode('$_userStateDomain${_securityCanonical(body)}'),
      keyPair: await Ed25519().newKeyPairFromSeed(custody.rootSeed),
    );
    next = next.change({
      'c': [body, base64Encode(signature.bytes)],
    });
    await CompanyUserStateRecord.decode(
      next.encode(),
      db: db,
      installation: installation,
    );
    final latest = await _readUserAccount(userId: current.userId);
    if (latest?.identityCommitment != account.identityCommitment) {
      throw const CompanyBootstrapRefusal(
        'User changed during terminal decision',
      );
    }
    await _checkUserAccount(latest!);
    await _requireUserAdministrator(owner);
    await _reconcileUserPinState(
      await _writeUserAccount(
        _UserAccount.decode(
          next.change({'a': latest.attempts}).encode(),
          revision: latest.revision,
          slot: latest.slot,
        ),
        requireCurrent: () async {
          await _requireUserAdministrator(owner);
        },
      ),
    );
    return CompanyUserDisableReceipt._(
      current.userId,
      request,
      _securityCanonical(next.values['c']),
    );
  }

  Future<CompanyUserStateCertificate> _currentUserState(
    _UserAccount account,
  ) async {
    final trust = await _userStateTrust();
    return CompanyUserStateCertificate.verify(
      account.certificate,
      db: db,
      trust: trust,
      floors: installation.knownSecurityFloors,
    );
  }

  Future<void> _insertUserEvent({
    required String certificate,
    required int sequence,
    required String request,
    required String user,
    required String company,
    required String previous,
    required String kind,
  }) async {
    final head = _joinDigest(_decodeUserJson(certificate));
    final expected = CompanyUserEventsCompanion.insert(
      companyId: company,
      userId: user,
      sequence: sequence,
      requestId: request,
      publicHead: head,
      previousHead: previous,
      certificateBytes: certificate,
      kind: kind,
    );
    final byIdentity =
        await (db.select(db.companyUserEvents)..where(
              (t) =>
                  t.companyId.equals(company) &
                  t.userId.equals(user) &
                  (t.sequence.equals(sequence) | t.requestId.equals(request)),
            ))
            .get();
    if (byIdentity.isNotEmpty) {
      if (byIdentity.length != 1 ||
          byIdentity.single.sequence != sequence ||
          byIdentity.single.requestId != request ||
          byIdentity.single.publicHead != head ||
          byIdentity.single.previousHead != previous ||
          byIdentity.single.certificateBytes != certificate ||
          byIdentity.single.kind != kind) {
        throw const CompanyBootstrapRefusal(
          'User lifecycle identity collision',
        );
      }
      return;
    }
    await db.into(db.companyUserEvents).insert(expected);
  }

  Future<void> _verifyUserPrefix(
    _UserAccount account,
    int through,
    String head,
  ) async {
    final current = await _currentUserState(account);
    final original = Map<String, Object?>.from(
      (jsonDecode(current.originalCertificateBytes) as Map)['body'] as Map,
    );
    final rows =
        await (db.select(db.companyUserEvents)
              ..where(
                (t) =>
                    t.companyId.equals(original['company'] as String) &
                    t.userId.equals(current.userId) &
                    t.sequence.isSmallerOrEqualValue(through),
              )
              ..orderBy([(t) => OrderingTerm.asc(t.sequence)]))
            .get();
    if (rows.length != through || rows.isEmpty) {
      throw const CompanyBootstrapRefusal('Anchored user history unavailable');
    }
    String previous = '';
    for (var index = 0; index < rows.length; index++) {
      final row = rows[index];
      if (row.sequence != index + 1 ||
          row.previousHead != previous ||
          row.publicHead !=
              _joinDigest(_decodeUserJson(row.certificateBytes))) {
        throw const CompanyBootstrapRefusal('User history chain differs');
      }
      if (index == 0) {
        if (row.certificateBytes != current.originalCertificateBytes ||
            row.requestId != original['request'] ||
            row.kind != 'created') {
          throw const CompanyBootstrapRefusal('User creation anchor differs');
        }
      } else {
        final trust = await _userStateTrust();
        final state = await CompanyUserStateCertificate.verify(
          row.certificateBytes,
          db: db,
          trust: trust,
          floors: _historicalUserFloors(
            installation.knownSecurityFloors,
            current.userId,
          ),
        );
        if (state.originalCertificateBytes !=
                current.originalCertificateBytes ||
            state.sequence != row.sequence ||
            state.requestId != row.requestId ||
            state.previousPublicHead != previous ||
            row.kind != (state.disabled ? 'disabled' : 'pinReset')) {
          throw const CompanyBootstrapRefusal('User history event differs');
        }
      }
      previous = row.publicHead;
    }
    if (previous != head) {
      throw const CompanyBootstrapRefusal(
        'Protected user history head differs',
      );
    }
  }

  Future<void> _requireUserJournal(_UserAccount account) async {
    if (!account.isCurrentState) return;
    final state = await _currentUserState(account);
    await _verifyUserPrefix(account, state.sequence, state.publicHead);
    final rows =
        await (db.select(db.companyUserEvents)..where(
              (t) =>
                  t.companyId.equals(
                    installation._record!.companyTrust!.companyId.value,
                  ) &
                  t.userId.equals(state.userId),
            ))
            .get();
    if (rows.length != state.sequence) {
      throw const CompanyBootstrapRefusal(
        'User journal exceeds protected checkpoint',
      );
    }
  }

  /// Resumes only the public projection authorized by the saved protected head.
  Future<void> reconcileUserPinRecovery() async {
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User recovery requires its own transaction',
      );
    }
    await _readUserAccounts();
  }

  Future<_UserAccount> _reconcileUserPinState(_UserAccount account) async {
    if (!account.isCurrentState) return account;
    await CompanyUserStateRecord._decode(
      account.encode(),
      db: db,
      installation: installation,
      heldTrust: await _userStateTrust(),
    );
    final intent = account.values['j'];
    if (intent == null) {
      await _requireUserJournal(account);
      return account;
    }
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User recovery requires its own transaction',
      );
    }
    final state = await _currentUserState(account);
    final prior = _stateTuple(intent, 2);
    final origin = Map<String, Object?>.from(
      (jsonDecode(state.originalCertificateBytes) as Map)['body'] as Map,
    );
    await db.transaction(() async {
      if (prior[1] == 1 &&
          state.sequence == 2 &&
          prior[0] ==
              _joinDigest(_decodeUserJson(state.originalCertificateBytes))) {
        await _insertUserEvent(
          certificate: state.originalCertificateBytes,
          sequence: 1,
          request: origin['request'] as String,
          user: state.userId,
          company: origin['company'] as String,
          previous: '',
          kind: 'created',
        );
      }
      await _verifyUserPrefix(account, prior[1] as int, prior[0] as String);
      // Receiver suffix admission supplies intervening public events separately.
      if (state.sequence != (prior[1] as int) + 1) {
        throw const CompanyBootstrapRefusal('Missing public user suffix');
      }
      await _insertUserEvent(
        certificate: state.certificateBytes,
        sequence: state.sequence,
        request: state.requestId,
        user: state.userId,
        company: origin['company'] as String,
        previous: state.previousPublicHead,
        kind: state.disabled ? 'disabled' : 'pinReset',
      );
    });
    final latest = await _readUserAccount(
      userId: state.userId,
      reconcile: false,
    );
    if (latest == null ||
        latest.identityCommitment != account.identityCommitment) {
      throw const CompanyBootstrapRefusal(
        'Protected user changed during projection',
      );
    }
    if (latest.values['j'] != null) {
      if (_securityCanonical(latest.values['j']) !=
          _securityCanonical(intent)) {
        throw const CompanyBootstrapRefusal('User projection intent changed');
      }
      return _writeUserAccount(
        latest.change({'j': null}),
        requireCurrent: () async {
          await _checkUserAccount(
            latest,
            requireActive: false,
            requireJournal: false,
          );
        },
      );
    }
    return latest;
  }

  Future<CompanyUserPinResetReceipt> resetRestrictedUserPin({
    required OwnerSession owner,
    required String userId,
    required String requestId,
    required int expectedCredentialVersion,
    required String pin,
  }) async {
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User PIN reset requires its own transaction',
      );
    }
    _stateId(userId);
    _stateId(requestId);
    _joinVersion(expectedCredentialVersion);
    final pattern = installation.namespace.startsWith('synthetic.')
        ? RegExp(r'^\d{4,12}$')
        : RegExp(r'^\d{8,12}$');
    if (!pattern.hasMatch(pin)) {
      throw const CompanyBootstrapRefusal('User PIN refused');
    }
    await _requireUserAdministrator(owner);
    return owner.runLocalCommand(() async {
      final custody = await _requireUserAdministrator(owner);
      final account = await _readUserAccount(userId: userId);
      if (account == null) {
        throw const CompanyBootstrapRefusal('User account unavailable');
      }
      final user = await _checkUserAccount(account);
      if (user.user['id'] != userId) {
        throw const CompanyBootstrapRefusal('User identity differs');
      }
      final priorState = account.isCurrentState
          ? await _currentUserState(account)
          : null;
      final oldReceipt = await _knownUserRequest(
        custody.company,
        userId,
        requestId,
      );
      if (oldReceipt != null) {
        if (oldReceipt.kind != 'pinReset') {
          throw const CompanyBootstrapRefusal(
            'User request identity is already spent',
          );
        }
        final same = oldReceipt.certificateBytes == account.certificate;
        final recorded = await CompanyUserStateCertificate.verify(
          oldReceipt.certificateBytes,
          db: db,
          trust: installation._record!.companyTrust!,
          floors: _historicalUserFloors(
            installation.knownSecurityFloors,
            userId,
          ),
        );
        if (recorded.credentialVersion != expectedCredentialVersion + 1) {
          throw const CompanyBootstrapRefusal(
            'Immutable reset predecessor differs',
          );
        }
        if (same && !await _userPinMatches(account, pin)) {
          throw const CompanyBootstrapRefusal(
            'Immutable PIN reset request differs',
          );
        }
        await _requireUserAdministrator(owner);
        final latest = await _readUserAccount(userId: userId);
        if (latest?.identityCommitment != account.identityCommitment) {
          throw const CompanyBootstrapRefusal(
            'User reset changed during retry',
          );
        }
        final old = await CompanyUserStateCertificate.verify(
          oldReceipt.certificateBytes,
          db: db,
          trust: installation._record!.companyTrust!,
          floors: _historicalUserFloors(
            installation.knownSecurityFloors,
            userId,
          ),
        );
        await _requireUserAdministrator(owner);
        if ((await _readUserAccount(userId: userId))?.identityCommitment !=
            account.identityCommitment) {
          throw const CompanyBootstrapRefusal(
            'User reset changed during receipt retry',
          );
        }
        await _requireUserAdministrator(owner);
        return CompanyUserPinResetReceipt._(
          userId,
          requestId,
          old.credentialVersion,
          old.certificateBytes,
          same,
        );
      }
      if (user.user['credential'] != expectedCredentialVersion) {
        throw const CompanyBootstrapRefusal(
          'User credential changed. Review current status and start a new reset request.',
        );
      }
      final originalBytes =
          priorState?.originalCertificateBytes ?? account.certificate;
      final originalSigned = jsonDecode(originalBytes) as Map;
      final origin = originalSigned['body'] as Map;
      if (origin['request'] == requestId) {
        throw const CompanyBootstrapRefusal(
          'User request identity is already spent',
        );
      }
      final credential = (priorState?.credentialVersion ?? 1) + 1;
      if (credential >= 9007199254740991) {
        throw const CompanyBootstrapRefusal('User credential capacity reached');
      }
      final previous =
          priorState?.publicHead ?? _joinDigest(jsonDecode(originalBytes));
      final body = <Object?>[
        2,
        origin['company'],
        origin['shop'],
        custody.authority,
        installation._record!.companyTrust!.factsCommitment,
        userId,
        origin['name'],
        [
          origin['issuer'],
          origin['device'],
          origin['request'],
          origin['authority'],
          origin['facts'],
          originalSigned['signature'],
        ],
        credential,
        credential,
        1,
        ['createJob'],
        0,
        requestId,
        requestId,
        previous,
      ];
      final placeholder = base64Encode(List<int>.filled(64, 255));
      var next = _UserAccount._(
        {
          'v': 3,
          'c': [body, placeholder],
          'b': _userBinding(),
          'p': [
            1,
            base64Encode(List<int>.filled(16, 255)),
            base64Encode(List<int>.filled(32, 255)),
          ],
          'a': _companyAttempts,
          'o': null,
          'r': null,
          'j': [previous, credential - 1],
        },
        account.revision,
        slot: account.slot,
      );
      _preflightUserCapacity(next);
      final salt = _secureRandom(16);
      final verifier = await _deriveCompanySecret(pin, salt);
      await _requireUserAdministrator(owner);
      final signature = await Ed25519().sign(
        utf8.encode('$_userStateDomain${_securityCanonical(body)}'),
        keyPair: await Ed25519().newKeyPairFromSeed(custody.rootSeed),
      );
      next = next.change({
        'c': [body, base64Encode(signature.bytes)],
        'p': [1, base64Encode(salt), base64Encode(verifier)],
      });
      await CompanyUserStateRecord.decode(
        next.encode(),
        db: db,
        installation: installation,
      );
      final latest = await _readUserAccount(userId: userId);
      if (latest == null ||
          latest.identityCommitment != account.identityCommitment) {
        throw const CompanyBootstrapRefusal(
          'User account changed during PIN reset',
        );
      }
      await _checkUserAccount(latest);
      await _requireUserAdministrator(owner);
      final saved = await _writeUserAccount(
        _UserAccount.decode(
          next.encode(),
          revision: latest.revision,
          slot: latest.slot,
        ),
        requireCurrent: () async {
          await _requireUserAdministrator(owner);
        },
      );
      await _reconcileUserPinState(saved);
      return CompanyUserPinResetReceipt._(
        userId,
        requestId,
        credential,
        _securityCanonical(next.values['c']),
        true,
      );
    });
  }

  Future<CompanyUserPinResetReceipt> resumeRestrictedUserPinReset({
    required OwnerSession owner,
    required String userId,
    required String requestId,
    required int expectedCredentialVersion,
  }) async {
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'User recovery requires its own transaction',
      );
    }
    _stateId(userId);
    _stateId(requestId);
    _joinVersion(expectedCredentialVersion);
    await _requireUserAdministrator(owner);
    final account = await _readUserAccount(userId: userId);
    if (account == null || !account.isCurrentState) {
      throw const CompanyBootstrapRefusal('Saved PIN replacement unavailable');
    }
    final user = await _checkUserAccount(account, requireActive: false);
    if (user.user['id'] != userId) {
      throw const CompanyBootstrapRefusal('User identity differs');
    }
    final row = await _knownUserRequest(
      owner.identity.companyId,
      userId,
      requestId,
    );
    if (row == null || row.kind != 'pinReset') {
      throw const CompanyBootstrapRefusal('Saved PIN replacement unavailable');
    }
    final state = await CompanyUserStateCertificate.verify(
      row.certificateBytes,
      db: db,
      trust: await _userStateTrust(),
      floors: _historicalUserFloors(installation.knownSecurityFloors, userId),
    );
    if (state.credentialVersion != expectedCredentialVersion + 1) {
      throw const CompanyBootstrapRefusal(
        'Immutable reset predecessor differs',
      );
    }
    final latest = await _readUserAccount(userId: userId);
    if (latest?.identityCommitment != account.identityCommitment) {
      throw const CompanyBootstrapRefusal(
        'User changed during receipt recovery',
      );
    }
    await _requireUserAdministrator(owner);
    return CompanyUserPinResetReceipt._(
      userId,
      requestId,
      state.credentialVersion,
      state.certificateBytes,
      account.certificate == state.certificateBytes,
    );
  }
}

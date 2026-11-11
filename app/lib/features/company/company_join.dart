part of '../installation/installation_security.dart';

Future<Map<String, Object?>> _signJoin(
  InstallationSecurity installation,
  Map<String, Object?> body,
  String domain,
) async {
  final pair = await Ed25519().newKeyPairFromSeed(installation._record!.seed);
  final signature = await Ed25519().sign(
    utf8.encode('$domain${_securityCanonical(body)}'),
    keyPair: pair,
  );
  return {'body': body, 'signature': base64Encode(signature.bytes)};
}

Future<void> _requireLiveEnroller(
  CompanyEnrollment enrollment,
  OwnerSession session,
  NearbyJoinChannel channel,
) async {
  channel._requireLive();
  final db = enrollment.db;
  if (!db.hasCallerTransaction) {
    throw const CompanyBootstrapRefusal('Issuer transaction required');
  }
  final custody = await enrollment._readCustody();
  if (custody == null ||
      custody.isMember ||
      custody.status != 'active' ||
      !identical(enrollment.currentSession, session)) {
    throw const CompanyBootstrapRefusal('Live authorized approver required');
  }
  // The writer transaction keeps the reconciled SQL ledger stable while
  // resolving membership. Protected records still need a fresh read.
  await enrollment._checkBinding(custody, requireActive: true);
  final installation = enrollment.installation;
  final persisted = installation._persisted;
  final trust = installation._record?.companyTrust;
  if (persisted == null || trust == null) {
    throw const CompanyBootstrapRefusal('Company trust unavailable');
  }
  final member = await _resolveCompanyMembership(
    db: db,
    installation: installation,
    trust: trust,
  );
  final currentCustody = await enrollment._readCustody();
  final current = await installation.store.readState(installation.namespace);
  if (currentCustody == null ||
      currentCustody.revision != custody.revision ||
      !listEquals(currentCustody.encode(), custody.encode()) ||
      current?.revision != persisted.revision ||
      !listEquals(current?.bytes, persisted.bytes) ||
      installation._persisted?.revision != persisted.revision ||
      !listEquals(installation._persisted?.bytes, persisted.bytes) ||
      installation.readiness != InstallationReadiness.ready ||
      !identical(enrollment.currentSession, session)) {
    throw const CompanyBootstrapRefusal('Live authorized approver changed');
  }
  session.validateAuthority(trust, installation.knownSecurityFloors);
  if (member.device['id'] != custody.device ||
      member.device['grant'] != custody.grant ||
      member.user['id'] != custody.user ||
      !(member.device['capabilities'] as List).contains('enrollDevice') ||
      !(member.user['capabilities'] as List).contains('enrollDevice')) {
    throw const CompanyBootstrapRefusal('Current enrollment permission denied');
  }
  channel._requireLive();
}

Future<ProtectedInstallationState> _freshJoinRecipient(
  InstallationSecurity installation,
) async {
  final persisted = await installation.store.readState(installation.namespace);
  if (persisted == null) {
    throw const CompanyBootstrapRefusal('Recipient key missing');
  }
  final record = _InstallationRecord.decode(persisted.bytes);
  final previous = installation._record!;
  if (record.identity.id.value != previous.identity.id.value ||
      record.identity.generation.value != previous.identity.generation.value ||
      record.identity.keyReference != previous.identity.keyReference ||
      base64Encode(record.identity.publicKey) !=
          base64Encode(previous.identity.publicKey) ||
      base64Encode(record.seed) != base64Encode(previous.seed) ||
      record.storeGeneration.value != previous.storeGeneration.value ||
      record.activation != InstallationActivation.active ||
      record.pendingCommand != null) {
    throw const CompanyBootstrapRefusal('Recipient protected identity changed');
  }
  installation._record = record;
  installation._persisted = persisted;
  return persisted;
}

Future<void> _verifyStaticJoinRequest(Map<String, Object?> signed) async {
  _joinObject(signed, {'body', 'signature'});
  final body = _joinObject(signed['body'], {
    'v',
    'kind',
    'request',
    'nonce',
    'installation',
    'generation',
    'key',
  });
  if (body['v'] != 1 ||
      body['kind'] != 'company.join.request@1' ||
      base64Decode(_joinString(body, 'nonce', maximum: 44)).length != 32) {
    throw const CompanyBootstrapRefusal('Unsupported signed Join request');
  }
  for (final key in ['request', 'installation', 'generation']) {
    _joinId(body, key);
  }
  await _joinVerify(
    body,
    signed['signature'],
    body['key'],
    'wiredpart.company.join.request@1:',
  );
}

void _validateJoinIssuerPins(Object? raw) {
  final value = _joinObject(raw, {'sequence', 'head', 'ledger', 'pending'});
  _joinHash(value['ledger']);
  if (value['sequence'] is! int ||
      (value['sequence'] as int) < 0 ||
      (value['sequence'] as int) > 128) {
    throw const FormatException('Unsupported issuer sequence');
  }
  if (value['sequence'] == 0) {
    if (value['head'] != null) {
      throw const FormatException('Invalid issuer head');
    }
  } else {
    _joinHash(value['head']);
  }
  if (value['pending'] != null) {
    final pending = _joinObject(value['pending'], {
      'request',
      'certificate',
      'before',
      'after',
      'priorSequence',
      'priorHead',
      'priorLedger',
    });
    _joinId(pending, 'request');
    _joinHash(pending['priorLedger']);
    for (final key in ['certificate', 'before']) {
      _joinHash(pending[key]);
    }
    if (pending['after'] != null) _joinHash(pending['after']);
    if (pending['priorSequence'] is! int ||
        (pending['priorSequence'] as int) < 0 ||
        (pending['priorSequence'] as int) > (value['sequence'] as int) ||
        (value['sequence'] as int) - (pending['priorSequence'] as int) > 1) {
      throw const FormatException('Invalid prior issuer sequence');
    }
    if (pending['priorSequence'] == 0) {
      if (pending['priorHead'] != null) {
        throw const FormatException('Invalid prior issuer head');
      }
    } else {
      _joinHash(pending['priorHead']);
    }
  }
}

Future<String> _issuerLedgerWitness(AppDatabase db) async {
  final values = <String, Object?>{};
  for (final table in [
    'company_membership_certificates',
    'company_join_requests',
    'company_join_events',
  ]) {
    final rows = await db.customSelect('SELECT * FROM "$table"').get();
    if (rows.length > (table == 'company_join_events' ? 1152 : 128)) {
      throw const CompanyBootstrapRefusal('Issuer ledger capacity reached');
    }
    values[table] = rows.map((r) => _securityCanonical(r.data)).toList()
      ..sort();
  }
  return _joinDigest(values);
}

Future<String> _joinStateWitness(
  AppDatabase db,
  String request,
  String certificate,
) async {
  final requests = await (db.select(
    db.companyJoinRequests,
  )..where((t) => t.requestId.equals(request))).get();
  final certificates = await (db.select(
    db.companyMembershipCertificates,
  )..where((t) => t.proofCommitment.equals(certificate))).get();
  final events =
      await (db.select(db.companyJoinEvents)
            ..where((t) => t.requestId.equals(request))
            ..orderBy([(t) => OrderingTerm.asc(t.ordinal)]))
          .get();
  if (requests.length > 1 || certificates.length > 1 || events.length > 9) {
    throw const CompanyBootstrapRefusal('Enrollment witness capacity reached');
  }
  return _joinDigest({
    'requests': requests.map((r) => r.toJson()).toList(),
    'certificates': certificates.map((r) => r.toJson()).toList(),
    'events': events.map((r) => r.toJson()).toList(),
    'facts':
        (await db.select(db.companyAuthorityFacts).get())
            .map((r) => _securityCanonical(r.toJson()))
            .toList()
          ..sort(),
  });
}

Future<void> _validateIssuerLedger(
  AppDatabase db,
  _CompanyCustody custody,
  CompanyTrustAnchor trust,
) async {
  final pins = Map<String, Object?>.from(custody.values['enrollment'] as Map);
  if (pins['pending'] == null &&
      pins['ledger'] != await _issuerLedgerWitness(db)) {
    throw const CompanyBootstrapRefusal(
      'Issuer ledger differs from protected commitment',
    );
  }
  final rows =
      await (db.select(db.companyMembershipCertificates)
            ..where((t) => t.issuerDeviceId.equals(custody.device))
            ..orderBy([(t) => OrderingTerm.asc(t.issuerSequence)]))
          .get();
  if (rows.length != pins['sequence'] || rows.length > 128) {
    throw const CompanyBootstrapRefusal(
      'Issuer history differs from protected sequence',
    );
  }
  final authority = await _membershipAuthority(db, trust);
  String? previous;
  for (var i = 0; i < rows.length; i++) {
    final row = rows[i];
    final member = await _resolveMemberCertificate(
      row.proofBytes,
      authority,
      trust,
      const {},
    );
    final body = (jsonDecode(row.proofBytes) as Map)['body'] as Map;
    if (row.issuerSequence != i + 1 ||
        body['sequence'] != i + 1 ||
        body['previous'] != previous ||
        row.proofCommitment != member.proofCommitment ||
        row.grantId != member.device['grant'] ||
        row.companyId != custody.company) {
      throw const CompanyBootstrapRefusal('Issuer certificate chain differs');
    }
    final request = await (db.select(
      db.companyJoinRequests,
    )..where((t) => t.requestId.equals(body['request'] as String))).getSingle();
    final signed = Map<String, Object?>.from(
      jsonDecode(request.requestBytes) as Map,
    );
    await _verifyStaticJoinRequest(signed);
    final requestBody = signed['body'] as Map;
    if (request.side != 'issuer' ||
        request.certificateCommitment != member.proofCommitment ||
        _joinDigest(signed) != body['requestCommitment'] ||
        request.requestCommitment != body['requestCommitment'] ||
        request.recipientKey != member.device['key'] ||
        request.recipientInstallation != member.device['installation'] ||
        request.recipientGeneration != member.device['generation'] ||
        requestBody['key'] != request.recipientKey ||
        requestBody['installation'] != request.recipientInstallation ||
        requestBody['generation'] != request.recipientGeneration) {
      throw const CompanyBootstrapRefusal('Issuer request evidence differs');
    }
    final events =
        await (db.select(db.companyJoinEvents)
              ..where(
                (t) =>
                    t.requestId.equals(request.requestId) &
                    t.kind.equals('issuance'),
              )
              ..orderBy([(t) => OrderingTerm.asc(t.ordinal)]))
            .get();
    if (events.isEmpty || events.length > 8) {
      throw const CompanyBootstrapRefusal('Issuer evidence missing');
    }
    for (var j = 0; j < events.length; j++) {
      final event = events[j];
      final evidence = _joinObject(jsonDecode(event.evidenceBytes), {
        'issuance',
        'credentialBox',
        'wire',
      });
      if (_securityCanonical(evidence) != event.evidenceBytes) {
        throw const CompanyBootstrapRefusal('Noncanonical issuance evidence');
      }
      final signedWitness = _joinObject(evidence['issuance'], {
        'body',
        'signature',
      });
      final witness = _joinObject(signedWitness['body'], {
        'v',
        'kind',
        'request',
        'freshRequest',
        'binding',
        'certificate',
        'recipient',
        'channel',
        'ordinal',
        'ciphertext',
        'floors',
      });
      if (witness['v'] != 1 ||
          witness['kind'] != 'company.join.issuance@1' ||
          witness['request'] != request.requestId ||
          witness['ordinal'] != j + 1 ||
          event.ordinal != j + 1 ||
          witness['certificate'] != row.proofCommitment ||
          witness['recipient'] != request.recipientKey ||
          witness['ciphertext'] != _joinDigest(evidence['credentialBox'])) {
        throw const CompanyBootstrapRefusal('Issuance evidence differs');
      }
      await _joinVerify(
        witness,
        signedWitness['signature'],
        (body['issuer'] as Map)['key'],
        'wiredpart.company.join.issuance@1:',
      );
    }
    previous = row.proofCommitment;
  }
  if (previous != pins['head']) {
    throw const CompanyBootstrapRefusal('Issuer head differs');
  }
}

Future<bool> _reconcileCompanyJoin(
  InstallationSecurity installation,
  AppDatabase db,
) async {
  final enrollment = CompanyEnrollment(installation: installation, db: db);
  var custody = await enrollment._readCustody();
  if (custody == null || custody.values['v'] == 1) return true;
  if (custody.isMember) {
    return _reconcileMember(installation, db, custody);
  }
  final pins = Map<String, Object?>.from(custody.values['enrollment'] as Map);
  if (pins['pending'] != null) {
    final pending = Map<String, Object?>.from(pins['pending'] as Map);
    Future<void> reconcile() async {
      await db.customStatement(
        'UPDATE app_settings SET value = value WHERE key = ?',
        [kInstallationBindingKey],
      );
      final current = await enrollment._readCustody();
      if (current?.revision != custody!.revision) {
        throw const CompanyBootstrapRefusal('Issuer intent changed');
      }
      final actual = await _joinStateWitness(
        db,
        pending['request'] as String,
        pending['certificate'] as String,
      );
      Map<String, Object?> next;
      if (pending['after'] != null && actual == pending['after']) {
        if (pins['ledger'] != await _issuerLedgerWitness(db)) {
          throw const CompanyBootstrapRefusal('Sealed issuer ledger differs');
        }
        next = {
          'sequence': pins['sequence'],
          'head': pins['head'],
          'ledger': pins['ledger'],
          'pending': null,
        };
      } else if (actual == pending['before']) {
        if (pending['priorLedger'] != await _issuerLedgerWitness(db)) {
          throw const CompanyBootstrapRefusal('Prior issuer ledger differs');
        }
        next = {
          'sequence': pending['priorSequence'],
          'head': pending['priorHead'],
          'ledger': pending['priorLedger'],
          'pending': null,
        };
      } else {
        throw const CompanyBootstrapRefusal(
          'Issuer intent has partial or changed evidence',
        );
      }
      custody = await enrollment._writeCustody(
        current!.change({'enrollment': next}),
      );
    }

    if (db.hasCallerTransaction) {
      if (pending['after'] == null ||
          await _joinStateWitness(
                db,
                pending['request'] as String,
                pending['certificate'] as String,
              ) !=
              pending['after']) {
        throw const CompanyBootstrapRefusal('Held enrollment evidence differs');
      }
    } else {
      await db.transaction(reconcile);
    }
  }
  final trust = installation._record?.companyTrust;
  if (trust == null) {
    throw const CompanyBootstrapRefusal('Issuer trust missing');
  }
  await _validateIssuerLedger(db, custody!, trust);
  return true;
}

final class VerifiedJoinRequest {
  VerifiedJoinRequest._(this._bytes, this._binding, this._channel);
  final String _bytes;
  final String _binding;
  final NearbyJoinChannel _channel;
  Map<String, Object?> get _signed =>
      Map<String, Object?>.from(jsonDecode(_bytes) as Map);
  Map<String, Object?> get _body =>
      Map<String, Object?>.from(_signed['body'] as Map);
  String get recipientFingerprint =>
      hashes.sha256.convert(base64Decode(_body['key'] as String)).toString();
  String get requestId => _body['request'] as String;
}

final class CompanyJoinPreview {
  CompanyJoinPreview._(
    this.identity,
    this._payload,
    this._credential,
    this._channel,
  );
  final CompanyIdentity identity;
  final String _payload;
  final String _credential;
  final NearbyJoinChannel _channel;
}

final class VerifiedJoinAcknowledgment {
  VerifiedJoinAcknowledgment._(this.requestId);
  final String requestId;
}

final class CompanyJoin {
  CompanyJoin({required this.enrollment, this.beforeCommit, this.afterCommit});
  final CompanyEnrollment enrollment;
  final Future<void> Function()? beforeCommit;
  final Future<void> Function()? afterCommit;
  Map<String, Object?>? _request;
  NearbyJoinChannel? _channel;

  Future<Map<String, Object?>> activationAcknowledgment(
    NearbyJoinChannel channel,
  ) async {
    channel._requireLive();
    final installation = enrollment.installation;
    await installation.reconcile(enrollment.db);
    final custody = await enrollment._readCustody();
    if (custody == null ||
        !custody.isMember ||
        custody.status != 'active' ||
        installation.readiness != InstallationReadiness.ready) {
      throw const CompanyBootstrapRefusal(
        'Active member acknowledgment required',
      );
    }
    final proof = await _validateMemberEvidence(
      installation,
      enrollment.db,
      custody,
    );
    final certificate =
        (jsonDecode(proof.member.certificateBytes!) as Map)['body'] as Map;
    final issuer = certificate['issuer'] as Map;
    final signed = await _signJoin(installation, {
      'v': 1,
      'kind': 'company.join.ack@1',
      'request': custody.intent,
      'certificate': custody.values['certificate'],
      'installation': custody.installation,
      'generation': custody.generation,
      'key': proof.member.device['key'],
      'channel': channel._keys.id,
    }, 'wiredpart.company.join.ack@1:');
    return _sealJoin(
      channel,
      'ack',
      custody.intent,
      issuer['key'] as String,
      signed,
    );
  }

  Future<VerifiedJoinAcknowledgment> acknowledgeJoin(
    NearbyJoinChannel channel,
    Map<String, Object?> wire, {
    required OwnerSession ownerSession,
  }) async {
    final installation = enrollment.installation;
    final db = enrollment.db;
    if (db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal(
        'Acknowledgment requires its own transaction',
      );
    }
    final signed = await _openJoin(
      channel,
      'ack',
      wire,
      recipient: base64Encode(installation.identity!.publicKey),
    );
    _joinObject(signed, {'body', 'signature'});
    final body = _joinObject(signed['body'], {
      'v',
      'kind',
      'request',
      'certificate',
      'installation',
      'generation',
      'key',
      'channel',
    });
    if (body['v'] != 1 ||
        body['kind'] != 'company.join.ack@1' ||
        body['request'] != wire['request'] ||
        body['channel'] != channel._keys.id) {
      throw const CompanyBootstrapRefusal('Acknowledgment binding differs');
    }
    return ownerSession.runLocalCommand(() async {
      await installation.reconcile(db);
      try {
        await db.transaction(() async {
          await db.customStatement(
            'UPDATE app_settings SET value = value WHERE key = ?',
            [kInstallationBindingKey],
          );
          final custody = await enrollment._readCustody();
          if (custody == null ||
              custody.isMember ||
              !identical(enrollment.currentSession, ownerSession)) {
            throw const CompanyBootstrapRefusal('Live approver required');
          }
          await enrollment._checkBinding(custody, requireActive: true);
          final trust = (await installation.readCompanyTrust(db))!;
          final floors = installation.knownSecurityFloors;
          ownerSession.validateAuthority(trust, floors);
          final certificate =
              await (db.select(db.companyMembershipCertificates)..where(
                    (t) =>
                        t.proofCommitment.equals(body['certificate'] as String),
                  ))
                  .getSingle();
          final member = await _resolveMemberCertificate(
            certificate.proofBytes,
            await _membershipAuthority(db, trust),
            trust,
            floors,
          );
          final certificateBody =
              (jsonDecode(certificate.proofBytes) as Map)['body'] as Map;
          if (certificateBody['request'] != body['request'] ||
              member.device['installation'] != body['installation'] ||
              member.device['generation'] != body['generation'] ||
              member.device['key'] != body['key']) {
            throw const CompanyBootstrapRefusal(
              'Acknowledgment recipient differs',
            );
          }
          await _joinVerify(
            body,
            signed['signature'],
            member.device['key'],
            'wiredpart.company.join.ack@1:',
          );
          final requestId = body['request'] as String;
          final prior =
              await (db.select(db.companyJoinEvents)..where(
                    (t) => t.requestId.equals(requestId) & t.ordinal.equals(9),
                  ))
                  .getSingleOrNull();
          if (prior != null) {
            await _requireLiveEnroller(enrollment, ownerSession, channel);
            return; // original signed activation acknowledgment stays immutable
          }
          final pins = Map<String, Object?>.from(
            custody.values['enrollment'] as Map,
          );
          final pending = {
            'request': requestId,
            'certificate': member.proofCommitment,
            'before': await _joinStateWitness(
              db,
              requestId,
              member.proofCommitment,
            ),
            'after': null,
            'priorSequence': pins['sequence'],
            'priorHead': pins['head'],
            'priorLedger': pins['ledger'],
          };
          final reserved = custody.change({
            'enrollment': {...pins, 'pending': pending},
          });
          reserved.change({
            'enrollment': {
              ...pins,
              'ledger': '0' * 64,
              'pending': {...pending, 'after': '0' * 64},
            },
          }).encode();
          await _requireLiveEnroller(enrollment, ownerSession, channel);
          var held = await enrollment._writeCustody(reserved);
          await db
              .into(db.companyJoinEvents)
              .insert(
                CompanyJoinEventsCompanion.insert(
                  requestId: requestId,
                  ordinal: 9,
                  kind: 'ack',
                  evidenceBytes: _securityCanonical(signed),
                ),
              );
          final after = await _joinStateWitness(
            db,
            requestId,
            member.proofCommitment,
          );
          final ledger = await _issuerLedgerWitness(db);
          held = await enrollment._writeCustody(
            held.change({
              'enrollment': {
                ...pins,
                'ledger': ledger,
                'pending': {...pending, 'after': after},
              },
            }),
          );
          await beforeCommit?.call();
          if ((await enrollment._readCustody())?.revision != held.revision ||
              await _issuerLedgerWitness(db) != ledger ||
              await _joinStateWitness(db, requestId, member.proofCommitment) !=
                  after) {
            throw const CompanyBootstrapRefusal(
              'Acknowledgment evidence changed',
            );
          }
          await enrollment._checkBinding(held, requireActive: true);
          await _requireLiveEnroller(enrollment, ownerSession, channel);
        });
      } catch (_) {
        await installation.reconcile(db);
        rethrow;
      }
      await afterCommit?.call();
      await installation.reconcile(db);
      return VerifiedJoinAcknowledgment._(body['request'] as String);
    });
  }

  Future<VerifiedJoinRequest> receiveJoinRequest(
    NearbyJoinChannel channel,
    Map<String, Object?> wire,
  ) async {
    final value = await _openJoin(channel, 'request', wire);
    _joinObject(value, {'request', 'binding', 'signature'});
    final signed = _joinObject(value['request'], {'body', 'signature'});
    final body = _joinObject(signed['body'], {
      'v',
      'kind',
      'request',
      'nonce',
      'installation',
      'generation',
      'key',
    });
    if (body['v'] != 1 ||
        body['kind'] != 'company.join.request@1' ||
        body['request'] != wire['request']) {
      throw const CompanyBootstrapRefusal('Join request binding differs');
    }
    for (final field in ['request', 'installation', 'generation']) {
      _joinId(body, field);
    }
    if (base64Decode(_joinString(body, 'nonce', maximum: 44)).length != 32) {
      throw const CompanyBootstrapRefusal('Invalid Join request nonce');
    }
    await _joinVerify(
      body,
      signed['signature'],
      body['key'],
      'wiredpart.company.join.request@1:',
    );
    await _checkJoinRecipient(channel, wire, body['key'] as String);
    final binding = _joinObject(value['binding'], {
      'v',
      'request',
      'channel',
      'challenge',
    });
    if (binding['v'] != 1 ||
        binding['request'] != _joinDigest(signed) ||
        binding['channel'] != channel._keys.id ||
        base64Decode(_joinString(binding, 'challenge', maximum: 44)).length !=
            32) {
      throw const CompanyBootstrapRefusal('Join request channel differs');
    }
    await _joinVerify(
      binding,
      value['signature'],
      body['key'],
      'wiredpart.company.join.channel@1:',
    );
    _claimCompanyChannel(enrollment.installation, channel);
    return VerifiedJoinRequest._(
      _securityCanonical(signed),
      _securityCanonical({'body': binding, 'signature': value['signature']}),
      channel,
    );
  }

  Future<Map<String, Object?>> approveJoin(
    NearbyJoinChannel channel,
    VerifiedJoinRequest request, {
    required OwnerSession ownerSession,
  }) async {
    if (!identical(request._channel, channel) ||
        enrollment.db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal('Join approval context differs');
    }
    channel._requireLive();
    return ownerSession.runLocalCommand(() async {
      final installation = enrollment.installation;
      final db = enrollment.db;
      await installation.reconcile(db);
      _CompanyCustody? held;
      late Map<String, Object?> result;
      try {
        result = await db.transaction(() async {
          await db.customStatement(
            'UPDATE app_settings SET value = value WHERE key = ?',
            [kInstallationBindingKey],
          );
          final custody = await enrollment._readCustody();
          if (custody == null ||
              custody.isMember ||
              custody.status != 'active' ||
              !identical(enrollment.currentSession, ownerSession)) {
            throw const CompanyBootstrapRefusal(
              'Live authorized owner approval required',
            );
          }
          await enrollment._checkBinding(custody, requireActive: true);
          final trust = (await installation.readCompanyTrust(db))!;
          final floors = installation.knownSecurityFloors;
          ownerSession.validateAuthority(trust, floors);
          final authority = await _membershipAuthority(db, trust);
          final user = Map<String, Object?>.from(
            (authority['users'] as List).single as Map,
          );
          final issuer = Map<String, Object?>.from(
            (authority['devices'] as List).single as Map,
          );
          _memberFloors(user, issuer, trust, floors);
          bool has(Map<String, Object?> value, String cap) =>
              (value['capabilities'] as List).contains(cap);
          if (!has(user, 'enrollDevice') ||
              !has(issuer, 'enrollDevice') ||
              issuer['id'] != custody.device ||
              issuer['grant'] != custody.grant ||
              issuer['key'] != base64Encode(installation.identity!.publicKey)) {
            throw const CompanyBootstrapRefusal(
              'Device enrollment permission denied',
            );
          }
          _claimCompanyChannel(installation, channel);
          final facts = await (db.select(
            db.companyAuthorityFacts,
          )..where((t) => t.companyId.equals(custody.company))).get();
          final factBytes = facts.map((f) => f.signedBytes).toList()..sort();
          if (utf8.encode(_securityCanonical(factBytes)).length > 32768) {
            throw const CompanyBootstrapRefusal(
              'Join authority proof capacity reached',
            );
          }
          final recipient = request._body;
          final capabilities = <String>[
            if (has(user, 'manageJobLifecycle') &&
                has(issuer, 'manageJobLifecycle'))
              'manageJobLifecycle',
            if (has(user, 'createJob') && has(issuer, 'createJob')) 'createJob',
            if (has(user, 'renameJob') && has(issuer, 'renameJob')) 'renameJob',
            if (has(user, 'editJobDetails') && has(issuer, 'editJobDetails'))
              'editJobDetails',
          ];
          final matches =
              await (db.select(db.companyJoinRequests)..where(
                    (t) =>
                        t.side.equals('issuer') &
                        t.recipientInstallation.equals(
                          recipient['installation'] as String,
                        ) &
                        t.recipientGeneration.equals(
                          recipient['generation'] as String,
                        ) &
                        t.recipientKey.equals(recipient['key'] as String),
                  ))
                  .get();
          if (matches.length > 1) {
            throw const CompanyBootstrapRefusal(
              'Conflicting recipient enrollments',
            );
          }
          final pins = custody.values['enrollment'] == null
              ? <String, Object?>{
                  'sequence': 0,
                  'head': null,
                  'ledger': await _issuerLedgerWitness(db),
                  'pending': null,
                }
              : Map<String, Object?>.from(custody.values['enrollment'] as Map);
          if (pins['pending'] != null) {
            throw const CompanyBootstrapRefusal(
              'Finish the pending enrollment',
            );
          }
          String certificateBytes;
          Map<String, Object?> fixedRequest;
          var sequence = pins['sequence'] as int;
          Object? head = pins['head'];
          if (matches.isEmpty) {
            final count = await db
                .customSelect(
                  "SELECT COUNT(*) AS n FROM company_join_requests WHERE side = 'issuer'",
                )
                .getSingle();
            if (count.read<int>('n') >= 128) {
              throw const CompanyBootstrapRefusal(
                'Enrollment capacity reached',
              );
            }
            fixedRequest = request._signed;
            final body = <String, Object?>{
              'v': 1,
              'kind': 'company.device.enroll@1',
              'depth': 1,
              'parent': trust.factsCommitment,
              'company': custody.company,
              'shop': custody.shop,
              'authority': trust.authorityVersion,
              'facts': trust.factsCommitment,
              'issuer': {
                'kind': 'rootFacts@2',
                'device': issuer['id'],
                for (final key in [
                  'grant',
                  'version',
                  'installation',
                  'generation',
                  'key',
                ])
                  key: issuer[key],
              },
              'recipient': {
                'device': const Uuid().v4(),
                'grant': const Uuid().v4(),
                'version': 1,
                'installation': recipient['installation'],
                'generation': recipient['generation'],
                'key': recipient['key'],
                'user': user['id'],
                'credential': user['credential'],
                'permission': user['permission'],
                'shops': [custody.shop],
                'capabilities': capabilities,
              },
              'request': request.requestId,
              'requestCommitment': _joinDigest(fixedRequest),
              'sequence': sequence + 1,
              'previous': head,
              'delegable': false,
            };
            await _requireLiveEnroller(enrollment, ownerSession, channel);
            certificateBytes = _securityCanonical(
              await _signJoin(
                installation,
                body,
                'wiredpart.company.device.enroll@1:',
              ),
            );
            sequence++;
            head = _joinDigest(jsonDecode(certificateBytes));
          } else {
            final original = matches.single;
            final certificate =
                await (db.select(db.companyMembershipCertificates)..where(
                      (t) => t.proofCommitment.equals(
                        original.certificateCommitment,
                      ),
                    ))
                    .getSingle();
            certificateBytes = certificate.proofBytes;
            fixedRequest = Map<String, Object?>.from(
              jsonDecode(original.requestBytes) as Map,
            );
          }
          final member = await _resolveMemberCertificate(
            certificateBytes,
            authority,
            trust,
            floors,
          );
          final certificate = Map<String, Object?>.from(
            (jsonDecode(certificateBytes) as Map)['body'] as Map,
          );
          if (_securityCanonical(member.device['capabilities']) !=
                  _securityCanonical(capabilities) ||
              member.device['installation'] != recipient['installation'] ||
              member.device['generation'] != recipient['generation'] ||
              member.device['key'] != recipient['key']) {
            throw const CompanyBootstrapRefusal(
              'Existing enrollment scope changed; resume cannot upgrade',
            );
          }
          final fixedBody = Map<String, Object?>.from(
            fixedRequest['body'] as Map,
          );
          await _verifyStaticJoinRequest(fixedRequest);
          if (_joinDigest(fixedRequest) != certificate['requestCommitment'] ||
              fixedBody['key'] != recipient['key'] ||
              fixedBody['installation'] != recipient['installation'] ||
              fixedBody['generation'] != recipient['generation']) {
            throw const CompanyBootstrapRefusal(
              'Saved enrollment request differs',
            );
          }
          final fixedId = fixedBody['request'] as String;
          final priorEvents =
              await (db.select(db.companyJoinEvents)
                    ..where(
                      (t) =>
                          t.requestId.equals(fixedId) &
                          t.kind.equals('issuance'),
                    )
                    ..orderBy([(t) => OrderingTerm.asc(t.ordinal)]))
                  .get();
          if (priorEvents.isNotEmpty) {
            final last = Map<String, Object?>.from(
              jsonDecode(priorEvents.last.evidenceBytes) as Map,
            );
            final wire = Map<String, Object?>.from(last['wire'] as Map);
            final witnessBody = ((last['issuance'] as Map)['body'] as Map);
            if (wire['session'] == channel._keys.id &&
                witnessBody['freshRequest'] == _joinDigest(request._signed)) {
              await _requireLiveEnroller(enrollment, ownerSession, channel);
              return wire;
            }
          }
          if (priorEvents.length >= 8) {
            throw const CompanyBootstrapRefusal(
              'Enrollment provisioning retry capacity reached',
            );
          }
          final ordinal = priorEvents.length + 1;
          await _requireLiveEnroller(enrollment, ownerSession, channel);
          final credential = <String, Object?>{
            'v': 1,
            'company': custody.company,
            'shop': custody.shop,
            'user': custody.user,
            'grant': member.device['grant'],
            'authority': trust.authorityVersion,
            'credential': user['credential'],
            'permission': user['permission'],
            'profile': custody.values['pinProfile'],
            'salt': custody.values['pinSalt'],
            'verifier': custody.values['pinVerifier'],
          };
          if (utf8.encode(_securityCanonical(credential)).length > 1024) {
            throw const CompanyBootstrapRefusal('Credential capacity reached');
          }
          final box = await _sealJoin(
            channel,
            'credential',
            fixedId,
            recipient['key'] as String,
            credential,
          );
          await _requireLiveEnroller(enrollment, ownerSession, channel);
          final issuance = await _signJoin(installation, {
            'v': 1,
            'kind': 'company.join.issuance@1',
            'request': fixedId,
            'freshRequest': _joinDigest(request._signed),
            'binding': _joinDigest(jsonDecode(request._binding)),
            'certificate': member.proofCommitment,
            'recipient': recipient['key'],
            'channel': channel._keys.id,
            'ordinal': ordinal,
            'ciphertext': _joinDigest(box),
            'floors': _joinDigest(floors),
          }, 'wiredpart.company.join.issuance@1:');
          final wire = await _sealJoin(
            channel,
            'provision',
            request.requestId,
            recipient['key'] as String,
            {
              'authority': trust.encode(),
              'facts': factBytes,
              'certificate': certificateBytes,
              'fixedRequest': fixedRequest,
              'freshRequest': request._signed,
              'binding': jsonDecode(request._binding),
              'issuance': issuance,
              'credentialBox': box,
              'floors': floors,
            },
          );
          final before = await _joinStateWitness(
            db,
            fixedId,
            member.proofCommitment,
          );
          final pending = <String, Object?>{
            'request': fixedId,
            'certificate': member.proofCommitment,
            'before': before,
            'after': null,
            'priorSequence': pins['sequence'],
            'priorHead': pins['head'],
            'priorLedger': pins['ledger'],
          };
          final reserved = custody.change({
            'v': 3,
            'enrollment': {
              'sequence': sequence,
              'head': head,
              'ledger': pins['ledger'],
              'pending': pending,
            },
          });
          reserved.change({
            'enrollment': {
              'sequence': sequence,
              'head': head,
              'ledger': '0' * 64,
              'pending': {...pending, 'after': '0' * 64},
            },
          }).encode();
          await _requireLiveEnroller(enrollment, ownerSession, channel);
          held = await enrollment._writeCustody(reserved);
          if (matches.isEmpty) {
            await db
                .into(db.companyMembershipCertificates)
                .insert(
                  CompanyMembershipCertificatesCompanion.insert(
                    grantId: member.device['grant'] as String,
                    companyId: custody.company,
                    proofCommitment: member.proofCommitment,
                    proofBytes: certificateBytes,
                    issuerDeviceId: custody.device,
                    issuerSequence: certificate['sequence'] as int,
                  ),
                );
            await db
                .into(db.companyJoinRequests)
                .insert(
                  CompanyJoinRequestsCompanion.insert(
                    requestId: fixedId,
                    side: 'issuer',
                    requestCommitment: _joinDigest(fixedRequest),
                    requestBytes: _securityCanonical(fixedRequest),
                    recipientInstallation: recipient['installation'] as String,
                    recipientGeneration: recipient['generation'] as String,
                    recipientKey: recipient['key'] as String,
                    certificateCommitment: member.proofCommitment,
                    stage: 'provisioned',
                  ),
                );
          }
          await db
              .into(db.companyJoinEvents)
              .insert(
                CompanyJoinEventsCompanion.insert(
                  requestId: fixedId,
                  ordinal: ordinal,
                  kind: 'issuance',
                  evidenceBytes: _securityCanonical({
                    'issuance': issuance,
                    'credentialBox': box,
                    'wire': wire,
                  }),
                ),
              );
          final after = await _joinStateWitness(
            db,
            fixedId,
            member.proofCommitment,
          );
          final ledger = await _issuerLedgerWitness(db);
          held = await enrollment._writeCustody(
            held!.change({
              'enrollment': {
                'sequence': sequence,
                'head': head,
                'ledger': ledger,
                'pending': {...pending, 'after': after},
              },
            }),
          );
          await beforeCommit?.call();
          final current = await enrollment._readCustody();
          if (current?.revision != held!.revision ||
              await _issuerLedgerWitness(db) != ledger ||
              await _joinStateWitness(db, fixedId, member.proofCommitment) !=
                  after) {
            throw const CompanyBootstrapRefusal(
              'Enrollment evidence changed before commit',
            );
          }
          await enrollment._checkBinding(current!, requireActive: true);
          await _requireLiveEnroller(enrollment, ownerSession, channel);
          return wire;
        });
      } catch (_) {
        if (held != null) await installation.reconcile(db);
        rethrow;
      }
      await afterCommit?.call();
      await installation.reconcile(db);
      return result;
    });
  }

  Future<CompanyJoinPreview> receiveProvision(
    NearbyJoinChannel channel,
    Map<String, Object?> wire,
  ) async {
    if (!identical(_channel, channel) || _request == null) {
      throw const CompanyBootstrapRefusal('No matching live Join request');
    }
    await _freshJoinRecipient(enrollment.installation);
    final payload = await _openJoin(
      channel,
      'provision',
      wire,
      recipient: base64Encode(enrollment.installation.identity!.publicKey),
    );
    if (wire['request'] != (_request!['body'] as Map)['request']) {
      throw const CompanyBootstrapRefusal('Provision request differs');
    }
    final proof = await _validateJoinProvision(
      payload,
      enrollment.installation,
      channel: channel,
      freshRequest: _request,
    );
    final box = Map<String, Object?>.from(payload['credentialBox'] as Map);
    if (box['request'] != proof.request) {
      throw const CompanyBootstrapRefusal('Credential request differs');
    }
    final credential = await _openJoin(
      channel,
      'credential',
      box,
      recipient: base64Encode(enrollment.installation.identity!.publicKey),
    );
    _validateJoinCredential(credential, proof);
    final previous = await enrollment._readCustody();
    if (previous != null &&
        (!previous.isMember ||
            previous.values['certificate'] != proof.member.proofCommitment ||
            previous.values['pinSalt'] != credential['salt'] ||
            previous.values['pinVerifier'] != credential['verifier'])) {
      throw const CompanyBootstrapRefusal(
        'Provision differs from admitted membership',
      );
    }
    channel._requireLive();
    return CompanyJoinPreview._(
      CompanyIdentity(
        companyId: proof.trust.companyId.value,
        shopId: proof.authority['shop'] as String,
        userId: proof.member.user['id'] as String,
        deviceId: proof.member.device['id'] as String,
        name: proof.authority['name'] as String,
        packageId: (proof.authority['recovery'] as Map)['package'] as String,
        isAuthorityOwner: false,
      ),
      _securityCanonical(payload),
      _securityCanonical(credential),
      channel,
    );
  }

  Future<CompanyIdentity> acceptProvision(CompanyJoinPreview preview) async {
    if (!identical(preview._channel, _channel) ||
        _request == null ||
        enrollment.db.hasCallerTransaction) {
      throw const CompanyBootstrapRefusal('Join consent context differs');
    }
    final channel = preview._channel;
    channel._requireLive();
    final installation = enrollment.installation;
    final db = enrollment.db;
    await installation.reconcile(db);
    final payload = Map<String, Object?>.from(
      jsonDecode(preview._payload) as Map,
    );
    final credential = Map<String, Object?>.from(
      jsonDecode(preview._credential) as Map,
    );
    final proof = await _validateJoinProvision(
      payload,
      installation,
      channel: channel,
      freshRequest: _request,
    );
    _validateJoinCredential(credential, proof);
    await db.transaction(() async {
      await db.customStatement(
        'UPDATE app_settings SET value = value WHERE key = ?',
        [kInstallationBindingKey],
      );
      final freshRecordState = await _freshJoinRecipient(installation);
      await _validateJoinProvision(
        payload,
        installation,
        channel: channel,
        freshRequest: _request,
      );
      final previous = await enrollment._readCustody();
      if (previous?.status == 'active') {
        if (previous!.values['certificate'] != proof.member.proofCommitment ||
            !await _memberCustodyReady(
              installation,
              db,
              installation._record!,
              previous,
            )) {
          throw const CompanyBootstrapRefusal(
            'Existing member evidence differs',
          );
        }
        return;
      }
      if (previous != null &&
          (!previous.isMember ||
              previous.values['certificate'] != proof.member.proofCommitment ||
              previous.values['pinSalt'] != credential['salt'] ||
              previous.values['pinVerifier'] != credential['verifier'])) {
        throw const CompanyBootstrapRefusal('Pending member binding differs');
      }
      await CompanyBootstrap.preflightFreshShop(db);
      final recordState = freshRecordState;
      final record = _InstallationRecord.decode(recordState.bytes);
      if (record.companyTrust != null ||
          record.pendingCommand != null ||
          await db.settingsDao.getSetting(kInstallationBindingKey) !=
              record.binding ||
          record.identity.id.value != installation.identity!.id.value ||
          base64Encode(record.identity.publicKey) !=
              proof.member.device['key']) {
        throw const CompanyBootstrapRefusal(
          'Fresh recipient installation changed',
        );
      }
      final path = await _companyStorePath(db);
      final before = await _joinStateWitness(
        db,
        proof.request,
        proof.member.proofCommitment,
      );
      final pins = <String, Object?>{
        'before': before,
        'after': null,
        'path': path,
        'trust': proof.trust.encode(),
        'priorBinding': _joinDigest(record.binding),
      };
      var held = _CompanyCustody.decode(
        Uint8List.fromList(
          utf8.encode(
            jsonEncode({
              'v': 2,
              'status': 'pending',
              'company': preview.identity.companyId,
              'shop': preview.identity.shopId,
              'user': preview.identity.userId,
              'device': preview.identity.deviceId,
              'grant': proof.member.device['grant'],
              'intent': proof.request,
              'installation': record.identity.id.value,
              'generation': record.identity.generation.value,
              'store': record.storeGeneration.value,
              'name': preview.identity.name,
              'package': preview.identity.packageId,
              'facts': proof.trust.factsCommitment,
              'pinSalt': credential['salt'],
              'pinVerifier': credential['verifier'],
              'pinProfile': credential['profile'],
              'attempts': previous?.attempts ?? _companyAttempts,
              'authority': proof.trust.authorityVersion,
              'certificate': proof.member.proofCommitment,
              'activation': pins,
            }),
          ),
        ),
        revision: previous?.revision,
      );
      held.change({
        'activation': {...pins, 'after': '0' * 64},
      }).encode();
      channel._requireLive();
      held = await enrollment._writeCustody(held);
      for (final bytes in (payload['facts'] as List).cast<String>()) {
        final body = (jsonDecode(bytes) as Map)['body'];
        await db
            .into(db.companyAuthorityFacts)
            .insert(
              CompanyAuthorityFactsCompanion.insert(
                companyId: proof.trust.companyId.value,
                commitment: _joinDigest(body),
                signedBytes: bytes,
              ),
            );
      }
      final certificate =
          (jsonDecode(proof.member.certificateBytes!) as Map)['body'] as Map;
      await db
          .into(db.companyMembershipCertificates)
          .insert(
            CompanyMembershipCertificatesCompanion.insert(
              grantId: held.grant,
              companyId: held.company,
              proofCommitment: proof.member.proofCommitment,
              proofBytes: proof.member.certificateBytes!,
              issuerDeviceId:
                  (certificate['issuer'] as Map)['device'] as String,
              issuerSequence: certificate['sequence'] as int,
            ),
          );
      await db
          .into(db.companyJoinRequests)
          .insert(
            CompanyJoinRequestsCompanion.insert(
              requestId: proof.request,
              side: 'member',
              requestCommitment: _joinDigest(proof.fixedRequest),
              requestBytes: _securityCanonical(proof.fixedRequest),
              recipientInstallation: held.installation,
              recipientGeneration: held.generation,
              recipientKey: proof.member.device['key'] as String,
              certificateCommitment: proof.member.proofCommitment,
              stage: 'activated',
            ),
          );
      final activation = await _signJoin(installation, {
        'v': 1,
        'kind': 'company.join.activation@1',
        'request': proof.request,
        'certificate': proof.member.proofCommitment,
        'provision': _joinDigest(payload),
        'installation': held.installation,
        'generation': held.generation,
        'store': held.storeGeneration,
        'path': path,
        'priorBinding': pins['priorBinding'],
      }, 'wiredpart.company.join.activation@1:');
      await db
          .into(db.companyJoinEvents)
          .insert(
            CompanyJoinEventsCompanion.insert(
              requestId: proof.request,
              ordinal: 0,
              kind: 'activation',
              evidenceBytes: _securityCanonical({
                'provision': payload,
                'activation': activation,
              }),
            ),
          );
      final after = await _joinStateWitness(
        db,
        proof.request,
        proof.member.proofCommitment,
      );
      held = await enrollment._writeCustody(
        held.change({
          'activation': {...pins, 'after': after},
        }),
      );
      await beforeCommit?.call();
      await _freshJoinRecipient(installation);
      if ((await enrollment._readCustody())?.revision != held.revision ||
          (await installation.store.readState(installation.namespace))
                  ?.revision !=
              recordState.revision ||
          await _joinStateWitness(
                db,
                proof.request,
                proof.member.proofCommitment,
              ) !=
              after) {
        throw const CompanyBootstrapRefusal(
          'Member activation changed before commit',
        );
      }
      await _validateJoinProvision(
        payload,
        installation,
        channel: channel,
        freshRequest: _request,
      );
      channel._requireLive();
    });
    await afterCommit?.call();
    await installation.reconcile(db);
    if (installation.readiness != InstallationReadiness.ready) {
      throw const CompanyBootstrapRefusal(
        'Member activation needs reconciliation',
      );
    }
    return (await enrollment.readIdentity())!;
  }

  Future<Map<String, Object?>> beginJoin(NearbyJoinChannel channel) async {
    channel._requireLive();
    final installation = enrollment.installation;
    final pending = await enrollment._readCustody();
    if ((installation.readiness != InstallationReadiness.ready &&
            !(pending?.isMember == true && pending?.status == 'pending')) ||
        installation._record?.companyTrust != null ||
        (pending != null &&
            (!pending.isMember || pending.status != 'pending'))) {
      throw const CompanyBootstrapRefusal(
        'Join needs a fresh unjoined installation',
      );
    }
    await CompanyBootstrap.preflightFreshShop(enrollment.db);
    _claimCompanyChannel(installation, channel);
    if (!identical(_channel, channel)) {
      final identity = installation.identity!;
      final body = <String, Object?>{
        'v': 1,
        'kind': 'company.join.request@1',
        'request': const Uuid().v4(),
        'nonce': base64Encode(_secureRandom(32)),
        'installation': identity.id.value,
        'generation': identity.generation.value,
        'key': base64Encode(identity.publicKey),
      };
      final pair = await Ed25519().newKeyPairFromSeed(
        installation._record!.seed,
      );
      final signature = await Ed25519().sign(
        utf8.encode(
          'wiredpart.company.join.request@1:${_securityCanonical(body)}',
        ),
        keyPair: pair,
      );
      _request = {'body': body, 'signature': base64Encode(signature.bytes)};
      _channel = channel;
    }
    final body = _request!['body'] as Map<String, Object?>;
    final binding = <String, Object?>{
      'v': 1,
      'request': _joinDigest(_request),
      'channel': channel._keys.id,
      'challenge': base64Encode(_secureRandom(32)),
    };
    final pair = await Ed25519().newKeyPairFromSeed(installation._record!.seed);
    final signature = await Ed25519().sign(
      utf8.encode(
        'wiredpart.company.join.channel@1:${_securityCanonical(binding)}',
      ),
      keyPair: pair,
    );
    return _sealJoin(
      channel,
      'request',
      body['request'] as String,
      body['key'] as String,
      {
        'request': _request,
        'binding': binding,
        'signature': base64Encode(signature.bytes),
      },
    );
  }
}

final class _JoinProvision {
  _JoinProvision(
    this.trust,
    this.authority,
    this.member,
    this.floors,
    this.payload,
    this.fixedRequest,
  );
  final CompanyTrustAnchor trust;
  final Map<String, dynamic> authority;
  final ResolvedCompanyMembership member;
  final Map<String, int> floors;
  final Map<String, Object?> payload;
  final Map<String, Object?> fixedRequest;
  String get request => (fixedRequest['body'] as Map)['request'] as String;
}

Future<_JoinProvision> _validateJoinProvision(
  Map<String, Object?> payload,
  InstallationSecurity installation, {
  NearbyJoinChannel? channel,
  Map<String, Object?>? freshRequest,
}) async {
  _joinObject(payload, {
    'authority',
    'facts',
    'certificate',
    'fixedRequest',
    'freshRequest',
    'binding',
    'issuance',
    'credentialBox',
    'floors',
  });
  final trust = CompanyTrustAnchor.decode(payload['authority']);
  final factBytes = payload['facts'];
  if (factBytes is! List ||
      factBytes.isEmpty ||
      factBytes.length > 17 ||
      factBytes.any((f) => f is! String) ||
      utf8.encode(_securityCanonical(factBytes)).length > 32768) {
    throw const CompanyBootstrapRefusal('Unsupported Join authority lineage');
  }
  final facts = factBytes.cast<String>();
  final current = facts
      .where(
        (f) =>
            _joinDigest((jsonDecode(f) as Map)['body']) ==
            trust.factsCommitment,
      )
      .single;
  final authority = await _verifyFactLineage(
    current: current,
    currentRoot: trust.rootKey,
    lineage: facts.where((f) => f != current).toList(),
  );
  if (authority['company'] != trust.companyId.value ||
      authority['authority'] != trust.authorityVersion ||
      authority['policy'] != trust.policy) {
    throw const CompanyBootstrapRefusal('Join authority checkpoint differs');
  }
  final rawFloors = payload['floors'];
  if (rawFloors is! Map ||
      rawFloors.length > 128 ||
      rawFloors.entries.any(
        (e) =>
            e.key is! String ||
            (e.key as String).length > 128 ||
            e.value is! int ||
            (e.value as int) < 0 ||
            (e.value as int) > 9007199254740991,
      )) {
    throw const CompanyBootstrapRefusal('Unsupported Join floors');
  }
  final floors = Map<String, int>.from(rawFloors);
  for (final known in installation.knownSecurityFloors.entries) {
    if (known.value > (floors[known.key] ?? 0)) floors[known.key] = known.value;
  }
  final existing = installation._record?.companyTrust;
  if (existing != null &&
      _securityCanonical(existing.encode()) !=
          _securityCanonical(trust.encode())) {
    throw const CompanyBootstrapRefusal('Join differs from pinned authority');
  }
  final certificate = _joinString(payload, 'certificate', maximum: 4096);
  final member = await _resolveMemberCertificate(
    certificate,
    authority,
    trust,
    floors,
  );
  final identity = installation.identity!;
  if (member.device['installation'] != identity.id.value ||
      member.device['generation'] != identity.generation.value ||
      member.device['key'] != base64Encode(identity.publicKey)) {
    throw const CompanyBootstrapRefusal(
      'Join is bound to another installation',
    );
  }
  final fixed = _joinObject(payload['fixedRequest'], {'body', 'signature'});
  final fresh = _joinObject(payload['freshRequest'], {'body', 'signature'});
  await _verifyStaticJoinRequest(fixed);
  await _verifyStaticJoinRequest(fresh);
  final certificateBody = (jsonDecode(certificate) as Map)['body'] as Map;
  if (certificateBody['requestCommitment'] != _joinDigest(fixed) ||
      certificateBody['request'] != (fixed['body'] as Map)['request']) {
    throw const CompanyBootstrapRefusal('Join fixed request differs');
  }
  for (final signed in [fixed, fresh]) {
    final body = signed['body'] as Map;
    if (body['installation'] != identity.id.value ||
        body['generation'] != identity.generation.value ||
        body['key'] != base64Encode(identity.publicKey)) {
      throw const CompanyBootstrapRefusal('Join request key proof differs');
    }
  }
  if (freshRequest != null &&
      _securityCanonical(fresh) != _securityCanonical(freshRequest)) {
    throw const CompanyBootstrapRefusal('Join request was replaced');
  }
  final bindingProof = _joinObject(payload['binding'], {'body', 'signature'});
  final binding = _joinObject(bindingProof['body'], {
    'v',
    'request',
    'channel',
    'challenge',
  });
  if (binding['v'] != 1 ||
      binding['request'] != _joinDigest(fresh) ||
      base64Decode(_joinString(binding, 'challenge', maximum: 44)).length !=
          32 ||
      (channel != null && binding['channel'] != channel._keys.id)) {
    throw const CompanyBootstrapRefusal('Join channel proof differs');
  }
  await _joinVerify(
    binding,
    bindingProof['signature'],
    member.device['key'],
    'wiredpart.company.join.channel@1:',
  );
  final signedIssuance = _joinObject(payload['issuance'], {
    'body',
    'signature',
  });
  final issuance = _joinObject(signedIssuance['body'], {
    'v',
    'kind',
    'request',
    'freshRequest',
    'binding',
    'certificate',
    'recipient',
    'channel',
    'ordinal',
    'ciphertext',
    'floors',
  });
  if (issuance['v'] != 1 ||
      issuance['kind'] != 'company.join.issuance@1' ||
      issuance['request'] != certificateBody['request'] ||
      issuance['freshRequest'] != _joinDigest(fresh) ||
      issuance['binding'] != _joinDigest(bindingProof) ||
      issuance['certificate'] != member.proofCommitment ||
      issuance['recipient'] != member.device['key'] ||
      issuance['channel'] != binding['channel'] ||
      issuance['ciphertext'] != _joinDigest(payload['credentialBox']) ||
      issuance['floors'] != _joinDigest(rawFloors) ||
      issuance['ordinal'] is! int ||
      (issuance['ordinal'] as int) < 1 ||
      (issuance['ordinal'] as int) > 8) {
    throw const CompanyBootstrapRefusal('Join issuance binding differs');
  }
  final issuer = Map<String, Object?>.from(certificateBody['issuer'] as Map);
  await _joinVerify(
    issuance,
    signedIssuance['signature'],
    issuer['key'],
    'wiredpart.company.join.issuance@1:',
  );
  return _JoinProvision(trust, authority, member, floors, payload, fixed);
}

void _validateJoinCredential(
  Map<String, Object?> credential,
  _JoinProvision proof,
) {
  _joinObject(credential, {
    'v',
    'company',
    'shop',
    'user',
    'grant',
    'authority',
    'credential',
    'permission',
    'profile',
    'salt',
    'verifier',
  });
  if (utf8.encode(_securityCanonical(credential)).length > 1024 ||
      credential['v'] != 1 ||
      credential['company'] != proof.trust.companyId.value ||
      credential['shop'] != proof.authority['shop'] ||
      credential['user'] != proof.member.user['id'] ||
      credential['grant'] != proof.member.device['grant'] ||
      credential['authority'] != proof.trust.authorityVersion ||
      credential['credential'] != proof.member.user['credential'] ||
      credential['permission'] != proof.member.user['permission'] ||
      credential['profile'] != _companyPinProfile ||
      base64Decode(_joinString(credential, 'salt', maximum: 24)).length != 16 ||
      base64Decode(_joinString(credential, 'verifier', maximum: 44)).length !=
          32) {
    throw const CompanyBootstrapRefusal('Join credential binding differs');
  }
}

Future<_JoinProvision> _validateMemberEvidence(
  InstallationSecurity installation,
  AppDatabase db,
  _CompanyCustody custody,
) async {
  final event =
      await (db.select(db.companyJoinEvents)..where(
            (t) => t.requestId.equals(custody.intent) & t.ordinal.equals(0),
          ))
          .getSingle();
  final evidence = _joinObject(jsonDecode(event.evidenceBytes), {
    'provision',
    'activation',
  });
  if (_securityCanonical(evidence) != event.evidenceBytes ||
      event.kind != 'activation') {
    throw const CompanyBootstrapRefusal('Member activation evidence differs');
  }
  final provision = await _validateJoinProvision(
    Map<String, Object?>.from(evidence['provision'] as Map),
    installation,
  );
  final signed = _joinObject(evidence['activation'], {'body', 'signature'});
  final activation = _joinObject(signed['body'], {
    'v',
    'kind',
    'request',
    'certificate',
    'provision',
    'installation',
    'generation',
    'store',
    'path',
    'priorBinding',
  });
  if (activation['v'] != 1 ||
      activation['kind'] != 'company.join.activation@1' ||
      activation['request'] != custody.intent ||
      activation['certificate'] != custody.values['certificate'] ||
      activation['provision'] != _joinDigest(evidence['provision']) ||
      activation['installation'] != custody.installation ||
      activation['generation'] != custody.generation ||
      activation['store'] != custody.storeGeneration ||
      activation['path'] != (custody.values['activation'] as Map)['path'] ||
      activation['priorBinding'] !=
          (custody.values['activation'] as Map)['priorBinding'] ||
      provision.member.proofCommitment != custody.values['certificate'] ||
      provision.member.device['id'] != custody.device ||
      provision.member.device['grant'] != custody.grant ||
      provision.member.user['id'] != custody.user ||
      provision.authority['shop'] != custody.shop ||
      provision.authority['name'] != custody.name ||
      provision.request != custody.intent ||
      provision.trust.factsCommitment != custody.factsCommitment) {
    throw const CompanyBootstrapRefusal('Member activation binding differs');
  }
  await _joinVerify(
    activation,
    signed['signature'],
    provision.member.device['key'],
    'wiredpart.company.join.activation@1:',
  );
  return provision;
}

Future<bool> _memberCustodyReady(
  InstallationSecurity installation,
  AppDatabase db,
  _InstallationRecord record,
  _CompanyCustody custody,
) async {
  final pins = Map<String, Object?>.from(custody.values['activation'] as Map);
  if (custody.status != 'active' ||
      custody.installation != record.identity.id.value ||
      custody.generation != record.identity.generation.value ||
      custody.storeGeneration != record.storeGeneration.value ||
      pins['path'] != await _companyStorePath(db) ||
      _securityCanonical(pins['trust']) !=
          _securityCanonical(record.companyTrust?.encode()) ||
      pins['after'] !=
          await _joinStateWitness(
            db,
            custody.intent,
            custody.values['certificate'] as String,
          )) {
    return false;
  }
  await _validateMemberEvidence(installation, db, custody);
  installation._membershipCommitment = custody.values['certificate'] as String;
  return true;
}

Future<bool> _reconcileMember(
  InstallationSecurity installation,
  AppDatabase db,
  _CompanyCustody custody,
) async {
  final record = installation._record!;
  final pins = Map<String, Object?>.from(custody.values['activation'] as Map);
  if (custody.installation != record.identity.id.value ||
      custody.generation != record.identity.generation.value ||
      custody.storeGeneration != record.storeGeneration.value ||
      pins['path'] != await _companyStorePath(db)) {
    throw const CompanyBootstrapRefusal('Member store binding differs');
  }
  if (custody.status == 'active') return true;
  final actual = await _joinStateWitness(
    db,
    custody.intent,
    custody.values['certificate'] as String,
  );
  if (actual == pins['before']) return false; // consent persisted, SQL rolled back: fresh reapproval required
  if (pins['after'] == null || actual != pins['after']) {
    throw const CompanyBootstrapRefusal(
      'Member activation has changed or partial evidence',
    );
  }
  Future<void> finish() async {
    await db.customStatement(
      'UPDATE app_settings SET value = value WHERE key = ?',
      [kInstallationBindingKey],
    );
    if (await _joinStateWitness(
          db,
          custody.intent,
          custody.values['certificate'] as String,
        ) !=
        pins['after']) {
      throw const CompanyBootstrapRefusal(
        'Member evidence changed during reconciliation',
      );
    }
    final proof = await _validateMemberEvidence(installation, db, custody);
    final persisted = (await installation.store.readState(
      installation.namespace,
    ))!;
    final current = _InstallationRecord.decode(persisted.bytes);
    if (current.identity.id.value != custody.installation ||
        current.identity.generation.value != custody.generation ||
        current.storeGeneration.value != custody.storeGeneration ||
        current.pendingCommand != null) {
      throw const CompanyBootstrapRefusal('Member protected identity changed');
    }
    final nextFloors = {
      ...proof.floors,
      'grant.${custody.grant}': 1,
      'credential.${custody.user}': proof.member.user['credential'] as int,
      'permission.${custody.user}': proof.member.user['permission'] as int,
    };
    if (current.floors.entries.any((e) => e.value > (nextFloors[e.key] ?? 0))) {
      throw const CompanyBootstrapRefusal(
        'Member activation would lower a security floor',
      );
    }
    final next = _InstallationRecord(
      current.identity,
      current.seed,
      InstallationActivation.active,
      current.storeGeneration,
      nextFloors,
      companyTrust: proof.trust,
      storePathFingerprint: pins['path'] as String,
    );
    final oldBinding = await db.settingsDao.getSetting(kInstallationBindingKey);
    final preJoinBinding = jsonEncode({
      'v': 1,
      'id': current.identity.id.value,
      'generation': current.identity.generation.value,
      'key': current.identity.keyReference,
      'public': base64Encode(current.identity.publicKey),
      'store': current.storeGeneration.value,
    });
    if (_joinDigest(preJoinBinding) != pins['priorBinding'] ||
        (oldBinding != preJoinBinding &&
            oldBinding != current.binding &&
            oldBinding != next.binding)) {
      throw const CompanyBootstrapRefusal(
        'Member SQL installation binding changed',
      );
    }
    if (current.companyTrust == null) {
      await installation._write(next, expectedRevision: persisted.revision);
    } else if (_securityCanonical(current.companyTrust!.encode()) !=
            _securityCanonical(proof.trust.encode()) ||
        current.storePathFingerprint != pins['path']) {
      throw const CompanyBootstrapRefusal('Member authority changed');
    }
    await db.settingsDao.setSetting(kInstallationBindingKey, next.binding);
  }

  if (db.hasCallerTransaction) {
    throw const CompanyBootstrapRefusal(
      'Activation reconciliation requires its own transaction',
    );
  }
  await db.transaction(finish);
  final enrollment = CompanyEnrollment(installation: installation, db: db);
  final current = await enrollment._readCustody();
  if (current?.revision != custody.revision) {
    throw const CompanyBootstrapRefusal('Member custody changed');
  }
  await enrollment._writeCustody(current!.change({'status': 'active'}));
  return true;
}

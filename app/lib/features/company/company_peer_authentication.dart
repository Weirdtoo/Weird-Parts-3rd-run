part of '../installation/installation_security.dart';

void requireCreatedJobSyncCapabilities({
  required Map<String, Object?> localUser,
  required Map<String, Object?> localDevice,
  required Map<String, Object?> peerUser,
  required Map<String, Object?> peerDevice,
  required String shop,
}) {
  for (final entry in [localUser, localDevice, peerUser, peerDevice]) {
    final shops = entry['shops'];
    final capabilities = entry['capabilities'];
    if (shops is! List ||
        !shops.contains(shop) ||
        capabilities is! List ||
        !capabilities.contains('createJob')) {
      throw const CompanyBootstrapRefusal(
        'Both installations require current shop access and Create Job permission',
      );
    }
  }
}

/// Retained, verified enrollment binding. Network callers cannot supply a key.
final class RetainedCompanyPeer {
  RetainedCompanyPeer._(this._membership);
  final ResolvedCompanyMembership _membership;
  String get deviceId => _membership.device['id'] as String;
  String get fingerprint => hashes.sha256
      .convert(base64Decode(_membership.device['key'] as String))
      .toString();
}

final class VerifiedPeerMembership {
  VerifiedPeerMembership._(this._owner, this._held);
  final CompanyPeerAuthentication _owner;
  final _PeerExchange _held;
  String get deviceId => _held.peer.deviceId;
  Future<void> requireCurrent() => _owner._recheck(_held);

  Future<void> requireJobSyncPermission() async {
    await requireCurrent();
    final local = _owner._localMembership!;
    final remote = _held.peer._membership;
    requireCreatedJobSyncCapabilities(
      localUser: local.user,
      localDevice: local.device,
      peerUser: remote.user,
      peerDevice: remote.device,
      shop: _held.owner.identity.shopId,
    );
    _held.owner.validateAuthority(
      _owner.enrollment.installation._record!.companyTrust!,
      _owner.enrollment.installation.knownSecurityFloors,
    );
    _held.channel._requireLive();
  }

  Future<HeldPeerCreateContext> prepareCreateCommand(OwnerSession owner) async {
    await requireCurrent();
    if (!identical(owner, _held.owner)) {
      throw const CompanyBootstrapRefusal(
        'Peer belongs to another local session',
      );
    }
    final installation = _owner.enrollment.installation;
    final trust = installation._record!.companyTrust!;
    final custody = (await _owner.enrollment._readCustody())!;
    await requireCurrent();
    return HeldPeerCreateContext._(
      this,
      trust,
      Map.of(installation.knownSecurityFloors),
      custody,
    );
  }
}

final class HeldPeerCreateContext {
  HeldPeerCreateContext._(this.peer, this._trust, this._floors, this._custody);
  final VerifiedPeerMembership peer;
  final CompanyTrustAnchor _trust;
  final Map<String, int> _floors;
  final _CompanyCustody _custody;
  ResolvedCompanyUserAuthority? _createActor;

  List<int> get createDevicePublicKey =>
      base64Decode(peer._held.peer._membership.device['key'] as String);

  void validateHistoricalCreateDevice(Map<String, Object?> body) {
    final member = peer._held.peer._membership;
    if (body['company'] != _trust.companyId.value ||
        body['shop'] != peer._held.owner.identity.shopId ||
        body['device'] != member.device['id'] ||
        body['installation'] != member.device['installation'] ||
        body['generation'] != member.device['generation']) {
      throw const CompanyBootstrapRefusal(
        'Historical create belongs to another device',
      );
    }
  }

  Future<bool> isCreateActorDisabled(Map<String, Object?> proof) async {
    final assertion = Map<String, Object?>.from(proof['body'] as Map);
    if (assertion['v'] != 4) return false;
    final member = peer._held.peer._membership;
    _joinObject(proof, {
      'body',
      'signature',
      'userAuthority',
      if (member.certificateBytes != null) 'membership',
    });
    _joinObject(assertion, {
      'v',
      'deviceProof',
      'userAuthority',
      'company',
      'shop',
      'job',
      'request',
      'command',
      'user',
      'device',
      'installation',
      'generation',
      'grant',
      'credential',
      'permission',
      'authority',
      'facts',
      'session',
      if (member.certificateBytes != null) 'membership',
    });
    _joinId(assertion, 'session');
    if (member.certificateBytes != null &&
        proof['membership'] != member.certificateBytes) {
      throw const CompanyBootstrapRefusal('Held device certificate differs');
    }
    final certificate = proof['userAuthority'];
    if (certificate is! String) {
      throw const CompanyBootstrapRefusal('User proof missing');
    }
    final enrollment = peer._owner.enrollment;
    final account = await enrollment._readUserAccount(
      userId: _userCertificateUserId(certificate),
    );
    if (account == null) {
      throw const CompanyBootstrapRefusal('Current user account unavailable');
    }
    final currentUser = await enrollment._checkUserAccount(
      account,
      requireActive: false,
    );
    final actor = await _resolveUserAuthority(
      enrollment.db,
      _trust,
      _historicalUserFloors(_floors, currentUser.user['id'] as String),
      certificate,
    );
    if (currentUser.user['id'] != actor.user['id']) {
      throw const CompanyBootstrapRefusal('Current user identity differs');
    }
    _createActor = actor;
    validateAuthorization(assertion);
    if (account.certificate != certificate &&
        (currentUser.user['credential'] as int) <=
            (actor.user['credential'] as int)) {
      throw const CompanyBootstrapRefusal('Conflicting current user epoch');
    }
    return account.isDisabled ||
        (currentUser.user['credential'] as int) >
            (actor.user['credential'] as int);
  }

  Future<void> admitCreateActor(Map<String, Object?> proof) async {
    final assertion = Map<String, Object?>.from(proof['body'] as Map);
    if (assertion['v'] != 4) return;
    final certificate = proof['userAuthority'];
    if (certificate is! String) {
      throw const CompanyBootstrapRefusal('Create user authority is missing');
    }
    final actor = await _resolveActiveUserAuthority(
      peer._owner.enrollment.db,
      peer._owner.enrollment.installation,
      _trust,
      _floors,
      certificate,
    );
    if (assertion['user'] != actor.user['id'] ||
        assertion['userAuthority'] != actor.commitment) {
      throw const CompanyBootstrapRefusal('Create selected user proof differs');
    }
    _createActor = actor;
    validateAuthorization(assertion);
  }

  void validateAuthor(Map<String, Object?> body, [List<int>? publicKey]) {
    final member = peer._held.peer._membership;
    if (body['company'] != _trust.companyId.value ||
        body['shop'] != peer._held.owner.identity.shopId ||
        body['device'] != member.device['id'] ||
        body['user'] != (_createActor?.user['id'] ?? member.user['id']) ||
        body['installation'] != member.device['installation'] ||
        body['generation'] != member.device['generation'] ||
        (publicKey != null &&
            base64Encode(publicKey) != member.device['key'])) {
      throw const CompanyBootstrapRefusal(
        'Create author is not this retained peer',
      );
    }
  }

  void validateAuthorization(Map<String, Object?> assertion) {
    final member = peer._held.peer._membership;
    final actor = _createActor;
    final user = actor?.user ?? member.user;
    validateAuthor(assertion);
    if (assertion['grant'] != member.device['grant'] ||
        assertion['credential'] != user['credential'] ||
        assertion['permission'] != user['permission'] ||
        assertion['authority'] != _trust.authorityVersion ||
        assertion['facts'] != _trust.factsCommitment ||
        (actor != null &&
            (assertion['v'] != 4 ||
                assertion['userAuthority'] != actor.commitment)) ||
        (member.certificateBytes == null
            ? (actor == null
                  ? assertion['v'] != 2
                  : assertion['deviceProof'] != 2)
            : (actor == null
                      ? assertion['v'] != 3
                      : assertion['deviceProof'] != 3) ||
                  assertion['membership'] != member.proofCommitment)) {
      throw const CompanyBootstrapRefusal(
        'Create authority differs from retained peer',
      );
    }
  }

  Future<void> requireHeld(CompanyCommandIntent intent) async {
    final enrollment = peer._owner.enrollment;
    final installation = enrollment.installation;
    final db = enrollment.db;
    if (!db.hasCallerTransaction ||
        (intent.family != CompanyCommandFamily.jobCreateIncoming &&
            intent.family != CompanyCommandFamily.jobNameIncoming &&
            intent.family != CompanyCommandFamily.jobDetailsIncoming &&
            intent.family != CompanyCommandFamily.jobLifecycleIncoming) ||
        !identical(peer._owner._exchange, peer._held)) {
      throw const CompanyBootstrapRefusal('No held peer create command');
    }
    final authority = await _membershipAuthority(db, _trust);
    final retained = peer._held.peer._membership;
    final ResolvedCompanyMembership current;
    if (retained.certificateBytes case final String certificate) {
      current = await _resolveMemberCertificate(
        certificate,
        authority,
        _trust,
        _floors,
      );
      if (!_custody.isMember) {
        final rows =
            await (db.select(db.companyMembershipCertificates)..where(
                  (t) => t.proofCommitment.equals(retained.proofCommitment),
                ))
                .get();
        if (rows.length != 1 || rows.single.proofBytes != certificate) {
          throw const CompanyBootstrapRefusal('Retained certificate changed');
        }
      }
    } else {
      current = ResolvedCompanyMembership._(
        _securityCanonical((authority['users'] as List).single),
        _securityCanonical((authority['devices'] as List).single),
        _trust.factsCommitment,
        null,
      );
      _memberFloors(current.user, current.device, _trust, _floors);
    }
    if (current._device != retained._device ||
        current._user != retained._user ||
        current.proofCommitment != retained.proofCommitment) {
      throw const CompanyBootstrapRefusal('Held peer membership changed');
    }
    final custody = await enrollment._readCustody();
    if (custody?.revision != _custody.revision ||
        _securityCanonical(custody?.values) !=
            _securityCanonical(_custody.values)) {
      throw const CompanyBootstrapRefusal('Held company custody changed');
    }
    final state = await installation.store.readState(installation.namespace);
    if (state == null) {
      throw const CompanyBootstrapRefusal('Protected identity missing');
    }
    final record = _InstallationRecord.decode(state.bytes);
    if (_securityCanonical(record.pendingCommand?.encode()) !=
            _securityCanonical(intent.encode()) ||
        _securityCanonical(record.companyTrust?.encode()) !=
            _securityCanonical(_trust.encode()) ||
        _securityCanonical(record.floors) != _securityCanonical(_floors) ||
        record.storeGeneration.value != intent.storeGeneration ||
        state.revision != installation._persisted?.revision) {
      throw const CompanyBootstrapRefusal('Held peer authority changed');
    }
    if (_createActor case final actor?) {
      final currentActor = await _resolveActiveUserAuthority(
        db,
        installation,
        _trust,
        _floors,
        actor.certificateBytes,
      );
      if (currentActor.commitment != actor.commitment) {
        throw const CompanyBootstrapRefusal(
          'Held create user authority changed',
        );
      }
    }
    peer._held.owner.validateAuthority(_trust, _floors);
    peer._held.channel._requireLive();
  }
}

final class _PeerExchange {
  _PeerExchange(
    this.channel,
    this.owner,
    this.peer,
    this.initiator,
    this.request,
    this.context,
    this.first,
  );
  final NearbyJoinChannel channel;
  final OwnerSession owner;
  final RetainedCompanyPeer peer;
  final bool initiator;
  final String request;
  final String context;
  final String first;
  String? response;
  String? completion;
}

enum CompanyPeerProofCheckpoint { afterExporter, afterEnvelope }

final class CompanyPeerAuthentication {
  CompanyPeerAuthentication({required this.enrollment, this.onProofCheckpoint});
  final CompanyEnrollment enrollment;
  // Fault injection after real async crypto. No key, proof or authority bytes
  // cross this seam; every caller still passes the following live checks.
  final Future<void> Function(CompanyPeerProofCheckpoint)? onProofCheckpoint;
  _PeerExchange? _exchange;
  ResolvedCompanyMembership? _localMembership;

  Future<List<RetainedCompanyPeer>> retainedPeers({
    required OwnerSession session,
  }) async {
    final installation = enrollment.installation;
    final trust = await installation.readCompanyTrust(enrollment.db);
    if (trust == null || !identical(enrollment.currentSession, session)) {
      throw const CompanyBootstrapRefusal('Company sign-in required');
    }
    session.validateAuthority(trust, installation.knownSecurityFloors);
    final local = await resolveCompanyMembership(
      db: enrollment.db,
      installation: installation,
    );
    final authority = await _membershipAuthority(enrollment.db, trust);
    final custody = (await enrollment._readCustody())!;
    final result = <RetainedCompanyPeer>[];
    if (custody.isMember) {
      // B retains only the exact approving root-fact device. A portable but
      // otherwise unknown child certificate is not an introduction protocol.
      final user = Map<String, Object?>.from(
        (authority['users'] as List).single as Map,
      );
      final device = Map<String, Object?>.from(
        (authority['devices'] as List).single as Map,
      );
      _memberFloors(user, device, trust, installation.knownSecurityFloors);
      result.add(
        RetainedCompanyPeer._(
          ResolvedCompanyMembership._(
            _securityCanonical(user),
            _securityCanonical(device),
            trust.factsCommitment,
            null,
          ),
        ),
      );
    } else {
      final certificates = await (enrollment.db.select(
        enrollment.db.companyMembershipCertificates,
      )..where((t) => t.companyId.equals(trust.companyId.value))).get();
      if (certificates.length > 128) {
        throw const CompanyBootstrapRefusal('Retained peer capacity reached');
      }
      for (final certificate in certificates) {
        final member = await _resolveMemberCertificate(
          certificate.proofBytes,
          authority,
          trust,
          const {},
        );
        // Validate historical signatures/shape first. Only a separately
        // checked, legitimate but currently ineligible peer may be omitted.
        try {
          _memberFloors(
            member.user,
            member.device,
            trust,
            installation.knownSecurityFloors,
          );
        } on CompanyBootstrapRefusal {
          continue;
        }
        if (member.device['id'] != local.device['id']) {
          result.add(RetainedCompanyPeer._(member));
        }
      }
    }
    return result;
  }

  Future<String> _context(
    NearbyJoinChannel channel,
    OwnerSession owner,
    RetainedCompanyPeer selected,
    bool initiator,
  ) async {
    channel._requireLive();
    final installation = enrollment.installation;
    final trust = await installation.readCompanyTrust(enrollment.db);
    if (trust == null || !identical(enrollment.currentSession, owner)) {
      throw const CompanyBootstrapRefusal('Current company session required');
    }
    final floors = installation.knownSecurityFloors;
    owner.validateAuthority(trust, floors);
    final local = await resolveCompanyMembership(
      db: enrollment.db,
      installation: installation,
    );
    final peers = await retainedPeers(session: owner);
    final peer = peers
        .where(
          (p) =>
              p.deviceId == selected.deviceId &&
              p._membership.proofCommitment ==
                  selected._membership.proofCommitment &&
              p._membership._device == selected._membership._device &&
              p._membership._user == selected._membership._user,
        )
        .single;
    owner.validateCommand(
      company: trust.companyId.value,
      shop: owner.identity.shopId,
      user: owner.identity.userId,
      device: owner.identity.deviceId,
      installation: installation.identity!.id.value,
      generation: installation.identity!.generation.value,
      session: owner.sessionId,
    );
    Map<String, Object?> actor(ResolvedCompanyMembership member) => {
      for (final key in [
        'id',
        'installation',
        'generation',
        'key',
        'grant',
        'version',
      ])
        key: member.device[key],
      'proof': member.proofCommitment,
      'user': member.user['id'],
      'credential': member.user['credential'],
      'permission': member.user['permission'],
    };
    // The actual directional session secrets, not a caller-provided transcript
    // string, contribute to the exporter. Guest/host order is the same at both ends.
    final expectedRevision = installation._persisted!.revision;
    final send = await channel._send.extractBytes();
    final receive = await channel._receive.extractBytes();
    final material = channel._keys.sendDirection == 'guest'
        ? [...send, ...receive]
        : [...receive, ...send];
    final exporter = await Hmac.sha256().calculateMac(
      utf8.encode('wiredpart.company.peer.exporter@1:${channel._keys.id}'),
      secretKey: SecretKey(material),
    );
    await onProofCheckpoint?.call(CompanyPeerProofCheckpoint.afterExporter);
    final current = await installation.store.readState(installation.namespace);
    if (current?.revision != expectedRevision ||
        !identical(enrollment.currentSession, owner)) {
      throw const CompanyBootstrapRefusal(
        'Peer authority changed during proof preparation',
      );
    }
    owner.validateAuthority(trust, floors);
    owner.validateCommand(
      company: trust.companyId.value,
      shop: owner.identity.shopId,
      user: owner.identity.userId,
      device: owner.identity.deviceId,
      installation: installation.identity!.id.value,
      generation: installation.identity!.generation.value,
      session: owner.sessionId,
    );
    channel._requireLive();
    _localMembership = local;
    return _securityCanonical({
      'v': 1,
      'purpose': 'company.peer@1',
      'transcript': channel._keys.id,
      'exporter': base64Encode(exporter.bytes),
      'authority': trust.encode(),
      'initiator': actor(initiator ? local : peer._membership),
      'responder': actor(initiator ? peer._membership : local),
    });
  }

  Future<void> _recheck(_PeerExchange held) async {
    final context = await _context(
      held.channel,
      held.owner,
      held.peer,
      held.initiator,
    );
    if (!identical(_exchange, held) || context != held.context) {
      throw const CompanyBootstrapRefusal('Retained peer context changed');
    }
  }

  Future<Map<String, Object?>> _sealPeer(
    _PeerExchange held,
    String kind,
    Map<String, Object?> body,
  ) async {
    final wire = await _sealJoin(
      held.channel,
      kind,
      held.request,
      held.peer._membership.device['key'] as String,
      body,
    );
    await onProofCheckpoint?.call(CompanyPeerProofCheckpoint.afterEnvelope);
    await _recheck(held);
    return wire;
  }

  Future<Map<String, Object?>> _proof(
    _PeerExchange held,
    String role,
    Map<String, Object?> evidence,
  ) async {
    await _recheck(held);
    final signed = await _signJoin(enrollment.installation, {
      'context': jsonDecode(held.context),
      ...evidence,
    }, 'wiredpart.company.peer.$role@1:');
    await _recheck(held);
    return {
      'v': 1,
      if (evidence.containsKey('nonce')) 'nonce': evidence['nonce'],
      'signature': signed['signature'],
    };
  }

  Future<Map<String, Object?>> beginPeerChallenge(
    NearbyJoinChannel channel,
    RetainedCompanyPeer selected, {
    required OwnerSession session,
  }) async {
    final context = await _context(channel, session, selected, true);
    _claimCompanyChannel(enrollment.installation, channel);
    final request = const Uuid().v4();
    final nonce = base64Encode(_secureRandom(32));
    final held = _PeerExchange(
      channel,
      session,
      selected,
      true,
      request,
      context,
      '',
    );
    _exchange = held;
    final proof = await _proof(held, 'initiator', {'nonce': nonce});
    final next = _PeerExchange(
      channel,
      session,
      selected,
      true,
      request,
      context,
      _securityCanonical(proof),
    );
    _exchange = next;
    return _sealPeer(next, 'peer-init', proof);
  }

  Future<Map<String, Object?>> receivePeerChallenge(
    NearbyJoinChannel channel,
    Map<String, Object?> wire, {
    required OwnerSession session,
  }) async {
    final proof = await _openJoin(
      channel,
      'peer-init',
      wire,
      recipient: base64Encode(enrollment.installation.identity!.publicKey),
    );
    _joinObject(proof, {'v', 'nonce', 'signature'});
    if (proof['v'] != 1 ||
        base64Decode(_joinString(proof, 'nonce', maximum: 44)).length != 32) {
      throw const CompanyBootstrapRefusal('Invalid peer challenge');
    }
    final matches = <_PeerExchange>[];
    for (final peer in await retainedPeers(session: session)) {
      final context = await _context(channel, session, peer, false);
      try {
        await _joinVerify(
          {'context': jsonDecode(context), 'nonce': proof['nonce']},
          proof['signature'],
          peer._membership.device['key'],
          'wiredpart.company.peer.initiator@1:',
        );
        matches.add(
          _PeerExchange(
            channel,
            session,
            peer,
            false,
            wire['request'] as String,
            context,
            _securityCanonical(proof),
          ),
        );
      } on CompanyBootstrapRefusal {
        /* unknown initiators get no response proof */
      }
    }
    if (matches.length != 1) {
      throw const CompanyBootstrapRefusal('Peer unavailable');
    }
    final held = matches.single;
    _claimCompanyChannel(enrollment.installation, channel);
    _exchange = held;
    final response = await _proof(held, 'responder', {
      'nonce': base64Encode(_secureRandom(32)),
      'first': jsonDecode(held.first),
    });
    held.response = _securityCanonical(response);
    return _sealPeer(held, 'peer-response', response);
  }

  Future<Map<String, Object?>> receivePeerResponse(
    NearbyJoinChannel channel,
    Map<String, Object?> wire,
  ) async {
    final held = _exchange;
    if (held == null ||
        !held.initiator ||
        !identical(held.channel, channel) ||
        held.request != wire['request']) {
      throw const CompanyBootstrapRefusal('No initiated peer challenge');
    }
    final response = await _openJoin(
      channel,
      'peer-response',
      wire,
      recipient: base64Encode(enrollment.installation.identity!.publicKey),
    );
    _joinObject(response, {'v', 'nonce', 'signature'});
    if (response['v'] != 1 ||
        base64Decode(_joinString(response, 'nonce', maximum: 44)).length !=
            32) {
      throw const CompanyBootstrapRefusal('Invalid responder challenge');
    }
    await _recheck(held);
    await _joinVerify(
      {
        'context': jsonDecode(held.context),
        'nonce': response['nonce'],
        'first': jsonDecode(held.first),
      },
      response['signature'],
      held.peer._membership.device['key'],
      'wiredpart.company.peer.responder@1:',
    );
    held.response = _securityCanonical(response);
    final completion = await _proof(held, 'completion', {
      'first': jsonDecode(held.first),
      'response': response,
    });
    held.completion = _securityCanonical(completion);
    return _sealPeer(held, 'peer-complete', completion);
  }

  Future<
    ({Map<String, Object?> acknowledgment, VerifiedPeerMembership membership})
  >
  receivePeerCompletion(
    NearbyJoinChannel channel,
    Map<String, Object?> wire,
  ) async {
    final held = _exchange;
    if (held == null ||
        held.initiator ||
        held.response == null ||
        !identical(held.channel, channel) ||
        held.request != wire['request']) {
      throw const CompanyBootstrapRefusal('No responder challenge');
    }
    final completion = await _openJoin(
      channel,
      'peer-complete',
      wire,
      recipient: base64Encode(enrollment.installation.identity!.publicKey),
    );
    _joinObject(completion, {'v', 'signature'});
    if (completion['v'] != 1) {
      throw const CompanyBootstrapRefusal('Invalid completion');
    }
    await _recheck(held);
    await _joinVerify(
      {
        'context': jsonDecode(held.context),
        'first': jsonDecode(held.first),
        'response': jsonDecode(held.response!),
      },
      completion['signature'],
      held.peer._membership.device['key'],
      'wiredpart.company.peer.completion@1:',
    );
    held.completion = _securityCanonical(completion);
    await _recheck(held);
    return (
      acknowledgment: await _sealPeer(held, 'peer-ack', {
        'v': 1,
        'completed': _joinDigest(completion),
      }),
      membership: VerifiedPeerMembership._(this, held),
    );
  }

  Future<VerifiedPeerMembership> receivePeerAcknowledgment(
    NearbyJoinChannel channel,
    Map<String, Object?> wire,
  ) async {
    final held = _exchange;
    if (held == null ||
        !held.initiator ||
        held.completion == null ||
        !identical(held.channel, channel) ||
        held.request != wire['request']) {
      throw const CompanyBootstrapRefusal('No completed initiator challenge');
    }
    final ack = await _openJoin(
      channel,
      'peer-ack',
      wire,
      recipient: base64Encode(enrollment.installation.identity!.publicKey),
    );
    _joinObject(ack, {'v', 'completed'});
    if (ack['v'] != 1 ||
        ack['completed'] != _joinDigest(jsonDecode(held.completion!))) {
      throw const CompanyBootstrapRefusal('Completion acknowledgment differs');
    }
    await _recheck(held);
    return VerifiedPeerMembership._(this, held);
  }
}

part of '../installation/installation_security.dart';

const _peerIntroductionCapacity = 128;
const _peerRosterPageSize = 8;
const _peerRosterProfile = 'company.peer.roster@1';

bool _indexedPeerIntroductionNamespace(String namespace) {
  const prefix = 'production.peer-intro-';
  if (!namespace.startsWith(prefix)) return false;
  final suffix = namespace.substring(prefix.length);
  final sequence = int.tryParse(suffix);
  return sequence != null &&
      sequence >= 1 &&
      sequence <= _peerIntroductionCapacity &&
      sequence.toString() == suffix;
}

String _peerIntroductionNamespace(InstallationSecurity installation, int slot) {
  if (slot < 1 || slot > _peerIntroductionCapacity) {
    throw const CompanyBootstrapRefusal('Peer introduction sequence refused');
  }
  final base = installation.namespace;
  // Apply the same base validation as the other protected company companions.
  companyCustodyNamespace(base);
  final namespace = '$base.peer-intro-$slot';
  validateInstallationNamespace(namespace);
  return namespace;
}

int _peerIntroductionSequence(ResolvedCompanyMembership member) {
  final certificate = member.certificateBytes;
  if (certificate == null) {
    throw const CompanyBootstrapRefusal('Child membership required');
  }
  return _peerIntroductionSequenceIn(certificate);
}

int _peerIntroductionSequenceIn(String certificate) {
  final sequence = (jsonDecode(certificate)['body'] as Map)['sequence'];
  if (sequence is! int ||
      sequence < 1 ||
      sequence > _peerIntroductionCapacity) {
    throw const CompanyBootstrapRefusal('Peer introduction sequence refused');
  }
  return sequence;
}

ResolvedCompanyMembership _issuingCompanyMember(
  Map<String, dynamic> authority,
  CompanyTrustAnchor trust,
  Map<String, int> floors,
) {
  final user = Map<String, Object?>.from(
    (authority['users'] as List).single as Map,
  );
  final device = Map<String, Object?>.from(
    (authority['devices'] as List).single as Map,
  );
  _memberFloors(user, device, trust, floors);
  return ResolvedCompanyMembership._(
    _securityCanonical(user),
    _securityCanonical(device),
    trust.factsCommitment,
    null,
  );
}

bool _samePeerMembership(
  ResolvedCompanyMembership a,
  ResolvedCompanyMembership b,
) =>
    a.proofCommitment == b.proofCommitment &&
    a._device == b._device &&
    a._user == b._user;

bool _peerIdentityOverlaps(
  ResolvedCompanyMembership a,
  ResolvedCompanyMembership b,
) {
  final left = a.device;
  final right = b.device;
  return [
    'id',
    'installation',
    'key',
    'grant',
  ].any((key) => left[key] == right[key]);
}

typedef _IntroducedPeer = ({
  int sequence,
  ProtectedInstallationState state,
  ResolvedCompanyMembership member,
});

Future<_IntroducedPeer?> _readIntroducedPeer(
  InstallationSecurity installation,
  int sequence,
  ResolvedCompanyMembership local,
  Map<String, dynamic> authority,
  CompanyTrustAnchor trust,
  Map<String, int> floors,
) async {
  try {
    final state = await installation.store.readState(
      _peerIntroductionNamespace(installation, sequence),
    );
    if (state == null) return null;
    if (state.bytes.length > kInstallationStateLimit) {
      throw const FormatException('Peer introduction exceeds capacity');
    }
    final text = utf8.decode(state.bytes);
    final body = _joinObject(jsonDecode(text), {
      'v',
      'binding',
      'local',
      'certificate',
    });
    if (_securityCanonical(body) != text ||
        body['v'] is! int ||
        body['v'] != 1 ||
        body['binding'] != _joinDigest(installation._record!.binding) ||
        body['local'] != local.proofCommitment) {
      throw const FormatException('Peer introduction binding differs');
    }
    final member = await _resolveMemberCertificate(
      _securityCanonical(body['certificate']),
      authority,
      trust,
      floors,
    );
    if (_peerIntroductionSequence(member) != sequence ||
        _peerIdentityOverlaps(member, local) ||
        _peerIdentityOverlaps(
          member,
          _issuingCompanyMember(authority, trust, floors),
        )) {
      throw const FormatException('Peer introduction identity differs');
    }
    return (sequence: sequence, state: state, member: member);
  } on PlatformException catch (error) {
    if (error.code != 'installation_corrupt') rethrow;
    throw const CompanyBootstrapRefusal('Protected peer introduction refused');
  } on FormatException {
    throw const CompanyBootstrapRefusal('Protected peer introduction refused');
  } on TypeError {
    throw const CompanyBootstrapRefusal('Protected peer introduction refused');
  }
}

Future<List<_IntroducedPeer>> _readIntroducedPeers(
  InstallationSecurity installation,
  ResolvedCompanyMembership local,
  Map<String, dynamic> authority,
  CompanyTrustAnchor trust,
  Map<String, int> floors, {
  bool includeConflicts = false,
}) async {
  final records = <_IntroducedPeer>[];
  for (var sequence = 1; sequence <= _peerIntroductionCapacity; sequence++) {
    try {
      final row = await _readIntroducedPeer(
        installation,
        sequence,
        local,
        authority,
        trust,
        floors,
      );
      if (row != null) records.add(row);
    } on CompanyBootstrapRefusal {
      // An ineligible or corrupt occupied slot is unavailable, never empty.
      // The exact issuer binding remains independent of introduction storage.
    }
  }
  if (includeConflicts) return records;
  final identities = <(String, Object?), int>{};
  final conflicts = <int>{};
  for (final row in records) {
    final device = row.member.device;
    for (final field in ['id', 'installation', 'key', 'grant']) {
      final prior = identities.putIfAbsent((
        field,
        device[field],
      ), () => row.sequence);
      if (prior != row.sequence) conflicts.addAll([prior, row.sequence]);
    }
  }
  return records.where((row) => !conflicts.contains(row.sequence)).toList();
}

Future<void> _recheckIntroducedPeerSlot(
  InstallationSecurity installation,
  _IntroducedPeer selected,
) async {
  final current = await installation.store.readState(
    _peerIntroductionNamespace(installation, selected.sequence),
  );
  if (current?.revision != selected.state.revision ||
      !listEquals(current!.bytes, selected.state.bytes)) {
    throw const CompanyBootstrapRefusal('Retained peer introduction changed');
  }
}

enum _PeerRosterRole { issuer, member }

typedef _PeerRosterCheckpoint = Map<int, String>;

_PeerRosterCheckpoint _decodePeerRosterCheckpoint(Object? raw) {
  if (raw is! List || raw.length > _peerIntroductionCapacity) {
    throw const CompanyBootstrapRefusal(
      'Peer roster checkpoint capacity refused',
    );
  }
  final result = <int, String>{};
  var previous = 0;
  for (final item in raw) {
    if (item is! List ||
        item.length != 2 ||
        item[0] is! int ||
        (item[0] as int) <= previous ||
        (item[0] as int) > _peerIntroductionCapacity) {
      throw const CompanyBootstrapRefusal(
        'Peer roster checkpoint order refused',
      );
    }
    _joinHash(item[1]);
    previous = item[0] as int;
    result[previous] = item[1] as String;
  }
  return result;
}

final class _CompanyPeerRoster {
  _CompanyPeerRoster._(
    this.availability,
    this.role,
    this.custody,
    this.local,
    this.remote,
    this.trust,
    this.authority,
    this.floors,
    this.binding,
  );

  final CompanyJobSyncAvailability availability;
  final _PeerRosterRole role;
  final _CompanyCustody custody;
  final ResolvedCompanyMembership local;
  final ResolvedCompanyMembership remote;
  final CompanyTrustAnchor trust;
  final Map<String, dynamic> authority;
  final Map<String, int> floors;
  final String binding;

  CompanyEnrollment get enrollment => availability.enrollment;
  InstallationSecurity get installation => enrollment.installation;
  AppDatabase get db => enrollment.db;

  static Future<_CompanyPeerRoster?> open(
    CompanyJobSyncAvailability availability,
  ) async {
    if (!availability.peerRosterConsent) return null;
    await availability.requireCurrent();
    final enrollment = availability.enrollment;
    final installation = enrollment.installation;
    final trust = (await installation.readCompanyTrust(enrollment.db))!;
    final custody = (await enrollment._readCustody())!;
    final floors = installation.knownSecurityFloors;
    final local = await resolveCompanyMembership(
      db: enrollment.db,
      installation: installation,
    );
    final remote = availability.peer._held.peer._membership;
    final authority = await _membershipAuthority(enrollment.db, trust);
    final issuer = _issuingCompanyMember(authority, trust, floors);
    final _PeerRosterRole role;
    if (!custody.isMember &&
        _samePeerMembership(local, issuer) &&
        remote.certificateBytes != null) {
      role = _PeerRosterRole.issuer;
    } else if (custody.isMember &&
        _samePeerMembership(remote, issuer) &&
        local.certificateBytes != null) {
      role = _PeerRosterRole.member;
    } else {
      return null;
    }
    final result = _CompanyPeerRoster._(
      availability,
      role,
      custody,
      local,
      remote,
      trust,
      authority,
      floors,
      installation._record!.binding,
    );
    await result.requireCurrent();
    return result;
  }

  Future<void> requireCurrent() async {
    await availability.requireCurrent();
    final currentCustody = await enrollment._readCustody();
    final protected = await installation.store.readState(
      installation.namespace,
    );
    final record = protected == null
        ? null
        : _InstallationRecord.decode(protected.bytes);
    if (currentCustody?.revision != custody.revision ||
        record?.binding != binding ||
        _securityCanonical(record?.companyTrust?.encode()) !=
            _securityCanonical(trust.encode()) ||
        _securityCanonical(record?.floors) != _securityCanonical(floors)) {
      throw const CompanyBootstrapRefusal('Peer roster authority changed');
    }
    availability.requireLive();
  }

  Future<List<List<Object>>> checkpoint() async {
    if (role != _PeerRosterRole.member) {
      throw const CompanyBootstrapRefusal('Roster recipient required');
    }
    final known = await _readIntroducedPeers(
      installation,
      local,
      authority,
      trust,
      floors,
    );
    await requireCurrent();
    return [
      for (final row in known) [row.sequence, row.member.proofCommitment],
    ];
  }

  Future<CompanyJoinEvent?> _activationAck(String request) =>
      (db.select(db.companyJoinEvents)
            ..where((t) => t.requestId.equals(request) & t.ordinal.equals(9)))
          .getSingleOrNull();

  Future<void> _requireActivated(
    ResolvedCompanyMembership member,
    String request,
    CompanyJoinEvent? ack,
  ) async {
    if (ack == null || ack.kind != 'ack') {
      throw const CompanyBootstrapRefusal(
        'Peer roster activation is unconfirmed',
      );
    }
    final signed = _joinObject(jsonDecode(ack.evidenceBytes), {
      'body',
      'signature',
    });
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
    if (_securityCanonical(signed) != ack.evidenceBytes ||
        body['v'] is! int ||
        body['v'] != 1 ||
        body['kind'] != 'company.join.ack@1' ||
        body['request'] != request ||
        body['certificate'] != member.proofCommitment ||
        body['installation'] != member.device['installation'] ||
        body['generation'] != member.device['generation'] ||
        body['key'] != member.device['key']) {
      throw const CompanyBootstrapRefusal('Peer roster activation differs');
    }
    _joinString(body, 'channel');
    await _joinVerify(
      body,
      signed['signature'],
      member.device['key'],
      'wiredpart.company.join.ack@1:',
    );
  }

  Future<Map<String, Object?>> page(_PeerRosterCheckpoint known) async {
    if (role != _PeerRosterRole.issuer) {
      throw const CompanyBootstrapRefusal(
        'Only the issuing installation shares a roster',
      );
    }
    final ledger = custody.values['enrollment'];
    if (ledger is! Map || ledger['pending'] != null) {
      throw const CompanyBootstrapRefusal(
        'Peer roster issuer ledger unavailable',
      );
    }
    await _validateIssuerLedger(db, custody, trust);
    final recipient = jsonDecode(remote.certificateBytes!)['body'] as Map;
    final recipientRequest = recipient['request'] as String;
    await _requireActivated(
      remote,
      recipientRequest,
      await _activationAck(recipientRequest),
    );
    final rows =
        await (db.select(db.companyMembershipCertificates)
              ..where((t) => t.issuerDeviceId.equals(custody.device))
              ..orderBy([(t) => OrderingTerm.asc(t.issuerSequence)]))
            .get();
    final certificates = <String>[];
    var through = 0;
    var more = false;
    for (final row in rows) {
      if (known[row.issuerSequence] == row.proofCommitment ||
          row.proofCommitment == remote.proofCommitment) {
        continue;
      }
      final body = _joinObject(jsonDecode(row.proofBytes), {
        'body',
        'signature',
      });
      final certificate = Map<String, Object?>.from(body['body'] as Map);
      final request = certificate['request'] as String;
      final ack = await _activationAck(request);
      if (ack == null) continue;
      final member = await _resolveMemberCertificate(
        row.proofBytes,
        authority,
        trust,
        const {},
      );
      try {
        _memberFloors(member.user, member.device, trust, floors);
      } on CompanyBootstrapRefusal {
        continue;
      }
      await _requireActivated(member, request, ack);
      if (certificates.length == _peerRosterPageSize) {
        more = true;
        break;
      }
      through = row.issuerSequence;
      certificates.add(row.proofBytes);
    }
    await requireCurrent();
    return {
      'profile': _peerRosterProfile,
      'through': through,
      'more': more,
      'certificates': certificates,
    };
  }

  Future<void> requireDisclosureCurrent() async {
    await requireCurrent();
    final ledger = custody.values['enrollment'] as Map;
    if (ledger['pending'] != null ||
        ledger['ledger'] != await _issuerLedgerWitness(db) ||
        (await enrollment._readCustody())?.revision != custody.revision) {
      throw const CompanyBootstrapRefusal('Peer roster issuer ledger changed');
    }
    availability.requireLive();
  }

  Future<Map<String, Object?>> acceptPage(Object? raw) =>
      availability.run(() => _acceptPage(raw));

  Future<Map<String, Object?>> _acceptPage(Object? raw) async {
    if (role != _PeerRosterRole.member) {
      throw const CompanyBootstrapRefusal('Roster recipient required');
    }
    final page = _joinObject(raw, {
      'profile',
      'through',
      'more',
      'certificates',
    });
    final certificates = page['certificates'];
    if (page['profile'] != _peerRosterProfile ||
        page['through'] is! int ||
        page['more'] is! bool ||
        certificates is! List ||
        certificates.length > _peerRosterPageSize ||
        (page['more'] == true && certificates.length != _peerRosterPageSize)) {
      throw const CompanyBootstrapRefusal('Peer roster page refused');
    }
    final known = await _readIntroducedPeers(
      installation,
      local,
      authority,
      trust,
      floors,
      includeConflicts: true,
    );
    final candidates = <ResolvedCompanyMembership>[];
    var previous = 0;
    for (final bytes in certificates) {
      if (bytes is! String) {
        throw const CompanyBootstrapRefusal('Peer roster certificate refused');
      }
      final member = await _resolveMemberCertificate(
        bytes,
        authority,
        trust,
        floors,
      );
      final sequence = _peerIntroductionSequence(member);
      if (sequence <= previous ||
          _peerIdentityOverlaps(member, local) ||
          _peerIdentityOverlaps(member, remote) ||
          candidates.any((prior) => _peerIdentityOverlaps(prior, member)) ||
          known.any(
            (row) =>
                row.sequence != sequence &&
                _peerIdentityOverlaps(row.member, member),
          )) {
        throw const CompanyBootstrapRefusal(
          'Peer roster certificate conflicts',
        );
      }
      candidates.add(member);
      previous = sequence;
    }
    if (page['through'] != previous) {
      throw const CompanyBootstrapRefusal('Peer roster high-water differs');
    }
    final expected = _slotBytesForPage(page);
    for (final entry in expected.entries) {
      await _checkSlot(entry.key, entry.value, allowEmpty: true);
    }
    for (final entry in expected.entries) {
      await _retain(entry.key, entry.value);
    }
    await _requireSlotsRetained(expected);
    return _receipt(page);
  }

  Map<String, Object?> _receipt(Map<String, Object?> page) => {
    'profile': _peerRosterProfile,
    'through': page['through'],
    'commitment': _joinDigest(page),
  };

  void checkReceipt(Map<String, Object?> page, Object? receipt) {
    if (_securityCanonical(receipt) != _securityCanonical(_receipt(page))) {
      throw const CompanyBootstrapRefusal('Peer roster receipt differs');
    }
  }

  Map<int, Uint8List> _slotBytesForPage(Map<String, Object?> page) {
    final result = <int, Uint8List>{};
    for (final certificate in (page['certificates'] as List).cast<String>()) {
      final bytes = Uint8List.fromList(
        utf8.encode(
          _securityCanonical({
            'v': 1,
            'binding': _joinDigest(binding),
            'local': local.proofCommitment,
            'certificate': jsonDecode(certificate),
          }),
        ),
      );
      if (bytes.length > kInstallationStateLimit) {
        throw const CompanyBootstrapRefusal(
          'Peer introduction exceeds capacity',
        );
      }
      result[_peerIntroductionSequenceIn(certificate)] = bytes;
    }
    return result;
  }

  Future<bool> _checkSlot(
    int sequence,
    Uint8List expected, {
    required bool allowEmpty,
  }) async {
    final state = await installation.store.readState(
      _peerIntroductionNamespace(installation, sequence),
    );
    if (state == null && allowEmpty) return false;
    if (state == null || !listEquals(state.bytes, expected)) {
      throw const CompanyBootstrapRefusal(
        'Protected peer introduction differs',
      );
    }
    return true;
  }

  Future<void> requirePageRetained(Map<String, Object?> page) =>
      _requireSlotsRetained(_slotBytesForPage(page));

  Future<void> _requireSlotsRetained(Map<int, Uint8List> expected) async {
    await requireCurrent();
    for (final entry in expected.entries) {
      await _checkSlot(entry.key, entry.value, allowEmpty: false);
    }
    availability.requireLive();
  }

  Future<void> _retain(int sequence, Uint8List bytes) async {
    final namespace = _peerIntroductionNamespace(installation, sequence);
    if (await _checkSlot(sequence, bytes, allowEmpty: true)) return;
    await requireCurrent();
    final revision = const Uuid().v4();
    try {
      await installation.store.compareAndSwapState(
        namespace,
        expectedRevision: null,
        nextRevision: revision,
        bytes: bytes,
      );
    } catch (_) {
      final saved = await installation.store.readState(namespace);
      if (saved == null || !listEquals(saved.bytes, bytes)) rethrow;
    }
    await requireCurrent();
  }
}

final class _PeerRosterReceive {
  bool _started = false;
  bool _checkpointSent = false;
  bool _finished = false;
  bool _failed = false;
  Map<String, Object?>? _offeredPage;

  bool get started => _started;
  bool get unfinished => _started && (!_finished || _failed);

  void fail() {
    _started = true;
    _failed = true;
  }

  Future<Map<String, Object?>> receive(
    _CompanyPeerRoster roster,
    Object? raw,
  ) async {
    _started = true;
    if (_finished ||
        _failed ||
        raw is! Map ||
        raw['profile'] != _peerRosterProfile) {
      throw const CompanyBootstrapRefusal('Peer roster exchange differs');
    }
    switch (raw['operation']) {
      case 'checkpoint':
        _joinObject(raw, {'profile', 'operation'});
        if (_checkpointSent || roster.role != _PeerRosterRole.member) break;
        final checkpoint = await roster.checkpoint();
        _checkpointSent = true;
        return {'profile': _peerRosterProfile, 'checkpoint': checkpoint};
      case 'push':
        final data = _joinObject(raw, {'profile', 'operation', 'page'});
        if (!_checkpointSent || roster.role != _PeerRosterRole.member) break;
        final receipt = await roster.acceptPage(data['page']);
        _finished = true;
        return receipt;
      case 'pull':
        final data = _joinObject(raw, {'profile', 'operation', 'checkpoint'});
        if (_offeredPage != null || roster.role != _PeerRosterRole.issuer) {
          break;
        }
        final page = await roster.page(
          _decodePeerRosterCheckpoint(data['checkpoint']),
        );
        _offeredPage = page;
        return page;
      case 'ack':
        final data = _joinObject(raw, {'profile', 'operation', 'receipt'});
        final page = _offeredPage;
        if (page == null || roster.role != _PeerRosterRole.issuer) break;
        roster.checkReceipt(page, data['receipt']);
        await roster.requireCurrent();
        _finished = true;
        return {'profile': _peerRosterProfile};
    }
    throw const CompanyBootstrapRefusal('Peer roster exchange differs');
  }
}

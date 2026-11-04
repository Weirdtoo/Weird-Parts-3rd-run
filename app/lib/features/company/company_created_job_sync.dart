part of '../installation/installation_security.dart';

final class CompanyJobSyncAvailability implements NearbyCompanyDisclosure {
  CompanyJobSyncAvailability._(this.enrollment, this.owner, this.peer);
  final CompanyEnrollment enrollment;
  final OwnerSession owner;
  final VerifiedPeerMembership peer;
  bool _open = true;

  static Future<CompanyJobSyncAvailability> open({
    required CompanyEnrollment enrollment,
    required OwnerSession owner,
    required VerifiedPeerMembership peer,
  }) async {
    final result = CompanyJobSyncAvailability._(enrollment, owner, peer);
    await result.requireCurrent();
    return result;
  }

  void close() => _open = false;
  @override
  void requireLive() {
    if (!_open ||
        !identical(enrollment.currentSession, owner) ||
        !identical(peer._held.owner, owner) ||
        !identical(peer._owner.enrollment, enrollment)) {
      throw const CompanyBootstrapRefusal('Manual Job sync is unavailable');
    }
    if (!identical(peer._owner._exchange, peer._held)) {
      throw const CompanyBootstrapRefusal('Retained peer context changed');
    }
    peer._held.channel._requireLive();
  }

  @override
  Future<void> requireCurrent() async {
    requireLive();
    await peer.requireJobSyncPermission();
    requireLive();
  }
}

const _syncKind = 'created-jobs';
const _syncProtocol = 'company.job.sync@7';
const _syncActorProfile = '$kCompanyUserProfile/job.create.authorization@4';

Set<String> _syncUserRoster(Object? value) {
  if (value is! List || value.length > kCompanyUserCapacity) {
    throw const CompanyBootstrapRefusal('Unsupported user roster capacity');
  }
  final result = <String>{};
  for (final id in value) {
    _stateId(id);
    if (!result.add(id as String)) {
      throw const CompanyBootstrapRefusal('Duplicate company user in roster');
    }
  }
  final sorted = result.toList()..sort();
  if (_securityCanonical(sorted) != _securityCanonical(value)) {
    throw const CompanyBootstrapRefusal('Company user roster order differs');
  }
  return result;
}

const _syncAckDomain = 'wiredpart.company.job.create.ack@1:';
const _nameSyncAckDomain = 'wiredpart.company.job.name.ack@1:';
const _lifecycleSyncAckDomain = 'wiredpart.company.job.lifecycle.ack@1:';
const _detailsSyncAckDomain = 'wiredpart.company.job.details.ack@1:';
({String prefix, String table, String ackKind, String domain, String contract})
_jobFamily(Object? kind) => switch (kind) {
  null => (
    prefix: '',
    table: 'company_job_peer_acks',
    ackKind: 'company.job.create.ack@1',
    domain: _syncAckDomain,
    contract: 'job.create@1',
  ),
  'job.name.set@1' || 'job.name.set@2' => (
    prefix: 'name/',
    table: 'company_job_name_peer_acks',
    ackKind: 'company.job.name.ack@1',
    domain: _nameSyncAckDomain,
    contract: kind as String,
  ),
  'job.details.patch@1' || 'job.details.patch@2' => (
    prefix: 'details/',
    table: 'company_job_detail_peer_acks',
    ackKind: 'company.job.details.ack@1',
    domain: _detailsSyncAckDomain,
    contract: kind as String,
  ),
  'job.lifecycle.set@1' => (
    prefix: 'lifecycle/',
    table: 'company_job_lifecycle_peer_acks',
    ackKind: 'company.job.lifecycle.ack@1',
    domain: _lifecycleSyncAckDomain,
    contract: 'job.lifecycle.set@1',
  ),
  _ => throw const CompanyBootstrapRefusal('Unsupported Job operation family'),
};
String _ackDomain(Map<String, Object?> d) => _jobFamily(d['kind']).domain;
String _ackKind(Map<String, Object?> d) => _jobFamily(d['kind']).ackKind;
Map<String, Object?> _detailsDescriptorFields(Uint8List bytes) {
  final command = PatchJobDetails.fromOperationBytes(bytes);
  return {
    'kind': command.observedLifecycleHeads == null
        ? 'job.details.patch@1'
        : 'job.details.patch@2',
    'creation': command.creationDigest,
    'fields': command.observedHeads.keys.map((f) => f.name).toList()..sort(),
    'parents':
        command.observedLifecycleHeads == null
              ? command.parentUnion
              : [
                  ...command.parentUnion.map((id) => 'd/$id'),
                  ...command.observedLifecycleHeads!.map((id) => 'l/$id'),
                ]
          ..sort(),
  };
}

Map<String, Object?> _nameDescriptorFields(Map body) => {
  'kind': body['contract'],
  'creation': body['creation'],
  'parents': body['v'] == 1
      ? body['parents']
      : ([
          ...(body['parents'] as List).map((id) => 'n/$id'),
          ...(body['lifecycle'] as List).map((id) => 'l/$id'),
        ]..sort()),
};
Map<String, Object?> _lifecycleDescriptorFields(Map body) => {
  'kind': 'job.lifecycle.set@1',
  'creation': body['creation'],
  'parents': body['parents'],
};
String _descriptorOperationTag(Map<String, Object?> d) =>
    '${switch (d['kind']) {
      'job.name.set@1' || 'job.name.set@2' => 'n',
      'job.details.patch@1' || 'job.details.patch@2' => 'd',
      'job.lifecycle.set@1' => 'l',
      _ => 'c',
    }}/${d['operation']}';
List<String> _descriptorParents(Map<String, Object?> d) =>
    (d['parents'] as List)
        .map(
          (r) => d['kind'] == 'job.name.set@1'
              ? 'n/$r'
              : d['kind'] == 'job.details.patch@1'
              ? 'd/$r'
              : r as String,
        )
        .toList();

const kCreatedJobSyncChunkBytes = 24 * 1024;

final class CreatedJobTransferBuffer {
  CreatedJobTransferBuffer({required this.length, required this.digest}) {
    if (length < 1 || length > 65536) {
      throw const CompanyBootstrapRefusal('Job reassembly byte limit');
    }
    _joinHash(digest);
  }
  final int length;
  final String digest;
  final List<int> _bytes = [];
  int get receivedBytes => _bytes.length;
  bool get complete => receivedBytes == length;
  Uint8List get bytes {
    if (!complete || _syncBytesDigest(_bytes) != digest) {
      throw const CompanyBootstrapRefusal('Job reassembly is incomplete');
    }
    return Uint8List.fromList(_bytes);
  }

  void append(Object? offset, Object? encoded) {
    if (offset != receivedBytes ||
        complete ||
        encoded is! String ||
        encoded.isEmpty ||
        encoded.length > 32768) {
      throw const CompanyBootstrapRefusal(
        'Job chunk gap, overlap or byte limit',
      );
    }
    final chunk = base64Decode(encoded);
    if (chunk.isEmpty ||
        chunk.length > kCreatedJobSyncChunkBytes ||
        base64Encode(chunk) != encoded ||
        receivedBytes + chunk.length > length) {
      throw const CompanyBootstrapRefusal(
        'Invalid Job chunk or reassembly overflow',
      );
    }
    _bytes.addAll(chunk);
    if (complete && _syncBytesDigest(_bytes) != digest) {
      throw const CompanyBootstrapRefusal('Job digest differs');
    }
  }
}

String _syncDigest(Object? value) => _joinDigest(value);
String _syncBytesDigest(List<int> bytes) =>
    hashes.sha256.convert(bytes).toString();
String _descriptorKey(Map<String, Object?> descriptor) =>
    '${_jobFamily(descriptor['kind']).prefix}${descriptor['origin']}/${descriptor['request']}';

({String operationBytes, String receiptBytes}) _recordBytes(Object row) =>
    switch (row) {
      CompanyJob r => (
        operationBytes: r.operationBytes,
        receiptBytes: r.receiptBytes,
      ),
      CompanyJobName r => (
        operationBytes: r.operationBytes,
        receiptBytes: r.receiptBytes,
      ),
      CompanyJobDetail r => (
        operationBytes: r.operationBytes,
        receiptBytes: r.receiptBytes,
      ),
      CompanyJobLifecycle r => (
        operationBytes: r.operationBytes,
        receiptBytes: r.receiptBytes,
      ),
      _ => throw const CompanyBootstrapRefusal('Unsupported Job record'),
    };

Map<String, Object?> _jobDescriptor(Object row) {
  final (origin, request, job, operation, command) = switch (row) {
    CompanyJob r => (
      r.originGeneration,
      r.requestId,
      r.jobId,
      r.operationCommitment,
      r.commandCommitment,
    ),
    CompanyJobName r => (
      r.originGeneration,
      r.requestId,
      r.jobId,
      r.operationCommitment,
      r.commandCommitment,
    ),
    CompanyJobDetail r => (
      r.originGeneration,
      r.requestId,
      r.jobId,
      r.operationCommitment,
      r.commandCommitment,
    ),
    CompanyJobLifecycle r => (
      r.originGeneration,
      r.requestId,
      r.jobId,
      r.operationCommitment,
      r.commandCommitment,
    ),
    _ => throw const CompanyBootstrapRefusal('Unsupported Job record'),
  };
  final bytes = _recordBytes(row).operationBytes;
  final body = (jsonDecode(bytes) as Map)['body'] as Map;
  return {
    if (row is CompanyJobName) ..._nameDescriptorFields(body),
    if (row is CompanyJobLifecycle) ..._lifecycleDescriptorFields(body),
    if (row is CompanyJobDetail)
      ..._detailsDescriptorFields(Uint8List.fromList(utf8.encode(bytes))),
    'origin': origin,
    'request': request,
    'job': job,
    'author': body['device'],
    'installation': body['installation'],
    'operation': operation,
    'command': command,
    'digest': _syncBytesDigest(utf8.encode(bytes)),
    'length': utf8.encode(bytes).length,
  };
}

Map<String, Object?> _parseDescriptor(Object? value) {
  final kind = value is Map ? value['kind'] : null;
  _jobFamily(kind);
  final mutable = kind != null;
  final details =
      kind == 'job.details.patch@1' || kind == 'job.details.patch@2';
  final result = _joinObject(value, {
    if (mutable) ...{'kind', 'creation', 'parents'},
    if (details) 'fields',
    'origin',
    'request',
    'job',
    'author',
    'installation',
    'operation',
    'command',
    'digest',
    'length',
  });
  for (final key in ['origin', 'request', 'job', 'author', 'installation']) {
    _joinId(result, key);
  }
  for (final key in ['operation', 'command', 'digest']) {
    _joinHash(result[key]);
  }
  if (mutable) {
    _joinHash(result['creation']);
    final parents = result['parents'];
    if (parents is! List ||
        parents.length > 32 ||
        parents.toSet().length != parents.length) {
      throw const CompanyBootstrapRefusal('Invalid name descriptor parents');
    }
    for (final parent in parents) {
      if (kind == 'job.lifecycle.set@1' ||
          kind == 'job.name.set@2' ||
          kind == 'job.details.patch@2') {
        JobOperationRef.parse(parent as String);
      } else {
        _joinHash(parent);
      }
    }
    final sorted = [...parents.cast<String>()]..sort();
    if (_securityCanonical(sorted) != _securityCanonical(parents)) {
      throw const CompanyBootstrapRefusal('Noncanonical name parents');
    }
  }
  if (details) {
    final fields = result['fields'];
    if (fields is! List ||
        fields.isEmpty ||
        fields.length > 5 ||
        fields.toSet().length != fields.length ||
        fields.any((f) => !JobDetailField.values.any((v) => v.name == f))) {
      throw const CompanyBootstrapRefusal('Invalid details descriptor fields');
    }
    final sorted = [...fields.cast<String>()]..sort();
    if (_securityCanonical(sorted) != _securityCanonical(fields)) {
      throw const CompanyBootstrapRefusal('Noncanonical details fields');
    }
  }
  if (result['length'] is! int ||
      (result['length'] as int) < 1 ||
      (result['length'] as int) > 65536 ||
      utf8.encode(_securityCanonical(result)).length > 4096) {
    throw const CompanyBootstrapRefusal('Job descriptor capacity exceeded');
  }
  return result;
}

final class CreatedJobHoldingsInventory {
  CreatedJobHoldingsInventory.local(List<Object> records) {
    descriptors = records.map(_jobDescriptor).map(_parseDescriptor).toList()
      ..sort((a, b) => _descriptorKey(a).compareTo(_descriptorKey(b)));
    if (descriptors.length > 1024) {
      throw const CompanyBootstrapRefusal('Job inventory capacity exceeded');
    }
    count = descriptors.length;
    var pageBytes = 256, pageItems = 0;
    for (var i = 0; i < descriptors.length; i++) {
      final bytes = utf8.encode(_securityCanonical(descriptors[i])).length + 40;
      if (pageItems == 32 || pageBytes + bytes > 32 * 1024) {
        _pageEnds.add(i);
        pageBytes = 256;
        pageItems = 0;
      }
      pageBytes += bytes;
      pageItems++;
    }
    if (pageItems > 0) _pageEnds.add(descriptors.length);
    _pageCount = _pageEnds.length;
    _adaptivePages = _pageEnds.asMap().entries.any(
      (entry) =>
          entry.key < _pageEnds.length - 1 &&
          entry.value - (entry.key == 0 ? 0 : _pageEnds[entry.key - 1]) != 32,
    );
    digest = _syncDigest(descriptors);
    _validateComplete();
  }
  CreatedJobHoldingsInventory.remote(Object? raw) {
    final adaptive = raw is Map && raw['packing'] == 'bytes@1';
    final meta = _joinObject(raw, {
      'count',
      'pages',
      'digest',
      if (adaptive) 'packing',
    });
    if (meta['count'] is! int ||
        (meta['count'] as int) < 0 ||
        (meta['count'] as int) > 1024 ||
        meta['pages'] is! int ||
        (adaptive
            ? ((meta['pages'] as int) < ((meta['count'] as int) + 31) ~/ 32 ||
                  (meta['pages'] as int) > (meta['count'] as int))
            : meta['pages'] != ((meta['count'] as int) + 31) ~/ 32)) {
      throw const CompanyBootstrapRefusal('Invalid inventory framing');
    }
    _joinHash(meta['digest']);
    count = meta['count'] as int;
    _pageCount = meta['pages'] as int;
    _adaptivePages = adaptive;
    digest = meta['digest'] as String;
    descriptors = [];
    if (count == 0) _validateComplete();
  }
  final List<int> _pageEnds = [];
  late int _pageCount;
  bool _adaptivePages = false;
  late List<Map<String, Object?>> descriptors;
  late int count;
  late String digest;
  int _receivedPages = 0;
  int _aggregateBytes = 0;
  bool _validated = false;
  final List<String?> _peerAckStores = [];
  String? peerAckStore(String key) {
    final index = descriptors.indexWhere((d) => _descriptorKey(d) == key);
    return index < 0 || index >= _peerAckStores.length
        ? null
        : _peerAckStores[index];
  }

  int get pages => _pageCount;
  bool get complete => _validated;
  Map<String, Object?> get meta => {
    'count': count,
    if (_adaptivePages) 'packing': 'bytes@1',
    'pages': pages,
    'digest': digest,
  };
  List<Map<String, Object?>> page(int ordinal) {
    if (ordinal < 0 || ordinal >= pages || !complete) {
      throw const CompanyBootstrapRefusal('Invalid inventory page');
    }
    return descriptors.sublist(
      ordinal == 0 ? 0 : _pageEnds[ordinal - 1],
      _pageEnds[ordinal],
    );
  }

  void acceptPage(Object? raw) {
    final page = _joinObject(raw, {
      'ordinal',
      'digest',
      'items',
      'confirmedStores',
    });
    if (page['ordinal'] != _receivedPages ||
        page['digest'] != digest ||
        _receivedPages >= pages ||
        page['items'] is! List) {
      throw const CompanyBootstrapRefusal(
        'Duplicate or conflicting inventory page',
      );
    }
    final items = page['items'] as List;
    final stores = page['confirmedStores'];
    if (stores is! List ||
        stores.length != items.length ||
        stores.any(
          (s) =>
              s != null && (s is! String || !Uuid.isValidUUID(fromString: s)),
        )) {
      throw const CompanyBootstrapRefusal(
        'Invalid bounded ACK checkpoint page',
      );
    }
    final bytes = utf8.encode(_securityCanonical(page)).length;
    _aggregateBytes += bytes;
    if (items.isEmpty ||
        items.length > 32 ||
        descriptors.length + items.length > count ||
        (!_adaptivePages &&
            items.length !=
                (count - descriptors.length > 32
                    ? 32
                    : count - descriptors.length)) ||
        bytes > 33 * 1024 ||
        _aggregateBytes > 4128 * 1024) {
      throw const CompanyBootstrapRefusal(
        'Inventory aggregate capacity exceeded',
      );
    }
    descriptors.addAll(items.map(_parseDescriptor));
    _peerAckStores.addAll(stores.cast<String?>());
    _receivedPages++;
    if (_receivedPages == pages) _validateComplete();
  }

  void _validateComplete() {
    final keys = descriptors.map(_descriptorKey).toList();
    final sorted = [...keys]..sort();
    if (descriptors.length != count ||
        keys.toSet().length != count ||
        descriptors
                .where((d) => d['kind'] == null)
                .map((d) => d['job'])
                .toSet()
                .length !=
            descriptors.where((d) => d['kind'] == null).length ||
        _securityCanonical(keys) != _securityCanonical(sorted) ||
        _syncDigest(descriptors) != digest) {
      throw const CompanyBootstrapRefusal(
        'Inventory identity or digest differs',
      );
    }
    _validated = true;
  }

  Map<String, Map<String, Object?>> get byKey => {
    for (final d in descriptors) _descriptorKey(d): d,
  };
}

enum CreatedJobSyncStage {
  preflight,
  channel,
  channelOpen,
  replySeal,
  localInventory,
  startRequest,
  holdings,
  transfer,
  confirmation,
}

enum CreatedJobSyncReason {
  unavailable,
  verificationChanged,
  moreJobsPending,
  unconfirmedSnapshot,
  unsupportedAuthor,
  timeout,
  transportRejected,
  transportUnavailable,
  refused,
  unexpected,
}

final class CreatedJobSyncFailure {
  const CreatedJobSyncFailure(this.stage, this.reason);

  factory CreatedJobSyncFailure.fromError(
    Object error,
    CreatedJobSyncStage stage,
  ) {
    final reason = switch (error) {
      CompanyBootstrapRefusal(:final message) => switch (message) {
        'Manual Job sync is unavailable' ||
        'Enable manual Job sync first' ||
        'Join is closed' ||
        'Join connection changed' => CreatedJobSyncReason.unavailable,
        'Retained peer context changed' =>
          CreatedJobSyncReason.verificationChanged,
        'More Jobs pending' ||
        'More Jobs pending; pair again' ||
        'Job sync channel budget exhausted' ||
        'Job sync frame ceiling reached' =>
          CreatedJobSyncReason.moreJobsPending,
        'Peer claimed an unconfirmed Job snapshot' =>
          CreatedJobSyncReason.unconfirmedSnapshot,
        _ => CreatedJobSyncReason.refused,
      },
      TimeoutException() => CreatedJobSyncReason.timeout,
      NearbyException() => CreatedJobSyncReason.transportRejected,
      SocketException() => CreatedJobSyncReason.transportUnavailable,
      _ => CreatedJobSyncReason.unexpected,
    };
    return CreatedJobSyncFailure(stage, reason);
  }

  final CreatedJobSyncStage stage;
  final CreatedJobSyncReason reason;
  String get message => 'Stage ${stage.name}. Reason ${reason.name}.';
}

enum CreatedJobSyncDiagnosticKind { started, receiverEntered, terminal }

final class CreatedJobSyncDiagnostic {
  const CreatedJobSyncDiagnostic.started({this.receiverCallbackReached = false})
    : kind = CreatedJobSyncDiagnosticKind.started,
      result = null;
  const CreatedJobSyncDiagnostic.receiverEntered()
    : kind = CreatedJobSyncDiagnosticKind.receiverEntered,
      receiverCallbackReached = true,
      result = null;
  const CreatedJobSyncDiagnostic.terminal(
    CreatedJobSyncResult this.result, {
    this.receiverCallbackReached = false,
  }) : kind = CreatedJobSyncDiagnosticKind.terminal;

  final CreatedJobSyncDiagnosticKind kind;
  final bool receiverCallbackReached;
  final CreatedJobSyncResult? result;

  void notify(void Function(CreatedJobSyncDiagnostic)? observer) {
    try {
      observer?.call(this);
    } catch (_) {
      // Observing a result must not change admission or drain behavior.
    }
  }
}

final class CreatedJobSyncResult {
  const CreatedJobSyncResult(
    this.sent,
    this.received,
    this.complete,
    this.unsupported, {
    this.failure,
    this.held = 0,
  });
  final int sent;
  final int received;
  final bool complete;
  final int unsupported;
  final CreatedJobSyncFailure? failure;
  final int held;
  String get message => complete
      ? 'Job snapshot synced. Sent $sent, received $received.'
      : 'Job sync incomplete. Confirmed sent $sent, received $received. Pair again and retry Sync Now.${held > 0
            ? ' User work is held for attention under the current account policy, with original bytes retained and no applied confirmation.'
            : unsupported > 0
            ? ' Unsupported author scope remains pending.'
            : ''}${failure == null ? '' : ' ${failure!.message}'}';
}

enum _CreatedJobRunDirection { initiating, receiving }

final class _CreatedJobRun {
  _CreatedJobRun(this.id, this.direction);
  final String id;
  final _CreatedJobRunDirection direction;
  bool disclosed = false;
}

final class CompanyCreatedJobSync {
  String? _lifecycleProfileRun;
  String? _lifecyclePolicyRun;
  String? _lifecycleReadyRun;
  bool _lifecycleMore = false;
  VerifiedUserLifecycleTarget? _lifecycleTarget;
  Set<String> _lifecycleUsers = {};
  Set<String> _lifecycleLocalUsers = {};
  Set<String> _lifecycleRemoteUsers = {};
  final Set<String> _lifecycleFinished = {};

  Future<List<String>> _localUserRoster() async {
    final accounts = await availability.enrollment._readUserAccounts();
    return accounts.byUserId.keys.toList()..sort();
  }

  Future<void> _requireUserRoster(Set<String> expected) async {
    final actual = (await _localUserRoster()).toSet();
    if (actual.length != expected.length || !actual.containsAll(expected)) {
      throw const CompanyBootstrapRefusal('Company user roster changed');
    }
  }

  Future<Set<String>> _policyUserRoster(
    Set<String> before,
    String targetUserId,
  ) async {
    final actual = (await _localUserRoster()).toSet();
    final allowed = {...before, targetUserId};
    if (!actual.containsAll(before) || !allowed.containsAll(actual)) {
      throw const CompanyBootstrapRefusal(
        'Company user roster changed during policy',
      );
    }
    return actual;
  }

  final Set<String> _heldJobKeys = {};
  final Set<String> _heldCreationJobs = {};
  int get _heldJobs => _heldJobKeys.length;
  void _markHeld(Map<String, Object?> descriptor) {
    _heldJobKeys.add(_descriptorKey(descriptor));
    if (descriptor['kind'] == null) {
      _heldCreationJobs.add(descriptor['job'] as String);
    }
  }

  static Future<Map<String, int>> confirmedPeerCounts(
    CompanyEnrollment enrollment,
    OwnerSession owner, {
    bool creationOnly = false,
  }) async {
    final commands = CompanyJobCommands(enrollment: enrollment);
    final records = <Object>[
      ...await commands.syncHoldings(ownerSession: owner),
      if (!creationOnly) ...[
        ...await commands.nameSyncHoldings(ownerSession: owner),
        ...await commands.detailsSyncHoldings(ownerSession: owner),
        ...await commands.lifecycleSyncHoldings(ownerSession: owner),
      ],
    ];
    final peers = await CompanyPeerAuthentication(enrollment: enrollment)
        .retainedPeers(session: owner);
    final members = {for (final p in peers) p.deviceId: p._membership};
    final descriptors = {
      for (final r in records)
        _descriptorKey(_jobDescriptor(r)): _jobDescriptor(r),
    };
    final expected = <String, Set<String>>{};
    for (final entry in descriptors.entries) {
      expected
          .putIfAbsent(entry.value['job'] as String, () => {})
          .add(entry.key);
    }
    final confirmed = <String, Map<String, Set<String>>>{};
    for (final kind in [
      null,
      if (!creationOnly) ...[
        'job.name.set@1',
        'job.details.patch@1',
        'job.lifecycle.set@1',
      ],
    ]) {
      final family = _jobFamily(kind);
      final table = family.table;
      final rows = await enrollment.db
          .customSelect(
            'SELECT * FROM $table WHERE company_id = ? LIMIT 65537',
            variables: [Variable(owner.identity.companyId)],
          )
          .get();
      if (rows.length > 65536) {
        throw const CompanyBootstrapRefusal(
          'Job ACK history capacity exceeded',
        );
      }
      for (final row in rows) {
        final peer = row.read<String>('peer_device_id');
        final member = members[peer];
        final key =
            '${family.prefix}${row.read<String>('origin_generation')}/${row.read<String>('request_id')}';
        final descriptor = descriptors[key];
        if (member == null || descriptor == null) continue;
        final bytes = row.read<String>('ack_bytes');
        if (row.read<String>('operation_digest') != descriptor['digest'] ||
            utf8.encode(bytes).length > 4096) {
          throw const CompanyBootstrapRefusal('Saved Job ACK differs');
        }
        final signed = _joinObject(jsonDecode(bytes), {'body', 'signature'});
        final body = _joinObject(signed['body'], {
          'v',
          'kind',
          'descriptor',
          'receiver',
          'generation',
          'store',
          'receipt',
        });
        _joinId(body, 'store');
        _joinHash(body['receipt']);
        if (body['v'] != 1 ||
            body['kind'] != _ackKind(descriptor) ||
            body['receiver'] != member.device['installation'] ||
            body['generation'] != member.device['generation'] ||
            _securityCanonical(body['descriptor']) !=
                _securityCanonical(descriptor)) {
          throw const CompanyBootstrapRefusal('Saved Job ACK binding differs');
        }
        await _joinVerify(
          body,
          signed['signature'],
          member.device['key'],
          _ackDomain(descriptor),
        );
        confirmed
            .putIfAbsent(descriptor['job'] as String, () => {})
            .putIfAbsent(peer, () => {})
            .add(key);
      }
    }
    final counts = <String, int>{};
    for (final entry in expected.entries) {
      counts[entry.key] =
          confirmed[entry.key]?.values
              .where((keys) => keys.containsAll(entry.value))
              .length ??
          0;
    }
    await commands.requireSyncPermission(owner);
    return counts;
  }

  CompanyCreatedJobSync({
    required this.availability,
    required this.controller,
    this.onStatus,
    this.onDiagnostic,
    this.chunkBytes = kCreatedJobSyncChunkBytes,
  }) {
    if (chunkBytes < 1 || chunkBytes > kCreatedJobSyncChunkBytes) {
      throw ArgumentError.value(chunkBytes, 'chunkBytes');
    }
    controller.companySyncDisclosure = availability;
  }
  final CompanyJobSyncAvailability availability;
  final NearbyController controller;
  final void Function(String)? onStatus;
  final void Function(CreatedJobSyncDiagnostic)? onDiagnostic;
  final int chunkBytes;
  Object? lastFailure;

  void _status(String message) {
    try {
      onStatus?.call(message);
    } catch (_) {
      // Status observers cannot change the sync result.
    }
  }

  void _terminal(CreatedJobSyncResult result, {bool receiving = false}) {
    if (!receiving || _activeRun == null) _status(result.message);
    CreatedJobSyncDiagnostic.terminal(
      result,
      receiverCallbackReached: receiving,
    ).notify(onDiagnostic);
  }

  bool get isLive {
    if (_closed) return false;
    try {
      availability.requireLive();
      return true;
    } catch (_) {
      return false;
    }
  }

  CompanyJobCommands get _commands =>
      CompanyJobCommands(enrollment: availability.enrollment);
  AppDatabase get _db => availability.enrollment.db;
  InstallationSecurity get _installation =>
      availability.enrollment.installation;
  Future<NearbyJoinChannel>? _channelPending;
  CreatedJobHoldingsInventory? _local;
  CreatedJobHoldingsInventory? _remote;
  _CreatedJobRun? _activeRun;
  // Each retained ID consumed an inbound start or an outbound frame. The
  // unchanged channel ceilings bound this set to at most 224 IDs.
  final Set<String> _retiredRuns = {};
  bool get isRunning => _activeRun != null || _receivePending;

  void _requireRunCapacity() {
    if (_retiredRuns.length >= 224) {
      throw const CompanyBootstrapRefusal('Job sync channel budget exhausted');
    }
  }

  void _requireRun(_CreatedJobRun run) {
    if (_closed || !identical(_activeRun, run)) {
      throw const CompanyBootstrapRefusal('Job sync run differs');
    }
    availability.requireLive();
  }

  void _retire(_CreatedJobRun run) {
    if (!identical(_activeRun, run)) return;
    if (run.direction == _CreatedJobRunDirection.receiving || run.disclosed) {
      _retiredRuns.add(run.id);
    }
    _activeRun = null;
    _local = null;
    _remote = null;
    _remoteStore = null;
    _cachedAckStores = {};
    _incoming = null;
    _incomingDescriptor = null;
    _served.clear();
    _confirmed.clear();
  }

  bool _closed = false;
  Future<CreatedJobSyncResult>? _initiating;
  int _remoteRemaining = 128;
  String? _remoteStore;
  Map<String, String> _cachedAckStores = {};
  int _sentFrames = 0;
  int _receivedFrames = 0;
  int _sentJobs = 0;
  int _receivedJobs = 0;
  Map<String, Object?>? _incomingDescriptor;
  CreatedJobTransferBuffer? _incoming;
  Future<void> _receiving = Future<void>.value();
  bool _receivePending = false;
  final Set<String> _served = {};
  final Set<String> _confirmed = {};

  void close() {
    _closed = true;
    if (identical(controller.companySyncDisclosure, availability)) {
      controller.companySyncDisclosure = null;
    }
    availability.close();
    if (_activeRun case final run?) _retire(run);
  }

  Future<void> closeAndDrain() async {
    close();
    await Future.wait<void>([
      _receiving,
      if (_initiating case final pending?) pending.then<void>((_) {}),
    ]);
  }

  Future<NearbyJoinChannel> _getChannel() => _channelPending ??= (() async {
    await availability.requireCurrent();
    final source = availability.peer._held.channel;
    Future<SecretKey> derive(SecretKey key, String direction) =>
        Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
          secretKey: key,
          nonce: utf8.encode(source._keys.id),
          info: utf8.encode(
            'wiredpart-v2/company-job-create-sync@1/$direction',
          ),
        );
    final channel = NearbyJoinChannel._(
      source._pair,
      source._keys,
      await derive(source._send, source._keys.sendDirection),
      await derive(source._receive, source._keys.receiveDirection),
    );
    await availability.requireCurrent();
    return channel;
  })();

  bool _canExchange(int requests) {
    final pair = availability.peer._held.channel._pair;
    return _sentFrames + requests <= 112 &&
        _receivedFrames + requests <= 112 &&
        pair.remainingReceivedNonces >= requests + 4 &&
        _remoteRemaining >= requests + 4 &&
        pair.timeUntilExpiry > Duration(seconds: requests * 20);
  }

  Future<Map<String, Object?>> _seal(
    String request,
    Map<String, Object?> body,
  ) async {
    await availability.requireCurrent();
    final channel = await _getChannel();
    if (_sentFrames >= 112 || channel._pair.remainingReceivedNonces < 2) {
      throw const CompanyBootstrapRefusal('Job sync channel budget exhausted');
    }
    final wire = await _sealJoin(
      channel,
      _syncKind,
      request,
      availability.peer._held.peer._membership.device['key'] as String,
      {
        'v': 1,
        'protocol': _syncProtocol,
        'remaining': channel._pair.remainingReceivedNonces,
        ...body,
      },
    );
    await availability.requireCurrent();
    _sentFrames++;
    return wire;
  }

  Future<Map<String, Object?>> _open(Map<String, Object?> wire) async {
    await availability.requireCurrent();
    if (_receivedFrames >= 112) {
      throw const CompanyBootstrapRefusal('Job sync frame ceiling reached');
    }
    final channel = await _getChannel();
    final body = await _openJoin(
      channel,
      _syncKind,
      wire,
      recipient: base64Encode(_installation.identity!.publicKey),
    );
    _receivedFrames++;
    _joinObject(body, {'v', 'protocol', 'remaining', 'action', 'run', 'data'});
    if (body['v'] != 1 ||
        body['protocol'] != _syncProtocol ||
        body['remaining'] is! int ||
        (body['remaining'] as int) < 0 ||
        (body['remaining'] as int) > 128) {
      throw const CompanyBootstrapRefusal('Unsupported Job sync protocol');
    }
    _joinId(body, 'run');
    _remoteRemaining = body['remaining'] as int;
    await availability.requireCurrent();
    return body;
  }

  Future<Map<String, Object?>> _rpc(
    String action,
    Map<String, Object?> data,
  ) async {
    final run = _activeRun;
    if (run == null || run.direction != _CreatedJobRunDirection.initiating) {
      throw const CompanyBootstrapRefusal('Job sync run differs');
    }
    _requireRun(run);
    if (!_canExchange(1)) {
      throw const CompanyBootstrapRefusal('More Jobs pending; pair again');
    }
    final request = const Uuid().v4();
    final wire = await _seal(request, {
      'action': action,
      'run': run.id,
      'data': data,
    });
    _requireRun(run);
    run.disclosed = true;
    final response = await controller.exchangeCompanyMessage(
      wire,
      disclosure: availability,
    );
    _requireRun(run);
    final body = await _open(response);
    _requireRun(run);
    if (response['request'] != request ||
        body['action'] != '$action.reply' ||
        body['run'] != run.id) {
      throw const CompanyBootstrapRefusal('Job sync response differs');
    }
    return Map<String, Object?>.from(body['data'] as Map);
  }

  Future<void> _freeze(_CreatedJobRun run) async {
    final records = <Object>[
      ...await _commands.syncHoldings(ownerSession: availability.owner),
      ...await _commands.nameSyncHoldings(ownerSession: availability.owner),
      ...await _commands.detailsSyncHoldings(ownerSession: availability.owner),
      ...await _commands.lifecycleSyncHoldings(
        ownerSession: availability.owner,
      ),
    ];
    _requireRun(run);
    final local = CreatedJobHoldingsInventory.local(records);
    final cached = await _readAckCache(records);
    _requireRun(run);
    _local = local;
    _cachedAckStores = cached;
    _incoming = null;
    _incomingDescriptor = null;
  }

  Map<String, Object?> _summary() => {
    'inventory': _local!.meta,
    'store': _installation.receivingStoreGeneration!.value,
  };

  void _readSummary(Map<String, Object?> data) {
    _joinObject(data, {'inventory', 'store'});
    _remoteStore = _joinId(data, 'store');
    _remote = CreatedJobHoldingsInventory.remote(data['inventory']);
  }

  Map<String, Object?> _holdingsPage(int ordinal) {
    final items = _local!.page(ordinal);
    final result = <String, Object?>{
      'ordinal': ordinal,
      'digest': _local!.digest,
      'items': items,
      'confirmedStores': [
        for (final d in items) _cachedAckStores[_descriptorKey(d)],
      ],
    };
    if (utf8.encode(_securityCanonical(result)).length > 33 * 1024) {
      throw const CompanyBootstrapRefusal('Job holdings page byte limit');
    }
    return result;
  }

  Future<Map<String, String>> _readAckCache(List<Object> records) async {
    final expected = {
      for (final row in records)
        _descriptorKey(_jobDescriptor(row)): _jobDescriptor(row),
    };
    final result = <String, String>{};
    for (final kind in [
      null,
      'job.name.set@1',
      'job.details.patch@1',
      'job.lifecycle.set@1',
    ]) {
      final family = _jobFamily(kind);
      final table = family.table;
      final rows = await _db
          .customSelect(
            'SELECT * FROM $table WHERE company_id = ? AND peer_device_id = ? LIMIT 1025',
            variables: [
              Variable(availability.owner.identity.companyId),
              Variable(availability.peer.deviceId),
            ],
          )
          .get();
      if (rows.length > 1024) {
        throw const CompanyBootstrapRefusal('Peer ACK capacity exceeded');
      }
      for (final row in rows) {
        final key =
            '${family.prefix}${row.read<String>('origin_generation')}/${row.read<String>('request_id')}';
        final descriptor = expected[key];
        if (descriptor == null ||
            row.read<String>('operation_digest') != descriptor['digest']) {
          throw const CompanyBootstrapRefusal(
            'Saved ACK has no matching scoped Job',
          );
        }
        final body = await _validatePeerAck(
          descriptor,
          jsonDecode(row.read<String>('ack_bytes')),
        );
        result[key] = body['store'] as String;
      }
    }
    return result;
  }

  Future<({String operationBytes, String receiptBytes})> _record(
    Map<String, Object?> descriptor,
  ) async {
    final Object row = switch (descriptor['kind']) {
      null => await _commands.verifySyncRecord(
        descriptor['job'] as String,
        availability.owner,
      ),
      'job.name.set@1' ||
      'job.name.set@2' => await _commands.verifyNameSyncRecord(
        descriptor['operation'] as String,
        availability.owner,
      ),
      'job.details.patch@1' ||
      'job.details.patch@2' => await _commands.verifyDetailsSyncRecord(
        descriptor['operation'] as String,
        availability.owner,
      ),
      'job.lifecycle.set@1' => await _commands.verifyLifecycleSyncRecord(
        descriptor['operation'] as String,
        availability.owner,
      ),
      _ => throw const CompanyBootstrapRefusal(
        'Unsupported Job operation family',
      ),
    };
    if (_securityCanonical(_jobDescriptor(row)) !=
        _securityCanonical(descriptor)) {
      throw const CompanyBootstrapRefusal('Job changed after inventory');
    }
    return _recordBytes(row);
  }

  Future<Map<String, Object?>> _ack(Map<String, Object?> descriptor) async {
    final row = await _record(descriptor);
    await availability.requireCurrent();
    final identity = _installation.identity!;
    final signed = await _signJoin(_installation, {
      'v': 1,
      'kind': _ackKind(descriptor),
      'descriptor': descriptor,
      'receiver': identity.id.value,
      'generation': identity.generation.value,
      'store': _installation.receivingStoreGeneration!.value,
      'receipt': _syncBytesDigest(utf8.encode(row.receiptBytes)),
    }, _ackDomain(descriptor));
    if (utf8.encode(_securityCanonical(signed)).length > 4096) {
      throw const CompanyBootstrapRefusal('Job ACK capacity exceeded');
    }
    await availability.requireCurrent();
    return signed;
  }

  Future<Map<String, Object?>> _validatePeerAck(
    Map<String, Object?> descriptor,
    Object? raw,
  ) async {
    final signed = _joinObject(raw, {'body', 'signature'});
    if (utf8.encode(_securityCanonical(signed)).length > 4096) {
      throw const CompanyBootstrapRefusal('Job ACK capacity exceeded');
    }
    final body = _joinObject(signed['body'], {
      'v',
      'kind',
      'descriptor',
      'receiver',
      'generation',
      'store',
      'receipt',
    });
    final member = availability.peer._held.peer._membership;
    _joinId(body, 'store');
    _joinHash(body['receipt']);
    if (body['v'] != 1 ||
        body['kind'] != _ackKind(descriptor) ||
        body['receiver'] != member.device['installation'] ||
        body['generation'] != member.device['generation'] ||
        _securityCanonical(body['descriptor']) !=
            _securityCanonical(descriptor)) {
      throw const CompanyBootstrapRefusal('Job ACK binding differs');
    }
    await _joinVerify(
      body,
      signed['signature'],
      member.device['key'],
      _ackDomain(descriptor),
    );
    return body;
  }

  Future<void> _saveAck(Map<String, Object?> descriptor, Object? raw) async {
    final run = _activeRun;
    if (run == null) {
      throw const CompanyBootstrapRefusal('Job sync run differs');
    }
    _requireRun(run);
    final body = await _validatePeerAck(descriptor, raw);
    if (body['store'] != _remoteStore) {
      throw const CompanyBootstrapRefusal(
        'ACK receiver store differs from live snapshot',
      );
    }
    final signed = _joinObject(raw, {'body', 'signature'});
    await _record(descriptor);
    await availability.requireCurrent();
    final table = _jobFamily(descriptor['kind']).table;
    await _db.transaction(() async {
      await _db.customStatement(
        'UPDATE app_settings SET value = value WHERE key = ?',
        [kInstallationBindingKey],
      );
      await availability.requireCurrent();
      await _db.customStatement(
        'INSERT INTO $table (company_id,origin_generation,request_id,peer_device_id,operation_digest,ack_bytes) VALUES (?,?,?,?,?,?) ON CONFLICT(company_id,origin_generation,request_id,peer_device_id) DO UPDATE SET operation_digest=excluded.operation_digest,ack_bytes=excluded.ack_bytes',
        [
          availability.owner.identity.companyId,
          descriptor['origin'],
          descriptor['request'],
          availability.peer.deviceId,
          descriptor['digest'],
          _securityCanonical(signed),
        ],
      );
      availability.requireLive();
    });
    _requireRun(run);
    _cachedAckStores[_descriptorKey(descriptor)] = body['store'] as String;
  }

  bool _authoredHere(Map<String, Object?> descriptor) =>
      descriptor['author'] == availability.owner.identity.deviceId &&
      descriptor['installation'] == _installation.identity!.id.value &&
      descriptor['origin'] == _installation.identity!.generation.value;

  Future<bool> _disabledDescriptor(Map<String, Object?> descriptor) async {
    if (descriptor['kind'] != null) {
      return _heldCreationJobs.contains(descriptor['job']);
    }
    final row = await _record(descriptor);
    final body = ((jsonDecode(row.operationBytes) as Map)['body']) as Map;
    final user = body['user'] as String;
    if (user == availability.owner.identity.userId) return false;
    final proof =
        (jsonDecode(row.operationBytes) as Map)['authorization'] as Map;
    final assertion = proof['body'] as Map;
    return availability.enrollment.isCompanyUserOperationHeld(
      user,
      assertion['credential'] as int,
    );
  }

  void _requireInventories() {
    if (_local?.complete != true || _remote?.complete != true) {
      throw const CompanyBootstrapRefusal(
        'Complete both holdings inventories first',
      );
    }
    final ours = _local!.byKey;
    for (final entry in _remote!.byKey.entries) {
      if (ours[entry.key] case final descriptor?) {
        if (_securityCanonical(descriptor) != _securityCanonical(entry.value)) {
          throw const CompanyBootstrapRefusal(
            'Job inventory identity collision',
          );
        }
      }
    }
  }

  Future<bool> _snapshotConfirmed() async {
    final run = _activeRun;
    if (run == null) {
      throw const CompanyBootstrapRefusal('Job sync run differs');
    }
    _requireRun(run);
    _requireInventories();
    final records = <Object>[
      ...await _commands.syncHoldings(ownerSession: availability.owner),
      ...await _commands.nameSyncHoldings(ownerSession: availability.owner),
      ...await _commands.detailsSyncHoldings(ownerSession: availability.owner),
      ...await _commands.lifecycleSyncHoldings(
        ownerSession: availability.owner,
      ),
    ];
    _requireRun(run);
    final actual = {
      for (final row in records)
        _descriptorKey(_jobDescriptor(row)): _jobDescriptor(row),
    };
    final expected = {..._local!.byKey, ..._remote!.byKey};
    if (actual.length != expected.length) return false;
    for (final entry in expected.entries) {
      if (_securityCanonical(actual[entry.key]) !=
          _securityCanonical(entry.value)) {
        return false;
      }
    }
    final verifiedAckStores = await _readAckCache(records);
    _requireRun(run);
    for (final descriptor in expected.values) {
      if (verifiedAckStores[_descriptorKey(descriptor)] != _remoteStore) {
        return false;
      }
    }
    await availability.requireCurrent();
    return true;
  }

  Future<Map<String, Object?>> receive(Map<String, Object?> wire) {
    if (_closed || _receivePending) {
      return Future.error(
        const CompanyBootstrapRefusal(
          'Job sync is closed or receiving a request',
        ),
      );
    }
    _receivePending = true;
    final result = _receiving.then((_) async {
      var stage = CreatedJobSyncStage.channelOpen;
      _CreatedJobRun? receivingRun;
      try {
        return await _receive(
          wire,
          (value) => stage = value,
          (run) => receivingRun = run,
        );
      } catch (error) {
        lastFailure = error;
        final ownCounts =
            receivingRun != null && identical(receivingRun, _activeRun);
        final sent = ownCounts ? _sentJobs : 0;
        final received = ownCounts ? _receivedJobs : 0;
        if (ownCounts) _retire(receivingRun!);
        if (ownCounts || (_activeRun == null && _retiredRuns.isEmpty)) {
          _terminal(
            CreatedJobSyncResult(
              sent,
              received,
              false,
              0,
              failure: CreatedJobSyncFailure.fromError(error, stage),
            ),
            receiving: true,
          );
        }
        rethrow;
      } finally {
        _receivePending = false;
      }
    });
    _receiving = result.then<void>(
      (_) {},
      onError: (Object _, StackTrace _) {},
    );
    return result;
  }

  Future<Map<String, Object?>> _receive(
    Map<String, Object?> wire,
    void Function(CreatedJobSyncStage) atStage,
    void Function(_CreatedJobRun) receiverInitialized,
  ) async {
    final body = await _open(wire);
    final action = body['action'];
    if (action == 'profile') {
      final data = _joinObject(body['data'], {'profile', 'capacity', 'users'});
      if (data['profile'] != _syncActorProfile ||
          data['capacity'] is! int ||
          data['capacity'] != kCompanyUserCapacity ||
          _activeRun != null) {
        throw const CompanyBootstrapRefusal(
          'Unsupported or busy Job user profile',
        );
      }
      final remoteUsers = _syncUserRoster(data['users']);
      final localUsers = await _localUserRoster();
      final users = {...remoteUsers, ...localUsers};
      if (users.length > kCompanyUserCapacity) {
        throw const CompanyBootstrapRefusal(
          'Company user roster exceeds capacity',
        );
      }
      _lifecycleUsers = users;
      _lifecycleRemoteUsers = remoteUsers;
      _lifecycleLocalUsers = localUsers.toSet();
      _lifecycleFinished.clear();
      _lifecycleProfileRun = body['run'] as String;
      _lifecycleReadyRun = users.isEmpty ? body['run'] as String : null;
      _lifecyclePolicyRun = null;
      _lifecycleTarget = null;
      _lifecycleMore = false;
      return _seal(wire['request'] as String, {
        'action': 'profile.reply',
        'run': body['run'],
        'data': {
          'profile': _syncActorProfile,
          'capacity': kCompanyUserCapacity,
          'users': localUsers,
        },
      });
    }
    if (action == 'policyOffer' ||
        action == 'policy' ||
        action == 'policyAck') {
      if (_lifecycleProfileRun != body['run'] || _activeRun != null) {
        throw const CompanyBootstrapRefusal(
          'Complete lifecycle capability negotiation first',
        );
      }
      final data = Map<String, Object?>.from(body['data'] as Map);
      await _requireUserRoster(_lifecycleLocalUsers);
      final peer = availability.peer;
      final enrollment = availability.enrollment;
      Map<String, Object?> result;
      if (action == 'policyOffer') {
        _joinObject(data, {'offer'});
        _lifecycleTarget = await enrollment.verifyUserLifecycleOffer(
          Map<String, Object?>.from(data['offer'] as Map),
          peer,
        );
        final userId = _lifecycleTarget!.userId;
        if (!_lifecycleUsers.contains(userId) ||
            _lifecycleFinished.contains(userId) ||
            (_lifecycleRemoteUsers.contains(userId) &&
                _lifecycleTarget!._checkpoint == null)) {
          throw const CompanyBootstrapRefusal(
            'Lifecycle user is outside the negotiated roster',
          );
        }
        _lifecyclePolicyRun = null;
        result = {
          'offer': await enrollment.createUserLifecycleOffer(
            peer,
            userId: userId,
          ),
        };
      } else {
        final target = _lifecycleTarget;
        if (target == null) {
          throw const CompanyBootstrapRefusal('Lifecycle target not verified');
        }
        if (action == 'policy') {
          _joinObject(data, {'policy'});
          final receipt = await enrollment.acceptUserDisablePolicy(
            data['policy'] == null
                ? null
                : Map<String, Object?>.from(data['policy'] as Map),
            peer,
            target,
          );
          final outgoingPolicy = await enrollment.prepareUserDisablePolicy(
            peer,
            target,
          );
          _lifecycleMore =
              _lifecycleMore ||
              (data['policy'] is Map &&
                  (data['policy'] as Map)['more'] == true) ||
              outgoingPolicy?['more'] == true;
          result = {'receipt': receipt, 'policy': outgoingPolicy};
          _lifecycleLocalUsers = await _policyUserRoster(
            _lifecycleLocalUsers,
            target.userId,
          );
          _lifecyclePolicyRun = body['run'] as String;
        } else {
          if (_lifecyclePolicyRun != body['run']) {
            throw const CompanyBootstrapRefusal(
              'Persist user policy before its acknowledgment',
            );
          }
          _joinObject(data, {'receipt'});
          await enrollment.acceptUserDisableReceipt(
            data['receipt'] == null
                ? null
                : Map<String, Object?>.from(data['receipt'] as Map),
            peer,
            userId: target.userId,
          );
          _lifecycleFinished.add(target.userId);
          await _requireUserRoster(_lifecycleLocalUsers);
          if (!_lifecycleMore &&
              _lifecycleFinished.containsAll(_lifecycleUsers)) {
            _lifecycleReadyRun = body['run'] as String;
          }
          result = {};
        }
      }
      await availability.requireCurrent();
      return _seal(wire['request'] as String, {
        'action': '$action.reply',
        'run': body['run'],
        'data': result,
      });
    }
    late _CreatedJobRun run;
    if (action == 'start') {
      await _requireUserRoster(_lifecycleLocalUsers);
      if (_lifecycleReadyRun != body['run']) {
        throw const CompanyBootstrapRefusal(
          'Persist compatible user lifecycle state before inventory',
        );
      }
      atStage(CreatedJobSyncStage.startRequest);
      if (_activeRun != null) {
        throw const CompanyBootstrapRefusal('A Job sync is already running');
      }
      _requireRunCapacity();
      final id = body['run'] as String;
      if (_retiredRuns.contains(id)) {
        throw const CompanyBootstrapRefusal('Job sync run differs');
      }
      run = _CreatedJobRun(id, _CreatedJobRunDirection.receiving);
      _activeRun = run;
      _sentJobs = 0;
      _receivedJobs = 0;
      _heldJobKeys.clear();
      _heldCreationJobs.clear();
      receiverInitialized(run);
      const CreatedJobSyncDiagnostic.started(receiverCallbackReached: true)
          .notify(onDiagnostic);
    } else {
      final active = _activeRun;
      if (active == null ||
          active.direction != _CreatedJobRunDirection.receiving ||
          body['run'] != active.id) {
        throw const CompanyBootstrapRefusal('Job sync run differs');
      }
      run = active;
      receiverInitialized(run);
      atStage(
        action == 'holdings' || action == 'page'
            ? CreatedJobSyncStage.holdings
            : action == 'finish'
            ? CreatedJobSyncStage.confirmation
            : CreatedJobSyncStage.transfer,
      );
    }
    _requireRun(run);
    final data = Map<String, Object?>.from(body['data'] as Map);
    Map<String, Object?> result;
    if (action == 'start') {
      atStage(CreatedJobSyncStage.localInventory);
      await _freeze(run);
      _requireRun(run);
      _readSummary(data);
      _served.clear();
      _confirmed.clear();
      result = _summary();
      _status('Exchanging Job holdings with the verified peer.');
    } else {
      if (action == 'holdings') {
        atStage(CreatedJobSyncStage.holdings);
        _remote!.acceptPage(data);
        result = {};
      } else if (action == 'page') {
        atStage(CreatedJobSyncStage.holdings);
        _joinObject(data, {'ordinal'});
        final ordinal = data['ordinal'];
        if (ordinal is! int) {
          throw const CompanyBootstrapRefusal('Invalid page ordinal');
        }
        result = _holdingsPage(ordinal);
      } else {
        atStage(
          action == 'finish'
              ? CreatedJobSyncStage.confirmation
              : CreatedJobSyncStage.transfer,
        );
        _requireInventories();
        _dependencyOrder();
        result = await _transfer(action, data, run);
        _requireRun(run);
      }
    }
    atStage(CreatedJobSyncStage.replySeal);
    _requireRun(run);
    final reply = await _seal(wire['request'] as String, {
      'action': '$action.reply',
      'run': run.id,
      'data': result,
    });
    _requireRun(run);
    if (action == 'finish') {
      final sent = _sentJobs;
      final received = _receivedJobs;
      _retire(run);
      final complete = data['complete'] as bool;
      final unsupported = data['unsupported'] as int;
      _terminal(
        CreatedJobSyncResult(
          sent,
          received,
          complete,
          unsupported,
          held: _heldJobs,
          failure: complete
              ? null
              : CreatedJobSyncFailure(
                  CreatedJobSyncStage.confirmation,
                  unsupported > 0
                      ? CreatedJobSyncReason.unsupportedAuthor
                      : CreatedJobSyncReason.unconfirmedSnapshot,
                ),
        ),
        receiving: true,
      );
    }
    return reply;
  }

  Future<IncomingCreateJobOutcome> _apply(
    Map<String, Object?> descriptor,
    Uint8List bytes, {
    required OwnerSession ownerSession,
    required CompanyJobSyncAvailability availability,
  }) async {
    final body = (jsonDecode(utf8.decode(bytes)) as Map)['body'] as Map;
    final family = _jobFamily(descriptor['kind']);
    final name =
        descriptor['kind'] == 'job.name.set@1' ||
        descriptor['kind'] == 'job.name.set@2';
    final details =
        descriptor['kind'] == 'job.details.patch@1' ||
        descriptor['kind'] == 'job.details.patch@2';
    final expected = {
      if (name) ..._nameDescriptorFields(body),
      if (descriptor['kind'] == 'job.lifecycle.set@1')
        ..._lifecycleDescriptorFields(body),
      if (details) ..._detailsDescriptorFields(bytes),
      'origin': body['generation'],
      'request': body['request'],
      'job': body['job'],
      'author': body['device'],
      'installation': body['installation'],
      'operation': _syncDigest(body),
      'command': body['command'],
      'digest': _syncBytesDigest(bytes),
      'length': bytes.length,
    };
    if (body['contract'] != family.contract ||
        _securityCanonical(expected) != _securityCanonical(descriptor)) {
      throw const CompanyBootstrapRefusal(
        'Job payload differs from frozen descriptor',
      );
    }
    if (descriptor['kind'] == null) {
      return _commands.applyIncomingCreateOutcome(
        bytes,
        ownerSession: ownerSession,
        availability: availability,
      );
    }
    return AppliedIncomingCreateJob(await switch (descriptor['kind']) {
      'job.name.set@1' || 'job.name.set@2' => _commands.applyIncomingName(
        bytes,
        ownerSession: ownerSession,
        availability: availability,
      ),
      'job.details.patch@1' ||
      'job.details.patch@2' => _commands.applyIncomingDetails(
        bytes,
        ownerSession: ownerSession,
        availability: availability,
      ),
      'job.lifecycle.set@1' => _commands.applyIncomingLifecycle(
        bytes,
        ownerSession: ownerSession,
        availability: availability,
      ),
      _ => throw const CompanyBootstrapRefusal(
        'Unsupported Job operation family',
      ),
    });
  }

  List<Map<String, Object?>> _dependencyOrder() {
    final all = {..._local!.byKey, ..._remote!.byKey};
    final byOperation = {
      for (final d in all.values) _descriptorOperationTag(d): d,
    };
    if (byOperation.length != all.length) {
      throw const CompanyBootstrapRefusal('Duplicate Job operation');
    }
    final visited = <String>{}, visiting = <String>{}, blocked = <String>{};
    final result = <Map<String, Object?>>[];
    bool visit(Map<String, Object?> d) {
      final id = _descriptorOperationTag(d);
      if (visited.contains(id)) return true;
      if (blocked.contains(id)) return false;
      if (!visiting.add(id)) {
        throw const CompanyBootstrapRefusal('Cyclic Job history');
      }
      var eligible = true;
      if (d['kind'] != null) {
        final creation = all.values
            .where(
              (c) =>
                  c['kind'] == null &&
                  c['digest'] == d['creation'] &&
                  c['job'] == d['job'],
            )
            .firstOrNull;
        if (creation == null || !visit(creation)) eligible = false;
        for (final parent in _descriptorParents(d)) {
          final p = byOperation[parent];
          if (p == null ||
              p['creation'] != d['creation'] ||
              p['job'] != d['job'] ||
              !visit(p)) {
            eligible = false;
          }
        }
      }
      visiting.remove(id);
      if (!eligible) {
        blocked.add(id);
        return false;
      }
      visited.add(id);
      result.add(d);
      return true;
    }

    final sorted = all.values.toList()
      ..sort((a, b) => _descriptorKey(a).compareTo(_descriptorKey(b)));
    for (final d in sorted) {
      visit(d);
    }
    return result;
  }

  Set<String> _eligibleTransfers(
    List<Map<String, Object?>> ordered,
    CreatedJobHoldingsInventory sender,
    CreatedJobHoldingsInventory receiver,
    bool Function(Map<String, Object?>) authoredBySender,
  ) {
    final available = receiver.byKey.keys.toSet();
    final operationKeys = {
      for (final d in ordered) _descriptorOperationTag(d): _descriptorKey(d),
    };
    final creationKeys = {
      for (final d in ordered)
        if (d['kind'] == null) d['digest']: _descriptorKey(d),
    };
    final eligible = <String>{};
    for (final d in ordered) {
      final key = _descriptorKey(d);
      if (!sender.byKey.containsKey(key) ||
          available.contains(key) ||
          !authoredBySender(d)) {
        continue;
      }
      if (d['kind'] != null &&
          (!available.contains(creationKeys[d['creation']]) ||
              !_descriptorParents(
                d,
              ).every((parent) => available.contains(operationKeys[parent])))) {
        continue;
      }
      available.add(key);
      eligible.add(key);
    }
    return eligible;
  }

  Future<Map<String, Object?>> _transfer(
    Object? action,
    Map<String, Object?> data,
    _CreatedJobRun run,
  ) async {
    _requireRun(run);
    if (action == 'finish') {
      _joinObject(data, {'complete', 'unsupported'});
      if (data['complete'] is! bool ||
          data['unsupported'] is! int ||
          (data['unsupported'] as int) < 0 ||
          (data['unsupported'] as int) > 1024) {
        throw const CompanyBootstrapRefusal('Invalid completion');
      }
      final confirmed = await _snapshotConfirmed();
      _requireRun(run);
      if (data['complete'] == true &&
          (!confirmed || data['unsupported'] != 0)) {
        throw const CompanyBootstrapRefusal(
          'Peer claimed an unconfirmed Job snapshot',
        );
      }
      return {};
    }
    final descriptor = _parseDescriptor(data['descriptor']);
    final key = _descriptorKey(descriptor);
    if (action == 'admission') {
      _joinObject(data, {'descriptor'});
      if (!_authoredHere(descriptor) || !_local!.byKey.containsKey(key)) {
        throw const CompanyBootstrapRefusal(
          'Admission check is outside local holdings',
        );
      }
      final held = await _disabledDescriptor(descriptor);
      if (held) _markHeld(descriptor);
      return {'held': held};
    }
    if (action == 'put') {
      _joinObject(data, {'descriptor', 'offset', 'bytes'});
      final remote = _remote!.byKey[key];
      final member = availability.peer._held.peer._membership;
      if (_securityCanonical(remote) != _securityCanonical(descriptor) ||
          descriptor['author'] != member.device['id'] ||
          descriptor['installation'] != member.device['installation'] ||
          descriptor['origin'] != member.device['generation']) {
        throw const CompanyBootstrapRefusal(
          'Job payload author is not sending peer',
        );
      }
      if (_incomingDescriptor == null) {
        if (data['offset'] != 0) {
          throw const CompanyBootstrapRefusal('Job chunk gap');
        }
        _incomingDescriptor = descriptor;
        _incoming = CreatedJobTransferBuffer(
          length: descriptor['length'] as int,
          digest: descriptor['digest'] as String,
        );
      }
      if (_securityCanonical(_incomingDescriptor) !=
              _securityCanonical(descriptor) ||
          data['offset'] != _incoming!.receivedBytes) {
        throw const CompanyBootstrapRefusal(
          'Job chunk overlap or identity changed',
        );
      }
      _incoming!.append(data['offset'], data['bytes']);
      if (_incoming!.complete) {
        final applied = await _apply(
          descriptor,
          _incoming!.bytes,
          ownerSession: availability.owner,
          availability: availability,
        );
        _requireRun(run);
        _incoming = null;
        _incomingDescriptor = null;
        if (applied is HeldIncomingCreateJob) {
          _markHeld(descriptor);
          return {'held': true};
        }
        final ack = await _ack(descriptor);
        _requireRun(run);
        _receivedJobs++;
        return {'ack': ack};
      }
      return {};
    }
    if (_securityCanonical(_local!.byKey[key] ?? _remote!.byKey[key]) !=
        _securityCanonical(descriptor)) {
      throw const CompanyBootstrapRefusal('Job is outside frozen holdings');
    }
    if (action == 'get') {
      _joinObject(data, {'descriptor', 'offset', 'limit'});
      if (!_authoredHere(descriptor)) {
        throw const CompanyBootstrapRefusal('Job relay is not supported');
      }
      final row = await _record(descriptor);
      _requireRun(run);
      _served.add(key);
      final bytes = utf8.encode(row.operationBytes);
      final offset = data['offset'];
      final limit = data['limit'];
      if (offset is! int ||
          offset < 0 ||
          offset >= bytes.length ||
          limit is! int ||
          limit < 1 ||
          limit > kCreatedJobSyncChunkBytes) {
        throw const CompanyBootstrapRefusal('Invalid Job chunk range');
      }
      final end = offset + limit > bytes.length ? bytes.length : offset + limit;
      return {
        'offset': offset,
        'bytes': base64Encode(bytes.sublist(offset, end)),
      };
    }
    if (action == 'ackBoth') {
      _joinObject(data, {'descriptor', 'ack'});
      await _saveAck(descriptor, data['ack']);
      _requireRun(run);
      if (_served.contains(key) && _confirmed.add(key)) _sentJobs++;
      final ack = await _ack(descriptor);
      _requireRun(run);
      return {'ack': ack};
    }
    throw const CompanyBootstrapRefusal('Unsupported Job sync action');
  }

  Future<CreatedJobSyncResult> syncNow() {
    if (_closed || isRunning) {
      throw const CompanyBootstrapRefusal('A Job sync is already running');
    }
    _requireRunCapacity();
    final run = _CreatedJobRun(
      const Uuid().v4(),
      _CreatedJobRunDirection.initiating,
    );
    _activeRun = run;
    return _initiating = _syncNow(run);
  }

  Future<CreatedJobSyncResult> _syncNow(_CreatedJobRun run) async {
    _sentJobs = 0;
    _receivedJobs = 0;
    _heldJobKeys.clear();
    _heldCreationJobs.clear();
    var unsupported = 0;
    var complete = false;
    var stage = CreatedJobSyncStage.preflight;
    CreatedJobSyncFailure? failure;
    const CreatedJobSyncDiagnostic.started().notify(onDiagnostic);
    try {
      lastFailure = null;
      _status('Checking Job sync permissions.');
      await availability.requireCurrent();
      stage = CreatedJobSyncStage.channelOpen;
      await _getChannel();
      stage = CreatedJobSyncStage.startRequest;
      final enrollment = availability.enrollment;
      final peer = availability.peer;
      var localUsers = (await _localUserRoster()).toSet();
      final profile = _joinObject(
        await _rpc('profile', {
          'profile': _syncActorProfile,
          'capacity': kCompanyUserCapacity,
          'users': localUsers.toList()..sort(),
        }),
        {'profile', 'capacity', 'users'},
      );
      if (profile['profile'] != _syncActorProfile ||
          profile['capacity'] is! int ||
          profile['capacity'] != kCompanyUserCapacity) {
        throw const CompanyBootstrapRefusal(
          'Peer does not support the company user collection. Jobs remain pending.',
        );
      }
      final remoteUsers = _syncUserRoster(profile['users']);
      final users = {...localUsers, ...remoteUsers}.toList()..sort();
      if (users.length > kCompanyUserCapacity) {
        throw const CompanyBootstrapRefusal(
          'Company user roster exceeds capacity',
        );
      }
      for (final userId in users) {
        await _requireUserRoster(localUsers);
        final offered = _joinObject(
          await _rpc('policyOffer', {
            'offer': await enrollment.createUserLifecycleOffer(
              peer,
              userId: userId,
            ),
          }),
          {'offer'},
        );
        final target = await enrollment.verifyUserLifecycleOffer(
          Map<String, Object?>.from(offered['offer'] as Map),
          peer,
        );
        if (target.userId != userId ||
            (remoteUsers.contains(userId) && target._checkpoint == null)) {
          throw const CompanyBootstrapRefusal(
            'Lifecycle reply targets another user',
          );
        }
        final outgoingPolicy = await enrollment.prepareUserDisablePolicy(
          peer,
          target,
        );
        final policy = _joinObject(
          await _rpc('policy', {'policy': outgoingPolicy}),
          {'policy', 'receipt'},
        );
        await enrollment.acceptUserDisableReceipt(
          policy['receipt'] == null
              ? null
              : Map<String, Object?>.from(policy['receipt'] as Map),
          peer,
          userId: userId,
        );
        final receipt = await enrollment.acceptUserDisablePolicy(
          policy['policy'] == null
              ? null
              : Map<String, Object?>.from(policy['policy'] as Map),
          peer,
          target,
        );
        localUsers = await _policyUserRoster(localUsers, userId);
        await _rpc('policyAck', {'receipt': receipt});
        if (outgoingPolicy?['more'] == true ||
            (policy['policy'] is Map &&
                (policy['policy'] as Map)['more'] == true)) {
          throw const CompanyBootstrapRefusal(
            'More public user history pending. Pair again and retry Sync Now.',
          );
        }
      }
      await _requireUserRoster(localUsers);
      stage = CreatedJobSyncStage.localInventory;
      await _freeze(run);
      _requireRun(run);
      _status('Comparing verified Job holdings.');
      stage = CreatedJobSyncStage.startRequest;
      _readSummary(await _rpc('start', _summary()));
      stage = CreatedJobSyncStage.holdings;
      for (var i = 0; i < _local!.pages; i++) {
        await _rpc('holdings', _holdingsPage(i));
      }
      for (var i = 0; i < _remote!.pages; i++) {
        _remote!.acceptPage(await _rpc('page', {'ordinal': i}));
      }
      _requireInventories();
      final ordered = _dependencyOrder();
      final ours = ordered
          .where((d) => _local!.byKey.containsKey(_descriptorKey(d)))
          .toList();
      final theirs = ordered
          .where((d) => _remote!.byKey.containsKey(_descriptorKey(d)))
          .toList();
      final ourKeys = _local!.byKey;
      final theirKeys = _remote!.byKey;
      final outgoing = _eligibleTransfers(
        ordered,
        _local!,
        _remote!,
        _authoredHere,
      );
      final member = availability.peer._held.peer._membership;
      final incoming = _eligibleTransfers(
        ordered,
        _remote!,
        _local!,
        (d) =>
            d['author'] == member.device['id'] &&
            d['installation'] == member.device['installation'] &&
            d['origin'] == member.device['generation'],
      );
      stage = CreatedJobSyncStage.transfer;
      for (
        var i = 0;
        i < (ours.length > theirs.length ? ours.length : theirs.length);
        i++
      ) {
        if (i < ours.length) {
          final d = ours[i];
          if (theirKeys.containsKey(_descriptorKey(d))) {
            final confirmed =
                _cachedAckStores[_descriptorKey(d)] == _remoteStore &&
                _remote!.peerAckStore(_descriptorKey(d)) ==
                    _installation.receivingStoreGeneration!.value;
            if (!confirmed) {
              if (!_canExchange(2)) {
                throw const CompanyBootstrapRefusal('More Jobs pending');
              }
              final reply = await _rpc('ackBoth', {
                'descriptor': d,
                'ack': await _ack(d),
              });
              await _saveAck(d, reply['ack']);
            }
          } else if (outgoing.contains(_descriptorKey(d))) {
            if (await _disabledDescriptor(d)) {
              unsupported++;
              _markHeld(d);
            } else {
              _status('Sending a Job change to the retained peer.');
              final row = await _record(d);
              final bytes = utf8.encode(row.operationBytes);
              if (!_canExchange(
                (bytes.length + chunkBytes - 1) ~/ chunkBytes + 2,
              )) {
                throw const CompanyBootstrapRefusal('More Jobs pending');
              }
              for (
                var offset = 0;
                offset < bytes.length;
                offset += chunkBytes
              ) {
                final end = offset + chunkBytes > bytes.length
                    ? bytes.length
                    : offset + chunkBytes;
                final reply = await _rpc('put', {
                  'descriptor': d,
                  'offset': offset,
                  'bytes': base64Encode(bytes.sublist(offset, end)),
                });
                if (end == bytes.length) {
                  if (reply['held'] == true && reply.length == 1) {
                    unsupported++;
                    _markHeld(d);
                    break;
                  }
                  await _saveAck(d, reply['ack']);
                  final confirmed = await _rpc('ackBoth', {
                    'descriptor': d,
                    'ack': await _ack(d),
                  });
                  await _saveAck(d, confirmed['ack']);
                  _sentJobs++;
                } else if (reply.isNotEmpty) {
                  throw const CompanyBootstrapRefusal('Premature Job ACK');
                }
              }
            }
          } else {
            unsupported++;
          }
        }
        if (i < theirs.length) {
          final d = theirs[i];
          if (ourKeys.containsKey(_descriptorKey(d))) continue;
          if (!incoming.contains(_descriptorKey(d))) {
            unsupported++;
            continue;
          }
          final admission = _joinObject(
            await _rpc('admission', {'descriptor': d}),
            {'held'},
          );
          if (admission['held'] is! bool) {
            throw const CompanyBootstrapRefusal('Invalid admission status');
          }
          if (admission['held'] == true) {
            unsupported++;
            _markHeld(d);
            continue;
          }
          if (!_canExchange(
            ((d['length'] as int) + chunkBytes - 1) ~/ chunkBytes + 2,
          )) {
            throw const CompanyBootstrapRefusal('More Jobs pending');
          }
          final buffer = CreatedJobTransferBuffer(
            length: d['length'] as int,
            digest: d['digest'] as String,
          );
          _status('Receiving a Job change from the retained peer.');
          while (!buffer.complete) {
            final reply = await _rpc('get', {
              'descriptor': d,
              'offset': buffer.receivedBytes,
              'limit': chunkBytes,
            });
            _joinObject(reply, {'offset', 'bytes'});
            buffer.append(reply['offset'], reply['bytes']);
          }
          final applied = await _apply(
            d,
            buffer.bytes,
            ownerSession: availability.owner,
            availability: availability,
          );
          if (applied is HeldIncomingCreateJob) {
            unsupported++;
            _markHeld(d);
            continue;
          }
          final confirmed = await _rpc('ackBoth', {
            'descriptor': d,
            'ack': await _ack(d),
          });
          await _saveAck(d, confirmed['ack']);
          _receivedJobs++;
        }
      }
      stage = CreatedJobSyncStage.confirmation;
      complete = unsupported == 0 && await _snapshotConfirmed();
      if (!complete) {
        failure = CreatedJobSyncFailure(
          stage,
          unsupported > 0
              ? CreatedJobSyncReason.unsupportedAuthor
              : CreatedJobSyncReason.unconfirmedSnapshot,
        );
      }
      _status('Confirming the Job snapshot exchange.');
      await _rpc('finish', {'complete': complete, 'unsupported': unsupported});
    } catch (error) {
      lastFailure = error;
      failure = CreatedJobSyncFailure.fromError(error, stage);
      complete = false;
    } finally {
      _retire(run);
    }
    final result = CreatedJobSyncResult(
      _sentJobs,
      _receivedJobs,
      complete,
      unsupported,
      failure: failure,
      held: _heldJobs,
    );
    _terminal(result);
    return result;
  }
}

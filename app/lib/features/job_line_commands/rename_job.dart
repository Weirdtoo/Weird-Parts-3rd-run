part of 'job_line_commands.dart';

final class RenameJob {
  RenameJob({
    required this.companyId,
    required this.shopId,
    required this.jobId,
    required this.requestId,
    required this.creationDigest,
    required List<String> observedHeads,
    required String name,
    List<String>? observedLifecycleHeads,
  }) : observedLifecycleHeads = observedLifecycleHeads == null
           ? null
           : List.unmodifiable([...observedLifecycleHeads]..sort()),
       observedHeads = List.unmodifiable([...observedHeads]..sort()),
       name = name.trim() {
    CreateJob(
      companyId: companyId,
      shopId: shopId,
      jobId: jobId,
      requestId: requestId,
      name: this.name,
    );
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(creationDigest) ||
        observedHeads.length > 32 ||
        observedHeads.toSet().length != observedHeads.length ||
        observedHeads.any((v) => !RegExp(r'^[a-f0-9]{64}$').hasMatch(v))) {
      throw const JobLineRefusal('Invalid name history or parent capacity');
    }
    if (observedLifecycleHeads != null) {
      final refs = [
        ...observedHeads.map(
          (id) => JobOperationRef(JobOperationFamily.name, id),
        ),
        ...observedLifecycleHeads.map(
          (id) => JobOperationRef(JobOperationFamily.lifecycle, id),
        ),
      ];
      JobCausalContext(refs);
    }
  }
  final String companyId, shopId, jobId, requestId, creationDigest, name;
  final List<String>? observedLifecycleHeads;
  final List<String> observedHeads;
  Map<String, Object?> _json() => {
    'v': observedLifecycleHeads == null ? 1 : 2,
    'contract': observedLifecycleHeads == null
        ? 'job.name.set@1'
        : 'job.name.set@2',
    if (observedLifecycleHeads != null) 'lifecycle': observedLifecycleHeads,
    'company': companyId,
    'shop': shopId,
    'job': jobId,
    'request': requestId,
    'creation': creationDigest,
    'parents': observedHeads,
    'name': name,
  };
  String get commitment => _digest(_json());
}

const kCompanyJobNameHistoryLimit = 128;
const kCompanyJobNameHistoryCompanyLimit = 512;
const _nameReceiptDomain = 'wiredpart.job.name.receipt@1:';
const _incomingNameReceiptDomain = 'wiredpart.job.name.incoming.receipt@1:';

final class CompanyJobNameContextRefusal extends JobLineRefusal {
  const CompanyJobNameContextRefusal._(super.reason);
}

final class CompanyJobNameCapacityRefusal extends JobLineRefusal {
  const CompanyJobNameCapacityRefusal.history()
    : super('Name history capacity reached. No edit was saved.');
  const CompanyJobNameCapacityRefusal.conflict()
    : super(
        'Name conflict capacity reached. Resolve existing names first. No edit was saved.',
      );
}

final class JobNameDependencyRefusal extends JobLineRefusal {
  const JobNameDependencyRefusal()
    : super('Name history dependency is missing');
}

final class _NameOperation {
  _NameOperation(this.body, this.authorization, this.signature);
  final Map<String, Object?> body, authorization;
  final String signature;
  String get commitment => _digest(body);
  String get bytes => _canonical({
    'body': body,
    'authorization': authorization,
    'signature': signature,
  });
  RenameJob get command => RenameJob(
    companyId: _string(body, 'company'),
    shopId: _string(body, 'shop'),
    jobId: _string(body, 'job'),
    requestId: _string(body, 'request'),
    creationDigest: _string(body, 'creation'),
    observedHeads: (body['parents'] as List).cast<String>(),
    name: _string(body, 'name'),
    observedLifecycleHeads: (body['lifecycle'] as List?)?.cast<String>(),
  );
  static _NameOperation parse(Uint8List bytes) {
    if (bytes.length > _maximumBytes) {
      throw const JobLineRefusal('name operation byte limit');
    }
    final text = utf8.decode(bytes);
    final value = _object(jsonDecode(text));
    _keys(value, {'body', 'authorization', 'signature'});
    final body = _object(value['body']);
    _keys(body, {
      'v',
      'contract',
      'company',
      'shop',
      'job',
      'request',
      'creation',
      'parents',
      'name',
      if (body['v'] == 2) 'lifecycle',
      'generation',
      'installation',
      'device',
      'user',
      'command',
      'facts',
    });
    if (_canonical(value) != text ||
        !((body['v'] == 1 && body['contract'] == 'job.name.set@1') ||
            (body['v'] == 2 &&
                body['contract'] == 'job.name.set@2' &&
                body['lifecycle'] is List)) ||
        body['parents'] is! List ||
        (body['parents'] as List).any((p) => p is! String)) {
      throw const JobLineRefusal('unsupported or noncanonical name operation');
    }
    for (final field in ['generation', 'installation', 'device', 'user']) {
      _id(_string(body, field));
    }
    final op = _NameOperation(
      body,
      _object(value['authorization']),
      _string(value, 'signature'),
    );
    if (op.command.commitment != body['command'] ||
        op.command.name != body['name'] ||
        _canonical(op.command.observedHeads) != _canonical(body['parents'])) {
      throw const JobLineRefusal('name command commitment differs');
    }
    return op;
  }
}

final class CompanyJobNameCandidate {
  CompanyJobNameCandidate._(_NameOperation op)
    : name = op.command.name,
      operationId = op.commitment,
      originalUserId = _string(op.body, 'user'),
      originalDeviceId = _string(op.body, 'device');
  final String name, operationId, originalUserId, originalDeviceId;
}

final class CompanyJobView {
  CompanyJobView._(
    this.baseJob,
    this.creationDigest,
    List<_NameOperation> operations,
    this.details,
    this.lifecycle,
  ) {
    final referenced = operations
        .expand((op) => op.command.observedHeads)
        .toSet();
    final heads =
        operations.where((op) => !referenced.contains(op.commitment)).toList()
          ..sort((a, b) => a.commitment.compareTo(b.commitment));
    nameHeads = List.unmodifiable(heads.map((op) => op.commitment));
    candidates = List.unmodifiable(heads.map(CompanyJobNameCandidate._));
    final values = candidates.map((c) => c.name).toSet();
    resolvedName = values.isEmpty
        ? baseJob.name
        : values.length == 1
        ? values.single
        : null;
    final byId = {for (final op in operations) op.commitment: op};
    final ancestry = <String, Set<String>>{};
    Set<String> ancestors(String id) => ancestry.putIfAbsent(
      id,
      () => {id, ...byId[id]!.command.observedHeads.expand(ancestors)},
    );
    var common = heads.isEmpty
        ? <String>{}
        : {...ancestors(heads.first.commitment)};
    for (final head in heads.skip(1)) {
      common.retainAll(ancestors(head.commitment));
    }
    var agreed = baseJob.name;
    while (common.isNotEmpty) {
      final frontier = common
          .where(
            (id) => !common.any(
              (other) => other != id && ancestors(other).contains(id),
            ),
          )
          .toList();
      final agreedValues = frontier.map((id) => byId[id]!.command.name).toSet();
      if (agreedValues.length == 1) {
        agreed = agreedValues.single;
        break;
      }
      final preceding = {...ancestors(frontier.first)};
      for (final id in frontier.skip(1)) {
        preceding.retainAll(ancestors(id));
      }
      common = preceding;
    }
    lastAgreedName = resolvedName ?? agreed;
  }
  final CompanyJobLifecycleView lifecycle;
  final Job baseJob;
  final CompanyJobDetailsView details;
  final String creationDigest;
  late final List<String> nameHeads;
  late final List<CompanyJobNameCandidate> candidates;
  late final String? resolvedName;
  late final String lastAgreedName;
  bool get hasConflict => resolvedName == null;
  String get displayName => resolvedName ?? lastAgreedName;
}

final class JobNameCommandReceipt {
  JobNameCommandReceipt._(this.bytes);
  final String bytes;
  String get operationId => _string(_object(jsonDecode(bytes)), 'operation');
}

Map<String, Object?> _nameReceipt(
  CompanyJobName row,
  InstallationIdentity identity,
  String store,
) => {
  'v': 1,
  'kind': row.outgoing ? 'job.name.receipt@1' : 'job.name.incoming.receipt@1',
  'key': row.receiptKey,
  'company': row.companyId,
  'shop': row.shopId,
  'job': row.jobId,
  'origin': row.originGeneration,
  'request': row.requestId,
  'operation': row.operationCommitment,
  'command': row.commandCommitment,
  'digest': _operationDigest(row.operationBytes),
  'receiver': identity.id.value,
  'generation': identity.generation.value,
  'store': store,
};

Future<void> verifyJobNameReceipt(
  String bytes,
  InstallationIdentity identity,
  String store,
  CompanyCommandFamily family,
) async {
  if (utf8.encode(bytes).length > 4096) {
    throw const JobLineRefusal('name receipt byte limit');
  }
  final receipt = _object(jsonDecode(bytes));
  _keys(receipt, {
    'v',
    'kind',
    'key',
    'company',
    'shop',
    'job',
    'origin',
    'request',
    'operation',
    'command',
    'digest',
    'receiver',
    'generation',
    'store',
    'seal',
  });
  final incoming = family == CompanyCommandFamily.jobNameIncoming;
  if ((!incoming && family != CompanyCommandFamily.jobName) ||
      receipt['v'] != 1 ||
      receipt['kind'] !=
          (incoming ? 'job.name.incoming.receipt@1' : 'job.name.receipt@1') ||
      receipt['receiver'] != identity.id.value ||
      receipt['generation'] != identity.generation.value ||
      receipt['store'] != store ||
      _canonical(receipt) != bytes) {
    throw const JobLineRefusal('name receipt binding differs');
  }
  final body = {...receipt}..remove('seal');
  await _verifySignature(
    body,
    _string(receipt, 'seal'),
    SimplePublicKey(identity.publicKey, type: KeyPairType.ed25519),
    domain: incoming ? _incomingNameReceiptDomain : _nameReceiptDomain,
  );
}

Future<void> _validateNameDependencies(
  AppDatabase db,
  RenameJob command,
) async {
  final base = await (db.select(
    db.companyJobs,
  )..where((t) => t.jobId.equals(command.jobId))).getSingleOrNull();
  if (base == null) throw const JobNameDependencyRefusal();
  if (base.companyId != command.companyId ||
      base.shopId != command.shopId ||
      _operationDigest(base.operationBytes) != command.creationDigest) {
    throw const JobLineRefusal('name creation binding differs');
  }
  final job = await (db.select(
    db.jobs,
  )..where((t) => t.id.equals(command.jobId))).getSingle();
  final create = _CreateOperation.parse(
    Uint8List.fromList(utf8.encode(base.operationBytes)),
  );
  if (base.projectionBytes != _canonical(job.toJson()) ||
      base.projectionBytes != _canonical(create.projection.toJson()) ||
      create.commitment != base.operationCommitment) {
    throw const JobLineRefusal('name creation baseline changed');
  }
  await _validateMetadataLifecycle(
    db,
    command.companyId,
    command.shopId,
    command.jobId,
    command.creationDigest,
    command.observedLifecycleHeads,
  );
  for (final parent in command.observedHeads) {
    final row = await (db.select(
      db.companyJobNames,
    )..where((t) => t.operationCommitment.equals(parent))).getSingleOrNull();
    if (row == null) throw const JobNameDependencyRefusal();
    final op = _NameOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    if (row.companyId != command.companyId ||
        row.shopId != command.shopId ||
        row.jobId != command.jobId ||
        op.command.creationDigest != command.creationDigest ||
        op.commitment != parent) {
      throw const JobLineRefusal('name parent scope differs');
    }
  }
}

CompanyCommandIntent _nameIntent(CompanyJobName row, String store) =>
    CompanyCommandIntent(
      family: row.outgoing
          ? CompanyCommandFamily.jobName
          : CompanyCommandFamily.jobNameIncoming,
      receiptKey: row.receiptKey,
      operationCommitment: row.operationCommitment,
      commandCommitment: row.commandCommitment,
      storeGeneration: store,
      companyId: row.companyId,
      lineId: row.jobId,
      originGeneration: row.originGeneration,
      requestId: row.requestId,
    );

Future<void> validateJobNameCommit(
  AppDatabase db,
  CompanyCommandIntent intent,
) async {
  final row = await (db.select(
    db.companyJobNames,
  )..where((t) => t.receiptKey.equals(intent.receiptKey))).getSingle();
  final op = _NameOperation.parse(
    Uint8List.fromList(utf8.encode(row.operationBytes)),
  );
  final receipt = _object(jsonDecode(row.receiptBytes));
  final unsigned = {...receipt}..remove('seal');
  final key = _digest({
    'family': 'job.name.set@1',
    'company': row.companyId,
    'origin': row.originGeneration,
    'request': row.requestId,
    'receiver': receipt['receiver'],
    'store': intent.storeGeneration,
  });
  final expected = {
    'v': 1,
    'kind': row.outgoing ? 'job.name.receipt@1' : 'job.name.incoming.receipt@1',
    'key': key,
    'company': row.companyId,
    'shop': row.shopId,
    'job': row.jobId,
    'origin': row.originGeneration,
    'request': row.requestId,
    'operation': op.commitment,
    'command': op.command.commitment,
    'digest': _operationDigest(row.operationBytes),
    'receiver': receipt['receiver'],
    'generation': receipt['generation'],
    'store': intent.storeGeneration,
  };
  if (_canonical(_nameIntent(row, intent.storeGeneration).encode()) !=
          _canonical(
            CompanyCommandIntent(
              family: intent.family,
              receiptKey: intent.receiptKey,
              operationCommitment: intent.operationCommitment,
              commandCommitment: intent.commandCommitment,
              storeGeneration: intent.storeGeneration,
              companyId: intent.companyId,
              lineId: intent.lineId,
              originGeneration: intent.originGeneration,
              requestId: intent.requestId,
            ).encode(),
          ) ||
      row.receiptKey != key ||
      _canonical(unsigned) != _canonical(expected) ||
      op.commitment != row.operationCommitment ||
      op.command.commitment != row.commandCommitment ||
      op.command.companyId != row.companyId ||
      op.command.shopId != row.shopId ||
      op.command.jobId != row.jobId ||
      op.command.requestId != row.requestId ||
      op.body['generation'] != row.originGeneration ||
      row.auditBytes !=
          _canonical({
            'operation': op.commitment,
            'originalUser': op.body['user'],
            'originalDevice': op.body['device'],
            'receipt': row.receiptKey,
            'outgoing': row.outgoing,
            'status': 'applied',
          })) {
    throw const JobLineRefusal('name commit evidence differs');
  }
  final proof = _object(op.authorization['body']);
  for (final field in [
    'company',
    'shop',
    'job',
    'request',
    'generation',
    'installation',
    'device',
    'user',
    'command',
    'facts',
  ]) {
    if (op.body[field] != proof[field]) {
      throw const JobLineRefusal('name attribution differs');
    }
  }
  await _validateNameDependencies(db, op.command);
}

final class _NameReceiptAdmission extends VerifiedCompanyReceiptAdmission {
  _NameReceiptAdmission(
    this.commands,
    this.bytes,
    this.session,
    this.intent, {
    this.context,
    this.availability,
  });
  final CompanyJobCommands commands;
  final String bytes;
  final VerifiedRenameJobSession session;
  final CompanyCommandIntent intent;
  final HeldPeerCreateContext? context;
  final CompanyJobSyncAvailability? availability;
  @override
  CompanyCommandFamily get family => intent.family;
  @override
  String get receiptDomain => family == CompanyCommandFamily.jobName
      ? _nameReceiptDomain
      : _incomingNameReceiptDomain;
  @override
  Future<Uint8List> validateSigningContent(
    AppDatabase db,
    InstallationIdentity identity,
    CompanyCommandIntent pending,
    CompanyTrustAnchor trust,
    Map<String, int> floors,
  ) async {
    if (!identical(db, commands._db) ||
        !db.hasCallerTransaction ||
        pending.beforeWitness == null ||
        pending.afterWitness != null ||
        _canonical(pending.encode()) != _canonical(intent.encode()) ||
        _canonical(trust.encode()) != _canonical(session._trust.encode()) ||
        _canonical(floors) != _canonical(session._floors)) {
      throw const JobLineRefusal('name receipt context changed');
    }
    final row = await (db.select(
      db.companyJobNames,
    )..where((t) => t.receiptKey.equals(pending.receiptKey))).getSingle();
    if (row.receiptBytes != bytes) {
      throw const JobLineRefusal('name receipt candidate changed');
    }
    final op = _NameOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    if (_canonical(op.authorization) != _canonical(session._proof)) {
      throw const JobLineRefusal('name receipt proof changed');
    }
    await _verifySignature(
      op.body,
      op.signature,
      session._publicKey,
      domain: session.operationDomain,
    );
    if (row.outgoing) {
      session.validateOperationSigningContent(
        Uint8List.fromList(utf8.encode(_canonical(op.body))),
        identity,
      );
    }
    await validateJobNameCommit(db, pending);
    await context?.requireHeld(pending);
    availability?.requireLive();
    return Uint8List.fromList(utf8.encode(bytes));
  }
}

extension CompanyJobNameCommands on CompanyJobCommands {
  Future<JobNameCommandReceipt> renameJob(
    RenameJob command, {
    required OwnerSession ownerSession,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal('name command owns top-level transaction');
    }
    return ownerSession.runLocalCommand(() async {
      var session = await enrollment.issueRenameJobAssertion(command);
      session.validateLiveOwner(ownerSession);
      CompanyCommandIntent? intent;
      late String result;
      try {
        result = await _db.transaction(() async {
          await _db.customStatement(
            'UPDATE app_settings SET value = value WHERE key = ?',
            [kInstallationBindingKey],
          );
          session = await enrollment.issueRenameJobAssertion(command);
          session.validateLiveOwner(ownerSession);
          final identity = _installation.identity!;
          final existing =
              await (_db.select(_db.companyJobNames)..where(
                    (t) =>
                        t.companyId.equals(command.companyId) &
                        t.originGeneration.equals(identity.generation.value) &
                        t.requestId.equals(command.requestId),
                  ))
                  .getSingleOrNull();
          if (existing != null) {
            final op = _NameOperation.parse(
              Uint8List.fromList(utf8.encode(existing.operationBytes)),
            );
            session.validateOperationSigningContent(
              Uint8List.fromList(utf8.encode(_canonical(op.body))),
              identity,
            );
            await _verifyNameRecord(existing);
            await beforeCommit?.call();
            (await enrollment.issueRenameJobAssertion(command))
                .validateLiveOwner(ownerSession);
            await _verifyNameRecord(existing);
            return existing.receiptBytes;
          }
          try {
            await _validateMetadataLifecycle(
              _db,
              command.companyId,
              command.shopId,
              command.jobId,
              command.creationDigest,
              command.observedLifecycleHeads,
              local: true,
            );
          } on _JobMetadataLifecycleRefusal catch (error) {
            throw CompanyJobNameContextRefusal._(error.reason);
          }
          await _verifyNameDependencies(command);
          await _nameCapacity(command);
          final body = <String, Object?>{
            ...command._json(),
            'generation': identity.generation.value,
            'installation': identity.id.value,
            'device': session._assertion['device'],
            'user': session._assertion['user'],
            'command': command.commitment,
            'facts': session._trust.factsCommitment,
          };
          final signature = await _installation.signCompanyOperation(
            _db,
            session,
            Uint8List.fromList(utf8.encode(_canonical(body))),
            ownerSession: ownerSession,
          );
          final op = _NameOperation(
            body,
            session._proof,
            base64Encode(signature.bytes),
          );
          final row = _nameRow(op, outgoing: true);
          intent = await _installation.beginCompanyCommand(
            _db,
            _nameIntent(row, _installation.receivingStoreGeneration!.value),
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          final bytes = await _saveName(row, session, intent!);
          intent = await _installation.sealCompanyCommand(_db, intent!);
          await beforeCommit?.call();
          await _validateMetadataLifecycle(
            _db,
            command.companyId,
            command.shopId,
            command.jobId,
            command.creationDigest,
            command.observedLifecycleHeads,
            local: true,
          );
          await _installation.validateHeldCompanyCommand(
            _db,
            intent!,
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          session.validateLiveOwner(ownerSession);
          return bytes;
        });
      } catch (_) {
        if (intent != null) await _installation.reconcile(_db);
        rethrow;
      }
      if (intent != null) {
        await afterCommit?.call();
        await _installation.completeCompanyCommand(_db, intent!);
      }
      return JobNameCommandReceipt._(result);
    });
  }

  CompanyJobName _nameRow(_NameOperation op, {required bool outgoing}) {
    final command = op.command;
    final key = _digest({
      'family': 'job.name.set@1',
      'company': command.companyId,
      'origin': op.body['generation'],
      'request': command.requestId,
      'receiver': _installation.identity!.id.value,
      'store': _installation.receivingStoreGeneration!.value,
    });
    return CompanyJobName(
      companyId: command.companyId,
      shopId: command.shopId,
      jobId: command.jobId,
      originGeneration: _string(op.body, 'generation'),
      requestId: command.requestId,
      operationCommitment: op.commitment,
      commandCommitment: command.commitment,
      operationBytes: op.bytes,
      receiptKey: key,
      receiptBytes: '',
      outgoing: outgoing,
      auditBytes: _canonical({
        'operation': op.commitment,
        'originalUser': op.body['user'],
        'originalDevice': op.body['device'],
        'receipt': key,
        'outgoing': outgoing,
        'status': 'applied',
      }),
    );
  }

  Future<void> _nameCapacity(RenameJob command) async {
    try {
      await _mutableJobCapacity(command.companyId, command.jobId);
    } on CompanyJobDetailsCapacityRefusal {
      throw const CompanyJobNameCapacityRefusal.history();
    }
    final rows =
        await (_db.select(_db.companyJobNames)
              ..where((t) => t.companyId.equals(command.companyId))
              ..limit(kCompanyJobNameHistoryCompanyLimit + 1))
            .get();
    final own = rows.where((r) => r.jobId == command.jobId).toList();
    if (rows.length >= kCompanyJobNameHistoryCompanyLimit ||
        own.length >= kCompanyJobNameHistoryLimit) {
      throw const CompanyJobNameCapacityRefusal.history();
    }
    final referenced = own
        .expand(
          (r) => _NameOperation.parse(
            Uint8List.fromList(utf8.encode(r.operationBytes)),
          ).command.observedHeads,
        )
        .toSet();
    final surviving = own
        .where(
          (r) =>
              !referenced.contains(r.operationCommitment) &&
              !command.observedHeads.contains(r.operationCommitment),
        )
        .length;
    if (surviving >= 32) {
      throw const CompanyJobNameCapacityRefusal.conflict();
    }
  }

  Future<String> _saveName(
    CompanyJobName row,
    VerifiedRenameJobSession session,
    CompanyCommandIntent intent, {
    HeldPeerCreateContext? context,
    CompanyJobSyncAvailability? availability,
  }) async {
    var bytes = _canonical(
      _nameReceipt(row, _installation.identity!, intent.storeGeneration),
    );
    await _db
        .into(_db.companyJobNames)
        .insert(row.copyWith(receiptBytes: bytes).toCompanion(false));
    final signature = await _installation.signCompanyReceipt(
      _db,
      _NameReceiptAdmission(
        this,
        bytes,
        session,
        intent,
        context: context,
        availability: availability,
      ),
    );
    bytes = _canonical({
      ..._object(jsonDecode(bytes)),
      'seal': base64Encode(signature.bytes),
    });
    await (_db.update(_db.companyJobNames)
          ..where((t) => t.receiptKey.equals(row.receiptKey)))
        .write(CompanyJobNamesCompanion(receiptBytes: Value(bytes)));
    return bytes;
  }

  Future<void> _verifyNameRecord(
    CompanyJobName row, {
    Set<String>? verified,
  }) async {
    verified ??= <String>{};
    if (verified.contains(row.operationCommitment)) return;
    final current =
        await (_db.select(_db.companyJobNames)..where(
              (t) => t.operationCommitment.equals(row.operationCommitment),
            ))
            .getSingle();
    if (current != row) {
      throw const JobLineRefusal('Saved name history changed');
    }
    final intent = _nameIntent(
      row,
      _installation.receivingStoreGeneration!.value,
    );
    await validateJobNameCommit(_db, intent);
    await verifyJobNameReceipt(
      row.receiptBytes,
      _installation.identity!,
      intent.storeGeneration,
      intent.family,
    );
    final operation = _NameOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    verified.add(row.operationCommitment);
    await _verifyNameDependencies(operation.command, verified: verified);
  }

  Future<void> _verifyNameDependencies(
    RenameJob command, {
    Set<String>? verified,
  }) async {
    verified ??= <String>{};
    await _validateNameDependencies(_db, command);
    await _verifyGraphReferences(
      JobCausalContext(
        (command.observedLifecycleHeads ?? []).map(
          (id) => JobOperationRef(JobOperationFamily.lifecycle, id),
        ),
      ),
      verified: verified,
    );
    final baseline = await (_db.select(
      _db.companyJobs,
    )..where((t) => t.jobId.equals(command.jobId))).getSingle();
    if (baseline.outgoing) {
      await _verifyRecord(baseline);
    } else {
      await verifyIncomingRecord(baseline);
    }
    for (final parent in command.observedHeads) {
      final row = await (_db.select(
        _db.companyJobNames,
      )..where((t) => t.operationCommitment.equals(parent))).getSingle();
      await _verifyNameRecord(row, verified: verified);
    }
  }

  Future<List<CompanyJobName>> nameSyncHoldings({
    required CompanySession ownerSession,
    CompanyJobSyncAvailability? availability,
  }) async {
    await requireSyncPermission(ownerSession, availability: availability);
    final scope = ownerSession.identity;
    final rows =
        await (_db.select(_db.companyJobNames)
              ..where(
                (t) =>
                    t.companyId.equals(scope.companyId) &
                    t.shopId.equals(scope.shopId),
              )
              ..limit(kCompanyJobNameHistoryCompanyLimit + 1))
            .get();
    if (rows.length > kCompanyJobNameHistoryCompanyLimit) {
      throw const JobLineRefusal('Name history capacity exceeded');
    }
    final verified = <String>{};
    for (final row in rows) {
      await _verifyNameRecord(row, verified: verified);
    }
    await requireSyncPermission(ownerSession, availability: availability);
    return rows;
  }

  Future<CompanyJobName> verifyNameSyncRecord(
    String operationId,
    CompanySession owner, {
    CompanyJobSyncAvailability? availability,
  }) async {
    final rows = await nameSyncHoldings(
      ownerSession: owner,
      availability: availability,
    );
    final matches = rows.where((r) => r.operationCommitment == operationId);
    if (matches.length != 1) {
      throw const JobLineRefusal('Name sync record outside current scope');
    }
    return matches.single;
  }

  Future<List<CompanyJobView>> listJobViews({
    required CompanySession ownerSession,
  }) async {
    final jobs = await listJobs(ownerSession: ownerSession);
    final names = await nameSyncHoldings(ownerSession: ownerSession);
    final details = await detailsSyncHoldings(ownerSession: ownerSession);
    await lifecycleSyncHoldings(ownerSession: ownerSession);
    final result = <CompanyJobView>[];
    for (final job in jobs) {
      final base = await (_db.select(
        _db.companyJobs,
      )..where((t) => t.jobId.equals(job.id))).getSingle();
      result.add(
        CompanyJobView._(
          job,
          _operationDigest(base.operationBytes),
          names
              .where((r) => r.jobId == job.id)
              .map(
                (r) => _NameOperation.parse(
                  Uint8List.fromList(utf8.encode(r.operationBytes)),
                ),
              )
              .toList(),
          CompanyJobDetailsView._(
            job,
            details
                .where((r) => r.jobId == job.id)
                .map(
                  (r) => _DetailsOperation.parse(
                    Uint8List.fromList(utf8.encode(r.operationBytes)),
                  ),
                )
                .toList(),
          ),
          await _loadJobGraph(
            _db,
            base.companyId,
            base.shopId,
            job.id,
            _operationDigest(base.operationBytes),
          ),
        ),
      );
    }
    return result;
  }

  Future<bool> canRenameJobs(CompanySession owner) async {
    if (owner is! OwnerSession) return false;
    final scope = owner.identity;
    try {
      final session = await enrollment.issueRenameJobAssertion(
        RenameJob(
          companyId: scope.companyId,
          shopId: scope.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          creationDigest: '0' * 64,
          observedHeads: [],
          name: 'Permission check',
        ),
      );
      session.validateLiveOwner(owner);
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<String> applyIncomingName(
    Uint8List bytes, {
    required CompanySession ownerSession,
    required CompanyJobSyncAvailability availability,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal('incoming name owns top-level transaction');
    }
    final op = _NameOperation.parse(Uint8List.fromList(bytes));
    return availability.run(() async {
      if (!identical(availability.enrollment, enrollment) ||
          !identical(availability.owner, ownerSession)) {
        throw const JobLineRefusal(
          'name sync availability belongs to another owner',
        );
      }
      await availability.requireCurrent();
      await requireSyncPermission(ownerSession, availability: availability);
      final context = await availability.peer.prepareCreateCommand(
        ownerSession,
      );
      context.validateAuthor(op.body);
      CompanyCommandIntent? intent;
      late String result;
      try {
        result = await _db.transaction(() async {
          await _db.customStatement(
            'UPDATE app_settings SET value = value WHERE key = ?',
            [kInstallationBindingKey],
          );
          await availability.requireCurrent();
          final session =
              await RenameJobAuthorization(
                db: _db,
                installation: _installation,
              ).verify(
                op.command,
                Uint8List.fromList(utf8.encode(_canonical(op.authorization))),
              );
          await _verifySignature(
            op.body,
            op.signature,
            session._publicKey,
            domain: session.operationDomain,
          );
          context.validateAuthor(op.body, session._publicKey.bytes);
          context.validateAuthorization(session._assertion);
          for (final field in [
            'company',
            'shop',
            'job',
            'request',
            'generation',
            'installation',
            'device',
            'user',
            'command',
            'facts',
          ]) {
            if (op.body[field] != session._assertion[field]) {
              throw const JobLineRefusal('incoming name author differs');
            }
          }
          final existing =
              await (_db.select(_db.companyJobNames)..where(
                    (t) =>
                        t.companyId.equals(op.command.companyId) &
                        t.originGeneration.equals(
                          _string(op.body, 'generation'),
                        ) &
                        t.requestId.equals(op.command.requestId),
                  ))
                  .getSingleOrNull();
          if (existing != null) {
            if (existing.operationBytes != op.bytes || existing.outgoing) {
              throw const JobLineRefusal('incoming name identity collision');
            }
            await _verifyNameRecord(existing);
            await beforeCommit?.call();
            await _verifyNameRecord(existing);
            await availability.requireCurrent();
            return existing.receiptBytes;
          }
          await _verifyNameDependencies(op.command);
          await _nameCapacity(op.command);
          final row = _nameRow(op, outgoing: false);
          intent = await _installation.beginCompanyCommand(
            _db,
            _nameIntent(row, _installation.receivingStoreGeneration!.value),
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          final receipt = await _saveName(
            row,
            session,
            intent!,
            context: context,
            availability: availability,
          );
          intent = await _installation.sealCompanyCommand(_db, intent!);
          await beforeCommit?.call();
          await _installation.validateHeldCompanyCommand(
            _db,
            intent!,
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          await context.requireHeld(intent!);
          availability.requireLive();
          return receipt;
        });
      } catch (_) {
        if (intent != null) await _installation.reconcile(_db);
        rethrow;
      }
      if (intent != null) {
        await afterCommit?.call();
        await _installation.completeCompanyCommand(_db, intent!);
      }
      await availability.requireCurrent();
      return result;
    });
  }
}

final class VerifiedRenameJobSession extends VerifiedCompanyOperation {
  VerifiedRenameJobSession._(
    this.command,
    this._proofBytes,
    this._trust,
    this._floors,
    this._publicKey,
  );
  final RenameJob command;
  final String _proofBytes;
  final CompanyTrustAnchor _trust;
  final Map<String, int> _floors;
  final SimplePublicKey _publicKey;
  Map<String, Object?> get _proof => _object(jsonDecode(_proofBytes));
  Map<String, Object?> get _assertion => _object(_proof['body']);
  @override
  String get operationDomain => 'wiredpart.job.name.operation@1:';

  @override
  void validateLiveOwner(CompanySession? owner) {
    if (owner is! OwnerSession) {
      throw const JobLineRefusal('Live administrator session required');
    }
    final a = _assertion;
    owner.validateCommand(
      company: command.companyId,
      shop: command.shopId,
      user: _string(a, 'user'),
      device: _string(a, 'device'),
      installation: _string(a, 'installation'),
      generation: _string(a, 'generation'),
      session: _string(a, 'session'),
    );
    owner.validateAuthority(_trust, _floors);
  }

  @override
  void validateOperationSigningContent(
    Uint8List bytes,
    InstallationIdentity identity,
  ) {
    final body = _object(jsonDecode(utf8.decode(bytes)));
    final parsed = _NameOperation.parse(
      Uint8List.fromList(
        utf8.encode(
          _canonical({
            'body': body,
            'authorization': _proof,
            'signature': 'candidate',
          }),
        ),
      ),
    );
    if (_canonical(body) != utf8.decode(bytes) ||
        parsed.command.commitment != command.commitment ||
        body['installation'] != identity.id.value ||
        body['generation'] != identity.generation.value ||
        base64Encode(_publicKey.bytes) != base64Encode(identity.publicKey)) {
      throw const JobLineRefusal('signer requires exact Rename Job command');
    }
    for (final field in [
      'company',
      'shop',
      'job',
      'request',
      'user',
      'device',
      'installation',
      'generation',
      'command',
      'facts',
    ]) {
      if (body[field] != _assertion[field]) {
        throw const JobLineRefusal('signer cannot substitute name author');
      }
    }
  }
}

class RenameJobAuthorization {
  RenameJobAuthorization({required this.db, required this.installation});
  final AppDatabase db;
  final InstallationSecurity installation;

  Future<VerifiedRenameJobSession> verify(
    RenameJob command,
    Uint8List signedAssertion,
  ) async {
    if (signedAssertion.length > _maximumBytes) {
      throw const JobLineRefusal('authorization byte limit');
    }
    final proof = _object(jsonDecode(utf8.decode(signedAssertion)));
    final a = _object(proof['body']);
    final memberProof = a['v'] == 3;
    _keys(proof, {'body', 'signature', if (memberProof) 'membership'});
    _keys(a, {
      'v',
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
      if (memberProof) 'membership',
    });
    final receiver =
        await JobLineAuthorization(
          db: db,
          installation: installation,
        )._verifyCurrentReceiver(
          null,
          companyId: command.companyId,
          shopId: command.shopId,
        );
    final trust = receiver.trust;
    final facts = receiver.facts;
    if ((!memberProof && a['v'] != 2) ||
        facts.body['v'] != 2 ||
        a['company'] != command.companyId ||
        a['shop'] != command.shopId ||
        a['job'] != command.jobId ||
        a['request'] != command.requestId ||
        a['command'] != command.commitment ||
        a['authority'] != trust.authorityVersion ||
        a['facts'] != trust.factsCommitment) {
      throw const JobLineRefusal(
        'name authorization scope or commitment differs',
      );
    }
    for (final field in [
      'user',
      'device',
      'installation',
      'generation',
      'grant',
      'session',
    ]) {
      _id(_string(a, field));
    }
    final membership = memberProof
        ? await resolveCompanyMembership(
            db: db,
            installation: installation,
            certificateBytes: _string(proof, 'membership'),
          )
        : null;
    final device =
        membership?.device ?? facts._entry('devices', _string(a, 'device'));
    final user = membership?.user ?? facts._entry('users', _string(a, 'user'));
    if (memberProof &&
        (a['membership'] != membership!.proofCommitment ||
            a['device'] != device['id'] ||
            a['user'] != user['id'])) {
      throw const JobLineRefusal('member authorization proof differs');
    }
    bool allows(Map<String, Object?> entry, String key, String value) =>
        entry[key] is List && (entry[key] as List).contains(value);
    if (device['revoked'] != false ||
        user['revoked'] != false ||
        device['installation'] != a['installation'] ||
        device['generation'] != a['generation'] ||
        device['grant'] != a['grant'] ||
        user['credential'] != a['credential'] ||
        user['permission'] != a['permission'] ||
        !allows(device, 'shops', command.shopId) ||
        !allows(user, 'shops', command.shopId) ||
        !allows(device, 'capabilities', 'renameJob') ||
        !allows(user, 'capabilities', 'renameJob')) {
      throw const JobLineRefusal(
        'Rename Job unavailable. Existing company authority needs an explicit capability upgrade.',
      );
    }
    final floors = receiver.floors;
    final versions = {
      'authority.${command.companyId}': facts.body['authority'],
      'grant.${device['grant']}': device['version'],
      'credential.${user['id']}': user['credential'],
      'permission.${user['id']}': user['permission'],
    };
    for (final entry in versions.entries) {
      if (entry.value is! int ||
          (entry.value as int) < 1 ||
          (entry.value as int) < (floors[entry.key] ?? 0)) {
        throw const JobLineRefusal('name authorization below protected floor');
      }
    }
    for (final key in [
      'revocation.device.${device['id']}',
      'revocation.grant.${device['grant']}',
      'revocation.user.${user['id']}',
    ]) {
      if ((floors[key] ?? 0) > 0) {
        throw const JobLineRefusal('name actor is revoked');
      }
    }
    final publicBytes = base64Decode(_string(device, 'key'));
    if (publicBytes.length != 32) {
      throw const JobLineRefusal('invalid device key');
    }
    final publicKey = SimplePublicKey(publicBytes, type: KeyPairType.ed25519);
    await _verifySignature(
      a,
      _string(proof, 'signature'),
      publicKey,
      domain: memberProof
          ? 'wiredpart.job.name.authorization@2:'
          : 'wiredpart.job.name.authorization@1:',
    );
    return VerifiedRenameJobSession._(
      command,
      _canonical(proof),
      trust,
      floors,
      publicKey,
    );
  }
}

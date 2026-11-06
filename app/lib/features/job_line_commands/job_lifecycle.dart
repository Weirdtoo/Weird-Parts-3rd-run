part of 'job_line_commands.dart';

enum JobOperationFamily { name, details, lifecycle }

enum JobLifecycleChoice { deleted, kept }

enum CompanyJobLifecycleState { live, deleted, deleteConflict }

final class JobOperationRef {
  JobOperationRef(this.family, this.digest) {
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(digest)) {
      throw const JobLineRefusal('Invalid Job operation digest');
    }
  }
  factory JobOperationRef.parse(String tagged) {
    final parts = tagged.split('/');
    if (parts.length != 2) {
      throw const JobLineRefusal('Unsupported Job reference');
    }
    final family = switch (parts.first) {
      'n' => JobOperationFamily.name,
      'd' => JobOperationFamily.details,
      'l' => JobOperationFamily.lifecycle,
      _ => throw const JobLineRefusal('Unsupported Job reference family'),
    };
    return JobOperationRef(family, parts.last);
  }
  final JobOperationFamily family;
  final String digest;
  String get tagged =>
      '${switch (family) {
        JobOperationFamily.name => 'n',
        JobOperationFamily.details => 'd',
        JobOperationFamily.lifecycle => 'l',
      }}/$digest';
  @override
  bool operator ==(Object other) =>
      other is JobOperationRef && other.tagged == tagged;
  @override
  int get hashCode => tagged.hashCode;
}

final class JobCausalContext {
  JobCausalContext(Iterable<JobOperationRef> refs)
    : references = List.unmodifiable(
        refs.toList()..sort((a, b) => a.tagged.compareTo(b.tagged)),
      ) {
    if (references.length > 32 ||
        references.toSet().length != references.length) {
      throw const JobLineRefusal(
        'Job dependency/frontier capacity or duplicate reference',
      );
    }
  }
  factory JobCausalContext.fromTagged(List<String> refs) =>
      JobCausalContext(refs.map(JobOperationRef.parse));
  final List<JobOperationRef> references;
  List<String> get tagged => references.map((r) => r.tagged).toList();
}

final class SetJobLifecycle {
  SetJobLifecycle({
    required this.companyId,
    required this.shopId,
    required this.jobId,
    required this.requestId,
    required this.creationDigest,
    required this.observed,
    required this.choice,
    this.resolvingConflict = false,
  }) {
    for (final id in [companyId, shopId, jobId, requestId]) {
      _id(id);
    }
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(creationDigest) ||
        (choice == JobLifecycleChoice.kept && !resolvingConflict)) {
      throw const JobLineRefusal(
        'Invalid lifecycle command or ordinary undelete',
      );
    }
  }
  final String companyId, shopId, jobId, requestId, creationDigest;
  final JobCausalContext observed;
  final JobLifecycleChoice choice;
  final bool resolvingConflict;
  Map<String, Object?> _json() => {
    'v': 1,
    'contract': 'job.lifecycle.set@1',
    'company': companyId,
    'shop': shopId,
    'job': jobId,
    'request': requestId,
    'creation': creationDigest,
    'parents': observed.tagged,
    'choice': choice.name,
    'resolve': resolvingConflict,
  };
  String get commitment => _digest(_json());
  static SetJobLifecycle fromOperationBytes(Uint8List bytes) =>
      _LifecycleOperation.parse(bytes).command;
}

final class _LifecycleOperation {
  _LifecycleOperation(this.body, this.authorization, this.signature);
  final Map<String, Object?> body, authorization;
  final String signature;
  String get commitment => _digest(body);
  String get bytes => _canonical({
    'body': body,
    'authorization': authorization,
    'signature': signature,
  });
  SetJobLifecycle get command => SetJobLifecycle(
    companyId: _string(body, 'company'),
    shopId: _string(body, 'shop'),
    jobId: _string(body, 'job'),
    requestId: _string(body, 'request'),
    creationDigest: _string(body, 'creation'),
    observed: JobCausalContext.fromTagged(
      (body['parents'] as List).cast<String>(),
    ),
    choice: JobLifecycleChoice.values.byName(_string(body, 'choice')),
    resolvingConflict: body['resolve'] as bool,
  );
  static _LifecycleOperation parse(Uint8List bytes) {
    if (bytes.length > _maximumBytes) {
      throw const JobLineRefusal('Lifecycle operation byte limit');
    }
    final text = utf8.decode(bytes),
        value = _object(jsonDecode(utf8.decode(bytes)));
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
      'choice',
      'resolve',
      'generation',
      'installation',
      'device',
      'user',
      'command',
      'facts',
    });
    if (_canonical(value) != text ||
        body['v'] != 1 ||
        body['contract'] != 'job.lifecycle.set@1' ||
        body['parents'] is! List ||
        (body['parents'] as List).any((r) => r is! String) ||
        !['deleted', 'kept'].contains(body['choice']) ||
        body['resolve'] is! bool) {
      throw const JobLineRefusal(
        'Unsupported or noncanonical lifecycle operation',
      );
    }
    for (final field in ['generation', 'installation', 'device', 'user']) {
      _id(_string(body, field));
    }
    final op = _LifecycleOperation(
      body,
      _object(value['authorization']),
      _string(value, 'signature'),
    );
    if (op.command.commitment != body['command'] ||
        _canonical(op.command.observed.tagged) != _canonical(body['parents'])) {
      throw const JobLineRefusal('Lifecycle command commitment differs');
    }
    return op;
  }
}

final class CompanyJobLifecycleCandidate {
  CompanyJobLifecycleCandidate._(
    this.reference,
    this.parents,
    this.originalUserId,
    this.originalDeviceId,
    this.value,
    this.choice,
  );
  final JobOperationRef reference;
  final List<JobOperationRef> parents;
  final String originalUserId, originalDeviceId;
  final Object? value;
  final JobLifecycleChoice? choice;
  String get operationId => reference.digest;
}

final class CompanyJobLifecycleView {
  CompanyJobLifecycleView._(this._nodes) {
    final referenced = _nodes.values.expand((n) => n.parents).toSet();
    heads = _nodes.keys.where((r) => !referenced.contains(r)).toList()
      ..sort((a, b) => a.tagged.compareTo(b.tagged));
    final maximal = heads.map((r) => _nodes[r]!).toList();
    final deleted = maximal.any((n) => n.choice == JobLifecycleChoice.deleted);
    final live = maximal.any((n) => n.choice != JobLifecycleChoice.deleted);
    state = deleted
        ? (live
              ? CompanyJobLifecycleState.deleteConflict
              : CompanyJobLifecycleState.deleted)
        : CompanyJobLifecycleState.live;
    alternatives = List.unmodifiable(maximal);
  }
  final Map<JobOperationRef, CompanyJobLifecycleCandidate> _nodes;
  late final List<JobOperationRef> heads;
  late final CompanyJobLifecycleState state;
  late final List<CompanyJobLifecycleCandidate> alternatives;
  JobCausalContext get context => JobCausalContext(heads);
  List<String> get lifecycleHeads {
    final covered = <JobOperationRef>{};
    void visit(JobOperationRef r) {
      if (!covered.add(r)) return;
      for (final p in _nodes[r]!.parents) {
        visit(p);
      }
    }

    final lifecycle = _nodes.values
        .where((n) => n.reference.family == JobOperationFamily.lifecycle)
        .toList();
    for (final n in lifecycle) {
      for (final p in n.parents) {
        visit(p);
      }
    }
    return lifecycle
        .where((n) => !covered.contains(n.reference))
        .map((n) => n.reference.digest)
        .toList()
      ..sort();
  }

  CompanyJobLifecycleView select(JobCausalContext context) {
    final selected = <JobOperationRef, CompanyJobLifecycleCandidate>{};
    final visiting = <JobOperationRef>{};
    void visit(JobOperationRef ref) {
      if (visiting.contains(ref)) {
        throw const JobLineRefusal('Cyclic Job history');
      }
      if (selected.containsKey(ref)) return;
      final n = _nodes[ref];
      if (n == null) throw const JobLifecycleDependencyRefusal();
      visiting.add(ref);
      for (final p in n.parents) {
        visit(p);
      }
      visiting.remove(ref);
      selected[ref] = n;
    }

    for (final ref in context.references) {
      visit(ref);
    }
    final result = CompanyJobLifecycleView._(selected);
    if (_canonical(result.context.tagged) != _canonical(context.tagged)) {
      throw const JobLineRefusal('Job context is not a frontier');
    }
    return result;
  }
}

Future<void> _requireLifecycleProfile(
  AppDatabase db,
  CompanyTrustAnchor trust,
  SetJobLifecycle command,
) async {
  final row =
      await (db.select(db.companyAuthorityFacts)..where(
            (t) =>
                t.companyId.equals(command.companyId) &
                t.commitment.equals(trust.factsCommitment),
          ))
          .getSingle();
  final signed = _object(jsonDecode(row.signedBytes));
  _keys(signed, {'body', 'signature'});
  final facts = _object(signed['body']);
  if (trust.authorityVersion != 1 ||
      facts['v'] != 2 ||
      facts['authority'] != 1 ||
      facts['company'] != command.companyId ||
      facts['shop'] != command.shopId ||
      facts['entities'] is! List ||
      (facts['entities'] as List).isNotEmpty ||
      _digest(facts) != trust.factsCommitment) {
    throw const JobLineRefusal(
      'Job deletion unavailable. Only fresh genesis authority with empty signed entities is supported.',
    );
  }
  await _verifySignature(
    facts,
    _string(signed, 'signature'),
    SimplePublicKey(trust.rootKey, type: KeyPairType.ed25519),
    domain: 'wiredpart.company.facts@2:',
  );
  final base = await (db.select(
    db.companyJobs,
  )..where((t) => t.jobId.equals(command.jobId))).getSingleOrNull();
  if (base == null ||
      base.companyId != command.companyId ||
      base.shopId != command.shopId ||
      _operationDigest(base.operationBytes) != command.creationDigest ||
      _CreateOperation.parse(
            Uint8List.fromList(utf8.encode(base.operationBytes)),
          ).body['facts'] !=
          trust.factsCommitment) {
    throw const JobLineRefusal(
      'Job deletion unavailable. Immutable creation must bind current genesis facts.',
    );
  }
  await _requireChildFree(db);
}

Future<void> _requireChildFree(AppDatabase db) async {
  for (final table in [
    'job_lines',
    'order_splits',
    'job_line_baselines',
    'job_line_operations',
    'job_line_receipts',
    'job_line_audits',
    'job_line_outgoing',
    'job_line_conflicts',
  ]) {
    if ((await db.customSelect('SELECT 1 FROM $table LIMIT 1').get())
        .isNotEmpty) {
      throw const JobLineRefusal(
        'Job deletion unavailable. Child rows or child history require a future lifecycle profile.',
      );
    }
  }
}

Future<CompanyJobLifecycleView> _loadJobGraph(
  AppDatabase db,
  String company,
  String shop,
  String job,
  String creation,
) async {
  final nodes = <JobOperationRef, CompanyJobLifecycleCandidate>{};
  void add(
    Map<String, Object?> body,
    String digest,
    JobOperationFamily family,
    List<JobOperationRef> parents,
    Object? value,
    JobLifecycleChoice? choice,
  ) {
    if (body['company'] != company ||
        body['shop'] != shop ||
        body['job'] != job ||
        body['creation'] != creation) {
      throw const JobLineRefusal(
        'Job graph scope or immutable creation differs',
      );
    }
    final ref = JobOperationRef(family, digest);
    if (parents.length > 32 ||
        parents.toSet().length != parents.length ||
        parents.contains(ref)) {
      throw const JobLineRefusal('Invalid Job graph dependencies');
    }
    nodes[ref] = CompanyJobLifecycleCandidate._(
      ref,
      parents,
      _string(body, 'user'),
      _string(body, 'device'),
      value,
      choice,
    );
  }

  for (final r in await (db.select(
    db.companyJobNames,
  )..where((t) => t.jobId.equals(job))).get()) {
    final op = _NameOperation.parse(
      Uint8List.fromList(utf8.encode(r.operationBytes)),
    );
    add(
      op.body,
      op.commitment,
      JobOperationFamily.name,
      [
        ...op.command.observedHeads.map(
          (id) => JobOperationRef(JobOperationFamily.name, id),
        ),
        ...?op.command.observedLifecycleHeads?.map(
          (id) => JobOperationRef(JobOperationFamily.lifecycle, id),
        ),
      ],
      op.command.name,
      null,
    );
  }
  for (final r in await (db.select(
    db.companyJobDetails,
  )..where((t) => t.jobId.equals(job))).get()) {
    final op = _DetailsOperation.parse(
      Uint8List.fromList(utf8.encode(r.operationBytes)),
    );
    add(
      op.body,
      op.commitment,
      JobOperationFamily.details,
      [
        ...op.command.parentUnion.map(
          (id) => JobOperationRef(JobOperationFamily.details, id),
        ),
        ...?op.command.observedLifecycleHeads?.map(
          (id) => JobOperationRef(JobOperationFamily.lifecycle, id),
        ),
      ],
      op.command.patch._values().map((k, v) => MapEntry(k.name, v)),
      null,
    );
  }
  for (final r in await (db.select(
    db.companyJobLifecycles,
  )..where((t) => t.jobId.equals(job))).get()) {
    final op = _LifecycleOperation.parse(
      Uint8List.fromList(utf8.encode(r.operationBytes)),
    );
    add(
      op.body,
      op.commitment,
      JobOperationFamily.lifecycle,
      op.command.observed.references,
      op.command.choice.name,
      op.command.choice,
    );
  }
  if (nodes.length > 128) {
    throw const JobLineRefusal('Job mutable history capacity exceeded');
  }
  final result = CompanyJobLifecycleView._(nodes);
  // Selection validates closure and cycles before the graph is consumed.
  for (final head in result.heads) {
    result.select(JobCausalContext([head]));
  }
  return result;
}

Future<void> _validateMetadataLifecycle(
  AppDatabase db,
  String company,
  String shop,
  String job,
  String creation,
  List<String>? heads, {
  bool local = false,
}) async {
  final graph = await _loadJobGraph(db, company, shop, job, creation);
  if (local &&
      (heads == null
          ? graph._nodes.keys.any(
              (r) => r.family == JobOperationFamily.lifecycle,
            )
          : _canonical(heads) != _canonical(graph.lifecycleHeads))) {
    throw const _JobMetadataLifecycleRefusal(
      'Job lifecycle changed. Review the current Job before editing.',
    );
  }
  if (heads == null) return;
  final context = JobCausalContext(
    heads.map((id) => JobOperationRef(JobOperationFamily.lifecycle, id)),
  );
  // Lifecycle-only references may contain transitive ancestry; their maximal closure is checked below.
  final observed = graph.select(context);
  if (observed.state != CompanyJobLifecycleState.live) {
    throw const _JobMetadataLifecycleRefusal(
      'Deleted or deletion-conflicted Job cannot be edited',
    );
  }
}

final class _JobMetadataLifecycleRefusal extends JobLineRefusal {
  const _JobMetadataLifecycleRefusal(super.reason);
}

const kCompanyJobLifecycleHistoryLimit = 128;
const kCompanyJobLifecycleHistoryCompanyLimit = 512;
const _lifecycleReceiptDomain = 'wiredpart.job.lifecycle.receipt@1:';
const _incomingLifecycleReceiptDomain =
    'wiredpart.job.lifecycle.incoming.receipt@1:';

final class CompanyJobLifecycleContextRefusal extends JobLineRefusal {
  const CompanyJobLifecycleContextRefusal()
    : super(
        'Displayed Job context changed. Review it before deleting or resolving.',
      );
}

final class JobLifecycleDependencyRefusal extends JobLineRefusal {
  const JobLifecycleDependencyRefusal()
    : super('Job lifecycle dependency is missing');
}

final class JobLifecycleCommandReceipt {
  JobLifecycleCommandReceipt._(this.bytes);
  final String bytes;
  String get operationId => _string(_object(jsonDecode(bytes)), 'operation');
}

Map<String, Object?> _lifecycleReceipt(
  CompanyJobLifecycle row,
  InstallationIdentity identity,
  String store,
) => {
  'v': 1,
  'kind': row.outgoing
      ? 'job.lifecycle.receipt@1'
      : 'job.lifecycle.incoming.receipt@1',
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

Future<void> verifyJobLifecycleReceipt(
  String bytes,
  InstallationIdentity identity,
  String store,
  CompanyCommandFamily family,
) async {
  if (utf8.encode(bytes).length > 4096) {
    throw const JobLineRefusal('lifecycle receipt byte limit');
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
  final incoming = family == CompanyCommandFamily.jobLifecycleIncoming;
  if ((!incoming && family != CompanyCommandFamily.jobLifecycle) ||
      receipt['v'] != 1 ||
      receipt['kind'] !=
          (incoming
              ? 'job.lifecycle.incoming.receipt@1'
              : 'job.lifecycle.receipt@1') ||
      receipt['receiver'] != identity.id.value ||
      receipt['generation'] != identity.generation.value ||
      receipt['store'] != store ||
      _canonical(receipt) != bytes) {
    throw const JobLineRefusal('lifecycle receipt binding differs');
  }
  final body = {...receipt}..remove('seal');
  await _verifySignature(
    body,
    _string(receipt, 'seal'),
    SimplePublicKey(identity.publicKey, type: KeyPairType.ed25519),
    domain: incoming
        ? _incomingLifecycleReceiptDomain
        : _lifecycleReceiptDomain,
  );
}

Future<void> _validateLifecycleDependencies(
  AppDatabase db,
  SetJobLifecycle command,
) async {
  final graph = await _loadJobGraph(
    db,
    command.companyId,
    command.shopId,
    command.jobId,
    command.creationDigest,
  );
  final observed = graph.select(command.observed);
  if (command.resolvingConflict !=
          (observed.state == CompanyJobLifecycleState.deleteConflict) ||
      (command.choice == JobLifecycleChoice.kept &&
          !command.resolvingConflict)) {
    throw const JobLineRefusal(
      'Lifecycle resolution must observe a deletion conflict',
    );
  }
  if (observed.state == CompanyJobLifecycleState.deleted) {
    throw const JobLineRefusal('Deleted Job cannot be generally undeleted');
  }
  await _requireChildFree(db);
}

CompanyCommandIntent _lifecycleIntent(CompanyJobLifecycle row, String store) =>
    CompanyCommandIntent(
      family: row.outgoing
          ? CompanyCommandFamily.jobLifecycle
          : CompanyCommandFamily.jobLifecycleIncoming,
      receiptKey: row.receiptKey,
      operationCommitment: row.operationCommitment,
      commandCommitment: row.commandCommitment,
      storeGeneration: store,
      companyId: row.companyId,
      lineId: row.jobId,
      originGeneration: row.originGeneration,
      requestId: row.requestId,
    );

Future<void> validateJobLifecycleCommit(
  AppDatabase db,
  CompanyCommandIntent intent,
) async {
  final row = await (db.select(
    db.companyJobLifecycles,
  )..where((t) => t.receiptKey.equals(intent.receiptKey))).getSingle();
  final op = _LifecycleOperation.parse(
    Uint8List.fromList(utf8.encode(row.operationBytes)),
  );
  final receipt = _object(jsonDecode(row.receiptBytes));
  final unsigned = {...receipt}..remove('seal');
  final key = _digest({
    'family': 'job.lifecycle.set@1',
    'company': row.companyId,
    'origin': row.originGeneration,
    'request': row.requestId,
    'receiver': receipt['receiver'],
    'store': intent.storeGeneration,
  });
  final expected = {
    'v': 1,
    'kind': row.outgoing
        ? 'job.lifecycle.receipt@1'
        : 'job.lifecycle.incoming.receipt@1',
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
  if (_canonical(_lifecycleIntent(row, intent.storeGeneration).encode()) !=
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
    throw const JobLineRefusal('lifecycle commit evidence differs');
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
      throw const JobLineRefusal('lifecycle attribution differs');
    }
  }
  await _validateLifecycleDependencies(db, op.command);
}

final class _LifecycleReceiptAdmission extends VerifiedCompanyReceiptAdmission {
  _LifecycleReceiptAdmission(
    this.commands,
    this.bytes,
    this.session,
    this.intent, {
    this.context,
    this.availability,
  });
  final CompanyJobCommands commands;
  final String bytes;
  final VerifiedJobLifecycleSession session;
  final CompanyCommandIntent intent;
  final HeldPeerCreateContext? context;
  final CompanyJobSyncAvailability? availability;
  @override
  CompanyCommandFamily get family => intent.family;
  @override
  String get receiptDomain => family == CompanyCommandFamily.jobLifecycle
      ? _lifecycleReceiptDomain
      : _incomingLifecycleReceiptDomain;
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
      throw const JobLineRefusal('lifecycle receipt context changed');
    }
    final row = await (db.select(
      db.companyJobLifecycles,
    )..where((t) => t.receiptKey.equals(pending.receiptKey))).getSingle();
    if (row.receiptBytes != bytes) {
      throw const JobLineRefusal('lifecycle receipt candidate changed');
    }
    final op = _LifecycleOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    if (_canonical(op.authorization) != _canonical(session._proof)) {
      throw const JobLineRefusal('lifecycle receipt proof changed');
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
    await validateJobLifecycleCommit(db, pending);
    await context?.requireHeld(pending);
    availability?.requireLive();
    return Uint8List.fromList(utf8.encode(bytes));
  }
}

extension CompanyJobLifecycleCommands on CompanyJobCommands {
  Future<JobLifecycleCommandReceipt> setJobLifecycle(
    SetJobLifecycle command, {
    required OwnerSession ownerSession,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal(
        'lifecycle command owns top-level transaction',
      );
    }
    return ownerSession.runLocalCommand(() async {
      var session = await enrollment.issueJobLifecycleAssertion(command);
      session.validateLiveOwner(ownerSession);
      CompanyCommandIntent? intent;
      late String result;
      try {
        result = await _db.transaction(() async {
          await _db.customStatement(
            'UPDATE app_settings SET value = value WHERE key = ?',
            [kInstallationBindingKey],
          );
          session = await enrollment.issueJobLifecycleAssertion(command);
          session.validateLiveOwner(ownerSession);
          final identity = _installation.identity!;
          final existing =
              await (_db.select(_db.companyJobLifecycles)..where(
                    (t) =>
                        t.companyId.equals(command.companyId) &
                        t.originGeneration.equals(identity.generation.value) &
                        t.requestId.equals(command.requestId),
                  ))
                  .getSingleOrNull();
          if (existing != null) {
            final op = _LifecycleOperation.parse(
              Uint8List.fromList(utf8.encode(existing.operationBytes)),
            );
            session.validateOperationSigningContent(
              Uint8List.fromList(utf8.encode(_canonical(op.body))),
              identity,
            );
            await _verifyLifecycleRecord(existing);
            await beforeCommit?.call();
            (await enrollment.issueJobLifecycleAssertion(command))
                .validateLiveOwner(ownerSession);
            await _verifyLifecycleRecord(existing);
            return existing.receiptBytes;
          }
          await _verifyLifecycleDependencies(command);
          final graph = await _loadJobGraph(
            _db,
            command.companyId,
            command.shopId,
            command.jobId,
            command.creationDigest,
          );
          if (_canonical(graph.context.tagged) !=
              _canonical(command.observed.tagged)) {
            throw const CompanyJobLifecycleContextRefusal();
          }
          await _lifecycleCapacity(command);
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
          final op = _LifecycleOperation(
            body,
            session._proof,
            base64Encode(signature.bytes),
          );
          final row = _lifecycleRow(op, outgoing: true);
          intent = await _installation.beginCompanyCommand(
            _db,
            _lifecycleIntent(
              row,
              _installation.receivingStoreGeneration!.value,
            ),
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          final bytes = await _saveLifecycle(row, session, intent!);
          intent = await _installation.sealCompanyCommand(_db, intent!);
          await beforeCommit?.call();
          await _requireLifecycleProfile(_db, session._trust, session.command);
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
      return JobLifecycleCommandReceipt._(result);
    });
  }

  CompanyJobLifecycle _lifecycleRow(
    _LifecycleOperation op, {
    required bool outgoing,
  }) {
    final command = op.command;
    final key = _digest({
      'family': 'job.lifecycle.set@1',
      'company': command.companyId,
      'origin': op.body['generation'],
      'request': command.requestId,
      'receiver': _installation.identity!.id.value,
      'store': _installation.receivingStoreGeneration!.value,
    });
    return CompanyJobLifecycle(
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

  Future<void> _lifecycleCapacity(SetJobLifecycle command) async {
    await _mutableJobCapacity(command.companyId, command.jobId);
    final graph = await _loadJobGraph(
      _db,
      command.companyId,
      command.shopId,
      command.jobId,
      command.creationDigest,
    );
    final surviving = graph.heads
        .where((r) => !command.observed.references.contains(r))
        .length;
    if (surviving >= 32) {
      throw const JobLineRefusal('Job causal frontier capacity reached');
    }
  }

  Future<String> _saveLifecycle(
    CompanyJobLifecycle row,
    VerifiedJobLifecycleSession session,
    CompanyCommandIntent intent, {
    HeldPeerCreateContext? context,
    CompanyJobSyncAvailability? availability,
  }) async {
    var bytes = _canonical(
      _lifecycleReceipt(row, _installation.identity!, intent.storeGeneration),
    );
    await _db
        .into(_db.companyJobLifecycles)
        .insert(row.copyWith(receiptBytes: bytes).toCompanion(false));
    final signature = await _installation.signCompanyReceipt(
      _db,
      _LifecycleReceiptAdmission(
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
    await (_db.update(_db.companyJobLifecycles)
          ..where((t) => t.receiptKey.equals(row.receiptKey)))
        .write(CompanyJobLifecyclesCompanion(receiptBytes: Value(bytes)));
    return bytes;
  }

  Future<void> _verifyLifecycleRecord(
    CompanyJobLifecycle row, {
    Set<String>? verified,
  }) async {
    verified ??= <String>{};
    if (verified.contains(row.operationCommitment)) return;
    final current =
        await (_db.select(_db.companyJobLifecycles)..where(
              (t) => t.operationCommitment.equals(row.operationCommitment),
            ))
            .getSingle();
    if (current != row) {
      throw const JobLineRefusal('Saved lifecycle history changed');
    }
    final intent = _lifecycleIntent(
      row,
      _installation.receivingStoreGeneration!.value,
    );
    await validateJobLifecycleCommit(_db, intent);
    await verifyJobLifecycleReceipt(
      row.receiptBytes,
      _installation.identity!,
      intent.storeGeneration,
      intent.family,
    );
    final operation = _LifecycleOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    final session =
        await JobLifecycleAuthorization(
          db: _db,
          installation: _installation,
        ).verify(
          operation.command,
          Uint8List.fromList(utf8.encode(_canonical(operation.authorization))),
        );
    await _verifySignature(
      operation.body,
      operation.signature,
      session._publicKey,
      domain: session.operationDomain,
    );
    verified.add(row.operationCommitment);
    await _verifyLifecycleDependencies(operation.command, verified: verified);
  }

  Future<void> _verifyLifecycleDependencies(
    SetJobLifecycle command, {
    Set<String>? verified,
  }) async {
    await _validateLifecycleDependencies(_db, command);
    final base = await (_db.select(
      _db.companyJobs,
    )..where((t) => t.jobId.equals(command.jobId))).getSingle();
    if (base.outgoing) {
      await _verifyRecord(base);
    } else {
      await verifyIncomingRecord(base);
    }
    await _verifyGraphReferences(command.observed, verified: verified);
  }

  Future<void> _verifyGraphReferences(
    JobCausalContext context, {
    Set<String>? verified,
  }) async {
    verified ??= <String>{};
    for (final ref in context.references) {
      if (verified.contains(ref.tagged)) continue;
      verified.add(ref.tagged);
      switch (ref.family) {
        case JobOperationFamily.name:
          final row =
              await (_db.select(_db.companyJobNames)
                    ..where((t) => t.operationCommitment.equals(ref.digest)))
                  .getSingle();
          await _verifyNameRecord(row, verified: verified);
        case JobOperationFamily.details:
          final row =
              await (_db.select(_db.companyJobDetails)
                    ..where((t) => t.operationCommitment.equals(ref.digest)))
                  .getSingle();
          await _verifyDetailsRecord(row, verified: verified);
        case JobOperationFamily.lifecycle:
          final row =
              await (_db.select(_db.companyJobLifecycles)
                    ..where((t) => t.operationCommitment.equals(ref.digest)))
                  .getSingle();
          await _verifyLifecycleRecord(row, verified: verified);
      }
    }
  }

  Future<List<CompanyJobLifecycle>> lifecycleSyncHoldings({
    required CompanySession ownerSession,
    CompanyJobSyncAvailability? availability,
  }) async {
    await requireSyncPermission(ownerSession, availability: availability);
    final scope = ownerSession.identity;
    final rows =
        await (_db.select(_db.companyJobLifecycles)
              ..where(
                (t) =>
                    t.companyId.equals(scope.companyId) &
                    t.shopId.equals(scope.shopId),
              )
              ..limit(kCompanyJobLifecycleHistoryCompanyLimit + 1))
            .get();
    if (rows.length > kCompanyJobLifecycleHistoryCompanyLimit) {
      throw const JobLineRefusal('Lifecycle history capacity exceeded');
    }
    final verified = <String>{};
    for (final row in rows) {
      await _verifyLifecycleRecord(row, verified: verified);
    }
    await requireSyncPermission(ownerSession, availability: availability);
    return rows;
  }

  Future<CompanyJobLifecycle> verifyLifecycleSyncRecord(
    String operationId,
    CompanySession owner, {
    CompanyJobSyncAvailability? availability,
  }) async {
    final rows = await lifecycleSyncHoldings(
      ownerSession: owner,
      availability: availability,
    );
    final matches = rows.where((r) => r.operationCommitment == operationId);
    if (matches.length != 1) {
      throw const JobLineRefusal('Lifecycle sync record outside current scope');
    }
    return matches.single;
  }

  Future<String?> lifecycleUnavailableReason(
    CompanyJobView view,
    CompanySession owner,
  ) async {
    if (owner is! OwnerSession) {
      return 'This user has Create Job permission only.';
    }
    try {
      final session = await enrollment.issueJobLifecycleAssertion(
        SetJobLifecycle(
          companyId: owner.identity.companyId,
          shopId: owner.identity.shopId,
          jobId: view.baseJob.id,
          requestId: const Uuid().v4(),
          creationDigest: view.creationDigest,
          observed: view.lifecycle.context,
          choice: JobLifecycleChoice.deleted,
        ),
      );
      session.validateLiveOwner(owner);
      return null;
    } on JobLineRefusal catch (e) {
      return e.reason;
    } catch (_) {
      return 'Job deletion unavailable. Verify current company authority.';
    }
  }

  Future<String> applyIncomingLifecycle(
    Uint8List bytes, {
    required CompanySession ownerSession,
    required CompanyJobSyncAvailability availability,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal(
        'incoming lifecycle owns top-level transaction',
      );
    }
    final op = _LifecycleOperation.parse(Uint8List.fromList(bytes));
    return availability.run(() async {
      if (!identical(availability.enrollment, enrollment) ||
          !identical(availability.owner, ownerSession)) {
        throw const JobLineRefusal(
          'lifecycle sync availability belongs to another owner',
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
              await JobLifecycleAuthorization(
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
              throw const JobLineRefusal('incoming lifecycle author differs');
            }
          }
          final existing =
              await (_db.select(_db.companyJobLifecycles)..where(
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
              throw const JobLineRefusal(
                'incoming lifecycle identity collision',
              );
            }
            await _verifyLifecycleRecord(existing);
            await beforeCommit?.call();
            await _verifyLifecycleRecord(existing);
            await availability.requireCurrent();
            return existing.receiptBytes;
          }
          await _verifyLifecycleDependencies(op.command);
          await _lifecycleCapacity(op.command);
          final row = _lifecycleRow(op, outgoing: false);
          intent = await _installation.beginCompanyCommand(
            _db,
            _lifecycleIntent(
              row,
              _installation.receivingStoreGeneration!.value,
            ),
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          final receipt = await _saveLifecycle(
            row,
            session,
            intent!,
            context: context,
            availability: availability,
          );
          intent = await _installation.sealCompanyCommand(_db, intent!);
          await beforeCommit?.call();
          await _requireLifecycleProfile(_db, session._trust, session.command);
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

final class VerifiedJobLifecycleSession extends VerifiedCompanyOperation {
  VerifiedJobLifecycleSession._(
    this.command,
    this._proofBytes,
    this._trust,
    this._floors,
    this._publicKey,
  );
  final SetJobLifecycle command;
  final String _proofBytes;
  final CompanyTrustAnchor _trust;
  final Map<String, int> _floors;
  final SimplePublicKey _publicKey;
  Map<String, Object?> get _proof => _object(jsonDecode(_proofBytes));
  Map<String, Object?> get _assertion => _object(_proof['body']);
  @override
  String get operationDomain => 'wiredpart.job.lifecycle.operation@1:';

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
    final parsed = _LifecycleOperation.parse(
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
      throw const JobLineRefusal('signer requires exact Job lifecycle command');
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
        throw const JobLineRefusal('signer cannot substitute lifecycle author');
      }
    }
  }
}

class JobLifecycleAuthorization {
  JobLifecycleAuthorization({required this.db, required this.installation});
  final AppDatabase db;
  final InstallationSecurity installation;

  Future<VerifiedJobLifecycleSession> verify(
    SetJobLifecycle command,
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
    await _requireLifecycleProfile(db, trust, command);
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
        'lifecycle authorization scope or commitment differs',
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
        !allows(device, 'capabilities', 'manageJobLifecycle') ||
        !allows(user, 'capabilities', 'manageJobLifecycle')) {
      throw const JobLineRefusal(
        'Job lifecycle unavailable. Existing company authority needs an explicit capability upgrade.',
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
        throw const JobLineRefusal(
          'lifecycle authorization below protected floor',
        );
      }
    }
    for (final key in [
      'revocation.device.${device['id']}',
      'revocation.grant.${device['grant']}',
      'revocation.user.${user['id']}',
    ]) {
      if ((floors[key] ?? 0) > 0) {
        throw const JobLineRefusal('lifecycle actor is revoked');
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
          ? 'wiredpart.job.lifecycle.authorization@2:'
          : 'wiredpart.job.lifecycle.authorization@1:',
    );
    return VerifiedJobLifecycleSession._(
      command,
      _canonical(proof),
      trust,
      floors,
      publicKey,
    );
  }
}

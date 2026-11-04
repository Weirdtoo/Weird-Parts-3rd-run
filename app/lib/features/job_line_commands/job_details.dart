part of 'job_line_commands.dart';

enum JobDetailField { customer, location, jobNumber, status, notes }

enum CompanyJobStatus { active, archived }

const _detailTextLimits = {
  JobDetailField.customer: 1024,
  JobDetailField.location: 1024,
  JobDetailField.jobNumber: 256,
  JobDetailField.notes: 16384,
};

void _validateDetailValue(JobDetailField field, Object? value) {
  if (field == JobDetailField.status) {
    if (value != 'active' && value != 'archived') {
      throw const JobLineRefusal('Invalid Job status');
    }
  } else if (value != null &&
      (value is! String ||
          utf8.encode(value).length > _detailTextLimits[field]!)) {
    throw const JobLineRefusal('Job detail exceeds its text byte limit');
  }
}

final class JobDetailsPatch {
  const JobDetailsPatch({
    this.customer = const Omitted(),
    this.location = const Omitted(),
    this.jobNumber = const Omitted(),
    this.status = const Omitted(),
    this.notes = const Omitted(),
  });
  final FieldPatch<String?> customer, location, jobNumber, notes;
  final FieldPatch<CompanyJobStatus> status;

  Map<JobDetailField, Object?> _values() => {
    if (customer case SetField(value: final v)) JobDetailField.customer: v,
    if (location case SetField(value: final v)) JobDetailField.location: v,
    if (jobNumber case SetField(value: final v)) JobDetailField.jobNumber: v,
    if (status case SetField(value: final v)) JobDetailField.status: v.name,
    if (notes case SetField(value: final v)) JobDetailField.notes: v,
  };
}

final class PatchJobDetails {
  PatchJobDetails({
    required this.companyId,
    required this.shopId,
    required this.jobId,
    required this.requestId,
    required this.creationDigest,
    required this.patch,
    required Map<JobDetailField, List<String>> observedHeads,
    Set<JobDetailField> resolvingFields = const {},
    List<String>? observedLifecycleHeads,
  }) : observedLifecycleHeads = observedLifecycleHeads == null
           ? null
           : List.unmodifiable([...observedLifecycleHeads]..sort()),
       observedHeads = Map.unmodifiable({
         for (final e in observedHeads.entries)
           e.key: List<String>.unmodifiable([...e.value]..sort()),
       }),
       resolvingFields = Set.unmodifiable(resolvingFields) {
    for (final id in [companyId, shopId, jobId, requestId]) {
      _id(id);
    }
    final values = patch._values();
    if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(creationDigest) ||
        values.isEmpty ||
        values.length != observedHeads.length ||
        !values.keys.every(observedHeads.containsKey) ||
        !resolvingFields.every(values.containsKey)) {
      throw const JobLineRefusal('Invalid details fields or observations');
    }
    for (final entry in values.entries) {
      _validateDetailValue(entry.key, entry.value);
      final parents = observedHeads[entry.key]!;
      if (parents.length > 32 ||
          parents.toSet().length != parents.length ||
          parents.any((v) => !RegExp(r'^[a-f0-9]{64}$').hasMatch(v))) {
        throw const JobLineRefusal('Invalid details field parents');
      }
    }
    if (parentUnion.length > 32) {
      throw const JobLineRefusal('Details parent union capacity reached');
    }
    if (observedLifecycleHeads != null) {
      final refs = [
        ...parentUnion.map(
          (id) => JobOperationRef(JobOperationFamily.details, id),
        ),
        ...observedLifecycleHeads.map(
          (id) => JobOperationRef(JobOperationFamily.lifecycle, id),
        ),
      ];
      JobCausalContext(refs);
    }
  }
  final String companyId, shopId, jobId, requestId, creationDigest;
  final JobDetailsPatch patch;
  final List<String>? observedLifecycleHeads;
  final Map<JobDetailField, List<String>> observedHeads;
  final Set<JobDetailField> resolvingFields;
  List<String> get parentUnion =>
      observedHeads.values.expand((v) => v).toSet().toList()..sort();
  Map<String, Object?> _json() => {
    'v': observedLifecycleHeads == null ? 1 : 2,
    'contract': observedLifecycleHeads == null
        ? 'job.details.patch@1'
        : 'job.details.patch@2',
    if (observedLifecycleHeads != null) 'lifecycle': observedLifecycleHeads,
    'company': companyId,
    'shop': shopId,
    'job': jobId,
    'request': requestId,
    'creation': creationDigest,
    'units': {
      for (final e in patch._values().entries)
        e.key.name: {'value': e.value, 'parents': observedHeads[e.key]},
    },
    'resolve': resolvingFields.map((f) => f.name).toList()..sort(),
  };
  String get commitment => _digest(_json());
  static PatchJobDetails fromOperationBytes(Uint8List bytes) =>
      _DetailsOperation.parse(bytes).command;
}

final class JobDetailCandidate<T> {
  JobDetailCandidate._(
    this.value,
    this.operationId,
    this.originalUserId,
    this.originalDeviceId,
  );
  final T value;
  final String operationId, originalUserId, originalDeviceId;
}

final class JobDetailValue<T> {
  JobDetailValue._(
    this.value,
    this.lastAgreedValue,
    this.heads,
    this.candidates,
  );
  final T value, lastAgreedValue;
  final List<String> heads;
  final List<JobDetailCandidate<T>> candidates;
  bool get hasConflict =>
      candidates
          .map((v) => _canonical(_detailComparable(v.value)))
          .toSet()
          .length >
      1;
}

final class CompanyJobDetailsView {
  CompanyJobDetailsView._(Job job, List<_DetailsOperation> operations)
    : customer = _reduceDetail(
        job.customer,
        operations,
        JobDetailField.customer,
        (v) => v as String?,
      ),
      location = _reduceDetail(
        job.location,
        operations,
        JobDetailField.location,
        (v) => v as String?,
      ),
      jobNumber = _reduceDetail(
        job.jobNumber,
        operations,
        JobDetailField.jobNumber,
        (v) => v as String?,
      ),
      status = _reduceDetail(
        CompanyJobStatus.values.byName(job.status),
        operations,
        JobDetailField.status,
        (v) => CompanyJobStatus.values.byName(v as String),
      ),
      notes = _reduceDetail(
        job.notes,
        operations,
        JobDetailField.notes,
        (v) => v as String?,
      );
  final JobDetailValue<String?> customer, location, jobNumber, notes;
  final JobDetailValue<CompanyJobStatus> status;
}

Object? _detailComparable(Object? value) =>
    value is CompanyJobStatus ? value.name : value;

List<_DetailsOperation> _detailsHeads(
  List<_DetailsOperation> operations,
  JobDetailField field, {
  List<String>? selected,
}) {
  final byId = {
    for (final op in operations.where(
      (op) => op.command.observedHeads.containsKey(field),
    ))
      op.commitment: op,
  };
  final ancestry = <String, Set<String>>{};
  Set<String> ancestors(String id) => ancestry.putIfAbsent(
    id,
    () => {id, ...byId[id]!.command.observedHeads[field]!.expand(ancestors)},
  );
  final ids = selected ?? byId.keys.toList();
  return ids
      .where(
        (id) =>
            !ids.any((other) => other != id && ancestors(other).contains(id)),
      )
      .map((id) => byId[id]!)
      .toList()
    ..sort((a, b) => a.commitment.compareTo(b.commitment));
}

JobDetailValue<T> _reduceDetail<T>(
  T baseline,
  List<_DetailsOperation> operations,
  JobDetailField field,
  T Function(Object?) decode,
) {
  final own = operations
      .where((op) => op.command.observedHeads.containsKey(field))
      .toList();
  final byId = {for (final op in own) op.commitment: op};
  final heads = _detailsHeads(own, field);
  final candidates = heads
      .map(
        (op) => JobDetailCandidate<T>._(
          decode(op.command.patch._values()[field]),
          op.commitment,
          _string(op.body, 'user'),
          _string(op.body, 'device'),
        ),
      )
      .toList();
  final ancestry = <String, Set<String>>{};
  Set<String> ancestors(String id) => ancestry.putIfAbsent(
    id,
    () => {id, ...byId[id]!.command.observedHeads[field]!.expand(ancestors)},
  );
  var common = heads.isEmpty
      ? <String>{}
      : {...ancestors(heads.first.commitment)};
  for (final head in heads.skip(1)) {
    common.retainAll(ancestors(head.commitment));
  }
  var agreed = baseline;
  while (common.isNotEmpty) {
    final frontier = _detailsHeads(own, field, selected: common.toList());
    final values = frontier
        .map((op) => _canonical(op.command.patch._values()[field]))
        .toSet();
    if (values.length == 1) {
      agreed = decode(frontier.first.command.patch._values()[field]);
      break;
    }
    final previous = {...ancestors(frontier.first.commitment)};
    for (final op in frontier.skip(1)) {
      previous.retainAll(ancestors(op.commitment));
    }
    common = previous;
  }
  final values = candidates
      .map((v) => _canonical(_detailComparable(v.value)))
      .toSet();
  final value = values.length == 1 ? candidates.first.value : baseline;
  return JobDetailValue._(
    values.length > 1 ? agreed : value,
    values.length == 1 ? value : agreed,
    List.unmodifiable(heads.map((op) => op.commitment)),
    List.unmodifiable(candidates),
  );
}

PatchJobDetails _detailsCommand(Map<String, Object?> body) {
  final rawUnits = _object(body['units']);
  final rawResolve = body['resolve'];
  if (rawResolve is! List ||
      rawResolve.any((v) => v is! String) ||
      rawResolve.toSet().length != rawResolve.length) {
    throw const JobLineRefusal('Invalid details resolution fields');
  }
  final values = <JobDetailField, Object?>{};
  final parents = <JobDetailField, List<String>>{};
  JobDetailField field(String key) {
    for (final f in JobDetailField.values) {
      if (f.name == key) return f;
    }
    throw const JobLineRefusal('Unsupported Job detail field');
  }

  for (final entry in rawUnits.entries) {
    final f = field(entry.key);
    final unit = _object(entry.value);
    _keys(unit, {'value', 'parents'});
    _validateDetailValue(f, unit['value']);
    if (unit['parents'] is! List ||
        (unit['parents'] as List).any((v) => v is! String)) {
      throw const JobLineRefusal('Invalid details parents');
    }
    values[f] = unit['value'];
    parents[f] = (unit['parents'] as List).cast<String>();
  }
  FieldPatch<String?> text(JobDetailField f) =>
      values.containsKey(f) ? SetField(values[f] as String?) : const Omitted();
  return PatchJobDetails(
    companyId: _string(body, 'company'),
    shopId: _string(body, 'shop'),
    jobId: _string(body, 'job'),
    requestId: _string(body, 'request'),
    creationDigest: _string(body, 'creation'),
    patch: JobDetailsPatch(
      customer: text(JobDetailField.customer),
      location: text(JobDetailField.location),
      jobNumber: text(JobDetailField.jobNumber),
      notes: text(JobDetailField.notes),
      status: values.containsKey(JobDetailField.status)
          ? SetField(
              CompanyJobStatus.values.byName(
                values[JobDetailField.status] as String,
              ),
            )
          : const Omitted(),
    ),
    observedHeads: parents,
    resolvingFields: rawResolve.cast<String>().map(field).toSet(),
    observedLifecycleHeads: (body['lifecycle'] as List?)?.cast<String>(),
  );
}

final class JobDetailsCommandReceipt {
  JobDetailsCommandReceipt._(this.bytes);
  final String bytes;
  String get operationId => _string(_object(jsonDecode(bytes)), 'operation');
}

const kCompanyJobDetailsHistoryLimit = 128;
const kCompanyJobDetailsHistoryCompanyLimit = 512;
const _detailsReceiptDomain = 'wiredpart.job.details.receipt@1:';
const _incomingDetailsReceiptDomain =
    'wiredpart.job.details.incoming.receipt@1:';

final class CompanyJobDetailsCapacityRefusal extends JobLineRefusal {
  const CompanyJobDetailsCapacityRefusal.history()
    : super('Details history capacity reached. No edit was saved.');
  const CompanyJobDetailsCapacityRefusal.conflict()
    : super(
        'Details conflict capacity reached. Resolve competing field values first. No edit was saved.',
      );
}

final class JobDetailsDependencyRefusal extends JobLineRefusal {
  const JobDetailsDependencyRefusal()
    : super('Details history dependency is missing');
}

final class CompanyJobDetailsResolutionRefusal extends JobLineRefusal {
  const CompanyJobDetailsResolutionRefusal()
    : super('Details resolution frontier changed. Reload alternatives.');
}

final class _DetailsOperation {
  _DetailsOperation(this.body, this.authorization, this.signature);
  final Map<String, Object?> body, authorization;
  final String signature;
  String get commitment => _digest(body);
  String get bytes => _canonical({
    'body': body,
    'authorization': authorization,
    'signature': signature,
  });
  PatchJobDetails get command => _detailsCommand(body);
  static _DetailsOperation parse(Uint8List bytes) {
    if (bytes.length > _maximumBytes) {
      throw const JobLineRefusal('details operation byte limit');
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
      'units',
      'resolve',
      if (body['v'] == 2) 'lifecycle',
      'generation',
      'installation',
      'device',
      'user',
      'command',
      'facts',
    });
    if (_canonical(value) != text ||
        !((body['v'] == 1 && body['contract'] == 'job.details.patch@1') ||
            (body['v'] == 2 &&
                body['contract'] == 'job.details.patch@2' &&
                body['lifecycle'] is List)) ||
        body['units'] is! Map ||
        body['resolve'] is! List) {
      throw const JobLineRefusal(
        'unsupported or noncanonical details operation',
      );
    }
    for (final field in ['generation', 'installation', 'device', 'user']) {
      _id(_string(body, field));
    }
    final op = _DetailsOperation(
      body,
      _object(value['authorization']),
      _string(value, 'signature'),
    );
    if (op.command.commitment != body['command'] ||
        _canonical(op.command._json()['units']) != _canonical(body['units']) ||
        _canonical(op.command._json()['resolve']) !=
            _canonical(body['resolve'])) {
      throw const JobLineRefusal('details command commitment differs');
    }
    return op;
  }
}

Map<String, Object?> _detailsReceipt(
  CompanyJobDetail row,
  InstallationIdentity identity,
  String store,
) => {
  'v': 1,
  'kind': row.outgoing
      ? 'job.details.receipt@1'
      : 'job.details.incoming.receipt@1',
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

Future<void> verifyJobDetailsReceipt(
  String bytes,
  InstallationIdentity identity,
  String store,
  CompanyCommandFamily family,
) async {
  if (utf8.encode(bytes).length > 4096) {
    throw const JobLineRefusal('details receipt byte limit');
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
  final incoming = family == CompanyCommandFamily.jobDetailsIncoming;
  if ((!incoming && family != CompanyCommandFamily.jobDetails) ||
      receipt['v'] != 1 ||
      receipt['kind'] !=
          (incoming
              ? 'job.details.incoming.receipt@1'
              : 'job.details.receipt@1') ||
      receipt['receiver'] != identity.id.value ||
      receipt['generation'] != identity.generation.value ||
      receipt['store'] != store ||
      _canonical(receipt) != bytes) {
    throw const JobLineRefusal('details receipt binding differs');
  }
  final body = {...receipt}..remove('seal');
  await _verifySignature(
    body,
    _string(receipt, 'seal'),
    SimplePublicKey(identity.publicKey, type: KeyPairType.ed25519),
    domain: incoming ? _incomingDetailsReceiptDomain : _detailsReceiptDomain,
  );
}

Future<void> _validateDetailsDependencies(
  AppDatabase db,
  PatchJobDetails command,
) async {
  final base = await (db.select(
    db.companyJobs,
  )..where((t) => t.jobId.equals(command.jobId))).getSingleOrNull();
  if (base == null) throw const JobDetailsDependencyRefusal();
  if (base.companyId != command.companyId ||
      base.shopId != command.shopId ||
      _operationDigest(base.operationBytes) != command.creationDigest) {
    throw const JobLineRefusal('details creation binding differs');
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
    throw const JobLineRefusal('details creation baseline changed');
  }
  final parents = <String, _DetailsOperation>{};
  for (final parent in command.parentUnion) {
    final row = await (db.select(
      db.companyJobDetails,
    )..where((t) => t.operationCommitment.equals(parent))).getSingleOrNull();
    if (row == null) throw const JobDetailsDependencyRefusal();
    final op = _DetailsOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    if (row.companyId != command.companyId ||
        row.shopId != command.shopId ||
        row.jobId != command.jobId ||
        op.command.creationDigest != command.creationDigest ||
        op.commitment != parent) {
      throw const JobLineRefusal('Details parent scope differs');
    }
    parents[parent] = op;
  }
  await _validateMetadataLifecycle(
    db,
    command.companyId,
    command.shopId,
    command.jobId,
    command.creationDigest,
    command.observedLifecycleHeads,
  );
  for (final entry in command.observedHeads.entries) {
    for (final parent in entry.value) {
      if (!parents[parent]!.command.patch._values().containsKey(entry.key)) {
        throw const JobLineRefusal(
          'Details parent does not change observed field',
        );
      }
    }
    final history =
        (await (db.select(db.companyJobDetails)
                  ..where(
                    (t) =>
                        t.companyId.equals(command.companyId) &
                        t.jobId.equals(command.jobId),
                  )
                  ..limit(129))
                .get())
            .map(
              (r) => _DetailsOperation.parse(
                Uint8List.fromList(utf8.encode(r.operationBytes)),
              ),
            )
            .toList();
    if (history.length > 128) {
      throw const JobLineRefusal('Details history capacity exceeded');
    }
    final parentValues = _detailsHeads(
      history,
      entry.key,
      selected: entry.value,
    ).map((op) => _canonical(op.command.patch._values()[entry.key])).toSet();
    if (parentValues.length > 1 &&
        !command.resolvingFields.contains(entry.key)) {
      throw const JobLineRefusal(
        'Divergent details parents require explicit resolution',
      );
    }
  }
}

CompanyCommandIntent _detailsIntent(CompanyJobDetail row, String store) =>
    CompanyCommandIntent(
      family: row.outgoing
          ? CompanyCommandFamily.jobDetails
          : CompanyCommandFamily.jobDetailsIncoming,
      receiptKey: row.receiptKey,
      operationCommitment: row.operationCommitment,
      commandCommitment: row.commandCommitment,
      storeGeneration: store,
      companyId: row.companyId,
      lineId: row.jobId,
      originGeneration: row.originGeneration,
      requestId: row.requestId,
    );

Future<void> validateJobDetailsCommit(
  AppDatabase db,
  CompanyCommandIntent intent,
) async {
  final row = await (db.select(
    db.companyJobDetails,
  )..where((t) => t.receiptKey.equals(intent.receiptKey))).getSingle();
  final op = _DetailsOperation.parse(
    Uint8List.fromList(utf8.encode(row.operationBytes)),
  );
  final receipt = _object(jsonDecode(row.receiptBytes));
  final unsigned = {...receipt}..remove('seal');
  final key = _digest({
    'family': 'job.details.patch@1',
    'company': row.companyId,
    'origin': row.originGeneration,
    'request': row.requestId,
    'receiver': receipt['receiver'],
    'store': intent.storeGeneration,
  });
  final expected = {
    'v': 1,
    'kind': row.outgoing
        ? 'job.details.receipt@1'
        : 'job.details.incoming.receipt@1',
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
  if (_canonical(_detailsIntent(row, intent.storeGeneration).encode()) !=
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
    throw const JobLineRefusal('details commit evidence differs');
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
      throw const JobLineRefusal('details attribution differs');
    }
  }
  await _validateDetailsDependencies(db, op.command);
}

final class _DetailsReceiptAdmission extends VerifiedCompanyReceiptAdmission {
  _DetailsReceiptAdmission(
    this.commands,
    this.bytes,
    this.session,
    this.intent, {
    this.context,
    this.availability,
  });
  final CompanyJobCommands commands;
  final String bytes;
  final VerifiedJobDetailsSession session;
  final CompanyCommandIntent intent;
  final HeldPeerCreateContext? context;
  final CompanyJobSyncAvailability? availability;
  @override
  CompanyCommandFamily get family => intent.family;
  @override
  String get receiptDomain => family == CompanyCommandFamily.jobDetails
      ? _detailsReceiptDomain
      : _incomingDetailsReceiptDomain;
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
      throw const JobLineRefusal('details receipt context changed');
    }
    final row = await (db.select(
      db.companyJobDetails,
    )..where((t) => t.receiptKey.equals(pending.receiptKey))).getSingle();
    if (row.receiptBytes != bytes) {
      throw const JobLineRefusal('details receipt candidate changed');
    }
    final op = _DetailsOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    if (_canonical(op.authorization) != _canonical(session._proof)) {
      throw const JobLineRefusal('details receipt proof changed');
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
    await validateJobDetailsCommit(db, pending);
    await context?.requireHeld(pending);
    availability?.requireLive();
    return Uint8List.fromList(utf8.encode(bytes));
  }
}

extension CompanyJobDetailsCommands on CompanyJobCommands {
  Future<JobDetailsCommandReceipt> patchJobDetails(
    PatchJobDetails command, {
    required OwnerSession ownerSession,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal('details command owns top-level transaction');
    }
    return ownerSession.runLocalCommand(() async {
      var session = await enrollment.issueJobDetailsAssertion(command);
      session.validateLiveOwner(ownerSession);
      CompanyCommandIntent? intent;
      late String result;
      try {
        result = await _db.transaction(() async {
          await _db.customStatement(
            'UPDATE app_settings SET value = value WHERE key = ?',
            [kInstallationBindingKey],
          );
          session = await enrollment.issueJobDetailsAssertion(command);
          session.validateLiveOwner(ownerSession);
          final identity = _installation.identity!;
          final existing =
              await (_db.select(_db.companyJobDetails)..where(
                    (t) =>
                        t.companyId.equals(command.companyId) &
                        t.originGeneration.equals(identity.generation.value) &
                        t.requestId.equals(command.requestId),
                  ))
                  .getSingleOrNull();
          if (existing != null) {
            final op = _DetailsOperation.parse(
              Uint8List.fromList(utf8.encode(existing.operationBytes)),
            );
            session.validateOperationSigningContent(
              Uint8List.fromList(utf8.encode(_canonical(op.body))),
              identity,
            );
            await _verifyDetailsRecord(existing);
            await beforeCommit?.call();
            (await enrollment.issueJobDetailsAssertion(command))
                .validateLiveOwner(ownerSession);
            await _verifyDetailsRecord(existing);
            return existing.receiptBytes;
          }
          await _validateMetadataLifecycle(
            _db,
            command.companyId,
            command.shopId,
            command.jobId,
            command.creationDigest,
            command.observedLifecycleHeads,
            local: true,
          );
          await _verifyDetailsDependencies(command);
          await _validateNewDetailsResolution(command);
          await _detailsCapacity(command);
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
          final op = _DetailsOperation(
            body,
            session._proof,
            base64Encode(signature.bytes),
          );
          final row = _detailsRow(op, outgoing: true);
          intent = await _installation.beginCompanyCommand(
            _db,
            _detailsIntent(row, _installation.receivingStoreGeneration!.value),
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          final bytes = await _saveDetails(row, session, intent!);
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
      return JobDetailsCommandReceipt._(result);
    });
  }

  CompanyJobDetail _detailsRow(_DetailsOperation op, {required bool outgoing}) {
    final command = op.command;
    final key = _digest({
      'family': 'job.details.patch@1',
      'company': command.companyId,
      'origin': op.body['generation'],
      'request': command.requestId,
      'receiver': _installation.identity!.id.value,
      'store': _installation.receivingStoreGeneration!.value,
    });
    return CompanyJobDetail(
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

  Future<void> _mutableJobCapacity(String company, String job) async {
    final names =
        await (_db.select(_db.companyJobNames)
              ..where((t) => t.companyId.equals(company))
              ..limit(513))
            .get();
    final details =
        await (_db.select(_db.companyJobDetails)
              ..where((t) => t.companyId.equals(company))
              ..limit(513))
            .get();
    final lifecycle =
        await (_db.select(_db.companyJobLifecycles)
              ..where((t) => t.companyId.equals(company))
              ..limit(513))
            .get();
    if (names.length + details.length + lifecycle.length >= 512 ||
        names.where((r) => r.jobId == job).length +
                details.where((r) => r.jobId == job).length +
                lifecycle.where((r) => r.jobId == job).length >=
            128) {
      throw const CompanyJobDetailsCapacityRefusal.history();
    }
  }

  Future<void> _validateNewDetailsResolution(PatchJobDetails command) async {
    if (command.resolvingFields.isEmpty) return;
    final operations = await _detailsOperations(
      command.companyId,
      command.jobId,
    );
    for (final field in command.resolvingFields) {
      final heads = _detailsHeads(
        operations,
        field,
      ).map((op) => op.commitment).toList()..sort();
      if (_canonical(heads) != _canonical(command.observedHeads[field])) {
        throw const CompanyJobDetailsResolutionRefusal();
      }
    }
  }

  Future<List<_DetailsOperation>> _detailsOperations(
    String company,
    String job,
  ) async =>
      (await (_db.select(_db.companyJobDetails)..where(
                (t) => t.companyId.equals(company) & t.jobId.equals(job),
              ))
              .get())
          .map(
            (r) => _DetailsOperation.parse(
              Uint8List.fromList(utf8.encode(r.operationBytes)),
            ),
          )
          .toList();

  Future<void> _detailsCapacity(PatchJobDetails command) async {
    await _mutableJobCapacity(command.companyId, command.jobId);
    final own = await _detailsOperations(command.companyId, command.jobId);
    for (final field in command.patch._values().keys) {
      final surviving = _detailsHeads(own, field)
          .where((op) => !command.observedHeads[field]!.contains(op.commitment))
          .length;
      if (surviving >= 32) {
        throw const CompanyJobDetailsCapacityRefusal.conflict();
      }
    }
  }

  Future<String> _saveDetails(
    CompanyJobDetail row,
    VerifiedJobDetailsSession session,
    CompanyCommandIntent intent, {
    HeldPeerCreateContext? context,
    CompanyJobSyncAvailability? availability,
  }) async {
    var bytes = _canonical(
      _detailsReceipt(row, _installation.identity!, intent.storeGeneration),
    );
    await _db
        .into(_db.companyJobDetails)
        .insert(row.copyWith(receiptBytes: bytes).toCompanion(false));
    final signature = await _installation.signCompanyReceipt(
      _db,
      _DetailsReceiptAdmission(
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
    await (_db.update(_db.companyJobDetails)
          ..where((t) => t.receiptKey.equals(row.receiptKey)))
        .write(CompanyJobDetailsCompanion(receiptBytes: Value(bytes)));
    return bytes;
  }

  Future<void> _verifyDetailsRecord(
    CompanyJobDetail row, {
    Set<String>? verified,
  }) async {
    verified ??= <String>{};
    if (verified.contains(row.operationCommitment)) return;
    final current =
        await (_db.select(_db.companyJobDetails)..where(
              (t) => t.operationCommitment.equals(row.operationCommitment),
            ))
            .getSingle();
    if (current != row) {
      throw const JobLineRefusal('Saved details history changed');
    }
    final intent = _detailsIntent(
      row,
      _installation.receivingStoreGeneration!.value,
    );
    await validateJobDetailsCommit(_db, intent);
    await verifyJobDetailsReceipt(
      row.receiptBytes,
      _installation.identity!,
      intent.storeGeneration,
      intent.family,
    );
    final operation = _DetailsOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    verified.add(row.operationCommitment);
    await _verifyDetailsDependencies(operation.command, verified: verified);
  }

  Future<void> _verifyDetailsDependencies(
    PatchJobDetails command, {
    Set<String>? verified,
  }) async {
    verified ??= <String>{};
    await _validateDetailsDependencies(_db, command);
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
    for (final parent in command.parentUnion) {
      final row = await (_db.select(
        _db.companyJobDetails,
      )..where((t) => t.operationCommitment.equals(parent))).getSingle();
      await _verifyDetailsRecord(row, verified: verified);
    }
  }

  Future<List<CompanyJobDetail>> detailsSyncHoldings({
    required CompanySession ownerSession,
    CompanyJobSyncAvailability? availability,
  }) async {
    await requireSyncPermission(ownerSession, availability: availability);
    final scope = ownerSession.identity;
    final rows =
        await (_db.select(_db.companyJobDetails)
              ..where(
                (t) =>
                    t.companyId.equals(scope.companyId) &
                    t.shopId.equals(scope.shopId),
              )
              ..limit(kCompanyJobDetailsHistoryCompanyLimit + 1))
            .get();
    if (rows.length > kCompanyJobDetailsHistoryCompanyLimit) {
      throw const JobLineRefusal('Details history capacity exceeded');
    }
    final verified = <String>{};
    for (final row in rows) {
      await _verifyDetailsRecord(row, verified: verified);
    }
    await requireSyncPermission(ownerSession, availability: availability);
    return rows;
  }

  Future<CompanyJobDetail> verifyDetailsSyncRecord(
    String operationId,
    CompanySession owner, {
    CompanyJobSyncAvailability? availability,
  }) async {
    final rows = await detailsSyncHoldings(
      ownerSession: owner,
      availability: availability,
    );
    final matches = rows.where((r) => r.operationCommitment == operationId);
    if (matches.length != 1) {
      throw const JobLineRefusal('Details sync record outside current scope');
    }
    return matches.single;
  }

  Future<bool> canEditJobDetails(CompanySession owner) async {
    if (owner is! OwnerSession) return false;
    final scope = owner.identity;
    try {
      final session = await enrollment.issueJobDetailsAssertion(
        PatchJobDetails(
          companyId: scope.companyId,
          shopId: scope.shopId,
          jobId: const Uuid().v4(),
          requestId: const Uuid().v4(),
          creationDigest: '0' * 64,
          patch: const JobDetailsPatch(notes: SetField(null)),
          observedHeads: {JobDetailField.notes: []},
        ),
      );
      session.validateLiveOwner(owner);
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<String> applyIncomingDetails(
    Uint8List bytes, {
    required CompanySession ownerSession,
    required CompanyJobSyncAvailability availability,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal('incoming details owns top-level transaction');
    }
    final op = _DetailsOperation.parse(Uint8List.fromList(bytes));
    return availability.run(() async {
      if (!identical(availability.enrollment, enrollment) ||
          !identical(availability.owner, ownerSession)) {
        throw const JobLineRefusal(
          'details sync availability belongs to another owner',
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
              await JobDetailsAuthorization(
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
              throw const JobLineRefusal('incoming details author differs');
            }
          }
          final existing =
              await (_db.select(_db.companyJobDetails)..where(
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
              throw const JobLineRefusal('incoming details identity collision');
            }
            await _verifyDetailsRecord(existing);
            await beforeCommit?.call();
            await _verifyDetailsRecord(existing);
            await availability.requireCurrent();
            return existing.receiptBytes;
          }
          await _verifyDetailsDependencies(op.command);
          await _detailsCapacity(op.command);
          final row = _detailsRow(op, outgoing: false);
          intent = await _installation.beginCompanyCommand(
            _db,
            _detailsIntent(row, _installation.receivingStoreGeneration!.value),
            expectedTrust: session._trust,
            expectedFloors: session._floors,
          );
          final receipt = await _saveDetails(
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

final class VerifiedJobDetailsSession extends VerifiedCompanyOperation {
  VerifiedJobDetailsSession._(
    this.command,
    this._proofBytes,
    this._trust,
    this._floors,
    this._publicKey,
  );
  final PatchJobDetails command;
  final String _proofBytes;
  final CompanyTrustAnchor _trust;
  final Map<String, int> _floors;
  final SimplePublicKey _publicKey;
  Map<String, Object?> get _proof => _object(jsonDecode(_proofBytes));
  Map<String, Object?> get _assertion => _object(_proof['body']);
  @override
  String get operationDomain => 'wiredpart.job.details.operation@1:';

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
    final parsed = _DetailsOperation.parse(
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
      throw const JobLineRefusal(
        'signer requires exact Edit Job details command',
      );
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
        throw const JobLineRefusal('signer cannot substitute details author');
      }
    }
  }
}

class JobDetailsAuthorization {
  JobDetailsAuthorization({required this.db, required this.installation});
  final AppDatabase db;
  final InstallationSecurity installation;

  Future<VerifiedJobDetailsSession> verify(
    PatchJobDetails command,
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
        'details authorization scope or commitment differs',
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
        !allows(device, 'capabilities', 'editJobDetails') ||
        !allows(user, 'capabilities', 'editJobDetails')) {
      throw const JobLineRefusal(
        'Edit Job details unavailable. Existing company authority needs an explicit capability upgrade.',
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
          'details authorization below protected floor',
        );
      }
    }
    for (final key in [
      'revocation.device.${device['id']}',
      'revocation.grant.${device['grant']}',
      'revocation.user.${user['id']}',
    ]) {
      if ((floors[key] ?? 0) > 0) {
        throw const JobLineRefusal('details actor is revoked');
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
          ? 'wiredpart.job.details.authorization@2:'
          : 'wiredpart.job.details.authorization@1:',
    );
    return VerifiedJobDetailsSession._(
      command,
      _canonical(proof),
      trust,
      floors,
      publicKey,
    );
  }
}

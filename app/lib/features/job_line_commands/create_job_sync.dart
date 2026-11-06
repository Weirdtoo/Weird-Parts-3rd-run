part of 'job_line_commands.dart';

sealed class IncomingCreateJobOutcome {
  const IncomingCreateJobOutcome();
}

final class AppliedIncomingCreateJob extends IncomingCreateJobOutcome {
  const AppliedIncomingCreateJob(this.receiptBytes);
  final String receiptBytes;
}

final class HeldIncomingCreateJob extends IncomingCreateJobOutcome {
  const HeldIncomingCreateJob(
    this.jobId,
    this.userId,
    this.operationCommitment,
  );
  final String jobId;
  final String userId;
  final String operationCommitment;
}

const kCreateJobCompactReceiptLimit = 4096;
const _incomingCreateReceiptDomain = 'wiredpart.job.create.incoming.receipt@1:';

String _operationDigest(String bytes) =>
    hashes.sha256.convert(utf8.encode(bytes)).toString();

Map<String, Object?> _incomingReceipt(
  CompanyJob row,
  String receiver,
  String generation,
  String store,
) => {
  'v': 1,
  'kind': 'job.create.incoming@1',
  'key': row.receiptKey,
  'company': row.companyId,
  'shop': row.shopId,
  'job': row.jobId,
  'origin': row.originGeneration,
  'request': row.requestId,
  'operation': row.operationCommitment,
  'command': row.commandCommitment,
  'digest': _operationDigest(row.operationBytes),
  'receiver': receiver,
  'generation': generation,
  'store': store,
};

Future<void> verifyIncomingCreateJobReceipt(
  String bytes,
  InstallationIdentity identity,
  String store,
) async {
  if (utf8.encode(bytes).length > kCreateJobCompactReceiptLimit) {
    throw const JobLineRefusal('incoming receipt byte limit');
  }
  final value = _object(jsonDecode(bytes));
  _keys(value, {
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
  if (value['v'] != 1 ||
      value['kind'] != 'job.create.incoming@1' ||
      value['receiver'] != identity.id.value ||
      value['generation'] != identity.generation.value ||
      value['store'] != store ||
      _canonical(value) != bytes) {
    throw const JobLineRefusal('incoming receipt binding differs');
  }
  final seal = _string(value, 'seal');
  final payload = {...value}..remove('seal');
  await _verifySignature(
    payload,
    seal,
    SimplePublicKey(identity.publicKey, type: KeyPairType.ed25519),
    domain: _incomingCreateReceiptDomain,
  );
}

Future<void> validateIncomingCreateJobCommit(
  AppDatabase db,
  CompanyCommandIntent intent,
) async {
  final row = await (db.select(
    db.companyJobs,
  )..where((t) => t.receiptKey.equals(intent.receiptKey))).getSingle();
  final operation = _CreateOperation.parse(
    Uint8List.fromList(utf8.encode(row.operationBytes)),
  );
  final job = await (db.select(
    db.jobs,
  )..where((t) => t.id.equals(row.jobId))).getSingle();
  final receipt = _object(jsonDecode(row.receiptBytes));
  final unsigned = {...receipt}..remove('seal');
  final expected = _incomingReceipt(
    row,
    _string(receipt, 'receiver'),
    _string(receipt, 'generation'),
    intent.storeGeneration,
  );
  final key = _digest({
    'company': row.companyId,
    'origin': row.originGeneration,
    'request': row.requestId,
    'receiver': receipt['receiver'],
    'store': intent.storeGeneration,
  });
  if (intent.family != CompanyCommandFamily.jobCreateIncoming ||
      row.outgoing ||
      intent.companyId != row.companyId ||
      intent.lineId != row.jobId ||
      intent.originGeneration != row.originGeneration ||
      intent.requestId != row.requestId ||
      intent.operationCommitment != row.operationCommitment ||
      intent.commandCommitment != row.commandCommitment ||
      key != row.receiptKey ||
      _canonical(unsigned) != _canonical(expected) ||
      operation.commitment != row.operationCommitment ||
      operation.command.commitment != row.commandCommitment ||
      operation.command.companyId != row.companyId ||
      operation.command.shopId != row.shopId ||
      operation.command.jobId != row.jobId ||
      operation.command.requestId != row.requestId ||
      operation.body['generation'] != row.originGeneration ||
      row.projectionBytes != _canonical(job.toJson()) ||
      row.projectionBytes != _canonical(operation.projection.toJson()) ||
      row.auditBytes !=
          _canonical({
            'operation': operation.commitment,
            'originalUser': operation.body['user'],
            'originalDevice': operation.body['device'],
            'status': 'applied',
            'receipt': row.receiptKey,
            'outgoing': false,
          })) {
    throw const JobLineRefusal('incoming create commit evidence differs');
  }
  final proof = _object(operation.authorization['body']);
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
    if (operation.body[field] != proof[field]) {
      throw const JobLineRefusal('incoming create attribution differs');
    }
  }
}

final class _IncomingCreateAdmission extends VerifiedCompanyReceiptAdmission {
  _IncomingCreateAdmission(
    this.commands,
    this.bytes,
    this.session,
    this.context,
    this.availability,
  );
  final CompanyJobCommands commands;
  final String bytes;
  final VerifiedCreateJobSession session;
  final HeldPeerCreateContext context;
  final CompanyJobSyncAvailability availability;
  @override
  String get receiptDomain => _incomingCreateReceiptDomain;
  @override
  CompanyCommandFamily get family => CompanyCommandFamily.jobCreateIncoming;
  @override
  Future<Uint8List> validateSigningContent(
    AppDatabase db,
    InstallationIdentity identity,
    CompanyCommandIntent pending,
    CompanyTrustAnchor trust,
    Map<String, int> floors,
  ) async {
    if (!identical(db, commands._db) ||
        _canonical(trust.encode()) != _canonical(session._trust.encode()) ||
        _canonical(floors) != _canonical(session._floors)) {
      throw const JobLineRefusal('incoming receipt authority differs');
    }
    final row = await (db.select(
      db.companyJobs,
    )..where((t) => t.receiptKey.equals(pending.receiptKey))).getSingle();
    if (row.receiptBytes != bytes) {
      throw const JobLineRefusal('incoming candidate changed');
    }
    final operation = _CreateOperation.parse(
      Uint8List.fromList(utf8.encode(row.operationBytes)),
    );
    if (_canonical(operation.authorization) != _canonical(session._proof)) {
      throw const JobLineRefusal('incoming authorization changed');
    }
    await _verifySignature(
      operation.body,
      operation.signature,
      session._publicKey,
      domain: session.operationDomain,
    );
    await validateIncomingCreateJobCommit(db, pending);
    await context.requireHeld(pending);
    availability.requireLive();
    return Uint8List.fromList(utf8.encode(bytes));
  }
}

extension CompanyJobSyncCommands on CompanyJobCommands {
  Future<String> applyIncomingCreate(
    Uint8List canonicalOperation, {
    required CompanySession ownerSession,
    required CompanyJobSyncAvailability availability,
  }) async {
    final result = await applyIncomingCreateOutcome(
      canonicalOperation,
      ownerSession: ownerSession,
      availability: availability,
    );
    return switch (result) {
      AppliedIncomingCreateJob(:final receiptBytes) => receiptBytes,
      HeldIncomingCreateJob() => throw const JobLineRefusal(
        'Disabled-user work is held for attention',
      ),
    };
  }

  Future<IncomingCreateJobOutcome> applyIncomingCreateOutcome(
    Uint8List canonicalOperation, {
    required CompanySession ownerSession,
    required CompanyJobSyncAvailability availability,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal('incoming create owns transaction');
    }
    if (!identical(availability.enrollment, enrollment) ||
        !identical(availability.owner, ownerSession)) {
      throw const JobLineRefusal('sync availability belongs to another owner');
    }
    final operation = _CreateOperation.parse(
      Uint8List.fromList(canonicalOperation),
    );
    return availability.run(() async {
      await availability.requireCurrent();
      await requireSyncPermission(ownerSession, availability: availability);
      final context = await availability.peer.prepareCreateCommand(
        ownerSession,
      );
      context.validateHistoricalCreateDevice(operation.body);
      final duplicate = await _db.transaction(() async {
        await _db.customStatement(
          'UPDATE app_settings SET value = value WHERE key = ?',
          [kInstallationBindingKey],
        );
        final existing =
            await (_db.select(_db.companyJobs)..where(
                  (t) =>
                      t.companyId.equals(operation.command.companyId) &
                      t.originGeneration.equals(
                        operation.body['generation'] as String,
                      ) &
                      t.requestId.equals(operation.command.requestId),
                ))
                .getSingleOrNull();
        if (existing == null) return null;
        if (existing.outgoing || existing.operationBytes != operation.bytes) {
          throw const JobLineRefusal('incoming create identity collision');
        }
        await verifyIncomingRecord(existing);
        await beforeCommit?.call();
        await verifyIncomingRecord(existing);
        await availability.requireCurrent();
        context.validateHistoricalCreateDevice(operation.body);
        return existing.receiptBytes;
      });
      if (duplicate != null) return AppliedIncomingCreateJob(duplicate);
      if (await context.isCreateActorDisabled(operation.authorization)) {
        final key = SimplePublicKey(
          context.createDevicePublicKey,
          type: KeyPairType.ed25519,
        );
        context.validateAuthor(operation.body, key.bytes);
        await _verifySignature(
          operation.body,
          operation.signature,
          key,
          domain: 'wiredpart.job.create.operation@1:',
        );
        await _verifySignature(
          _object(operation.authorization['body']),
          _string(operation.authorization, 'signature'),
          key,
          domain: 'wiredpart.job.create.authorization@3:',
        );
        final assertion = _object(operation.authorization['body']);
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
          if (operation.body[field] != assertion[field]) {
            throw const JobLineRefusal('held signed author differs');
          }
        }
        await availability.requireCurrent();
        return HeldIncomingCreateJob(
          operation.command.jobId,
          operation.body['user'] as String,
          operation.commitment,
        );
      }
      return AppliedIncomingCreateJob(
        await _applyActiveIncomingCreate(
          canonicalOperation,
          ownerSession: ownerSession,
          availability: availability,
        ),
      );
    });
  }

  Future<CompanyJob> verifySyncRecord(
    String jobId,
    CompanySession owner, {
    CompanyJobSyncAvailability? availability,
  }) async {
    await requireSyncPermission(owner, availability: availability);
    final row = await (_db.select(
      _db.companyJobs,
    )..where((t) => t.jobId.equals(jobId))).getSingle();
    if (row.companyId != owner.identity.companyId ||
        row.shopId != owner.identity.shopId) {
      throw const JobLineRefusal('sync record outside current scope');
    }
    if (row.outgoing) {
      await _verifyRecord(row);
    } else {
      await verifyIncomingRecord(row);
    }
    await requireSyncPermission(owner, availability: availability);
    return row;
  }

  Future<void> requireSyncPermission(
    CompanySession owner, {
    CompanyJobSyncAvailability? availability,
  }) async {
    if (availability != null) {
      if (!identical(availability.enrollment, enrollment) ||
          !identical(availability.owner, owner)) {
        throw const JobLineRefusal(
          'sync availability belongs to another session',
        );
      }
      await availability.requireCurrent();
      return;
    }
    final scope = owner.identity;
    final session = await enrollment.issueCreateJobAssertion(
      CreateJob(
        companyId: scope.companyId,
        shopId: scope.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: 'Sync permission check',
      ),
    );
    session.validateLiveOwner(owner);
  }

  Future<void> verifyIncomingRecord(CompanyJob row) async {
    final current = await (_db.select(
      _db.companyJobs,
    )..where((t) => t.jobId.equals(row.jobId))).getSingle();
    if (current != row) {
      throw const JobLineRefusal('saved incoming create changed');
    }
    final intent = _incomingIntent(row);
    await validateIncomingCreateJobCommit(_db, intent);
    await verifyIncomingCreateJobReceipt(
      row.receiptBytes,
      _installation.identity!,
      intent.storeGeneration,
    );
  }

  CompanyCommandIntent _incomingIntent(CompanyJob row) => CompanyCommandIntent(
    family: CompanyCommandFamily.jobCreateIncoming,
    receiptKey: row.receiptKey,
    operationCommitment: row.operationCommitment,
    commandCommitment: row.commandCommitment,
    storeGeneration: _installation.receivingStoreGeneration!.value,
    companyId: row.companyId,
    lineId: row.jobId,
    originGeneration: row.originGeneration,
    requestId: row.requestId,
  );

  Future<List<CompanyJob>> syncHoldings({
    required CompanySession ownerSession,
    CompanyJobSyncAvailability? availability,
  }) async {
    await requireSyncPermission(ownerSession, availability: availability);
    final scope = ownerSession.identity;
    final rows =
        await (_db.select(_db.companyJobs)
              ..where(
                (t) =>
                    t.companyId.equals(scope.companyId) &
                    t.shopId.equals(scope.shopId),
              )
              ..limit(kCompanyJobListLimit + 1))
            .get();
    if (rows.length > kCompanyJobListLimit) {
      throw const CompanyJobCapacityRefusal();
    }
    for (final row in rows) {
      if (row.outgoing) {
        await _verifyRecord(row);
      } else {
        await verifyIncomingRecord(row);
      }
    }
    await requireSyncPermission(ownerSession, availability: availability);
    return rows;
  }

  Future<String> _applyActiveIncomingCreate(
    Uint8List canonicalOperation, {
    required CompanySession ownerSession,
    required CompanyJobSyncAvailability availability,
  }) async {
    if (_db.hasCallerTransaction) {
      throw const JobLineRefusal('incoming create owns transaction');
    }
    final operation = _CreateOperation.parse(
      Uint8List.fromList(canonicalOperation),
    );
    {
      if (!identical(availability.enrollment, enrollment) ||
          !identical(availability.owner, ownerSession)) {
        throw const JobLineRefusal(
          'sync availability belongs to another owner',
        );
      }
      await availability.requireCurrent();
      final peer = availability.peer;
      await requireSyncPermission(ownerSession, availability: availability);
      final context = await peer.prepareCreateCommand(ownerSession);
      await context.admitCreateActor(operation.authorization);
      context.validateAuthor(operation.body);
      CompanyCommandIntent? intent;
      String result;
      try {
        result = await _db.transaction(() async {
          await _db.customStatement(
            'UPDATE app_settings SET value = value WHERE key = ?',
            [kInstallationBindingKey],
          );
          await requireSyncPermission(ownerSession, availability: availability);
          await peer.requireCurrent();
          final verified =
              await CreateJobAuthorization(
                db: _db,
                installation: _installation,
              ).verify(
                operation.command,
                Uint8List.fromList(
                  utf8.encode(_canonical(operation.authorization)),
                ),
              );
          await _verifySignature(
            operation.body,
            operation.signature,
            verified._publicKey,
            domain: verified.operationDomain,
          );
          context.validateAuthor(operation.body, verified._publicKey.bytes);
          context.validateAuthorization(verified._assertion);
          for (final key in [
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
            if (operation.body[key] != verified._assertion[key]) {
              throw const JobLineRefusal('incoming signed author differs');
            }
          }
          context.validateAuthor(operation.body);
          final existing =
              await (_db.select(_db.companyJobs)..where(
                    (t) =>
                        t.companyId.equals(operation.command.companyId) &
                        t.originGeneration.equals(
                          operation.body['generation'] as String,
                        ) &
                        t.requestId.equals(operation.command.requestId),
                  ))
                  .getSingleOrNull();
          if (existing != null) {
            if (existing.operationBytes != operation.bytes ||
                existing.outgoing) {
              throw const JobLineRefusal('incoming create identity collision');
            }
            await verifyIncomingRecord(existing);
            await beforeCommit?.call();
            await verifyIncomingRecord(existing);
            await peer.requireCurrent();
            availability.requireLive();
            return existing.receiptBytes;
          }
          if (await (_db.select(_db.jobs)
                        ..where((t) => t.id.equals(operation.command.jobId)))
                      .getSingleOrNull() !=
                  null ||
              await (_db.select(_db.companyJobs)
                        ..where((t) => t.jobId.equals(operation.command.jobId)))
                      .getSingleOrNull() !=
                  null) {
            throw const JobLineRefusal('Job ID already exists');
          }
          final count = await _db
              .customSelect(
                'SELECT COUNT(*) AS total FROM company_jobs WHERE company_id = ? AND shop_id = ?',
                variables: [
                  Variable(operation.command.companyId),
                  Variable(operation.command.shopId),
                ],
              )
              .getSingle();
          if (count.read<int>('total') >= kCompanyJobListLimit) {
            throw const CompanyJobCapacityRefusal();
          }
          final identity = _installation.identity!;
          final store = _installation.receivingStoreGeneration!.value;
          final key = _digest({
            'company': operation.command.companyId,
            'origin': operation.body['generation'],
            'request': operation.command.requestId,
            'receiver': identity.id.value,
            'store': store,
          });
          final row = CompanyJob(
            jobId: operation.command.jobId,
            companyId: operation.command.companyId,
            shopId: operation.command.shopId,
            originGeneration: operation.body['generation'] as String,
            requestId: operation.command.requestId,
            operationCommitment: operation.commitment,
            commandCommitment: operation.command.commitment,
            operationBytes: operation.bytes,
            projectionBytes: _canonical(operation.projection.toJson()),
            receiptKey: key,
            receiptBytes: '',
            outgoing: false,
            auditBytes: _canonical({
              'operation': operation.commitment,
              'originalUser': operation.body['user'],
              'originalDevice': operation.body['device'],
              'status': 'applied',
              'receipt': key,
              'outgoing': false,
            }),
          );
          intent = await _installation.beginCompanyCommand(
            _db,
            _incomingIntent(row),
            expectedTrust: verified._trust,
            expectedFloors: verified._floors,
          );
          var receipt = _canonical(
            _incomingReceipt(
              row,
              identity.id.value,
              identity.generation.value,
              store,
            ),
          );
          await _db
              .into(_db.jobs)
              .insert(operation.projection.toCompanion(false));
          await _db
              .into(_db.companyJobs)
              .insert(row.copyWith(receiptBytes: receipt).toCompanion(false));
          final seal = await _installation.signCompanyReceipt(
            _db,
            _IncomingCreateAdmission(
              this,
              receipt,
              verified,
              context,
              availability,
            ),
          );
          receipt = _canonical({
            ..._object(jsonDecode(receipt)),
            'seal': base64Encode(seal.bytes),
          });
          await (_db.update(_db.companyJobs)
                ..where((t) => t.receiptKey.equals(key)))
              .write(CompanyJobsCompanion(receiptBytes: Value(receipt)));
          intent = await _installation.sealCompanyCommand(_db, intent!);
          await beforeCommit?.call();
          await _installation.validateHeldCompanyCommand(
            _db,
            intent!,
            expectedTrust: verified._trust,
            expectedFloors: verified._floors,
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
      await peer.requireCurrent();
      return result;
    }
  }
}

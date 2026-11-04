import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:uuid/uuid.dart';

import '../installation/installation_security.dart';
import 'company_job_details_section.dart';
import 'company_bootstrap.dart';
import '../job_line_commands/job_line_commands.dart';

class CompanyJobsPanel extends StatefulWidget {
  const CompanyJobsPanel({
    required this.commands,
    required this.owner,
    super.key,
  });
  final CompanyJobCommands commands;
  final CompanySession owner;

  @override
  State<CompanyJobsPanel> createState() => _CompanyJobsPanelState();
}

class _CompanyJobsPanelState extends State<CompanyJobsPanel> {
  final _name = TextEditingController();
  List<CompanyJobView> _jobs = const [];
  final _editName = TextEditingController();
  CompanyJobView? _editing;
  RenameJob? _pendingRename;
  SetJobLifecycle? _pendingLifecycle;
  Map<String, String?> _lifecycleReasons = const {};
  bool _renameAvailable = false;
  bool _detailsAvailable = false;
  Map<String, int> _confirmedPeers = const {};
  Set<String> _heldUserJobs = const {};
  Set<String> _heldDisabledJobs = const {};
  String? _userPolicyMessage;
  CreateJob? _pending;
  String? _error;
  bool _loading = true;
  bool _busy = false;
  bool _available = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _name.dispose();
    _editName.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final jobs = await widget.commands.listJobViews(
        ownerSession: widget.owner,
      );
      final renameAvailable = await widget.commands.canRenameJobs(widget.owner);
      final lifecycleReasons = <String, String?>{};
      for (final job in jobs) {
        lifecycleReasons[job.baseJob.id] = await widget.commands
            .lifecycleUnavailableReason(job, widget.owner);
      }
      final detailsAvailable = await widget.commands.canEditJobDetails(
        widget.owner,
      );
      final confirmed = widget.owner is OwnerSession
          ? await CompanyCreatedJobSync.confirmedPeerCounts(
              widget.commands.enrollment,
              widget.owner as OwnerSession,
            )
          : <String, int>{};
      final lifecycles = <String, CompanyUserLifecycleStatus>{};
      String? policyMessage;
      try {
        for (final user
            in (await widget.commands.enrollment.listCompanyUsers()).skip(1)) {
          if (user.userId.isEmpty) {
            throw const CompanyBootstrapRefusal('User policy unavailable');
          }
          final lifecycle = await widget.commands.enrollment
              .userLifecycleStatus(userId: user.userId);
          if (lifecycle != null) lifecycles[user.userId] = lifecycle;
        }
      } on CompanyBootstrapRefusal {
        policyMessage = 'Additional-user policy is unavailable. Owner Jobs remain readable; local owner work can continue. That user\'s work remains pending.';
      }
      final held = <String>{};
      final heldDisabledJobs = <String>{};
      if (lifecycles.values.any(
            (state) => state.disabled || state.credentialVersion > 1,
          ) &&
          widget.owner is OwnerSession) {
        final creationConfirmed =
            await CompanyCreatedJobSync.confirmedPeerCounts(
              widget.commands.enrollment,
              widget.owner as OwnerSession,
              creationOnly: true,
            );
        for (final row in await widget.commands.syncHoldings(
          ownerSession: widget.owner as OwnerSession,
        )) {
          final operation = jsonDecode(row.operationBytes) as Map;
          final lifecycle = lifecycles[(operation['body'] as Map)['user']];
          if (row.outgoing &&
              (creationConfirmed[row.jobId] ?? 0) == 0 &&
              lifecycle != null) {
            final proof = operation['authorization'] as Map;
            if (await widget.commands.enrollment.isCompanyUserOperationHeld(
              lifecycle.userId,
              (proof['body'] as Map)['credential'] as int,
            )) {
              held.add(row.jobId);
              if (lifecycle.disabled) heldDisabledJobs.add(row.jobId);
            }
          }
        }
      }
      await widget.commands.requireSyncPermission(widget.owner);
      if (!mounted || !widget.owner.isValid) return;
      setState(() {
        _jobs = jobs;
        _lifecycleReasons = lifecycleReasons;
        _renameAvailable = renameAvailable;
        _detailsAvailable = detailsAvailable;
        _confirmedPeers = confirmed;
        _heldUserJobs = held;
        _heldDisabledJobs = heldDisabledJobs;
        _userPolicyMessage = policyMessage;
        _available = true;
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _jobs = const [];
        _available = false;
        _loading = false;
        _error = error is JobLineRefusal
            ? error.reason
            : 'Company Jobs are locked. Sign in again to verify authority.';
      });
    }
  }

  Future<void> _create() async {
    if (_busy) return;
    try {
      final scope = widget.owner.identity;
      _pending ??= CreateJob(
        companyId: scope.companyId,
        shopId: scope.shopId,
        jobId: const Uuid().v4(),
        requestId: const Uuid().v4(),
        name: _name.text,
      );
    } on JobLineRefusal catch (error) {
      setState(() => _error = error.reason);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.commands.createJob(_pending!, ownerSession: widget.owner);
      if (!mounted || !widget.owner.isValid) return;
      setState(() {
        _pending = null;
        _name.clear();
      });
      await _load();
    } on CompanyJobCapacityRefusal catch (error) {
      if (mounted) {
        setState(() {
          _pending = null;
          _error = error.reason;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(
          () => _error =
              'This Job may already be saved. Retry to check its result.',
        );
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  void _edit(CompanyJobView job, [String? selected]) {
    if (_busy || _pendingRename != null) return;
    setState(() {
      _editing = job;
      _editName.text = selected ?? job.displayName;
      _error = null;
    });
  }

  Future<void> _saveName() async {
    final owner = widget.owner;
    if (_busy || _editing == null || owner is! OwnerSession) return;
    try {
      final scope = widget.owner.identity;
      final job = _editing!;
      _pendingRename ??= RenameJob(
        companyId: scope.companyId,
        shopId: scope.shopId,
        jobId: job.baseJob.id,
        requestId: const Uuid().v4(),
        creationDigest: job.creationDigest,
        observedHeads: job.nameHeads,
        observedLifecycleHeads: job.lifecycle.lifecycleHeads,
        name: _editName.text,
      );
    } on JobLineRefusal catch (error) {
      setState(() => _error = error.reason);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.commands.renameJob(_pendingRename!, ownerSession: owner);
      final jobs = await widget.commands.listJobViews(
        ownerSession: widget.owner,
      );
      final confirmed = await CompanyCreatedJobSync.confirmedPeerCounts(
        widget.commands.enrollment,
        owner,
      );
      if (!mounted || !widget.owner.isValid) return;
      setState(() {
        _jobs = jobs;
        _confirmedPeers = confirmed;
        _editing = null;
        _pendingRename = null;
        _editName.clear();
      });
    } on CompanyJobNameContextRefusal catch (error) {
      if (mounted) {
        setState(() => _pendingRename = null);
        await _load();
        if (mounted) setState(() => _error = error.reason);
      }
    } on CompanyJobNameCapacityRefusal catch (error) {
      if (mounted) {
        setState(() {
          _pendingRename = null;
          _editing = null;
          _error = error.reason;
        });
        await _load();
      }
    } catch (_) {
      if (mounted) {
        setState(
          () => _error = 'This name edit may already be saved. Retry the same edit to check its result.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _setLifecycle(
    CompanyJobView job,
    JobLifecycleChoice choice,
  ) async {
    if (_busy || _pendingLifecycle != null || !_lifecycleAllowed(job)) return;
    if (choice == JobLifecycleChoice.deleted) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Delete Job?'),
          content: Text(
            '${job.displayName} will move to deleted history. Concurrent edits will remain visible as a deletion conflict.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Delete Job'),
            ),
          ],
        ),
      );
      if (confirmed != true || !mounted) return;
    }
    try {
      _pendingLifecycle = SetJobLifecycle(
        companyId: widget.owner.identity.companyId,
        shopId: widget.owner.identity.shopId,
        jobId: job.baseJob.id,
        requestId: const Uuid().v4(),
        creationDigest: job.creationDigest,
        observed: job.lifecycle.context,
        choice: choice,
        resolvingConflict:
            job.lifecycle.state == CompanyJobLifecycleState.deleteConflict,
      );
    } on JobLineRefusal catch (e) {
      setState(() => _error = e.reason);
      return;
    }
    await _saveLifecycle();
  }

  bool _lifecycleAllowed(CompanyJobView job) =>
      _lifecycleReasons.containsKey(job.baseJob.id) &&
      _lifecycleReasons[job.baseJob.id] == null;

  Future<void> _saveLifecycle() async {
    final owner = widget.owner;
    if (_busy || _pendingLifecycle == null || owner is! OwnerSession) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.commands.setJobLifecycle(
        _pendingLifecycle!,
        ownerSession: owner,
      );
      if (mounted) setState(() => _pendingLifecycle = null);
      await _load();
    } on CompanyJobLifecycleContextRefusal catch (error) {
      if (mounted) setState(() => _pendingLifecycle = null);
      await _load();
      if (mounted) setState(() => _error = error.reason);
    } catch (_) {
      await _load();
      if (mounted) {
        setState(
          () => _error = 'This lifecycle choice may already be saved. Retry the same choice to check its result.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Widget _jobTile(CompanyJobView job) => Column(
    key: Key('company-job-view-${job.baseJob.id}'),
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      ListTile(
        key: Key('company-job-${job.baseJob.id}'),
        title: Text(job.displayName),
        subtitle: Text(
          'Job ID: ${job.baseJob.id}\n${(_confirmedPeers[job.baseJob.id] ?? 0) > 0 ? 'Last confirmed by ${_confirmedPeers[job.baseJob.id]} retained peer(s)' : 'Peer delivery status unknown'}',
        ),
        trailing:
            !job.hasConflict &&
                _renameAvailable &&
                job.lifecycle.state == CompanyJobLifecycleState.live
            ? TextButton(
                key: Key('company-job-edit-${job.baseJob.id}'),
                onPressed: _busy || _pendingRename != null
                    ? null
                    : () => _edit(job),
                child: const Text('Edit name'),
              )
            : null,
      ),
      if (_heldUserJobs.contains(job.baseJob.id))
        Text(
          'Held for attention. ${_heldDisabledJobs.contains(job.baseJob.id) ? 'Disabled-user' : 'Superseded-credential'} work has no applied peer confirmation. Original bytes and authorship are retained.',
          key: Key('company-job-held-${job.baseJob.id}'),
        ),
      if (job.hasConflict)
        Column(
          key: Key('company-job-name-conflict-${job.baseJob.id}'),
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Competing names. Last agreed name: ${job.lastAgreedName}'),
            for (final candidate in job.candidates)
              ListTile(
                key: Key('company-job-name-candidate-${candidate.operationId}'),
                title: Text(candidate.name),
                subtitle: Text(
                  'User: ${candidate.originalUserId}\nDevice: ${candidate.originalDeviceId}\nOperation: ${candidate.operationId}',
                ),
                onTap:
                    _renameAvailable &&
                        job.lifecycle.state == CompanyJobLifecycleState.live &&
                        !_busy &&
                        _pendingRename == null
                    ? () => _edit(job, candidate.name)
                    : null,
              ),
            if (_renameAvailable &&
                job.lifecycle.state == CompanyJobLifecycleState.live)
              TextButton(
                key: Key('company-job-resolve-name-${job.baseJob.id}'),
                onPressed: _busy || _pendingRename != null
                    ? null
                    : () => _edit(job),
                child: const Text('Resolve competing names'),
              ),
          ],
        ),
      if (widget.owner case final OwnerSession owner)
        CompanyJobDetailsSection(
          key: Key('company-job-details-${job.baseJob.id}'),
          job: job,
          commands: widget.commands,
          owner: owner,
          available:
              _detailsAvailable &&
              job.lifecycle.state == CompanyJobLifecycleState.live,
          onSaved: _load,
        ),
      if (job.lifecycle.state == CompanyJobLifecycleState.deleteConflict) ...[
        Text(
          'Deletion conflict',
          key: Key('company-job-delete-conflict-${job.baseJob.id}'),
        ),
        for (final alternative in job.lifecycle.alternatives)
          ListTile(
            title: Text(
              '${alternative.reference.family.name}: ${alternative.value}',
            ),
            subtitle: Text(
              'User: ${alternative.originalUserId}\nDevice: ${alternative.originalDeviceId}\nOperation: ${alternative.operationId}',
            ),
          ),
        if (_lifecycleAllowed(job))
          TextButton(
            key: Key('company-job-keep-${job.baseJob.id}'),
            onPressed: _busy || _pendingLifecycle != null
                ? null
                : () => _setLifecycle(job, JobLifecycleChoice.kept),
            child: const Text('Keep edited Job'),
          ),
      ],
      if (job.lifecycle.state != CompanyJobLifecycleState.deleted)
        if (_lifecycleAllowed(job))
          TextButton(
            key: Key('company-job-delete-${job.baseJob.id}'),
            onPressed: _busy || _pendingLifecycle != null
                ? null
                : () => _setLifecycle(job, JobLifecycleChoice.deleted),
            child: const Text('Delete Job'),
          )
        else
          Text(
            _lifecycleReasons[job.baseJob.id] ??
                'Checking Job deletion availability.',
          ),
    ],
  );

  @override
  Widget build(BuildContext context) {
    if (!widget.owner.isValid) {
      return const Text('Company Jobs are locked.');
    }
    if (_loading) {
      return const Text('Loading company Jobs...');
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Company Jobs', style: TextStyle(fontSize: 20)),
        if (_available) ...[
          TextField(
            key: const Key('company-job-name'),
            controller: _name,
            enabled: !_busy && _pending == null,
            maxLength: kCompanyJobNameLimit,
            decoration: const InputDecoration(labelText: 'Job name'),
          ),
          FilledButton(
            key: const Key('company-create-job'),
            onPressed: _busy ? null : _create,
            child: Text(
              _busy
                  ? 'Saving…'
                  : _pending == null
                  ? 'Create Job'
                  : 'Retry same Job',
            ),
          ),
          const Text(
            'Jobs are saved on this installation. Use Sync Now with a verified retained peer. Confirmations describe the last successful exchange.',
          ),
          if (_heldUserJobs.isNotEmpty)
            Text(
              'Additional-user work without a prior applied confirmation is held for attention. Original Job bytes and authorship are retained; owner work can continue.',
              key: Key('company-user-held-work'),
            ),
          if (_userPolicyMessage case final message?)
            Text(message, key: const Key('company-user-policy-unavailable')),
          if (!_renameAvailable)
            const Text(
              'Name editing requires an explicit company permission upgrade.',
            ),
          if (_editing != null) ...[
            Text(
              _editing!.hasConflict ? 'Resolve name conflict' : 'Edit Job name',
            ),
            TextField(
              key: const Key('company-job-edit-name'),
              controller: _editName,
              enabled: !_busy && _pendingRename == null,
              maxLength: kCompanyJobNameLimit,
              decoration: const InputDecoration(labelText: 'New Job name'),
            ),
            FilledButton(
              key: Key(
                _pendingRename == null
                    ? 'company-job-save-name'
                    : 'company-job-retry-name',
              ),
              onPressed: _busy ? null : _saveName,
              child: Text(
                _busy
                    ? 'Saving...'
                    : _pendingRename == null
                    ? 'Save name'
                    : 'Retry same name edit',
              ),
            ),
            if (_pendingRename == null)
              TextButton(
                onPressed: _busy ? null : () => setState(() => _editing = null),
                child: const Text('Cancel name edit'),
              ),
          ],
          if (_jobs.isEmpty) const Text('No company Jobs yet.'),
          if (_pendingLifecycle != null) ...[
            Text(
              'Pending lifecycle choice for Job ${_pendingLifecycle!.jobId}',
            ),
            FilledButton(
              key: const Key('company-job-retry-lifecycle'),
              onPressed: _busy ? null : _saveLifecycle,
              child: const Text('Retry same lifecycle choice'),
            ),
          ],
          Column(
            key: const Key('company-jobs-list'),
            children: [
              for (final job in _jobs.where(
                (j) => j.lifecycle.state != CompanyJobLifecycleState.deleted,
              ))
                _jobTile(job),
            ],
          ),
          if (_jobs.any(
            (j) => j.lifecycle.state == CompanyJobLifecycleState.deleted,
          ))
            ExpansionTile(
              key: const Key('company-deleted-jobs'),
              title: const Text('Deleted Job history'),
              children: [
                for (final job in _jobs.where(
                  (j) => j.lifecycle.state == CompanyJobLifecycleState.deleted,
                ))
                  _jobTile(job),
              ],
            ),
        ],
        if (_error != null)
          Text(
            _error!,
            key: const Key('company-job-error'),
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
      ],
    );
  }
}

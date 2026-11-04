import 'dart:async';

import 'package:flutter/material.dart';
import 'package:uuid/uuid.dart';

import '../installation/installation_security.dart';
import 'company_bootstrap.dart';
import '../nearby/nearby_controller.dart';
import '../nearby/nearby_discovery.dart';
import '../nearby/nearby_protocol.dart';

/// Explicit approval and consent; Match alone never enrolls a company device.
class CompanyJoinPage extends StatefulWidget {
  const CompanyJoinPage({
    required this.enrollment,
    this.approver,
    this.reconnect = false,
    this.createController,
    this.onJobSyncDiagnostic,
    super.key,
  });
  final CompanyEnrollment enrollment;
  final OwnerSession? approver;
  final bool reconnect;
  final NearbyController Function(String encounterAlias)? createController;
  final void Function(CreatedJobSyncDiagnostic)? onJobSyncDiagnostic;
  @override
  State<CompanyJoinPage> createState() => _CompanyJoinPageState();
}

class _CompanyJoinPageState extends State<CompanyJoinPage>
    with WidgetsBindingObserver {
  late final CompanyJoin _join;
  late final CompanyPeerAuthentication _authentication;
  List<RetainedCompanyPeer> _retained = const [];
  RetainedCompanyPeer? _selected;
  late final NearbyController _controller;
  StreamSubscription<NearbyViewState>? _subscription;
  NearbyJoinChannel? _channel;
  Future<NearbyJoinChannel>? _channelPending;
  NearbyPairedJoinSession? _pair;
  VerifiedJoinRequest? _request;
  VerifiedPeerMembership? _peerMembership;
  CompanyCreatedJobSync? _jobSync;
  UserProvisionInvitation? _userInvitation;
  bool _userTransferPending = false;
  String? _userTransferUserId;
  VerifiedPeerMembership? _userTransferPeer;
  List<CompanyUserChoice> _provisionUsers = const [];
  String? _provisionUserId;
  CompanyUserProvisionStatus? _provisionStatus;
  int _provisionSelectionEpoch = 0;
  bool _additionalUserDisabled = false;
  bool _userReceiving = false;
  Timer? _jobAvailabilityTimer;
  String? _lastConfirmedJobSync;
  CompanyJoinPreview? _preview;
  String? _error;
  String _status = 'Pair and compare the code on both devices.';
  bool _busy = false;
  bool _activated = false;
  bool _confirmed = false;
  bool _closed = false;
  bool get _approving => widget.approver != null && !widget.reconnect;

  String _provisionLabel(CompanyUserChoice user) {
    final duplicateName =
        _provisionUsers.where((other) => other.name == user.name).length > 1;
    return '${user.name} — ${duplicateName ? '${user.userId} — ' : ''}'
        'Create Job only${user.disabled ? ' (disabled)' : ''}';
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _join = CompanyJoin(enrollment: widget.enrollment);
    _authentication = CompanyPeerAuthentication(enrollment: widget.enrollment);
    final alias = const Uuid().v4();
    _controller =
        widget.createController?.call(alias) ??
        NearbyController(
          deviceId: alias,
          deviceName: 'Nearby ${alias.substring(0, 6)}',
          discovery: LanNearbyDiscovery(),
          companyJoin: true,
        );
    _controller.onJoinMessage = _receive;
    _subscription = _controller.states.listen((_) {
      if (mounted) setState(() {});
    });
    _run(() async {
      if (widget.reconnect) {
        final peers = await _authentication.retainedPeers(
          session: widget.approver!,
        );
        final users = widget.approver!.identity.isAuthorityOwner
            ? await widget.enrollment.listCompanyUsers()
            : <CompanyUserChoice>[];
        if (mounted) {
          setState(() {
            _retained = peers;
            final additional = users.skip(1).toList();
            if (additional.every(
                  (user) =>
                      user.userId.isNotEmpty &&
                      user.capabilities.length == 1 &&
                      user.capabilities.single == 'createJob',
                ) &&
                users.map((user) => user.userId).toSet().length ==
                    users.length) {
              _provisionUsers = additional;
            }
          });
        }
      }
      await _controller.start();
    });
  }

  Future<NearbyJoinChannel> _currentChannel(NearbyPairedJoinSession pair) {
    if (!mounted || _closed) {
      throw const CompanyBootstrapRefusal('Join is closed');
    }
    pair.requireCurrent();
    if (identical(pair, _pair)) return _channelPending!;
    _channel?.close();
    _jobAvailabilityTimer?.cancel();
    _jobSync?.close();
    _jobSync = null;
    _peerMembership = null;
    _userInvitation = null;
    _userTransferPending = false;
    _userTransferUserId = null;
    _userTransferPeer = null;
    _channel = null;
    _pair = pair;
    _request = null;
    _preview = null;
    _confirmed = false;
    // All first users of this actual Pair share its single derivation.
    return _channelPending = NearbyJoinChannel.fromPairedSession(pair)
        .then((channel) {
          if (!mounted || _closed || !identical(pair, _pair)) {
            channel.close();
            throw const CompanyBootstrapRefusal('Join connection changed');
          }
          try {
            pair.requireCurrent();
          } catch (_) {
            channel.close();
            rethrow;
          }
          _channel = channel;
          return channel;
        });
  }

  Future<Map<String, Object?>> _receive(
    NearbyPairedJoinSession pair,
    Map<String, Object?> wire,
  ) async {
    if (widget.reconnect && wire['kind'] == 'created-jobs') {
      if (_userTransferPending || _userReceiving) {
        throw const CompanyBootstrapRefusal(
          'Finish user provisioning before exchanging Jobs',
        );
      }
      const CreatedJobSyncDiagnostic.receiverEntered().notify(
        widget.onJobSyncDiagnostic,
      );
      late CompanyCreatedJobSync sync;
      try {
        await _currentChannel(pair);
        final current = _jobSync;
        if (current == null) {
          throw const CompanyBootstrapRefusal('Enable manual Job sync first');
        }
        sync = current;
      } catch (error) {
        final result = CreatedJobSyncResult(
          0,
          0,
          false,
          0,
          failure: CreatedJobSyncFailure.fromError(
            error,
            CreatedJobSyncStage.channel,
          ),
        );
        if (mounted && !_closed) setState(() => _status = result.message);
        CreatedJobSyncDiagnostic.terminal(
          result,
          receiverCallbackReached: true,
        ).notify(widget.onJobSyncDiagnostic);
        rethrow;
      }
      final receiving = sync.receive(wire);
      if (mounted && !_closed) setState(() {});
      try {
        return await receiving;
      } finally {
        if (mounted && !_closed) setState(() {});
      }
    }
    final channel = await _currentChannel(pair);
    if (widget.reconnect) {
      if ([
        'user-provision-invite',
        'user-provision-request',
        'user-provision-bundle',
        'user-provision-ack',
      ].contains(wire['kind'])) {
        return _receiveUser(wire);
      }
      Map<String, Object?>? reply;
      if (wire['kind'] == 'peer-init') {
        reply = await _authentication.receivePeerChallenge(
          channel,
          wire,
          session: widget.approver!,
        );
      } else if (wire['kind'] == 'peer-response') {
        reply = await _authentication.receivePeerResponse(channel, wire);
      } else if (wire['kind'] == 'peer-complete') {
        final result = await _authentication.receivePeerCompletion(
          channel,
          wire,
        );
        await result.membership.requireCurrent();
        _peerMembership = result.membership;
        reply = result.acknowledgment;
        if (mounted) {
          setState(
            () =>
                _status = 'Trusted peer authenticated. Confirming completion.',
          );
        }
      } else if (wire['kind'] == 'peer-ack') {
        final membership = await _authentication.receivePeerAcknowledgment(
          channel,
          wire,
        );
        await membership.requireCurrent();
        _peerMembership = membership;
        if (mounted) {
          setState(
            () => _status = 'Trusted peer authenticated. Verification alone does not exchange Jobs.',
          );
        }
      } else {
        throw const CompanyBootstrapRefusal('Unexpected peer proof');
      }
      // Let the incoming HTTP request finish. The controller's existing queue
      // owns outbound sequence order, including this reply and completion.
      if (reply != null) unawaited(_sendPeerReply(reply));
    } else if (_approving && wire['kind'] == 'request') {
      final request = await _join.receiveJoinRequest(channel, wire);
      if (_request != null) {
        throw const CompanyBootstrapRefusal(
          'Finish the current approval first',
        );
      }
      if (!mounted) throw const CompanyBootstrapRefusal('Join is closed');
      setState(() {
        _request = request;
        _status = 'Review this installation before approving.';
      });
    } else if (!_approving && wire['kind'] == 'provision') {
      final preview = await _join.receiveProvision(channel, wire);
      if (!mounted) throw const CompanyBootstrapRefusal('Join is closed');
      setState(() {
        _preview = preview;
        _status = 'Review the company and choose whether to join.';
      });
    } else if (_approving && wire['kind'] == 'ack') {
      await _join.acknowledgeJoin(
        channel,
        wire,
        ownerSession: widget.approver!,
      );
      if (mounted) {
        setState(() {
          _confirmed = true;
          _status = 'The other installation confirmed activation.';
        });
      }
    } else {
      throw const CompanyBootstrapRefusal('Unexpected Join message');
    }
    return {'ok': true};
  }

  Future<void> _sendPeerReply(Map<String, Object?> wire) async {
    final peerReply =
        wire['kind'] == 'peer-response' ||
        wire['kind'] == 'peer-complete' ||
        wire['kind'] == 'peer-ack';
    final pair = _pair;
    final channel = _channel;
    final membership = _peerMembership;
    final status = _status;
    final error = _error;
    bool ownsStatus() =>
        mounted &&
        !_closed &&
        identical(pair, _pair) &&
        identical(pair, _controller.pairedJoinSession) &&
        identical(channel, _channel) &&
        identical(membership, _peerMembership) &&
        status == _status &&
        error == _error;
    Future<bool> currentPeerReply() async {
      if (pair == null || !ownsStatus()) return false;
      try {
        pair.requireCurrent();
        if (wire['kind'] == 'peer-ack') {
          await membership?.requireCurrent();
        }
        return ownsStatus();
      } catch (_) {
        return false;
      }
    }

    try {
      await _controller.sendJoinMessage(wire);
      if (wire['kind'] == 'peer-ack' &&
          membership != null &&
          await currentPeerReply()) {
        setState(
          () => _status = 'Trusted peer authenticated. Verification alone does not exchange Jobs.',
        );
      }
    } catch (failure) {
      if (mounted && (!peerReply || await currentPeerReply())) {
        setState(() => _error = '$failure');
      }
    }
  }

  void _requireTransferPeer(VerifiedPeerMembership peer, [String? userId]) {
    if (!mounted ||
        _closed ||
        !identical(_peerMembership, peer) ||
        (userId != null &&
            (_userTransferUserId != userId ||
                !identical(_userTransferPeer, peer)))) {
      throw const CompanyBootstrapRefusal('Selected user transfer changed');
    }
  }

  Future<Map<String, Object?>> _receiveUser(Map<String, Object?> wire) async {
    final peer = _peerMembership;
    if (peer == null || _userReceiving || (_jobSync?.isRunning ?? false)) {
      throw const CompanyBootstrapRefusal(
        'Finish the current exchange and verify the retained peer first',
      );
    }
    _userReceiving = true;
    try {
      if (wire['kind'] == 'user-provision-invite') {
        final invitation = await widget.enrollment
            .receiveUserProvisionInvitation(wire, peer: peer);
        _requireTransferPeer(peer);
        if (_userTransferPending && _userTransferUserId != invitation.userId) {
          throw const CompanyBootstrapRefusal(
            'Finish the selected user transfer first',
          );
        }
        if (mounted) {
          setState(() {
            _userInvitation = invitation;
            _userTransferPending = true;
            _userTransferUserId = invitation.userId;
            _userTransferPeer = peer;
            _status =
                'The company owner offers ${invitation.name}. Confirm to make this user available offline.';
          });
        }
      } else if (wire['kind'] == 'user-provision-request') {
        final target = _userTransferUserId;
        if (target == null || !identical(_userTransferPeer, peer)) {
          throw const CompanyBootstrapRefusal(
            'No selected user transfer is pending',
          );
        }
        final request = await widget.enrollment.receiveUserProvisionRequest(
          Map<String, Object?>.from(wire['data'] as Map),
          peer: peer,
        );
        _requireTransferPeer(peer, target);
        if (request.userId != target) {
          throw const CompanyBootstrapRefusal('User transfer target differs');
        }
        final provision = await widget.enrollment.prepareUserProvision(
          owner: widget.approver!,
          peer: peer,
          request: request,
        );
        _requireTransferPeer(peer, target);
        unawaited(
          _sendPeerReply({'kind': 'user-provision-bundle', 'data': provision}),
        );
        if (mounted) {
          setState(() {
            _userTransferPending = true;
            _status = 'User provisioning saved locally. Waiting for durable confirmation from the other installation.';
          });
        }
      } else if (wire['kind'] == 'user-provision-bundle') {
        final target = _userTransferUserId;
        final invitation = _userInvitation;
        if (target == null ||
            (invitation != null && invitation.userId != target) ||
            !identical(_userTransferPeer, peer)) {
          throw const CompanyBootstrapRefusal(
            'No accepted user transfer is pending',
          );
        }
        final ack = await widget.enrollment.acceptUserProvision(
          Map<String, Object?>.from(wire['data'] as Map),
          peer: peer,
        );
        _requireTransferPeer(peer, target);
        unawaited(_sendPeerReply(ack));
        if (mounted) {
          setState(() {
            _userTransferPending = false;
            _userInvitation = null;
            _status = 'Additional user saved on this installation. Close this page and switch user to sign in offline.';
          });
        }
      } else {
        final target = _userTransferUserId;
        if (target == null || !identical(_userTransferPeer, peer)) {
          throw const CompanyBootstrapRefusal(
            'No selected user receipt is pending',
          );
        }
        await widget.enrollment.acceptUserProvisionReceipt(
          wire,
          peer: peer,
          userId: target,
        );
        final status = await widget.enrollment.userProvisionStatus(
          widget.approver!,
          userId: target,
        );
        _requireTransferPeer(peer, target);
        if (mounted) {
          setState(() {
            _userTransferPending = false;
            _provisionStatus = status;
            _status = 'The retained installation confirmed the additional user is saved. Repeating this transfer preserves PIN attempts.';
          });
        }
      }
      return {'ok': true};
    } finally {
      _userReceiving = false;
    }
  }

  Future<void> _provisionUser() async {
    final peer = _peerMembership;
    final target = _provisionUserId;
    final status = _provisionStatus;
    if (peer == null ||
        target == null ||
        status == null ||
        status.userId != target ||
        status.disabled ||
        _userReceiving ||
        (_jobSync?.isRunning ?? false) ||
        (_userTransferPending &&
            (_userTransferUserId != target ||
                !identical(_userTransferPeer, peer)))) {
      throw const CompanyBootstrapRefusal(
        'Verify this retained peer and finish the current Job exchange first',
      );
    }
    final alreadyPending = _userTransferPending;
    _userTransferUserId = target;
    _userTransferPeer = peer;
    _userTransferPending = true;
    late final Map<String, Object?> invitation;
    try {
      invitation = await widget.enrollment.prepareUserProvisionInvitation(
        owner: widget.approver!,
        peer: peer,
        userId: target,
      );
      _requireTransferPeer(peer, target);
    } catch (_) {
      if (!alreadyPending &&
          _userTransferUserId == target &&
          identical(_userTransferPeer, peer)) {
        _userTransferPending = false;
        _userTransferUserId = null;
        _userTransferPeer = null;
      }
      rethrow;
    }
    await _controller.sendJoinMessage(invitation);
    if (mounted &&
        !_closed &&
        identical(_peerMembership, peer) &&
        _userTransferUserId == target &&
        _userTransferPending) {
      setState(() {
        _userTransferPending = true;
        _status = 'Waiting for the other installation to confirm the additional user. After interruption, reconnect and retry this transfer.';
      });
    }
  }

  Future<void> _selectProvisionUser(String? userId) async {
    if (_busy ||
        _userReceiving ||
        _userTransferPending ||
        (_jobSync?.isRunning ?? false) ||
        !_provisionUsers.any((user) => user.userId == userId)) {
      return;
    }
    final epoch = ++_provisionSelectionEpoch;
    setState(() {
      _provisionUserId = userId;
      _provisionStatus = null;
      _userTransferUserId = null;
      _userTransferPeer = null;
      _additionalUserDisabled = false;
    });
    await _run(() async {
      final status = await widget.enrollment.userProvisionStatus(
        widget.approver!,
        userId: userId!,
      );
      if (mounted &&
          !_closed &&
          epoch == _provisionSelectionEpoch &&
          userId == _provisionUserId &&
          status?.userId == userId) {
        setState(() {
          _provisionStatus = status;
          _additionalUserDisabled = status!.disabled;
        });
      }
    });
  }

  Future<void> _acceptUserInvitation() async {
    final invitation = _userInvitation;
    if (invitation == null || (_jobSync?.isRunning ?? false)) return;
    final request = await widget.enrollment.acceptUserProvisionInvitation(
      invitation,
    );
    if (mounted) {
      setState(
        () => _status = 'Confirmed this user and installation. Waiting for protected provisioning.',
      );
    }
    await _controller.sendJoinMessage({
      'kind': 'user-provision-request',
      'data': request,
    });
  }

  Future<void> _enableJobSync() async {
    if (_userTransferPending ||
        _userReceiving ||
        (_jobSync?.isRunning ?? false)) {
      throw const CompanyBootstrapRefusal('A Job exchange is already running');
    }
    final peer = _peerMembership;
    if (peer == null) {
      throw const CompanyBootstrapRefusal('Verify the retained peer first');
    }
    final available = await CompanyJobSyncAvailability.open(
      enrollment: widget.enrollment,
      owner: widget.approver!,
      peer: peer,
    );
    if (!mounted || _closed || (_jobSync?.isRunning ?? false)) {
      available.close();
      return;
    }
    _jobSync?.close();
    final sync = _jobSync = CompanyCreatedJobSync(
      availability: available,
      controller: _controller,
      onDiagnostic: (diagnostic) =>
          diagnostic.notify(widget.onJobSyncDiagnostic),
      onStatus: (status) {
        if (mounted && !_closed) {
          setState(() {
            _status = status;
            if (status.startsWith('Job snapshot synced.')) {
              _lastConfirmedJobSync = status;
            }
          });
        }
      },
    );
    _jobAvailabilityTimer?.cancel();
    final remaining =
        _controller.pairedJoinSession?.timeUntilExpiry ?? Duration.zero;
    _jobAvailabilityTimer = Timer(
      remaining + const Duration(milliseconds: 1),
      () {
        if (mounted && !_closed && identical(_jobSync, sync)) {
          setState(() {});
        }
      },
    );
    setState(
      () => _status = 'Ready to exchange Jobs with this verified peer while this page is open and unlocked. Either device can choose Sync Now.',
    );
  }

  Future<void> _syncJobs() async {
    if (_userTransferPending || _userReceiving) {
      throw const CompanyBootstrapRefusal(
        'Finish user provisioning before exchanging Jobs',
      );
    }
    final sync = _jobSync;
    if (sync == null) {
      throw const CompanyBootstrapRefusal('Enable manual Job sync first');
    }
    setState(
      () => _status = 'Exchanging offline-created Jobs in both directions.',
    );
    final result = await sync.syncNow();
    if (mounted && !_closed) setState(() => _status = result.message);
  }

  Future<void> _challenge() async {
    final pair = _controller.pairedJoinSession;
    if (pair == null || _selected == null) {
      throw const CompanyBootstrapRefusal(
        'Select a retained peer and pair first',
      );
    }
    final channel = await _currentChannel(pair);
    final wire = await _authentication.beginPeerChallenge(
      channel,
      _selected!,
      session: widget.approver!,
    );
    if (mounted) {
      setState(
        () => _status = 'Checking the selected retained peer. The first encrypted signature may identify this installation to that endpoint.',
      );
    }
    await _controller.sendJoinMessage(wire);
  }

  Future<void> _run(Future<void> Function() work) async {
    if (_busy) return;
    if (mounted) {
      setState(() {
        _busy = true;
        _error = null;
      });
    }
    try {
      await work();
    } catch (error) {
      if (mounted) setState(() => _error = '$error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _requestJoin() async {
    final pair = _controller.pairedJoinSession;
    if (pair == null) {
      throw const CompanyBootstrapRefusal('Compare and match the code first');
    }
    final channel = await _currentChannel(pair);
    await _controller.sendJoinMessage(await _join.beginJoin(channel));
    if (mounted) {
      setState(
        () => _status = 'Waiting for explicit approval on the company device.',
      );
    }
  }

  Future<void> _approve() async {
    final wire = await _join.approveJoin(
      _channel!,
      _request!,
      ownerSession: widget.approver!,
    );
    if (mounted) {
      setState(
        () => _status = 'Provision prepared locally. Waiting for the other installation to consent.',
      );
    }
    await _controller.sendJoinMessage(wire);
  }

  Future<void> _accept() async {
    await _join.acceptProvision(_preview!);
    if (mounted) {
      setState(() {
        _activated = true;
        _status = 'Joined locally. Sending activation confirmation.';
      });
    }
    await _acknowledge();
  }

  Future<void> _acknowledge() async {
    await _controller.sendJoinMessage(
      await _join.activationAcknowledgment(_channel!),
    );
    if (mounted) {
      setState(() {
        _confirmed = true;
        _status = 'Joined. Sign in with the existing company PIN. Reconnect to the trusted peer and enable Job availability to use Sync Now.';
      });
    }
  }

  Future<void> _cancel() async {
    _jobAvailabilityTimer?.cancel();
    await _jobSync?.closeAndDrain();
    _channel?.close();
    await _controller.stop();
    if (mounted) Navigator.of(context).pop(_activated);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) {
      _jobAvailabilityTimer?.cancel();
      _jobSync?.close();
      _channel?.close();
      _controller.stop(
        reason: switch (state) {
          AppLifecycleState.inactive => NearbyTransportStopReason.inactive,
          AppLifecycleState.hidden => NearbyTransportStopReason.hidden,
          AppLifecycleState.paused => NearbyTransportStopReason.paused,
          AppLifecycleState.detached => NearbyTransportStopReason.detached,
          AppLifecycleState.resumed => NearbyTransportStopReason.requested,
        },
      );
      if (mounted) {
        setState(() {
          _closed = true;
          _request = null;
          _preview = null;
          _retained = const [];
          _selected = null;
        });
      }
    }
  }

  @override
  void dispose() {
    _jobAvailabilityTimer?.cancel();
    _jobSync?.close();
    WidgetsBinding.instance.removeObserver(this);
    _channel?.close();
    _controller.onJoinMessage = null;
    _subscription?.cancel();
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_closed) {
      return Scaffold(
        appBar: AppBar(title: const Text('Company connection closed')),
        body: Center(
          child: TextButton(
            onPressed: _cancel,
            child: const Text('Return and sign in to pair again'),
          ),
        ),
      );
    }
    final state = _controller.state;
    final jobsLive = _jobSync?.isLive ?? false;
    return Scaffold(
      appBar: AppBar(
        title: Text(
          widget.reconnect
              ? 'Verify retained company peer'
              : _approving
              ? 'Approve company device'
              : 'Join company nearby',
        ),
      ),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          const Text(
            'Use the same Wi-Fi. Match establishes a private channel; company access still requires approval and consent.',
          ),
          Text(_status, key: const Key('company-join-status')),
          if (_busy)
            const LinearProgressIndicator(key: Key('company-join-busy')),
          if (_lastConfirmedJobSync case final confirmed?)
            if (_status != confirmed || !jobsLive)
              Text(
                'Last successful exchange: $confirmed',
                key: const Key('company-jobs-last-confirmed'),
              ),
          if (_jobSync != null && !jobsLive)
            const Text(
              'This connection is no longer available. Pair again and verify the company device.',
            ),
          if (_error ?? state.error case final error?)
            Text(error, key: const Key('company-join-error')),
          if (state.verifyCode case final code?) ...[
            Text(code, key: const Key('company-join-code')),
            const Text('Compare this code in person on both devices.'),
            FilledButton(
              key: const Key('company-join-match'),
              onPressed: _busy ? null : () => _run(_controller.confirmCode),
              child: const Text('Codes match'),
            ),
            TextButton(
              onPressed: _busy ? null : () => _run(_controller.rejectCode),
              child: const Text('Codes differ'),
            ),
          ],
          for (final peer in state.peers)
            ListTile(
              title: Text(peer.name),
              trailing: OutlinedButton(
                key: ValueKey('company-join-pair-${peer.deviceId}'),
                onPressed: _busy
                    ? null
                    : () => _run(() => _controller.pair(peer)),
                child: const Text('Pair'),
              ),
            ),
          if (widget.reconnect) ...[
            const Text(
              'Choose a previously approved installation. Starting verification sends one encrypted installation signature before the endpoint is authenticated. This does not introduce unknown peers or sync Jobs.',
            ),
            for (final peer in _retained)
              ListTile(
                key: ValueKey('company-peer-${peer.deviceId}'),
                title: Text(peer.deviceId),
                subtitle: Text(peer.fingerprint),
                selected: identical(_selected, peer),
                onTap: _busy ? null : () => setState(() => _selected = peer),
              ),
            FilledButton(
              key: const Key('company-peer-verify'),
              onPressed:
                  _busy ||
                      _selected == null ||
                      _controller.pairedJoinSession == null
                  ? null
                  : () => _run(_challenge),
              child: const Text('Verify selected retained peer'),
            ),
            if (_peerMembership != null &&
                widget.approver!.identity.isAuthorityOwner &&
                _provisionUsers.isNotEmpty) ...[
              DropdownButtonFormField<String>(
                key: const Key('company-provision-user-selector'),
                isExpanded: true,
                isDense: false,
                itemHeight: null,
                initialValue: _provisionUserId,
                decoration: const InputDecoration(
                  labelText: 'Additional user to provision',
                ),
                items: [
                  for (final user in _provisionUsers)
                    DropdownMenuItem(
                      value: user.userId,
                      child: Text(_provisionLabel(user)),
                    ),
                ],
                onChanged:
                    _busy ||
                        _userReceiving ||
                        _userTransferPending ||
                        (_jobSync?.isRunning ?? false)
                    ? null
                    : (value) => _selectProvisionUser(value),
              ),
              if (_provisionStatus case final status?)
                Text(
                  status.disabled
                      ? 'Selected user is disabled. Reconnect and Sync Now to deliver the decision.'
                      : status.targetDeviceId == null
                      ? 'Selected user has not been provisioned to a retained peer.'
                      : status.confirmed
                      ? 'Selected user provisioning is confirmed. Repeating it preserves PIN attempts.'
                      : 'Selected user provisioning is pending. Retry with the same retained peer.',
                ),
              OutlinedButton(
                key: const Key('company-user-provision'),
                onPressed:
                    _busy ||
                        _userReceiving ||
                        (_jobSync?.isRunning ?? false) ||
                        _provisionStatus == null ||
                        _additionalUserDisabled
                    ? null
                    : () => _run(_provisionUser),
                child: Text(
                  _userTransferPending
                      ? 'Retry same additional user transfer'
                      : 'Provision additional user to this peer',
                ),
              ),
            ],
            if (_userInvitation case final invitation?) ...[
              Text(
                'Additional user: ${invitation.name}. Create Job permission only.',
              ),
              FilledButton(
                key: const Key('company-user-provision-accept'),
                onPressed:
                    _busy || _userReceiving || (_jobSync?.isRunning ?? false)
                    ? null
                    : () => _run(_acceptUserInvitation),
                child: const Text('Accept this additional user'),
              ),
            ],
            if (_peerMembership != null && (_jobSync == null || !jobsLive))
              FilledButton(
                key: const Key('company-jobs-enable-sync'),
                onPressed: _busy || (_jobSync?.isRunning ?? false)
                    ? null
                    : () => _run(_enableJobSync),
                child: const Text('Make Jobs available to this verified peer'),
              ),
            if (_jobSync != null)
              FilledButton(
                key: const Key('company-jobs-sync-now'),
                onPressed: _busy || !jobsLive || (_jobSync?.isRunning ?? false)
                    ? null
                    : () => _run(_syncJobs),
                child: const Text('Sync Now'),
              ),
          ],
          if (!widget.reconnect &&
              !_approving &&
              _controller.pairedJoinSession != null &&
              _preview == null &&
              !_activated)
            FilledButton(
              key: const Key('company-join-request'),
              onPressed: _busy ? null : () => _run(_requestJoin),
              child: const Text('Request company approval'),
            ),
          if (_approving && _request != null) ...[
            Text(
              'Installation fingerprint: ${_request!.recipientFingerprint}',
              key: const Key('company-join-recipient'),
            ),
            Text(
              'Enroll this installation for ${widget.approver!.identity.name} as the existing company user. Its PIN stays the same. It cannot enroll others.',
            ),
            FilledButton(
              key: const Key('company-join-approve'),
              onPressed: _busy || _confirmed ? null : () => _run(_approve),
              child: const Text('Approve this installation'),
            ),
            TextButton(
              key: const Key('company-join-deny'),
              onPressed: _busy ? null : () => _run(_cancel),
              child: const Text('Deny and close'),
            ),
          ],
          if (!_approving && _preview != null) ...[
            Text(
              _preview!.identity.name,
              key: const Key('company-join-company'),
            ),
            Text(
              'Company: ${_preview!.identity.companyId}\nUser: ${_preview!.identity.userId}',
            ),
            const Text(
              'Only company identity and the existing PIN credential are provisioned. No Jobs, Parts, photos or authority recovery seed are copied. Local continuity cannot know unseen offline revocations.',
            ),
            if (!_activated)
              FilledButton(
                key: const Key('company-join-consent'),
                onPressed: _busy ? null : () => _run(_accept),
                child: const Text('Join this company'),
              ),
            if (_activated && !_confirmed)
              FilledButton(
                key: const Key('company-join-ack-retry'),
                onPressed: _busy ? null : () => _run(_acknowledge),
                child: const Text('Retry activation confirmation'),
              ),
          ],
          TextButton(
            key: const Key('company-join-close'),
            onPressed: _busy ? null : () => _run(_cancel),
            child: Text(_activated ? 'Continue to sign in' : 'Close Join'),
          ),
        ],
      ),
    );
  }
}

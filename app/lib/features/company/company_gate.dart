import 'dart:io';
import 'dart:async';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:uuid/uuid.dart';

import '../../data/app_database.dart';
import '../installation/installation_security.dart';
import '../shell/home_shell.dart';
import '../nearby/nearby_controller.dart';
import 'company_bootstrap.dart';
import 'company_jobs_panel.dart';
import 'company_join_page.dart';
import '../job_line_commands/job_line_commands.dart';

/// Replaces the legacy navigator root once this store has company authority.
/// The company workspace deliberately has no legacy business writer routes.
class CompanyBootstrapGate extends StatefulWidget {
  const CompanyBootstrapGate({
    required this.db,
    required this.installation,
    this.photosDirectory,
    this.supportDirectory,
    this.pickRecoveryPath,
    this.pickSourcePath,
    this.createJoinController,
    super.key,
  });

  final AppDatabase db;
  final InstallationSecurity installation;
  final Directory? photosDirectory;
  final Directory? supportDirectory;
  final Future<String?> Function()? pickRecoveryPath;
  final Future<String?> Function()? pickSourcePath;
  final NearbyController Function(String encounterAlias)? createJoinController;

  @override
  State<CompanyBootstrapGate> createState() => _CompanyBootstrapGateState();
}

class _CompanyBootstrapGateState extends State<CompanyBootstrapGate>
    with WidgetsBindingObserver {
  late final CompanyEnrollment _enrollment;
  final _name = TextEditingController();
  final _pin = TextEditingController();
  final _passphrase = TextEditingController();
  final _passphraseConfirmation = TextEditingController();
  final _sourcePassphrase = TextEditingController();
  CompanyBootstrapStatus? _status;
  CompanySession? _session;
  List<CompanyUserChoice> _users = const [];
  String? _selectedUser;
  String? _managedUserId;
  int _userLoadEpoch = 0;
  final _userName = TextEditingController();
  final _userPin = TextEditingController();
  final _replacementPin = TextEditingController();
  String? _userResetRequest;
  int? _userResetExpected;
  String? _userResetPin;
  String? _userResetTarget;
  String? _userCreateRequest;
  String? _userDisableRequest;
  String? _userDisableTarget;
  CompanyUserLifecycleStatus? _userLifecycle;
  String? _error;
  String? _recoveryPath;
  String? _sourcePath;
  bool _recovering = false;
  bool _localContinuity = false;
  bool _authorityOnly = false;
  bool _legacy = false;
  bool _busy = false;
  Timer? _expiryTimer;
  bool _foreground = true;
  int _loginIntentEpoch = 0;
  int _jobsViewEpoch = 0;

  List<CompanyUserChoice> get _additionalUsers => _users.skip(1).toList();
  bool get _userDirectoryValid =>
      _users.isNotEmpty &&
      _additionalUsers.every(
        (user) =>
            user.userId.isNotEmpty &&
            user.capabilities.length == 1 &&
            user.capabilities.single == 'createJob',
      ) &&
      _users.map((user) => user.userId).toSet().length == _users.length;
  CompanyUserChoice? get _managedUser {
    if (!_userDirectoryValid) return null;
    final matches = _additionalUsers
        .where((user) => user.userId == _managedUserId)
        .toList();
    return matches.length == 1 ? matches.single : null;
  }

  bool get _managementPending =>
      _userResetRequest != null || _userDisableRequest != null;

  String _managementLabel(CompanyUserChoice user) {
    final duplicateName =
        _additionalUsers.where((other) => other.name == user.name).length > 1;
    return '${user.name} — ${duplicateName ? '${user.userId} — ' : ''}'
        'Create Job only${user.disabled ? ' (disabled)' : ''}';
  }

  String _signInLabel(CompanyUserChoice user) {
    final duplicateName =
        _users.where((other) => other.name == user.name).length > 1;
    return '${user.name}${duplicateName ? ' — ${user.userId}' : ''}'
        '${user.disabled ? ' (disabled)' : ''}';
  }

  Future<void> _selectManagedUser(String? userId) async {
    if (_busy ||
        _managementPending ||
        !_userDirectoryValid ||
        !_additionalUsers.any((user) => user.userId == userId)) {
      return;
    }
    setState(() {
      _managedUserId = userId;
      _userLifecycle = null;
      _replacementPin.clear();
      _error = null;
    });
    await _load();
  }

  @override
  void initState() {
    super.initState();
    _enrollment = CompanyEnrollment(
      installation: widget.installation,
      db: widget.db,
    );
    WidgetsBinding.instance.addObserver(this);
    _load();
  }

  @override
  void dispose() {
    _loginIntentEpoch++;
    WidgetsBinding.instance.removeObserver(this);
    _expiryTimer?.cancel();
    _enrollment.signOut();
    _name.dispose();
    _pin.dispose();
    _passphrase.dispose();
    _passphraseConfirmation.dispose();
    _sourcePassphrase.dispose();
    _userName.dispose();
    _userPin.dispose();
    _replacementPin.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _foreground = true;
    } else {
      _foreground = false;
      _lock();
    }
  }

  Future<void> _lock() async {
    _loginIntentEpoch++;
    _expiryTimer?.cancel();
    if (mounted) setState(() => _session = null);
    await _enrollment.signOut();
    if (mounted) await _load();
  }

  Future<void> _joinNearby({bool reconnect = false}) async {
    final owner = _session;
    final joining =
        owner == null &&
        !reconnect &&
        (_status == CompanyBootstrapStatus.unjoined ||
            _status == CompanyBootstrapStatus.pendingJoin);
    if (!joining &&
        (owner is! OwnerSession ||
            !owner.isValid ||
            (!reconnect && !owner.identity.isAuthorityOwner))) {
      return;
    }
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => CompanyJoinPage(
          enrollment: _enrollment,
          approver: owner is OwnerSession ? owner : null,
          reconnect: reconnect,
          createController: widget.createJoinController,
        ),
      ),
    );
    if (mounted) {
      setState(() => _jobsViewEpoch++);
      await _load();
    }
  }

  void _scheduleExpiry(CompanySession session) {
    _expiryTimer?.cancel();
    final remaining = session.timeUntilExpiry;
    _expiryTimer = Timer(
      remaining > Duration.zero
          ? remaining + const Duration(milliseconds: 1)
          : Duration.zero,
      () {
        if (!mounted || !identical(_session, session)) return;
        if (!session.isValid) {
          _lock();
        } else {
          _scheduleExpiry(session);
        }
      },
    );
  }

  Future<Directory> _photos() async {
    if (widget.photosDirectory case final photos?) return photos;
    final support =
        widget.supportDirectory ?? await getApplicationSupportDirectory();
    return Directory(p.join(support.path, 'part_photos'));
  }

  Future<void> _load() async {
    final epoch = ++_userLoadEpoch;
    final managedUserId = _managedUserId;
    var status = await _enrollment.readStatus();
    final users = status == CompanyBootstrapStatus.active
        ? await _enrollment.listCompanyUsers()
        : <CompanyUserChoice>[];
    CompanyUserLifecycleStatus? lifecycle;
    if (status == CompanyBootstrapStatus.active &&
        managedUserId != null &&
        users.where((user) => user.userId == managedUserId).length == 1) {
      try {
        lifecycle = await _enrollment.userLifecycleStatus(
          userId: managedUserId,
        );
      } catch (_) {}
    }
    var legacy = status == CompanyBootstrapStatus.legacyUnsupported;
    if (status == CompanyBootstrapStatus.unjoined) {
      try {
        await CompanyBootstrap.preflightFreshShop(
          widget.db,
          photosDirectory: await _photos(),
        );
      } on CompanyBootstrapRefusal {
        // Recheck after preflight: a company marker may have caused refusal.
        status = await _enrollment.readStatus();
        legacy = status == CompanyBootstrapStatus.unjoined;
      } catch (_) {
        status = CompanyBootstrapStatus.needsRecovery;
      }
    }
    if (!mounted || epoch != _userLoadEpoch) return;
    setState(() {
      _users = users;
      _userLifecycle = lifecycle;
      if (!users.skip(1).any((user) => user.userId == _managedUserId)) {
        _managedUserId = null;
      }
      if (!users.any((u) => u.userId == _selectedUser && u.available)) {
        _selectedUser = users.where((u) => u.available).firstOrNull?.userId;
      }
    });
    _applyStatus(status, legacy: legacy);
  }

  void _applyStatus(CompanyBootstrapStatus status, {bool legacy = false}) {
    setState(() {
      _status = status;
      _legacy = legacy;
      if (status == CompanyBootstrapStatus.pendingRecovery) {
        _recovering = true;
      } else if (status == CompanyBootstrapStatus.pending) {
        _recovering = false;
      }
    });
  }

  Future<void> _continueLocalShop() async {
    final status = await _enrollment.readStatus();
    if (!mounted) return;
    _applyStatus(
      status,
      legacy:
          status == CompanyBootstrapStatus.unjoined ||
          status == CompanyBootstrapStatus.legacyUnsupported,
    );
  }

  Future<void> _refreshStatusAfterRefusal() async {
    final status = await _enrollment.readStatus();
    if (!mounted) return;
    _applyStatus(
      status,
      legacy: status == CompanyBootstrapStatus.legacyUnsupported,
    );
  }

  Future<void> _chooseSourcePath() async {
    try {
      final path = widget.pickSourcePath == null
          ? (await openFile(
              acceptedTypeGroups: const [
                XTypeGroup(
                  label: 'Wired Parts authority package',
                  extensions: ['wpca'],
                ),
              ],
            ))?.path
          : await widget.pickSourcePath!();
      if (mounted && path != null) {
        setState(() => _sourcePath = path);
      }
    } catch (_) {
      if (mounted) {
        setState(() => _error = 'Could not open the authority package.');
      }
    }
  }

  Future<void> _choosePath() async {
    try {
      final path = widget.pickRecoveryPath == null
          ? (await getSaveLocation(
              suggestedName: 'company-authority.wpca',
              acceptedTypeGroups: const [
                XTypeGroup(
                  label: 'Wired Parts authority package',
                  extensions: ['wpca'],
                ),
              ],
            ))?.path
          : await widget.pickRecoveryPath!();
      if (mounted && path != null) setState(() => _recoveryPath = path);
    } catch (_) {
      if (mounted) setState(() => _error = 'Could not choose a recovery file.');
    }
  }

  Future<void> _create() async {
    if (_busy) return;
    final loginIntent = _loginIntentEpoch;
    if (!_localContinuity || !_authorityOnly || _recoveryPath == null) {
      setState(
        () => _error = 'Choose local continuity, acknowledge the authority-only backup, and select a recovery file.',
      );
      return;
    }
    if (_passphrase.text.isEmpty ||
        _passphrase.text != _passphraseConfirmation.text) {
      setState(() => _error = 'Confirm the new recovery passphrase exactly.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await _enrollment.create(
        companyName: _name.text,
        policy: CompanyContinuityPolicy.localContinuity,
        pin: _pin.text,
        recoveryPassphrase: _passphrase.text,
        recoveryFile: File(_recoveryPath!),
        photosDirectory: await _photos(),
      );
      if (mounted) setState(() => _status = CompanyBootstrapStatus.active);
      if (!mounted || !_foreground || loginIntent != _loginIntentEpoch) {
        _pin.clear();
        _passphrase.clear();
        _passphraseConfirmation.clear();
        return;
      }
      final session = await _enrollment.signIn(_pin.text);
      final users = await _enrollment.listCompanyUsers();
      _pin.clear();
      _passphrase.clear();
      _passphraseConfirmation.clear();
      if (mounted && _foreground && loginIntent == _loginIntentEpoch) {
        setState(() {
          _session = session;
          _users = users;
          _selectedUser = session.identity.userId;
          _status = CompanyBootstrapStatus.active;
        });
        _scheduleExpiry(session);
      } else {
        await _enrollment.signOut();
      }
    } catch (error) {
      await _refreshStatusAfterRefusal();
      if (mounted) {
        setState(
          () => _error = error is CompanyBootstrapRefusal ? error.message : 'Company creation needs recovery or a retry with the same details.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _createUser() async {
    final owner = _session;
    if (_busy || owner is! OwnerSession || !owner.identity.isAuthorityOwner) {
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      _userCreateRequest ??= const Uuid().v4();
      await _enrollment.createRestrictedUser(
        owner: owner,
        requestId: _userCreateRequest!,
        name: _userName.text.trim(),
        pin: _userPin.text,
      );
      _userName.clear();
      _userPin.clear();
      _userCreateRequest = null;
      await _load();
    } on CompanyBootstrapRefusal catch (error) {
      if (mounted) setState(() => _error = error.message);
    } catch (_) {
      if (mounted) {
        setState(
          () => _error =
              'User creation may already be saved. Retry the same details.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _disableUser() async {
    final owner = _session;
    final user = _managedUser;
    if (_busy ||
        owner is! OwnerSession ||
        !owner.identity.isAuthorityOwner ||
        user == null ||
        user.disabled ||
        _userLifecycle?.userId != user.userId ||
        _userResetRequest != null ||
        (_userDisableTarget != null && _userDisableTarget != user.userId)) {
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      _userDisableRequest ??= const Uuid().v4();
      _userDisableTarget ??= user.userId;
      await _enrollment.disableRestrictedUser(
        owner: owner,
        userId: _userDisableTarget!,
        requestId: _userDisableRequest!,
      );
      _userDisableRequest = null;
      _userDisableTarget = null;
      await _load();
    } on CompanyBootstrapRefusal catch (error) {
      if (mounted) setState(() => _error = error.message);
    } catch (_) {
      if (mounted) {
        setState(
          () => _error = 'Disablement may already be saved. Retry or reopen the user status.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _resetUserPin() async {
    final owner = _session;
    final user = _managedUser;
    if (_busy ||
        owner is! OwnerSession ||
        !owner.identity.isAuthorityOwner ||
        user == null ||
        user.userId.isEmpty ||
        user.disabled ||
        _userLifecycle?.userId != user.userId ||
        _userDisableRequest != null ||
        (_userResetTarget != null && _userResetTarget != user.userId)) {
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      _userResetRequest ??= const Uuid().v4();
      _userResetTarget ??= user.userId;
      _userResetExpected ??= _userLifecycle!.credentialVersion;
      _userResetPin ??= _replacementPin.text;
      final receipt = await _enrollment.resetRestrictedUserPin(
        owner: owner,
        userId: _userResetTarget!,
        requestId: _userResetRequest!,
        expectedCredentialVersion: _userResetExpected!,
        pin: _userResetPin!,
      );
      _replacementPin.clear();
      _userResetRequest = null;
      _userResetExpected = null;
      _userResetPin = null;
      _userResetTarget = null;
      await _load();
      if (!receipt.isCurrent && mounted) {
        setState(
          () => _error = 'That earlier replacement was already recorded. The current PIN was not changed.',
        );
      }
    } on CompanyBootstrapRefusal catch (error) {
      if (mounted) setState(() => _error = error.message);
    } catch (_) {
      if (mounted) {
        setState(
          () => _error = 'PIN replacement may already be saved. Retry the same request and PIN or reopen user status.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _signIn() async {
    if (_busy) return;
    final loginIntent = _loginIntentEpoch;
    var ownerSelected =
        _selectedUser == null ||
        _users.isEmpty ||
        _selectedUser == _users.first.userId;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final users = await _enrollment.listCompanyUsers();
      final selected = _selectedUser ?? users.first.userId;
      ownerSelected = selected == users.first.userId;
      final session = await _enrollment.signInUser(selected, _pin.text);
      _pin.clear();
      if (mounted && _foreground && loginIntent == _loginIntentEpoch) {
        setState(() => _session = session);
        _scheduleExpiry(session);
      } else {
        await _enrollment.signOut();
      }
    } catch (_) {
      if (mounted) {
        setState(
          () => _error = ownerSelected
              ? 'Administrator PIN refused or company needs recovery.'
              : 'User PIN refused or this user needs provisioning.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _recover() async {
    if (_busy) return;
    final loginIntent = _loginIntentEpoch;
    if (!_localContinuity ||
        !_authorityOnly ||
        _sourcePath == null ||
        _recoveryPath == null) {
      setState(
        () => _error = 'Select the old authority package and a new recovery destination, then acknowledge local continuity and authority-only recovery.',
      );
      return;
    }
    if (_passphrase.text.isEmpty ||
        _passphrase.text != _passphraseConfirmation.text) {
      setState(() => _error = 'Confirm the new recovery passphrase exactly.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await _enrollment.recover(
        policy: CompanyContinuityPolicy.localContinuity,
        sourceFile: File(_sourcePath!),
        sourcePassphrase: _sourcePassphrase.text,
        newPin: _pin.text,
        newRecoveryPassphrase: _passphrase.text,
        newRecoveryFile: File(_recoveryPath!),
        photosDirectory: await _photos(),
      );
      if (mounted) setState(() => _status = CompanyBootstrapStatus.active);
      if (!mounted || !_foreground || loginIntent != _loginIntentEpoch) {
        _pin.clear();
        _passphrase.clear();
        _passphraseConfirmation.clear();
        _sourcePassphrase.clear();
        return;
      }
      final session = await _enrollment.signIn(_pin.text);
      _pin.clear();
      _passphrase.clear();
      _passphraseConfirmation.clear();
      _sourcePassphrase.clear();
      if (mounted && _foreground && loginIntent == _loginIntentEpoch) {
        setState(() {
          _session = session;
          _status = CompanyBootstrapStatus.active;
        });
        _scheduleExpiry(session);
      } else {
        await _enrollment.signOut();
      }
    } catch (error) {
      await _refreshStatusAfterRefusal();
      if (mounted) {
        setState(
          () => _error = error is CompanyBootstrapRefusal ? error.message : 'Recovery refused. Check the package and retry with the same details.',
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Widget _frame(String title, List<Widget> children) => Scaffold(
    appBar: AppBar(title: Text(title)),
    body: SafeArea(
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: ListView(
            key: ValueKey(
              'company-frame:$title:${_session?.sessionId ?? 'locked'}',
            ),
            padding: const EdgeInsets.all(20),
            children: [
              ...children,
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 16),
                  child: Text(
                    _error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    ),
  );

  @override
  Widget build(BuildContext context) {
    if (_status == null) {
      return _frame('Wired Parts', const [
        Center(child: CircularProgressIndicator()),
      ]);
    }
    if (_status == CompanyBootstrapStatus.needsRecovery) {
      return _frame('Company recovery needed', const [
        Text(
          'This installation cannot verify its company authority. Company data is locked. Keep the encrypted authority package and contact the company administrator for the supported recovery flow.',
        ),
      ]);
    }
    if (_status == CompanyBootstrapStatus.pendingJoin) {
      return _frame('Finish company Join', [
        const Text(
          'This installation has a consented Join awaiting completion. Pair again and ask the authorized company device to reapprove the same installation. It remains locked until activation finishes.',
        ),
        FilledButton(
          key: const Key('company-join-resume'),
          onPressed: _busy ? null : _joinNearby,
          child: const Text('Resume nearby Join'),
        ),
      ]);
    }
    if ((_status == CompanyBootstrapStatus.unjoined ||
            _status == CompanyBootstrapStatus.legacyUnsupported) &&
        _legacy) {
      return const HomeShell();
    }
    if (_status == CompanyBootstrapStatus.unjoined ||
        _status == CompanyBootstrapStatus.pending ||
        _status == CompanyBootstrapStatus.pendingRecovery) {
      return _frame(
        _status == CompanyBootstrapStatus.pendingRecovery
            ? 'Finish authority recovery'
            : _status == CompanyBootstrapStatus.pending
            ? 'Finish company setup'
            : _recovering
            ? 'Recover company authority'
            : 'Create company',
        [
          if (_status == CompanyBootstrapStatus.unjoined)
            OutlinedButton(
              key: const Key('company-join-open'),
              onPressed: _busy ? null : _joinNearby,
              child: const Text('Join an existing company nearby'),
            ),
          if (_status == CompanyBootstrapStatus.pending)
            const Text(
              'Enter the same company name and PIN, then select the recovery file destination to finish the pending setup.',
            ),
          if (_status == CompanyBootstrapStatus.pendingRecovery)
            const Text(
              'Select the same source package and enter the same new PIN and destinations to finish recovery.',
            ),
          if (_status == CompanyBootstrapStatus.unjoined)
            TextButton(
              key: const Key('switch-company-recovery'),
              onPressed: _busy
                  ? null
                  : () {
                      _passphrase.clear();
                      _passphraseConfirmation.clear();
                      _sourcePassphrase.clear();
                      setState(() => _recovering = !_recovering);
                    },
              child: Text(
                _recovering
                    ? 'Create a new company instead'
                    : 'Recover company authority on this new installation',
              ),
            ),
          if (!_recovering)
            TextField(
              key: const Key('company-name'),
              controller: _name,
              maxLength: 100,
              decoration: const InputDecoration(labelText: 'Company name'),
            ),
          if (_recovering)
            OutlinedButton(
              key: const Key('choose-source-package'),
              onPressed: _busy ? null : _chooseSourcePath,
              child: Text(
                _sourcePath == null
                    ? 'Open old authority package'
                    : 'Old authority package selected',
              ),
            ),
          if (_recovering)
            TextField(
              key: const Key('source-passphrase'),
              controller: _sourcePassphrase,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Old package passphrase',
              ),
            ),
          TextField(
            key: const Key('company-pin'),
            controller: _pin,
            obscureText: true,
            keyboardType: TextInputType.number,
            decoration: InputDecoration(
              labelText: _recovering
                  ? 'New administrator PIN'
                  : 'Administrator PIN',
            ),
          ),
          TextField(
            key: const Key('recovery-passphrase'),
            controller: _passphrase,
            obscureText: true,
            decoration: InputDecoration(
              labelText: _recovering
                  ? 'New recovery passphrase'
                  : 'Recovery passphrase',
            ),
          ),
          TextField(
            key: const Key('recovery-passphrase-confirm'),
            controller: _passphraseConfirmation,
            obscureText: true,
            decoration: const InputDecoration(
              labelText: 'Confirm new recovery passphrase',
            ),
          ),
          CheckboxListTile(
            key: const Key('local-continuity-consent'),
            value: _localContinuity,
            onChanged: _busy
                ? null
                : (value) => setState(() => _localContinuity = value ?? false),
            title: const Text('Use local continuity while offline'),
            subtitle: const Text(
              'An older offline copy may not know later revocations.',
            ),
          ),
          CheckboxListTile(
            key: const Key('authority-only-consent'),
            value: _authorityOnly,
            onChanged: _busy
                ? null
                : (value) => setState(() => _authorityOnly = value ?? false),
            title: const Text(
              'I understand the recovery file restores authority only',
            ),
            subtitle: const Text('It does not restore Parts, Jobs, or photos.'),
          ),
          OutlinedButton(
            onPressed: _busy ? null : _choosePath,
            child: Text(
              _recoveryPath == null
                  ? 'Choose encrypted recovery file'
                  : 'Recovery file destination selected',
            ),
          ),
          FilledButton(
            key: const Key('create-company'),
            onPressed: _busy
                ? null
                : _recovering
                ? _recover
                : _create,
            child: Text(
              _busy
                  ? 'Working…'
                  : _recovering
                  ? 'Recover authority'
                  : 'Create company',
            ),
          ),
          if (_status == CompanyBootstrapStatus.unjoined)
            TextButton(
              onPressed: _busy ? null : _continueLocalShop,
              child: const Text('Continue local shop'),
            ),
        ],
      );
    }
    final session = _session;
    if (session == null || !session.isValid) {
      return _frame('Company locked', [
        const Text('Select a company user and enter their PIN.'),
        DropdownButtonFormField<String>(
          key: const Key('company-user-selector'),
          isExpanded: true,
          isDense: false,
          itemHeight: null,
          initialValue: _selectedUser,
          decoration: const InputDecoration(labelText: 'Company user'),
          items: [
            for (final user in _users)
              DropdownMenuItem(
                value: user.userId,
                enabled: user.available,
                child: Text(_signInLabel(user)),
              ),
          ],
          onChanged: _busy
              ? null
              : (value) => setState(() {
                  _selectedUser = value;
                  _pin.clear();
                }),
        ),
        TextField(
          key: const Key('company-signin-pin'),
          controller: _pin,
          obscureText: true,
          keyboardType: TextInputType.number,
          decoration: const InputDecoration(labelText: 'Company PIN'),
        ),
        FilledButton(
          key: const Key('company-signin'),
          onPressed: _busy ? null : _signIn,
          child: const Text('Sign in'),
        ),
      ]);
    }
    final identity = session.identity;
    return _frame(identity.name, [
      const Text('Company authority is active on this installation.'),
      const SizedBox(height: 16),
      if (session is OwnerSession && identity.isAuthorityOwner)
        OutlinedButton(
          key: const Key('company-enroll-open'),
          onPressed: _busy ? null : _joinNearby,
          child: const Text('Approve a nearby company device'),
        ),
      if (session is OwnerSession)
        OutlinedButton(
          key: const Key('company-peer-open'),
          onPressed: _busy ? null : () => _joinNearby(reconnect: true),
          child: const Text('Verify a retained company peer'),
        ),
      Text('Company ID: ${identity.companyId}'),
      Text('Shop ID: ${identity.shopId}'),
      Text('User ID: ${identity.userId}'),
      Text('Device ID: ${identity.deviceId}'),
      const SizedBox(height: 16),
      if (session is RestrictedUserSession)
        const Text(
          'Create Job permission only. Sign in as the owner to exchange pending Jobs with a retained peer.',
        ),
      if (session is OwnerSession &&
          !identity.isAuthorityOwner &&
          _userLifecycle?.disabled == true)
        Text(
          '${_userLifecycle!.name} is disabled on this installation by the authority owner.',
        ),
      const SizedBox(height: 16),
      const Text(
        'Local continuity is selected. The encrypted authority package cannot restore shop data. Parts and Job line editing remain unavailable until their company-authorized migration.',
      ),
      const SizedBox(height: 16),
      CompanyJobsPanel(
        key: ValueKey('${session.sessionId}:$_jobsViewEpoch'),
        commands: CompanyJobCommands(enrollment: _enrollment),
        owner: session,
      ),
      const SizedBox(height: 16),
      if (session is OwnerSession && identity.isAuthorityOwner) ...[
        const Text(
          'Company users. Additional users have Create Job permission only.',
        ),
        for (final user in _users)
          Text(
            '${user.name}${user.disabled
                ? ' (disabled)'
                : user.available
                ? ''
                : ' (unavailable)'}',
          ),
        if (_userDirectoryValid && _additionalUsers.isNotEmpty)
          DropdownButtonFormField<String>(
            key: const Key('company-managed-user-selector'),
            isExpanded: true,
            isDense: false,
            itemHeight: null,
            initialValue: _managedUserId,
            decoration: const InputDecoration(
              labelText: 'Manage additional user',
            ),
            items: [
              for (final user in _additionalUsers)
                DropdownMenuItem(
                  value: user.userId,
                  child: Text(_managementLabel(user)),
                ),
            ],
            onChanged: _busy || _managementPending
                ? null
                : (value) => _selectManagedUser(value),
          ),
        if (!_userDirectoryValid)
          const Text(
            'Additional-user policy is unavailable. Management needs recovery.',
          ),
        if (_managedUser != null &&
            !_managedUser!.disabled &&
            _userLifecycle?.userId == _managedUserId)
          OutlinedButton(
            key: const Key('company-disable-user'),
            onPressed: _busy || _userResetRequest != null ? null : _disableUser,
            child: Text('Disable ${_managedUser!.name} permanently'),
          ),
        if (_managedUser != null &&
            !_managedUser!.disabled &&
            _userLifecycle?.userId == _managedUserId) ...[
          TextField(
            key: const Key('company-reset-pin'),
            controller: _replacementPin,
            enabled: !_busy && _userResetRequest == null,
            obscureText: true,
            keyboardType: TextInputType.number,
            decoration: InputDecoration(
              labelText: 'Replacement PIN for ${_managedUser!.name}',
            ),
          ),
          OutlinedButton(
            key: const Key('company-reset-user'),
            onPressed: _busy || _userDisableRequest != null
                ? null
                : _resetUserPin,
            child: Text('Replace PIN for ${_managedUser!.name}'),
          ),
          if (_userResetRequest != null) ...[
            const Text(
              'This PIN replacement request is pending. Retry uses the same chosen PIN. Review status before starting another request.',
            ),
            TextButton(
              onPressed: _busy
                  ? null
                  : () async {
                      setState(() {
                        _userResetRequest = null;
                        _userResetExpected = null;
                        _userResetPin = null;
                        _userResetTarget = null;
                        _replacementPin.clear();
                      });
                      await _load();
                    },
              child: const Text('Review status and start a new reset request'),
            ),
          ],
        ],
        if ((_userLifecycle?.credentialVersion ?? 1) > 1 &&
            _userLifecycle?.disabled == false)
          Text(
            _userLifecycle!.awaitingCredential
                ? 'Newer user PIN policy is saved. Protected credential material is pending; this user cannot sign in here.'
                : _userLifecycle!.confirmed
                ? 'Additional-user PIN replacement is saved and confirmed by the retained installation.'
                : 'Additional-user PIN replaced here. Remote confirmation is pending; disconnected devices retain their cached PIN. Verify the retained peer and Sync Now.',
          ),
        if (_userLifecycle?.disabled == true)
          Text(
            _userLifecycle!.confirmed
                ? 'Additional user disabled. The retained installation confirmed the decision.'
                : 'Additional user disabled here. Remote confirmation is pending; disconnected devices retain their cached rights. Verify the retained peer and Sync Now.',
          ),
        if (_userDisableRequest != null) ...[
          const Text(
            'This disable request is pending for the selected user. Retry the same request.',
          ),
          TextButton(
            onPressed: _busy
                ? null
                : () async {
                    setState(() {
                      _userDisableRequest = null;
                      _userDisableTarget = null;
                    });
                    await _load();
                  },
            child: const Text('Review selected user status'),
          ),
        ],
        if (_userDirectoryValid &&
            _additionalUsers.length < kCompanyUserCapacity) ...[
          TextField(
            key: const Key('company-user-name'),
            controller: _userName,
            decoration: const InputDecoration(
              labelText: 'Additional user name',
            ),
          ),
          TextField(
            key: const Key('company-user-pin'),
            controller: _userPin,
            obscureText: true,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(labelText: 'Additional user PIN'),
          ),
          FilledButton(
            key: const Key('company-create-user'),
            onPressed: _busy ? null : _createUser,
            child: const Text('Create restricted user'),
          ),
        ] else if (_userDirectoryValid)
          const Text(
            'Additional user capacity reached. Select a user on the retained peer page to provision them.',
          ),
      ],
      FilledButton(
        key: const Key('company-signout'),
        onPressed: _busy ? null : _lock,
        child: const Text('Sign out'),
      ),
      TextButton(
        key: const Key('company-switch-user'),
        onPressed: _busy ? null : _lock,
        child: const Text('Switch user'),
      ),
    ]);
  }
}

import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' show SemanticsRole;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wired_parts/features/company/company_gate.dart';
import 'package:wired_parts/features/company/company_bootstrap.dart';
import 'package:wired_parts/features/company/company_jobs_panel.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/job_line_commands/job_line_commands.dart';
import 'package:uuid/uuid.dart';

import 'company_join_test.dart' show JoinFixture;

Future<void> _wait(WidgetTester tester, Finder finder) async {
  for (var i = 0; i < 400 && finder.evaluate().isEmpty; i++) {
    await tester.runAsync(
      () async => Future<void>.delayed(const Duration(milliseconds: 25)),
    );
    await tester.pump(const Duration(milliseconds: 25));
  }
  expect(
    finder,
    findsOneWidget,
    reason: tester
        .widgetList<Text>(find.byType(Text))
        .map((t) => t.data ?? '')
        .join(' | '),
  );
}

Future<void> _manageUser(
  WidgetTester tester,
  String name, {
  String? userId,
}) async {
  final selector = find.byKey(const Key('company-managed-user-selector'));
  await tester.scrollUntilVisible(
    selector,
    200,
    scrollable: find.byType(Scrollable).first,
  );
  // Lay out ensureVisible's final scroll jump before computing the tap point.
  await tester.pump();
  expect(selector.hitTestable(), findsOneWidget);
  await tester.tap(selector);
  await tester.pump(const Duration(milliseconds: 300));
  final menu = find.byWidgetPredicate(
    (widget) =>
        widget is Semantics && widget.properties.role == SemanticsRole.menu,
  );
  await _wait(tester, menu);
  final menuScrollable = find.descendant(
    of: menu,
    matching: find.byType(Scrollable),
  );
  expect(menuScrollable, findsOneWidget);
  final option = find.descendant(
    of: menu,
    matching: find.text(
      '$name — ${userId == null ? '' : '$userId — '}Create Job only',
    ),
  );
  await tester.scrollUntilVisible(option, 80, scrollable: menuScrollable);
  await tester.pump();
  await _wait(tester, option);
  expect(option.hitTestable(), findsOneWidget);
  await tester.runAsync(() => tester.tap(option));
  await tester.pump();
  await _wait(tester, find.byKey(const Key('company-reset-user')));
}

void main() {
  testWidgets(
    'second-user ambiguous reset freezes target and PIN while first user stays unchanged',
    (tester) async {
      late JoinFixture f;
      late String userId;
      late String firstUserId;
      late ProtectedInstallationState firstProtected;
      await tester.runAsync(() async {
        f = await JoinFixture.create();
        firstUserId = (await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Casey retry',
          pin: '7890',
        )).userId;
        userId = (await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Casey retry',
          pin: '0123',
        )).userId;
        firstProtected = f.aStore.states[companyUserNamespace(f.a.namespace)]!;
        await f.aEnrollment.signOut();
      });
      await tester.pumpWidget(
        MaterialApp(
          home: CompanyBootstrapGate(db: f.aDb, installation: f.a),
        ),
      );
      await _wait(tester, find.byKey(const Key('company-signin')));
      final signInChoices = tester
          .widget<DropdownButton<String>>(
            find.descendant(
              of: find.byKey(const Key('company-user-selector')),
              matching: find.byWidgetPredicate(
                (widget) => widget is DropdownButton<String>,
              ),
            ),
          )
          .items!;
      for (final id in [firstUserId, userId]) {
        final item = signInChoices.singleWhere((item) => item.value == id);
        expect((item.child as Text).data, contains(id));
      }
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '1234',
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('Company ID:'));
      expect(find.byKey(const Key('company-reset-user')), findsNothing);
      await _manageUser(tester, 'Casey retry', userId: userId);
      final selectorCallback = tester
          .widget<DropdownButtonFormField<String>>(
            find.byKey(const Key('company-managed-user-selector')),
          )
          .onChanged!;
      await tester.scrollUntilVisible(
        find.byKey(const Key('company-reset-user')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await _wait(tester, find.byKey(const Key('company-reset-user')));
      await tester.scrollUntilVisible(
        find.byKey(const Key('company-reset-pin')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.enterText(
        find.byKey(const Key('company-reset-pin')),
        '4567',
      );
      await tester.runAsync(
        () => f.aDb.customStatement(
          "CREATE TRIGGER widget_projection_fault BEFORE INSERT ON company_user_events BEGIN SELECT RAISE(ABORT, 'synthetic projection fault'); END",
        ),
      );
      await tester.ensureVisible(find.byKey(const Key('company-reset-user')));
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-reset-user'))),
      );
      await tester.pump();
      await _wait(
        tester,
        find.byWidgetPredicate(
          (widget) =>
              widget is OutlinedButton &&
              widget.key == const Key('company-reset-user') &&
              widget.onPressed != null,
        ),
      );
      expect(
        find.textContaining('This PIN replacement request is pending.'),
        findsOneWidget,
      );
      expect(
        tester
            .widget<DropdownButtonFormField<String>>(
              find.byKey(const Key('company-managed-user-selector')),
            )
            .onChanged,
        isNull,
      );
      selectorCallback(firstUserId);
      await tester.pump();
      expect(
        tester
            .state<FormFieldState<String>>(
              find.byKey(const Key('company-managed-user-selector')),
            )
            .value,
        userId,
      );
      final field = tester.widget<TextField>(
        find.byKey(const Key('company-reset-pin')),
      );
      expect(field.enabled, isFalse);
      // Even programmatic controller edits cannot change an existing intent.
      field.controller!.text = '6789';
      await tester.runAsync(
        () => f.aDb.customStatement('DROP TRIGGER widget_projection_fault'),
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-reset-user'))),
      );
      await _wait(
        tester,
        find.textContaining('Additional-user PIN replaced here.'),
      );
      await tester.runAsync(() async {
        final events = await f.aDb.select(f.aDb.companyUserEvents).get();
        events.sort((a, b) => a.sequence.compareTo(b.sequence));
        expect(
          events.map((event) => (event.userId, event.sequence, event.kind)),
          [(userId, 1, 'created'), (userId, 2, 'pinReset')],
        );
        final savedFirst =
            f.aStore.states[companyUserNamespace(f.a.namespace)]!;
        expect(savedFirst.revision, firstProtected.revision);
        expect(
          base64Encode(savedFirst.bytes) == base64Encode(firstProtected.bytes),
          isTrue,
          reason: 'Untouched legacy user A retains its protected bytes',
        );
        final first = await f.aEnrollment.userLifecycleStatus(
          userId: firstUserId,
        );
        expect(first!.credentialVersion, 1);
        expect(first.attemptsRemaining, 8);
        expect(first.disabled, isFalse);
        await f.aEnrollment.signInUser(firstUserId, '7890');
        await expectLater(
          f.aEnrollment.signInUser(userId, '6789'),
          throwsA(isA<CompanyBootstrapRefusal>()),
        );
        await f.aEnrollment.signInUser(userId, '4567');
      });
      await tester.pumpWidget(const SizedBox());
    },
  );
  testWidgets(
    'Owner replaces a forgotten PIN through Gate and user signs in with replacement offline',
    (tester) async {
      late JoinFixture f;
      await tester.runAsync(() async {
        f = await JoinFixture.create(allowOwnerAdditions: true);
        await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Casey UI',
          pin: '0123',
        );
        await f.aEnrollment.signOut();
      });
      await tester.pumpWidget(
        MaterialApp(
          home: CompanyBootstrapGate(db: f.aDb, installation: f.a),
        ),
      );
      await _wait(tester, find.byKey(const Key('company-signin')));
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '1234',
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('Company ID:'));
      await _manageUser(tester, 'Casey UI');
      await tester.scrollUntilVisible(
        find.byKey(const Key('company-reset-user')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await _wait(tester, find.byKey(const Key('company-reset-user')));
      await tester.scrollUntilVisible(
        find.byKey(const Key('company-reset-pin')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.enterText(
        find.byKey(const Key('company-reset-pin')),
        '4567',
      );
      await tester.ensureVisible(find.byKey(const Key('company-reset-user')));
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-reset-user'))),
      );
      await _wait(
        tester,
        find.textContaining('Additional-user PIN replaced here.'),
      );
      await tester.scrollUntilVisible(
        find.byKey(const Key('company-switch-user')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-switch-user'))),
      );
      await _wait(tester, find.byKey(const Key('company-user-selector')));
      await tester.tap(find.byKey(const Key('company-user-selector')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Casey UI').last);
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '0123',
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('User PIN refused'));
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '4567',
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('Company ID:'));
      expect(find.byKey(const Key('company-reset-user')), findsNothing);
      expect(find.byKey(const Key('company-disable-user')), findsNothing);
      expect(find.byKey(const Key('company-enroll-open')), findsNothing);
      await tester.pumpWidget(const SizedBox());
    },
  );
  testWidgets(
    'damaged additional-user policy does not lock the owner Job list',
    (tester) async {
      late JoinFixture f;
      late String name;
      late String userId;
      await tester.runAsync(() async {
        f = await JoinFixture.create();
        userId = (await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Casey',
          pin: '0123',
        )).userId;
        name = (await f.aDb.select(f.aDb.jobs).get()).single.name;
        f.aStore.states[companyUserNamespace(
          f.a.namespace,
        )] = ProtectedInstallationState(
          const Uuid().v4(),
          Uint8List.fromList(utf8.encode('{"v":77}')),
        );
      });
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: CompanyJobsPanel(
                commands: CompanyJobCommands(enrollment: f.aEnrollment),
                owner: f.owner,
              ),
            ),
          ),
        ),
      );
      await _wait(tester, find.byKey(const Key('company-create-job')));
      expect(find.text(name), findsOneWidget);
      expect(
        find.textContaining('Additional-user policy is unavailable'),
        findsOneWidget,
      );
      await tester.runAsync(
        () => expectLater(
          f.aEnrollment.signInUser(userId, '0123'),
          throwsA(isA<CompanyBootstrapRefusal>()),
        ),
      );
      await tester.pumpWidget(const SizedBox());
    },
  );
  testWidgets(
    'owner sees the exact retained additional-user Job as held without an applied confirmation',
    (tester) async {
      late JoinFixture f;
      late OwnerSession owner;
      late String id;
      late String resetJobId;
      await tester.runAsync(() async {
        f = await JoinFixture.create(allowOwnerAdditions: true);
        final user = await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Casey',
          pin: '0123',
        );
        final selected = await f.aEnrollment.signInUser(user.userId, '0123');
        id = const Uuid().v4();
        await CompanyJobCommands(enrollment: f.aEnrollment).createJob(
          CreateJob(
            companyId: selected.identity.companyId,
            shopId: selected.identity.shopId,
            jobId: id,
            requestId: const Uuid().v4(),
            name: 'Offline retained work',
          ),
          ownerSession: selected,
        );
        owner = await f.aEnrollment.signIn('1234');
        final other = await f.aEnrollment.createRestrictedUser(
          owner: owner,
          requestId: const Uuid().v4(),
          name: 'Reset user',
          pin: '4567',
        );
        final otherSession = await f.aEnrollment.signInUser(
          other.userId,
          '4567',
        );
        resetJobId = const Uuid().v4();
        await CompanyJobCommands(enrollment: f.aEnrollment).createJob(
          CreateJob(
            companyId: otherSession.identity.companyId,
            shopId: otherSession.identity.shopId,
            jobId: resetJobId,
            requestId: const Uuid().v4(),
            name: 'Superseded retained work',
          ),
          ownerSession: otherSession,
        );
        owner = await f.aEnrollment.signIn('1234');
        await f.aEnrollment.resetRestrictedUserPin(
          owner: owner,
          userId: other.userId,
          requestId: const Uuid().v4(),
          expectedCredentialVersion: 1,
          pin: '6789',
        );
        await f.aEnrollment.disableRestrictedUser(
          owner: owner,
          userId: user.userId,
          requestId: const Uuid().v4(),
        );
      });
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: CompanyJobsPanel(
                commands: CompanyJobCommands(enrollment: f.aEnrollment),
                owner: owner,
              ),
            ),
          ),
        ),
      );
      await _wait(tester, find.byKey(Key('company-job-held-$id')));
      expect(
        find.textContaining(
          'Disabled-user work has no applied peer confirmation',
        ),
        findsOneWidget,
      );
      expect(find.text('Offline retained work'), findsOneWidget);
      expect(find.byKey(Key('company-job-held-$resetJobId')), findsOneWidget);
      expect(
        find.textContaining(
          'Superseded-credential work has no applied peer confirmation',
        ),
        findsOneWidget,
      );
      await tester.pumpWidget(const SizedBox());
    },
  );
  testWidgets(
    'owner disables selected second user and preserves first-user access',
    (tester) async {
      late JoinFixture f;
      late String firstUserId;
      await tester.runAsync(() async {
        f = await JoinFixture.create();
        firstUserId = (await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: 'Alex first',
          pin: '7890',
        )).userId;
        await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: '11111111-1111-4111-8111-111111111111',
          name: 'Casey Work',
          pin: '0123',
        );
        await f.aEnrollment.signOut();
      });
      await tester.pumpWidget(
        MaterialApp(
          home: CompanyBootstrapGate(db: f.aDb, installation: f.a),
        ),
      );
      await _wait(tester, find.byKey(const Key('company-signin')));
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '1234',
      );
      await tester.runAsync(
        () => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('Company ID:'));
      await _manageUser(tester, 'Casey Work');
      await tester.scrollUntilVisible(
        find.textContaining('Additional user capacity reached'),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      final disable = find.byKey(const Key('company-disable-user'));
      expect(disable, findsOneWidget);
      await tester.ensureVisible(disable);
      await tester.runAsync(() => tester.tap(disable));
      await _wait(tester, find.text('Casey Work (disabled)'));
      expect(find.byKey(const Key('company-disable-user')), findsNothing);
      await tester.runAsync(() async {
        final first = await f.aEnrollment.userLifecycleStatus(
          userId: firstUserId,
        );
        expect(first!.disabled, isFalse);
        expect(first.credentialVersion, 1);
        expect(first.attemptsRemaining, 8);
        await f.aEnrollment.signInUser(firstUserId, '7890');
      });
      await tester.scrollUntilVisible(
        find.textContaining('Company ID:'),
        -200,
        scrollable: find.byType(Scrollable).first,
      );
      expect(find.textContaining('Company ID:'), findsOneWidget);
      expect(
        await tester.runAsync(() => f.aEnrollment.readStatus()),
        CompanyBootstrapStatus.active,
      );
      final record = jsonDecode(
        utf8.decode(
          f.aStore.states[companyUserNamespace(f.a.namespace, slot: 2)]!.bytes,
        ),
      ) as Map;
      expect(record['v'], 2);
      expect(record['p'], isNull);
      expect(record['d'], hasLength(5));
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('company lock screen offers a stable company user selector', (
    tester,
  ) async {
    late JoinFixture f;
    await tester.runAsync(() async {
      f = await JoinFixture.create();
      await f.aEnrollment.signOut();
    });
    await tester.pumpWidget(
      MaterialApp(
        home: CompanyBootstrapGate(db: f.aDb, installation: f.a),
      ),
    );
    for (
      var i = 0;
      i < 80 && find.byKey(const Key('company-signin')).evaluate().isEmpty;
      i++
    ) {
      await tester.runAsync(
        () async => Future<void>.delayed(const Duration(milliseconds: 25)),
      );
      await tester.pump(const Duration(milliseconds: 25));
    }
    expect(find.byKey(const Key('company-signin')), findsOneWidget);
    expect(find.byKey(const Key('company-user-selector')), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    '360px Gate retains full identities for maximum-length duplicate user names',
    (tester) async {
      final name = List.filled(64, 'W').join();
      expect(utf8.encode(name), hasLength(64));
      late JoinFixture f;
      late String firstId;
      late String secondId;
      await tester.runAsync(() async {
        f = await JoinFixture.create();
        firstId = (await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: name,
          pin: '0123',
        )).userId;
        secondId = (await f.aEnrollment.createRestrictedUser(
          owner: f.owner,
          requestId: const Uuid().v4(),
          name: name,
          pin: '7890',
        )).userId;
        await f.aEnrollment.signOut();
      });
      expect(firstId, isNot(secondId));
      expect(firstId, hasLength(36));
      expect(secondId, hasLength(36));
      await tester.binding.setSurfaceSize(const Size(360, 800));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: CompanyBootstrapGate(db: f.aDb, installation: f.a),
        ),
      );
      await _wait(tester, find.byKey(const Key('company-signin')));
      final lockSelector = find.byKey(const Key('company-user-selector'));
      final lockDropdown = tester.widget<DropdownButton<String>>(
        find.descendant(
          of: lockSelector,
          matching: find.byWidgetPredicate(
            (widget) => widget is DropdownButton<String>,
          ),
        ),
      );
      for (final id in [firstId, secondId]) {
        final identityText =
            lockDropdown.items!.singleWhere((item) => item.value == id).child
                as Text;
        expect(identityText.data, '$name — $id');
        expect(identityText.overflow, isNot(TextOverflow.ellipsis));
        expect(identityText.maxLines, isNull);
      }
      await tester.ensureVisible(lockSelector);
      await tester.tap(lockSelector);
      await tester.pump(const Duration(milliseconds: 300));
      await tester.runAsync(
        () => tester.tap(find.text('$name — $secondId').last),
      );
      await tester.pump();
      expect(
        tester.state<FormFieldState<String>>(lockSelector).value,
        secondId,
      );
      await tester.tap(lockSelector);
      await tester.pump(const Duration(milliseconds: 300));
      await tester.runAsync(() => tester.tap(find.text('Owner').last));
      await tester.pump();
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '1234',
      );
      await tester.ensureVisible(find.byKey(const Key('company-signin')));
      await tester.runAsync(
        () => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('Company ID:'));
      await _manageUser(tester, name, userId: secondId);
      final managementSelector = find.byKey(
        const Key('company-managed-user-selector'),
      );
      expect(
        tester.state<FormFieldState<String>>(managementSelector).value,
        secondId,
      );
      final managementDropdown = tester.widget<DropdownButton<String>>(
        find.descendant(
          of: managementSelector,
          matching: find.byWidgetPredicate(
            (widget) => widget is DropdownButton<String>,
          ),
        ),
      );
      for (final id in [firstId, secondId]) {
        final identityText =
            managementDropdown.items!
                    .singleWhere((item) => item.value == id)
                    .child
                as Text;
        expect(identityText.data, '$name — $id — Create Job only');
        expect(identityText.overflow, isNot(TextOverflow.ellipsis));
        expect(identityText.maxLines, isNull);
      }
      await tester.pumpWidget(const SizedBox());
      await tester.pump();
    },
  );

  testWidgets(
    'owner creates named user and switches to restricted offline Job through production gate',
    (tester) async {
      late JoinFixture f;
      await tester.runAsync(() async {
        f = await JoinFixture.create(allowOwnerAdditions: true);
        await f.aEnrollment.signOut();
      });
      await tester.pumpWidget(
        MaterialApp(
          home: CompanyBootstrapGate(db: f.aDb, installation: f.a),
        ),
      );
      await _wait(tester, find.byKey(const Key('company-signin')));
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '1234',
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('Company ID:'));
      await tester.scrollUntilVisible(
        find.byKey(const Key('company-create-user')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      final createUser = tester
          .widget<FilledButton>(find.byKey(const Key('company-create-user')))
          .onPressed!;
      final nameController = tester
          .widget<TextField>(find.byKey(const Key('company-user-name')))
          .controller!;
      final pinController = tester
          .widget<TextField>(find.byKey(const Key('company-user-pin')))
          .controller!;
      await tester.enterText(
        find.byKey(const Key('company-user-name')),
        'Sam UI',
      );
      await tester.enterText(find.byKey(const Key('company-user-pin')), '0123');
      await tester.ensureVisible(find.byKey(const Key('company-create-user')));
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-create-user'))),
      );
      // EditableText already contains the entered name before creation saves.
      // Observe the directory row and the completed handler instead.
      await _wait(
        tester,
        find.byWidgetPredicate(
          (widget) => widget is Text && widget.data == 'Sam UI',
        ),
      );
      await _wait(
        tester,
        find.byWidgetPredicate(
          (widget) =>
              widget is FilledButton &&
              widget.key == const Key('company-create-user') &&
              widget.onPressed != null,
        ),
      );
      final firstDirectory = await tester.runAsync(
        () => f.aEnrollment.listCompanyUsers(),
      );
      final samId = firstDirectory!
          .singleWhere((user) => user.name == 'Sam UI')
          .userId;
      expect(firstDirectory, hasLength(2));
      expect(find.byKey(const Key('company-create-user')), findsOneWidget);
      await tester.enterText(
        find.byKey(const Key('company-user-name')),
        'Alex second',
      );
      await tester.enterText(find.byKey(const Key('company-user-pin')), '7890');
      await tester.ensureVisible(find.byKey(const Key('company-create-user')));
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-create-user'))),
      );
      await _wait(
        tester,
        find.textContaining('Additional user capacity reached'),
      );
      final fullDirectory = await tester.runAsync(
        () => f.aEnrollment.listCompanyUsers(),
      );
      final alexId = fullDirectory!
          .singleWhere((user) => user.name == 'Alex second')
          .userId;
      expect(fullDirectory, hasLength(3));
      expect(alexId, isNot(samId));
      final fullIds = fullDirectory.map((user) => user.userId).toSet();
      expect(fullIds, hasLength(3));
      expect(find.byKey(const Key('company-create-user')), findsNothing);
      expect(find.byKey(const Key('company-user-name')), findsNothing);
      // A retained callback must still refuse a third account through the Gate handler.
      nameController.text = 'Third refused';
      pinController.text = '4567';
      await tester.runAsync(() async {
        createUser();
      });
      await _wait(tester, find.text('Company user capacity reached'));
      final afterThird = await tester.runAsync(
        () => f.aEnrollment.listCompanyUsers(),
      );
      expect(afterThird!.map((user) => user.userId).toSet(), fullIds);
      expect(afterThird.any((user) => user.name == 'Third refused'), isFalse);
      await tester.scrollUntilVisible(
        find.byKey(const Key('company-switch-user')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-switch-user'))),
      );
      await _wait(tester, find.byKey(const Key('company-user-selector')));
      await tester.tap(find.byKey(const Key('company-user-selector')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Sam UI').last);
      await tester.pumpAndSettle();
      expect(
        tester
            .state<FormFieldState<String>>(
              find.byKey(const Key('company-user-selector')),
            )
            .value,
        samId,
      );
      await tester.enterText(
        find.byKey(const Key('company-signin-pin')),
        '0123',
      );
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-signin'))),
      );
      await _wait(tester, find.textContaining('Company ID:'));
      expect(find.byKey(const Key('company-enroll-open')), findsNothing);
      expect(find.byKey(const Key('company-peer-open')), findsNothing);
      expect(find.byKey(const Key('company-join-open')), findsNothing);
      expect(find.byKey(const Key('company-join-resume')), findsNothing);
      expect(find.byKey(const Key('company-create-user')), findsNothing);
      await tester.scrollUntilVisible(
        find.textContaining('Create Job permission only. Sign in as the owner'),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.scrollUntilVisible(
        find.byType(CompanyJobsPanel),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await _wait(tester, find.byKey(const Key('company-job-name')));
      await tester.enterText(
        find.byKey(const Key('company-job-name')),
        'Sam UI Job',
      );
      await tester.ensureVisible(find.byKey(const Key('company-create-job')));
      await tester.runAsync(
        () async => tester.tap(find.byKey(const Key('company-create-job'))),
      );
      await _wait(
        tester,
        find.descendant(
          of: find.byKey(const Key('company-jobs-list')),
          matching: find.text('Sam UI Job'),
        ),
      );
      final rows = await tester.runAsync(
        () => f.aDb.select(f.aDb.companyJobs).get(),
      );
      final authored = rows!.singleWhere(
        (r) =>
            (jsonDecode(r.operationBytes)['body'] as Map)['name'] ==
            'Sam UI Job',
      );
      expect(jsonDecode(authored.operationBytes)['body']['user'], samId);
      expect(
        jsonDecode(authored.operationBytes)['body']['device'],
        f.owner.identity.deviceId,
      );
      expect(find.byKey(const Key('company-disable-user')), findsNothing);
      await tester.pumpWidget(const SizedBox());
    },
  );
}

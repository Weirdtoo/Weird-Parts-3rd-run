import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'package:wired_parts/features/company/company_join_page.dart';
import 'package:wired_parts/features/installation/installation_security.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';

import 'company_join_test.dart'
    show JoinFixture, activateFixtureB, joinChannels, sqlSnapshot;
import 'company_join_widget_test.dart'
    show JoinLoopbackHttpOverrides, joinWidgetSignal;
import 'company_user_initial_provision_test.dart'
    show protectedUnchanged, provisionInitialUser, thirdInstallation;

void main() {
  testWidgets(
    'retained third installation accepts existing user only after consent while first user stays selected',
    (tester) => HttpOverrides.runWithHttpOverrides(() async {
      final setup = (await tester.runAsync(
        () => HttpOverrides.runWithHttpOverrides(() async {
          final f = await JoinFixture.create();
          await activateFixtureB(f);
          await f.bEnrollment.signIn('1234');
          final first = await f.aEnrollment.createRestrictedUser(
            owner: f.owner,
            requestId: const Uuid().v4(),
            name: 'First builder',
            pin: '0123',
          );
          final second = await f.aEnrollment.createRestrictedUser(
            owner: f.owner,
            requestId: const Uuid().v4(),
            name: 'Existing builder',
            pin: '4567',
          );
          await provisionInitialUser(
            f.aEnrollment,
            f.bEnrollment,
            first.userId,
          );
          await provisionInitialUser(
            f.aEnrollment,
            f.bEnrollment,
            second.userId,
          );
          final c = await thirdInstallation(f);
          await provisionInitialUser(f.aEnrollment, c.enrollment, first.userId);
          final selected = await c.enrollment.signInUser(first.userId, '0123');
          late NearbyController source, recipient;
          await joinChannels(
            onPaired: (bc, ac) {
              source = ac;
              recipient = bc;
            },
          );
          return (
            f: f,
            c: c,
            first: first,
            second: second,
            selected: selected,
            source: source,
            recipient: recipient,
            otherSql: await sqlSnapshot(f.bDb),
            otherProtected: Map.of(f.bStore.states),
            recipientSql: await sqlSnapshot(c.db),
            recipientProtected: Map.of(c.store.states),
            firstCredential:
                c.store.states[companyUserNamespace(
                  c.installation.namespace,
                  slot: 1,
                )]!,
          );
        }, JoinLoopbackHttpOverrides()),
      ))!;
      final f = setup.f;
      final c = setup.c;
      expect(f.owner.identity.isAuthorityOwner, isTrue);
      expect(f.aEnrollment.currentSession, same(f.owner));
      expect(setup.selected.identity.isAuthorityOwner, isFalse);
      expect(setup.selected.identity.userId, setup.first.userId);
      expect(c.enrollment.currentCompanySession, same(setup.selected));
      expect(
        (await tester.runAsync(() => c.enrollment.listCompanyUsers()))!
            .map((user) => user.userId),
        isNot(contains(setup.second.userId)),
      );
      await tester.binding.setSurfaceSize(const Size(1500, 1400));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: Row(
            children: [
              Expanded(
                child: CompanyJoinPage(
                  enrollment: f.aEnrollment,
                  approver: f.owner,
                  reconnect: true,
                  createController: (_) => setup.source,
                ),
              ),
              Expanded(
                child: CompanyJoinPage(
                  enrollment: c.enrollment,
                  syncSession: setup.selected,
                  reconnect: true,
                  createController: (_) => setup.recipient,
                ),
              ),
            ],
          ),
        ),
      );
      final retained = find.byKey(
        ValueKey('company-peer-${f.owner.identity.deviceId}'),
      );
      await joinWidgetSignal(tester, () => retained.evaluate().isNotEmpty);
      await tester.tap(retained);
      await tester.pump();
      await tester.runAsync(
        () => tester.tap(find.byKey(const Key('company-peer-verify')).at(1)),
      );
      final selector = find.byKey(const Key('company-provision-user-selector'));
      await joinWidgetSignal(tester, () => selector.evaluate().isNotEmpty);
      await tester.ensureVisible(selector);
      await tester.tap(selector);
      await tester.pump(const Duration(milliseconds: 300));
      final option = find.text('Existing builder — Create Job only').last;
      await joinWidgetSignal(tester, () => option.evaluate().isNotEmpty);
      await tester.runAsync(() => tester.tap(option));
      await tester.pump();
      final provision = find.byKey(const Key('company-user-provision'));
      await joinWidgetSignal(
        tester,
        () => tester.widget<OutlinedButton>(provision).onPressed != null,
      );
      expect(
        tester.state<FormFieldState<String>>(selector).value,
        setup.second.userId,
      );

      final messages = <String>[];
      final receiveSource = setup.source.onJoinMessage!;
      final receiveRecipient = setup.recipient.onJoinMessage!;
      setup.source.onJoinMessage = (pair, wire) async {
        if ((wire['kind'] as String).startsWith('user-')) {
          messages.add('source:${wire['kind']}');
        }
        return receiveSource(pair, wire);
      };
      setup.recipient.onJoinMessage = (pair, wire) async {
        if ((wire['kind'] as String).startsWith('user-')) {
          messages.add('recipient:${wire['kind']}');
        }
        return receiveRecipient(pair, wire);
      };
      await tester.ensureVisible(provision);
      await tester.runAsync(() => tester.tap(provision));
      final accept = find.byKey(const Key('company-user-provision-accept'));
      await joinWidgetSignal(tester, () => accept.evaluate().isNotEmpty);
      expect(messages, [
        'recipient:user-initial-provision-probe@2',
        'source:user-initial-provision-response@2',
        'recipient:user-provision-invite',
      ]);
      expect(
        await tester.runAsync(() => sqlSnapshot(c.db)),
        setup.recipientSql,
      );
      expect(protectedUnchanged(c.store, setup.recipientProtected), isTrue);
      expect(c.enrollment.currentCompanySession, same(setup.selected));
      expect(find.byKey(const Key('company-join-error')), findsNothing);

      await tester.ensureVisible(accept);
      await tester.runAsync(() => tester.tap(accept));
      const confirmed =
          'The retained installation confirmed the additional user is saved. Repeating this transfer preserves PIN attempts.';
      await joinWidgetSignal(
        tester,
        () => find.text(confirmed).evaluate().isNotEmpty,
      );
      expect(messages, [
        'recipient:user-initial-provision-probe@2',
        'source:user-initial-provision-response@2',
        'recipient:user-provision-invite',
        'source:user-provision-request',
        'recipient:user-provision-bundle',
        'source:user-provision-ack',
      ]);
      expect(
        find.text(
          'Additional user saved on this installation. Close this page and switch user to sign in offline.',
        ),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('company-user-provision-accept')),
        findsNothing,
      );
      expect(find.byKey(const Key('company-join-error')), findsNothing);
      expect(c.enrollment.currentCompanySession, same(setup.selected));
      expect(setup.selected.isValid, isTrue);
      final firstCredential = c
          .store
          .states[companyUserNamespace(c.installation.namespace, slot: 1)]!;
      expect(
        firstCredential.bytes.length == setup.firstCredential.bytes.length &&
            List.generate(
              firstCredential.bytes.length,
              (i) => firstCredential.bytes[i] == setup.firstCredential.bytes[i],
            ).every((same) => same),
        isTrue,
      );
      expect(firstCredential.revision, setup.firstCredential.revision);
      expect(await tester.runAsync(() => sqlSnapshot(f.bDb)), setup.otherSql);
      expect(protectedUnchanged(f.bStore, setup.otherProtected), isTrue);
      await tester.runAsync(() async {
        final users = await c.enrollment.listCompanyUsers();
        final second = users.singleWhere(
          (u) => u.userId == setup.second.userId,
        );
        expect(second.capabilities, ['createJob']);
        expect(
          (await c.enrollment.userLifecycleStatus(userId: setup.second.userId))!
              .attemptsRemaining,
          8,
        );
      });
      await tester.runAsync(() async {
        final second = await c.enrollment.signInUser(
          setup.second.userId,
          '4567',
        );
        expect(second.identity.userId, setup.second.userId);
        expect(second.identity.isAuthorityOwner, isFalse);
        await setup.source.dispose();
        await setup.recipient.dispose();
        await c.db.close();
        await f.closeAndCheckOwnerData();
      });
      await tester.pumpWidget(const SizedBox());
      await tester.pump();
    }, JoinLoopbackHttpOverrides()),
    timeout: const Timeout(Duration(minutes: 4)),
  );
}

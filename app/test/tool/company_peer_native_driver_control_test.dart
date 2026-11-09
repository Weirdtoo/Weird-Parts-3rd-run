import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';
import 'package:wired_parts/features/nearby/nearby_protocol.dart';

import '../../tool/company_peer_native_driver_control.dart';
import '../../tool/company_peer_native_driver_ui.dart';
import '../../tool/native_nearby_test_commands.dart';
import '../../tool/native_nearby_test_crypto.dart';
import '../../tool/native_nearby_test_rpc.dart';
import '../../tool/native_nearby_test_tap.dart';

const _peer = NearbyPeer(
  deviceId: 'actual-peer',
  name: 'Actual peer',
  host: '127.0.0.1',
  port: 1234,
);
const _target = 'selected-user';
final _deadline = DateTime.fromMillisecondsSinceEpoch(10000);
const _code = '654321';

NearbyViewState _state({String? code, String? id}) => NearbyViewState(
  phase: NearbyPhase.pairing,
  deviceName: 'candidate',
  deviceId: 'candidate-discovery',
  peerName: _peer.label,
  verifyCode: code,
  verificationAttemptId: id,
  verificationExpiresAt: code == null ? null : _deadline,
);

void main() {
  test(
    'candidate startup stays unopened until a live one-use configure',
    () async {
      final session = TestSession(
        epoch: 'startup-session',
        run: companyPeerDriverRun,
        role: TestRole.receiver,
        deviceId: 'candidate-control',
        peerId: companyPeerDriverOperator,
        encryptionPublicKey: nativeTestRandom(32),
        signingPublicKey: nativeTestRandom(32),
      );
      NativeTestResidentRpc rpc() => NativeTestResidentRpc(
        appPid: 100,
        run: session.run,
        role: session.role,
        deviceId: session.deviceId,
        peerId: session.peerId,
        clockMillis: () => 1000,
        readInfoInLoop: () => const NativeTestResidentViewInfo(
          phase: NativeTestPhase.starting,
          sameNearbyState: false,
          discovered: false,
          codePresent: false,
        ),
      );
      final startup = CompanyPeerDriverStartup();
      final control = rpc();
      addTearDown(control.close);
      var opened = 0;
      Future<void> mount() async {
        expect(startup.started, isFalse);
        opened++;
      }

      Future<void> start(TestSession? configured) => startup.start(
        session: configured,
        isCurrent: () => true,
        initialize: mount,
      );
      final rejected = {'version': 1, 'outcome': 'rejected'};
      await start(null);
      expect(await control.configure('{'), rejected);
      expect(
        await control.configure(
          jsonEncode({...session.toJson(), 'peerId': 'unexpected'}),
        ),
        rejected,
      );
      await start(null);
      expect(opened, 0);
      expect(startup.started, isFalse);

      final configured = control.configure(jsonEncode(session.toJson()));
      TestSession? admitted;
      control.processConfigurationInLoop((current) => admitted = current);
      expect(await configured, {'version': 1, 'outcome': 'configured'});
      await start(admitted);
      expect(startup.started, isTrue);
      expect(opened, 1);
      expect(await control.configure(jsonEncode(session.toJson())), rejected);
      await expectLater(start(admitted), throwsA(isA<NativeTestFailure>()));
      expect(opened, 1);

      final background = rpc();
      addTearDown(background.close);
      final pending = background.configure(jsonEncode(session.toJson()));
      background.processConfigurationInLoop(
        (_) => rejectNativeTest('background'),
      );
      expect(await pending, rejected);
      final unopened = CompanyPeerDriverStartup();
      await unopened.start(
        session: null,
        isCurrent: () => false,
        initialize: mount,
      );
      expect(unopened.started, isFalse);
      expect(opened, 1);

      final interrupted = CompanyPeerDriverStartup();
      var resumed = true;
      await expectLater(
        interrupted.start(
          session: session,
          isCurrent: () => resumed,
          initialize: () async => resumed = false,
        ),
        throwsA(isA<NativeTestFailure>()),
      );
      expect(interrupted.started, isFalse);
    },
  );

  testWidgets('live user B refuses an A permit before PIN input or tap', (
    tester,
  ) async {
    final pinField = TextEditingController();
    addTearDown(pinField.dispose);
    var authorizations = 0;
    var signInTaps = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Column(
            children: [
              DropdownButtonFormField<String>(
                key: const Key('company-user-selector'),
                initialValue: 'user-a',
                items: const [
                  DropdownMenuItem(value: 'user-a', child: Text('User A')),
                  DropdownMenuItem(value: 'user-b', child: Text('User B')),
                ],
                onChanged: (_) {},
              ),
              TextField(
                key: const Key('company-signin-pin'),
                controller: pinField,
              ),
              FilledButton(
                key: const Key('company-signin'),
                onPressed: () => signInTaps++,
                child: const Text('Sign in'),
              ),
            ],
          ),
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('company-user-selector')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('User B').last);
    await tester.pumpAndSettle();
    expect(companyPeerDriverSelectedUser(), 'user-b');
    await expectLater(
      companyPeerDriverSignIn(
        tester,
        targetUser: 'user-a',
        isStillCurrent: () => true,
        authorizePin: () async {
          authorizations++;
          throw StateError('Wrong user reached PIN authorization');
        },
      ),
      throwsA(isA<NativeTestFailure>()),
    );
    expect(authorizations, 0);
    expect(pinField.text.isEmpty, isTrue);
    expect(signInTaps, 0);

    await companyPeerDriverSignIn(
      tester,
      targetUser: 'user-b',
      isStillCurrent: () => true,
      authorizePin: () async {
        authorizations++;
        return List.generate(6, (index) => (index * 3 + 1) % 10).join();
      },
    );
    expect(authorizations, 1);
    expect(pinField.text.length, 6);
    expect(signInTaps, 1);
  });

  testWidgets('a second connecting transition cancels Match pointer-up', (
    tester,
  ) async {
    final page = Object();
    final binding = CompanyPeerDriverPair(page, _peer);
    final matched = _state(code: _code, id: 'first-attempt');
    binding.observe(_state());
    binding.observe(matched);
    var taps = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Listener(
            onPointerDown: (_) => binding.observe(_state()),
            child: FilledButton(
              key: const Key('company-join-match'),
              onPressed: () => taps++,
              child: const Text('Codes match'),
            ),
          ),
        ),
      ),
    );
    var rejected = false;
    try {
      await guardedNativeTap(
        tester,
        find.byKey(const Key('company-join-match')).hitTestable(),
        isStillCurrent: () => binding.current(
          page: page,
          peerId: _peer.deviceId,
          state: matched,
          renderedCode: _code,
          resumed: true,
          nowMillis: 1000,
        ),
      );
    } on NativeTestFailure {
      rejected = true;
    }
    await tester.pump();
    expect(rejected, isTrue);
    expect(taps, 0);
  });

  testWidgets(
    'one current observed attempt permits exactly one rendered Match tap',
    (tester) async {
      final page = Object();
      final binding = CompanyPeerDriverPair(page, _peer);
      final matched = _state(code: _code, id: 'first-attempt');
      final target = find.byKey(const Key('company-join-match')).hitTestable();
      bool current() => binding.current(
        page: page,
        peerId: _peer.deviceId,
        state: matched,
        renderedCode: _code,
        resumed: true,
        nowMillis: 1000,
      );
      var taps = 0;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: FilledButton(
              key: const Key('company-join-match'),
              onPressed: () => taps++,
              child: const Text('Codes match'),
            ),
          ),
        ),
      );
      await expectLater(
        guardedNativeTap(tester, target, isStillCurrent: current),
        throwsA(isA<NativeTestFailure>()),
      );
      await tester.runAsync(() async {
        final signer = await Ed25519().newKeyPair();
        final proof = nativeTestRandom(32);
        final session = TestSession(
          epoch: 'match-session',
          run: companyPeerDriverRun,
          role: TestRole.receiver,
          deviceId: 'candidate-control',
          peerId: companyPeerDriverOperator,
          encryptionPublicKey: nativeTestRandom(32),
          signingPublicKey: base64Url.encode(
            (await signer.extractPublicKey()).bytes,
          ),
        );
        final context = CompanyPeerDriverPermit.context(
          session: session,
          appPid: 100,
          sequence: 1,
          step: CompanyPeerDriverStep.match,
          target: _peer.deviceId,
          expires: 2500,
          proof: proof,
        );
        Future<CompanyPeerDriverPermit> signed(KeyPair key) async {
          final signature = await Ed25519().sign(
            CompanyPeerDriverPermit.signingBytes(context, null),
            keyPair: key,
          );
          return CompanyPeerDriverPermit.parse({
            'expires': 2500,
            'proof': proof,
            'signature': base64Url.encode(signature.bytes),
          }, forPin: false);
        }

        Future<void> authorize(
          CompanyPeerDriverPermit permit,
          String observed,
        ) => binding.authorizeMatch(
          permit: permit,
          observedProof: observed,
          session: session,
          context: context,
          nowMillis: 1000,
          isStillCurrent: current,
        );
        final rejected = throwsA(isA<NativeTestFailure>());
        final permit = await signed(signer);
        await expectLater(authorize(permit, proof), rejected);
        binding.observe(_state());
        binding.observe(matched);
        await expectLater(authorize(permit, nativeTestRandom(32)), rejected);
        await expectLater(
          authorize(await signed(await Ed25519().newKeyPair()), proof),
          rejected,
        );
        await authorize(permit, proof);
        await expectLater(authorize(permit, proof), rejected);
      });
      await guardedNativeTap(tester, target, isStillCurrent: current);
      expect(taps, 1);
    },
  );

  test(
    'wrong peer, background, route replacement, changed code and expiry refuse',
    () {
      final page = Object();
      final binding = CompanyPeerDriverPair(page, _peer);
      final matched = _state(code: _code, id: 'first-attempt');
      binding.observe(_state());
      binding.observe(matched);
      bool current({
        Object? route,
        String peerId = 'actual-peer',
        NearbyViewState? state,
        String code = _code,
        bool resumed = true,
        int now = 1000,
      }) => binding.current(
        page: route ?? page,
        peerId: peerId,
        state: state ?? matched,
        renderedCode: code,
        resumed: resumed,
        nowMillis: now,
      );
      expect(current(), isTrue);
      expect(current(peerId: 'same-label-other-peer'), isFalse);
      expect(current(resumed: false), isFalse);
      expect(current(route: Object()), isFalse);
      expect(current(code: '654322'), isFalse);
      expect(
        current(
          state: _state(code: _code, id: 'replacement'),
        ),
        isFalse,
      );
      expect(current(now: 10000), isFalse);
      binding.observe(_state());
      binding.observe(_state(code: _code, id: 'replacement'));
      expect(current(), isFalse);
      expect(
        current(
          state: _state(code: _code, id: 'replacement'),
        ),
        isFalse,
      );
    },
  );

  test('signed PIN envelope binds candidate, action, selected user, sequence and expiry', () async {
    final signing = await Ed25519().newKeyPair();
    final recipient = await X25519().newKeyPair();
    final sender = await X25519().newKeyPair();
    final receiverPublic = await recipient.extractPublicKey();
    final proof = base64Url.encode(receiverPublic.bytes);
    final session = TestSession(
      epoch: 'control-session',
      run: companyPeerDriverRun,
      role: TestRole.receiver,
      deviceId: 'candidate-control',
      peerId: companyPeerDriverOperator,
      encryptionPublicKey: proof,
      signingPublicKey: base64Url.encode(
        (await signing.extractPublicKey()).bytes,
      ),
    );
    List<int> context({
      int pid = 112,
      int sequence = 1,
      String target = _target,
      CompanyPeerDriverStep step = CompanyPeerDriverStep.signIn,
    }) => CompanyPeerDriverPermit.context(
      session: session,
      appPid: pid,
      sequence: sequence,
      step: step,
      target: target,
      expires: 2500,
      proof: proof,
    );
    final shared = await X25519().sharedSecretKey(
      keyPair: sender,
      remotePublicKey: receiverPublic,
    );
    final key = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: shared,
      nonce: utf8.encode('company-peer-driver-sign-in@1'),
      info: context(),
    );
    final pin = List.generate(6, (index) => (index * 3 + 1) % 10).join();
    final sealed = await AesGcm.with256bits().encrypt(
      utf8.encode(pin),
      secretKey: key,
      aad: context(),
    );
    final box = <String, dynamic>{
      'key': base64Url.encode((await sender.extractPublicKey()).bytes),
      'nonce': base64Url.encode(sealed.nonce),
      'ciphertext': base64Url.encode(sealed.cipherText),
      'tag': base64Url.encode(sealed.mac.bytes),
    };
    Future<CompanyPeerDriverPermit> permit(
      Map<String, dynamic> payload,
      KeyPair signer,
    ) async {
      final signature = await Ed25519().sign(
        CompanyPeerDriverPermit.signingBytes(context(), payload),
        keyPair: signer,
      );
      return CompanyPeerDriverPermit.parse({
        'expires': 2500,
        'proof': proof,
        'signature': base64Url.encode(signature.bytes),
        'box': payload,
      }, forPin: true);
    }

    final valid = await permit(box, signing);
    await valid.verify(session: session, context: context(), nowMillis: 1200);
    expect(await valid.openPin(recipient, context()) == pin, isTrue);
    final refused = throwsA(isA<NativeTestFailure>());
    for (final wrong in [
      context(pid: 113),
      context(sequence: 2),
      context(target: 'different-user'),
      context(step: CompanyPeerDriverStep.match),
    ]) {
      await expectLater(
        valid.verify(session: session, context: wrong, nowMillis: 1200),
        refused,
      );
    }
    await expectLater(
      valid.verify(session: session, context: context(), nowMillis: 2500),
      refused,
    );
    final unauthorized = await permit(box, await Ed25519().newKeyPair());
    await expectLater(
      unauthorized.verify(
        session: session,
        context: context(),
        nowMillis: 1200,
      ),
      refused,
    );
    for (final field in ['key', 'nonce', 'ciphertext', 'tag']) {
      final changed = base64Url.decode(box[field] as String);
      changed[0] ^= 1;
      final tampered = await permit({
        ...box,
        field: base64Url.encode(changed),
      }, signing);
      await expectLater(tampered.openPin(recipient, context()), refused);
    }

    final action = CompanyPeerDriverArgument.parse({
      'step': 'signIn',
      'target': _target,
      'permit': valid.toJson(),
    }, session);
    final command = NativeTestCommand.encodeRequest(
      session: session,
      sequence: 1,
      action: NativeTestAction.companyPeerUi,
      deadlineMillis: 2000,
      companyPeerArgument: action,
    );
    final cache = NativeTestCommandCache(
      session: session,
      clockMillis: () => 1000,
    );
    cache.submitJson(command, allowedActions: {NativeTestAction.companyPeerUi});
    final accepted = cache.takeNext()!;
    cache.complete(accepted, const NativeTestCommandResult.effect());
    cache.submitJson(command, allowedActions: {NativeTestAction.companyPeerUi});
    expect(cache.takeNext(), isNull);
    expect(
      () => CompanyPeerDriverArgument.parse({
        'step': 'signIn',
        'target': _target,
        'permit': valid.toJson(),
        'pin': 'unsafe',
      }, session),
      refused,
    );
  });
}

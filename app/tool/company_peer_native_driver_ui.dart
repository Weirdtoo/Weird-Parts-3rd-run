import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wired_parts/features/nearby/nearby_controller.dart';
import 'package:wired_parts/features/nearby/nearby_protocol.dart';

import 'company_peer_native_driver_control.dart';
import 'native_nearby_test_crypto.dart';
import 'native_nearby_test_tap.dart';

String? companyPeerDriverSelectedUser() {
  final matches = find.byKey(const Key('company-user-selector')).evaluate();
  if (matches.length != 1) return null;
  final element = matches.single;
  final state = element is StatefulElement ? element.state : null;
  return state is FormFieldState<String> ? state.value : null;
}

Future<void> companyPeerDriverSignIn(
  WidgetTester tester, {
  required String targetUser,
  required bool Function() isStillCurrent,
  required Future<String> Function() authorizePin,
}) async {
  final field = find.byKey(const Key('company-signin-pin')).hitTestable();
  final button = find.byKey(const Key('company-signin')).hitTestable();
  bool current() {
    final buttons = button.evaluate();
    if (!isStillCurrent() ||
        companyPeerDriverSelectedUser() != targetUser ||
        field.evaluate().length != 1 ||
        buttons.length != 1) {
      return false;
    }
    final widget = buttons.single.widget;
    return widget is ButtonStyleButton && widget.onPressed != null;
  }

  if (!current()) rejectNativeTest('state-changed');
  final pin = await authorizePin();
  if (!current()) rejectNativeTest('state-changed');
  await tester.showKeyboard(field);
  final editors = find
      .descendant(of: field, matching: find.byType(EditableText))
      .evaluate();
  if (!current() ||
      editors.length != 1 ||
      !(editors.single.widget as EditableText).focusNode.hasFocus) {
    rejectNativeTest('state-changed');
  }
  tester.testTextInput.enterText(pin);
  await tester.idle();
  await guardedNativeTap(tester, button, isStillCurrent: current);
}

/// Tracks the controller events after one actual outgoing Pair tap.
final class CompanyPeerDriverPair {
  CompanyPeerDriverPair(this.page, this.peer);

  final Object page;
  final NearbyPeer peer;
  bool _connecting = false;
  bool _invalid = false;
  bool _consumed = false;
  NearbyViewState? _observation;

  void invalidate() => _invalid = true;

  Future<void> authorizeMatch({
    required CompanyPeerDriverPermit permit,
    required String observedProof,
    required TestSession session,
    required List<int> context,
    required int nowMillis,
    required bool Function() isStillCurrent,
  }) async {
    if (_consumed ||
        _invalid ||
        _observation == null ||
        permit.box != null ||
        permit.proof != observedProof ||
        !isStillCurrent()) {
      rejectNativeTest('grant-rejected');
    }
    await permit.verify(
      session: session,
      context: context,
      nowMillis: nowMillis,
    );
    if (_consumed || !isStillCurrent()) rejectNativeTest('grant-rejected');
    _consumed = true;
  }

  void observe(NearbyViewState state) {
    if (_invalid) return;
    if (state.phase != NearbyPhase.pairing || state.peerName != peer.label) {
      invalidate();
      return;
    }
    if (state.verifyCode == null) {
      if (_connecting || _observation != null) {
        invalidate();
      } else {
        _connecting = true;
      }
      return;
    }
    if (!_connecting ||
        state.verificationAttemptId == null ||
        state.verificationExpiresAt == null ||
        (_observation != null && !_sameAttempt(state, _observation!))) {
      invalidate();
      return;
    }
    _observation ??= state;
  }

  bool current({
    required Object page,
    required String peerId,
    required NearbyViewState state,
    required String? renderedCode,
    required bool resumed,
    required int nowMillis,
  }) {
    final observed = _observation;
    return !_invalid &&
        identical(page, this.page) &&
        peerId == peer.deviceId &&
        resumed &&
        observed != null &&
        state.phase == NearbyPhase.pairing &&
        state.peerName == peer.label &&
        _sameAttempt(state, observed) &&
        observed.verifyCode == renderedCode &&
        nowMillis < observed.verificationExpiresAt!.millisecondsSinceEpoch;
  }

  static bool _sameAttempt(NearbyViewState a, NearbyViewState b) =>
      a.verificationAttemptId == b.verificationAttemptId &&
      a.verificationExpiresAt == b.verificationExpiresAt &&
      a.verifyCode == b.verifyCode;
}

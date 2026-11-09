import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'native_nearby_test_crypto.dart';

const companyPeerDriverRun = 'g2-users-20261109-peer-member-win';
const companyPeerDriverOperator = 'operator-$companyPeerDriverRun';

final class CompanyPeerDriverStartup {
  bool _attempted = false;
  bool _started = false;
  bool get started => _started;

  Future<void> start({
    required TestSession? session,
    required bool Function() isCurrent,
    required Future<void> Function() initialize,
  }) async {
    if (session == null) return;
    if (_attempted ||
        !isCurrent() ||
        session.run != companyPeerDriverRun ||
        session.role != TestRole.receiver ||
        session.peerId != companyPeerDriverOperator) {
      rejectNativeTest('candidate-startup-refused');
    }
    _attempted = true;
    await initialize();
    if (!isCurrent()) rejectNativeTest('candidate-startup-refused');
    _started = true;
  }
}

Map<String, Object?> companyPeerDriverUi(Object? value) {
  final fields = nativeTestMap(value, {
    'initialized',
    'discovered',
    'selectedUser',
    'canVerify',
    'canMakeAvailable',
    'canSync',
    'sync',
  });
  final discovered = fields['discovered'];
  if (fields['initialized'] is! bool ||
      discovered is! List ||
      discovered.length > 8 ||
      !{'none', 'complete', 'incomplete'}.contains(fields['sync']) ||
      fields['canVerify'] is! bool ||
      fields['canMakeAvailable'] is! bool ||
      fields['canSync'] is! bool) {
    rejectNativeTest();
  }
  return {
    ...fields,
    'discovered': discovered.map(nativeTestId).toList(),
    'selectedUser': fields['selectedUser'] == null
        ? null
        : nativeTestId(fields['selectedUser']),
  };
}

enum CompanyPeerDriverStep {
  openJoin,
  openRetained,
  pair,
  match,
  requestJoin,
  acceptJoin,
  closeJoin,
  signIn,
  selectRetained,
  verifyRetained,
  makeAvailable,
  syncNow,
}

/// The transport accepts only these arguments for the candidate UI action.
final class CompanyPeerDriverArgument {
  CompanyPeerDriverArgument._(this.step, this.target, this.permit);

  final CompanyPeerDriverStep step;
  final String? target;
  final CompanyPeerDriverPermit? permit;

  static CompanyPeerDriverArgument parse(Object? value, TestSession session) {
    if (session.run != companyPeerDriverRun ||
        session.role != TestRole.receiver ||
        session.peerId != companyPeerDriverOperator ||
        value is! Map<String, dynamic>) {
      rejectNativeTest('context-mismatch');
    }
    final steps = CompanyPeerDriverStep.values.where(
      (step) => step.name == value['step'],
    );
    if (steps.length != 1) rejectNativeTest();
    final step = steps.single;
    final needsTarget = {
      CompanyPeerDriverStep.pair,
      CompanyPeerDriverStep.match,
      CompanyPeerDriverStep.acceptJoin,
      CompanyPeerDriverStep.signIn,
      CompanyPeerDriverStep.selectRetained,
    }.contains(step);
    final needsPermit =
        step == CompanyPeerDriverStep.match ||
        step == CompanyPeerDriverStep.signIn;
    final fields = nativeTestMap(value, {
      'step',
      if (needsTarget) 'target',
      if (needsPermit) 'permit',
    });
    return CompanyPeerDriverArgument._(
      step,
      needsTarget ? nativeTestId(fields['target']) : null,
      needsPermit
          ? CompanyPeerDriverPermit.parse(
              fields['permit'],
              forPin: step == CompanyPeerDriverStep.signIn,
            )
          : null,
    );
  }

  Map<String, Object> toJson() => {
    'step': step.name,
    'target': ?target,
    if (permit != null) 'permit': permit!.toJson(),
  };
}

final class CompanyPeerDriverPermit {
  CompanyPeerDriverPermit._(this.expires, this.proof, this.signature, this.box);

  final int expires;
  final String proof, signature;
  final Map<String, dynamic>? box;

  static CompanyPeerDriverPermit parse(Object? value, {required bool forPin}) {
    final fields = nativeTestMap(value, {
      'expires',
      'proof',
      'signature',
      if (forPin) 'box',
    });
    final proof = nativeTestText(fields['proof']);
    nativeTestBytes(proof, 32);
    final signature = nativeTestText(fields['signature']);
    nativeTestBytes(signature, 64);
    Map<String, dynamic>? box;
    if (forPin) {
      final data = nativeTestMap(fields['box'], {
        'key',
        'nonce',
        'ciphertext',
        'tag',
      });
      nativeTestBytes(data['key'], 32);
      nativeTestBytes(data['nonce'], 12);
      nativeTestBytes(data['tag'], 16);
      final ciphertext = base64Url.decode(nativeTestText(data['ciphertext']));
      if (ciphertext.length < 4 || ciphertext.length > 12) rejectNativeTest();
      box = Map<String, dynamic>.from(data);
    }
    return CompanyPeerDriverPermit._(
      nativeTestInt(fields['expires']),
      proof,
      signature,
      box,
    );
  }

  Map<String, Object> toJson() => {
    'expires': expires,
    'proof': proof,
    'signature': signature,
    'box': ?box,
  };

  static List<int> context({
    required TestSession session,
    required int appPid,
    required int sequence,
    required CompanyPeerDriverStep step,
    required String target,
    required int expires,
    required String proof,
  }) => nativeTestCanonical([
    'company-peer-driver@1',
    appPid,
    session.epoch,
    session.run,
    session.deviceId,
    session.peerId,
    sequence,
    step.name,
    target,
    expires,
    proof,
  ]);

  static List<int> signingBytes(List<int> context, Map<String, dynamic>? box) =>
      nativeTestCanonical([
        base64Url.encode(context),
        if (box != null) ...[
          box['key'],
          box['nonce'],
          box['ciphertext'],
          box['tag'],
        ],
      ]);

  Future<void> verify({
    required TestSession session,
    required List<int> context,
    required int nowMillis,
  }) async {
    if (expires <= nowMillis ||
        expires - nowMillis > nativeTestMaxGrantMillis ||
        !await Ed25519().verify(
          signingBytes(context, box),
          signature: Signature(
            nativeTestBytes(signature, 64),
            publicKey: SimplePublicKey(
              nativeTestBytes(session.signingPublicKey, 32),
              type: KeyPairType.ed25519,
            ),
          ),
        )) {
      rejectNativeTest('grant-rejected');
    }
  }

  Future<String> openPin(KeyPair keyPair, List<int> context) async {
    final data = box;
    if (data == null) rejectNativeTest('invalid-envelope');
    try {
      final shared = await X25519().sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: SimplePublicKey(
          nativeTestBytes(data['key'], 32),
          type: KeyPairType.x25519,
        ),
      );
      if ((await shared.extractBytes()).every((byte) => byte == 0)) {
        rejectNativeTest('invalid-envelope');
      }
      final key = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: shared,
        nonce: utf8.encode('company-peer-driver-sign-in@1'),
        info: context,
      );
      final bytes = await AesGcm.with256bits().decrypt(
        SecretBox(
          base64Url.decode(nativeTestText(data['ciphertext'])),
          nonce: nativeTestBytes(data['nonce'], 12),
          mac: Mac(nativeTestBytes(data['tag'], 16)),
        ),
        secretKey: key,
        aad: context,
      );
      final pin = utf8.decode(bytes);
      if (!RegExp(r'^\d{4,12}$').hasMatch(pin)) {
        rejectNativeTest('invalid-envelope');
      }
      return pin;
    } catch (_) {
      rejectNativeTest('invalid-envelope');
    }
  }
}

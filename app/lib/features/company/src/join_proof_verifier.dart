import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

typedef JoinProofStatistics = ({
  int hits,
  int verifications,
  int entries,
  int codeUnits,
  int evictions,
});

typedef _JoinProof = ({
  String domain,
  String canonicalBody,
  String publicKeyText,
  String signatureText,
});

final class JoinProofVerifier {
  static const _domains = {
    'wiredpart.company.device.enroll@1:',
    'wiredpart.company.join.request@1:',
    'wiredpart.company.join.channel@1:',
    'wiredpart.company.join.issuance@1:',
    'wiredpart.company.join.activation@1:',
    'wiredpart.company.user.authority@1:',
    'wiredpart.company.user.state@1:',
    'wiredpart.company.facts@2:',
  };
  final _completed = <_JoinProof>{};
  int _codeUnits = 0;
  int _hits = 0;
  int _verifications = 0;
  int _evictions = 0;

  JoinProofStatistics get statistics => (
    hits: _hits,
    verifications: _verifications,
    entries: _completed.length,
    codeUnits: _codeUnits,
    evictions: _evictions,
  );

  Future<bool> verify({
    required String domain,
    required String Function() canonicalBody,
    required String publicKeyText,
    required String signatureText,
  }) async {
    final public = base64Decode(publicKeyText);
    final bytes = base64Decode(signatureText);
    if (public.length != 32 || bytes.length != 64) return false;
    final provider = Cryptography.instance;
    final algorithm = provider.ed25519();
    final body = canonicalBody();
    final proof = (
      domain: domain,
      canonicalBody: body,
      publicKeyText: publicKeyText,
      signatureText: signatureText,
    );
    // Custom providers may change their verification behavior internally.
    final reusable =
        identical(provider, DartCryptography.defaultInstance) &&
        _domains.contains(domain);
    if (reusable && _completed.contains(proof)) {
      _hits++;
      return true;
    }
    _verifications++;
    final valid = await algorithm.verify(
      utf8.encode('$domain$body'),
      signature: Signature(
        bytes,
        publicKey: SimplePublicKey(public, type: KeyPairType.ed25519),
      ),
    );
    if (valid && reusable && !_completed.contains(proof)) {
      final size = _size(proof);
      if (size <= 8192) {
        while (_completed.length >= 64 || _codeUnits + size > 65536) {
          final oldest = _completed.first;
          _completed.remove(oldest);
          _codeUnits -= _size(oldest);
          _evictions++;
        }
        _completed.add(proof);
        _codeUnits += size;
      }
    }
    return valid;
  }

  static int _size(_JoinProof proof) =>
      proof.domain.length +
      proof.canonicalBody.length +
      proof.publicKeyText.length +
      proof.signatureText.length;
}

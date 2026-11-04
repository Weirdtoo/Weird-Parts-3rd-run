import 'dart:async';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wired_parts/features/company/src/join_proof_verifier.dart';

const certificateDomain = 'wiredpart.company.device.enroll@1:';
const factsDomain = 'wiredpart.company.facts@2:';
const userAuthorityDomain = 'wiredpart.company.user.authority@1:';
const userStateDomain = 'wiredpart.company.user.state@1:';

class ProbeCryptography extends DartCryptography {
  int calls = 0;
  bool refuse = false;
  bool fail = false;
  Completer<void>? gate;

  @override
  Ed25519 ed25519() => ProbeEd25519(this);
}

class ProbeEd25519 extends DartEd25519 {
  ProbeEd25519(this.provider);
  final ProbeCryptography provider;

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) async {
    provider.calls++;
    await provider.gate?.future;
    if (provider.fail) throw StateError('synthetic verifier unavailable');
    if (provider.refuse) return false;
    return DartCryptography.defaultInstance.ed25519().verify(
      message,
      signature: signature,
    );
  }
}

void main() {
  late SimpleKeyPair keyPair;
  late String publicKey;
  final pure = DartCryptography.defaultInstance;

  setUp(() async {
    Cryptography.instance = pure;
    keyPair = await pure.ed25519().newKeyPairFromSeed(List.filled(32, 17));
    publicKey = base64Encode((await keyPair.extractPublicKey()).bytes);
  });
  tearDown(() => Cryptography.instance = pure);

  Future<String> sign(String body, [String domain = certificateDomain]) async =>
      base64Encode(
        (await pure.ed25519().sign(
          utf8.encode('$domain$body'),
          keyPair: keyPair,
        )).bytes,
      );

  Future<bool> verify(
    JoinProofVerifier verifier,
    String body,
    String signature, {
    String domain = certificateDomain,
    String? key,
  }) => verifier.verify(
    domain: domain,
    canonicalBody: () => body,
    publicKeyText: key ?? publicKey,
    signatureText: signature,
  );

  test('only a completed exact positive avoids another verification', () async {
    final verifier = JoinProofVerifier();
    const body = '{"v":1}';
    final signature = await sign(body);
    final first = verify(verifier, body, signature);
    expect(verifier.statistics.entries, 0);
    expect(await first, isTrue);
    expect(await verify(verifier, body, signature), isTrue);
    expect(verifier.statistics.hits, 1);
    expect(verifier.statistics.verifications, 1);
    expect(verifier.statistics.entries, 1);
    expect(
      verifier.statistics.codeUnits,
      certificateDomain.length +
          body.length +
          publicKey.length +
          signature.length,
    );
    expect(await verify(verifier, '{"v":2}', signature), isFalse);
    expect(
      await verify(verifier, body, base64Encode(List.filled(64, 0))),
      isFalse,
    );
    expect(
      await verify(
        verifier,
        body,
        signature,
        key: base64Encode(List.filled(32, 3)),
      ),
      isFalse,
    );
    expect(
      await verify(
        verifier,
        body,
        signature,
        domain: 'wiredpart.company.join.request@1:',
      ),
      isFalse,
    );
    expect(verifier.statistics.entries, 1);
    expect(verifier.statistics.verifications, 5);
  });

  for (final domain in [userAuthorityDomain, userStateDomain, factsDomain]) {
    test(
      '$domain reuses only exact positives and honors custom providers',
      () async {
        final verifier = JoinProofVerifier();
        const body = '{"v":1}';
        final signature = await sign(body, domain);
        expect(await verify(verifier, body, signature, domain: domain), isTrue);
        expect(await verify(verifier, body, signature, domain: domain), isTrue);
        expect(verifier.statistics.hits, 1);
        expect(verifier.statistics.verifications, 1);
        expect(verifier.statistics.entries, 1);
        expect(
          verifier.statistics.codeUnits,
          domain.length + body.length + publicKey.length + signature.length,
        );
        expect(
          await verify(verifier, '{"v":2}', signature, domain: domain),
          isFalse,
        );
        expect(
          await verify(
            verifier,
            body,
            base64Encode(List.filled(64, 0)),
            domain: domain,
          ),
          isFalse,
        );
        expect(
          await verify(
            verifier,
            body,
            signature,
            domain: domain,
            key: base64Encode(List.filled(32, 3)),
          ),
          isFalse,
        );
        expect(
          await verify(
            verifier,
            body,
            signature,
            domain: domain == userAuthorityDomain
                ? userStateDomain
                : userAuthorityDomain,
          ),
          isFalse,
        );
        expect(verifier.statistics.hits, 1);
        expect(verifier.statistics.verifications, 5);
        expect(verifier.statistics.entries, 1);
        final provider = ProbeCryptography()..refuse = true;
        Cryptography.instance = provider;
        expect(
          await verify(verifier, body, signature, domain: domain),
          isFalse,
        );
        provider.fail = true;
        await expectLater(
          verify(verifier, body, signature, domain: domain),
          throwsStateError,
        );
        expect(provider.calls, 2);
        expect(verifier.statistics.entries, 1);
        expect(verifier.statistics.hits, 1);
        expect(verifier.statistics.verifications, 7);
        Cryptography.instance = pure;
        expect(await verify(verifier, body, signature, domain: domain), isTrue);
        expect(verifier.statistics.hits, 2);
        expect(verifier.statistics.verifications, 7);
      },
    );
  }

  test(
    'concurrent misses retain one completed tuple without coalescing work',
    () async {
      final verifier = JoinProofVerifier();
      const body = '{}';
      final signature = await sign(body);
      final first = verify(verifier, body, signature);
      final second = verify(verifier, body, signature);
      expect(verifier.statistics.entries, 0);
      expect(verifier.statistics.verifications, 2);
      expect(await first, isTrue);
      expect(await second, isTrue);
      expect(verifier.statistics.entries, 1);
      expect(verifier.statistics.hits, 0);
    },
  );

  test('accepted base64 aliases keep exact text identity without changing decoding policy', () async {
    final verifier = JoinProofVerifier();
    String alias(String text) => text.replaceAll('+', '-').replaceAll('/', '_');
    for (var seed = 0; alias(publicKey) == publicKey; seed++) {
      keyPair = await pure.ed25519().newKeyPairFromSeed(List.filled(32, seed));
      publicKey = base64Encode((await keyPair.extractPublicKey()).bytes);
    }
    var body = '{}';
    var signature = await sign(body);
    for (var n = 0; alias(signature) == signature; n++) {
      body = '{"n":$n}';
      signature = await sign(body);
    }
    expect(await verify(verifier, body, signature), isTrue);
    expect(await verify(verifier, body, alias(signature)), isTrue);
    expect(
      await verify(verifier, body, signature, key: alias(publicKey)),
      isTrue,
    );
    expect(verifier.statistics.verifications, 3);
    expect(verifier.statistics.entries, 3);
    expect(verifier.statistics.hits, 0);
  });

  test('eight public persisted domains are admitted and private peer or ACK proofs never are', () async {
    final verifier = JoinProofVerifier();
    const body = '{}';
    for (final domain in [
      certificateDomain,
      'wiredpart.company.join.request@1:',
      'wiredpart.company.join.channel@1:',
      'wiredpart.company.join.issuance@1:',
      'wiredpart.company.join.activation@1:',
      userAuthorityDomain,
      userStateDomain,
      factsDomain,
    ]) {
      final signature = await sign(body, domain);
      expect(await verify(verifier, body, signature, domain: domain), isTrue);
      expect(await verify(verifier, body, signature, domain: domain), isTrue);
    }
    expect(verifier.statistics.entries, 8);
    expect(verifier.statistics.hits, 8);
    for (final domain in [
      'wiredpart.company.join.ack@1:',
      'wiredpart.company.peer.initiator@1:',
      'wiredpart.company.peer.responder@1:',
      'wiredpart.company.peer.completion@1:',
      'wiredpart.company.user.credential.grant@1:',
      'wiredpart.company.user.provision.issuance@1:',
      'wiredpart.company.user.pin.issuance@1:',
      'wiredpart.company.user.provision.receipt@1:',
      'wiredpart.company.user.state.receipt@1:',
      'unknown:',
    ]) {
      final signature = await sign(body, domain);
      expect(await verify(verifier, body, signature, domain: domain), isTrue);
      expect(await verify(verifier, body, signature, domain: domain), isTrue);
    }
    expect(verifier.statistics.entries, 8);
    expect(verifier.statistics.hits, 8);
    expect(verifier.statistics.verifications, 28);
  });

  test(
    'malformed proofs and failed verification never insert or hit',
    () async {
      final verifier = JoinProofVerifier();
      const body = '{}';
      final signature = await sign(body);
      expect(await verify(verifier, body, signature), isTrue);
      final before = verifier.statistics;
      await expectLater(
        verify(verifier, body, '!' * 88),
        throwsFormatException,
      );
      expect(await verify(verifier, body, 'A' * 88), isFalse);
      expect(
        await verify(verifier, body, base64Encode(List.filled(63, 1))),
        isFalse,
      );
      expect(
        await verify(
          verifier,
          body,
          signature,
          key: base64Encode(List.filled(31, 1)),
        ),
        isFalse,
      );
      expect(
        await verify(verifier, body, base64Encode(List.filled(64, 0))),
        isFalse,
      );
      expect(
        await verify(verifier, body, base64Encode(List.filled(64, 0))),
        isFalse,
      );
      expect(verifier.statistics.entries, before.entries);
      expect(verifier.statistics.hits, before.hits);
    },
  );

  test(
    'a captured canonical body is verified once even when caller data mutates',
    () async {
      final verifier = JoinProofVerifier();
      final body = <String, Object?>{
        'nested': <Object?>[1],
      };
      final original = jsonEncode(body);
      final signature = await sign(original);
      var captures = 0;
      final pending = verifier.verify(
        domain: certificateDomain,
        canonicalBody: () {
          captures++;
          return jsonEncode(body);
        },
        publicKeyText: publicKey,
        signatureText: signature,
      );
      (body['nested'] as List)[0] = 2;
      expect(await pending, isTrue);
      expect(captures, 1);
      expect(await verify(verifier, original, signature), isTrue);
      expect(await verify(verifier, jsonEncode(body), signature), isFalse);
      expect(verifier.statistics.hits, 1);
    },
  );

  test(
    'custom providers always run, including old async successes and failures',
    () async {
      final verifier = JoinProofVerifier();
      const body = '{}';
      final signature = await sign(body);
      expect(await verify(verifier, body, signature), isTrue);
      const newBody = '{"new":true}';
      final newSignature = await sign(newBody);
      final provider = ProbeCryptography()..gate = Completer<void>();
      Cryptography.instance = provider;
      final old = verify(verifier, newBody, newSignature);
      expect(provider.calls, 1);
      Cryptography.instance = pure;
      provider.gate!.complete();
      expect(await old, isTrue);
      expect(verifier.statistics.entries, 1);
      Cryptography.instance = provider;
      provider.refuse = true;
      expect(await verify(verifier, body, signature), isFalse);
      provider.fail = true;
      await expectLater(verify(verifier, body, signature), throwsStateError);
      expect(provider.calls, 3);
      expect(verifier.statistics.hits, 0);
      Cryptography.instance = pure;
      expect(await verify(verifier, body, signature), isTrue);
      expect(verifier.statistics.hits, 1);
    },
  );

  test('default completion during provider replacement cannot authorize the replacement', () async {
    final verifier = JoinProofVerifier();
    const body = '{}';
    final signature = await sign(body);
    final pending = verify(verifier, body, signature);
    final provider = ProbeCryptography()..refuse = true;
    Cryptography.instance = provider;
    expect(await pending, isTrue);
    expect(await verify(verifier, body, signature), isFalse);
    expect(provider.calls, 1);
    expect(verifier.statistics.hits, 0);
    Cryptography.instance = pure;
    expect(await verify(verifier, body, signature), isTrue);
    expect(verifier.statistics.hits, 1);
  });

  test('a canonicalization exception cannot add a positive', () async {
    final verifier = JoinProofVerifier();
    final signature = await sign('{}');
    await expectLater(
      verifier.verify(
        domain: certificateDomain,
        canonicalBody: () =>
            throw StateError('synthetic canonicalization failure'),
        publicKeyText: publicKey,
        signatureText: signature,
      ),
      throwsStateError,
    );
    expect(verifier.statistics.entries, 0);
    expect(verifier.statistics.verifications, 0);
  });

  test(
    'entry capacity evicts positives and evicted proofs verify normally',
    () async {
      final verifier = JoinProofVerifier();
      for (var i = 0; i < 65; i++) {
        final body = '{"n":$i}';
        expect(await verify(verifier, body, await sign(body)), isTrue);
        expect(verifier.statistics.entries, lessThanOrEqualTo(64));
        expect(verifier.statistics.codeUnits, lessThanOrEqualTo(65536));
      }
      expect(verifier.statistics.entries, 64);
      expect(verifier.statistics.evictions, 1);
      expect(await verify(verifier, '{"n":0}', await sign('{"n":0}')), isTrue);
      expect(verifier.statistics.verifications, 66);
    },
  );

  test(
    'UTF16 retention bounds and oversized proofs fall back without refusal',
    () async {
      final verifier = JoinProofVerifier();
      for (var i = 0; i < 12; i++) {
        final body = jsonEncode({'n': i, 'text': '😀' * 3000});
        expect(await verify(verifier, body, await sign(body)), isTrue);
        expect(verifier.statistics.codeUnits, lessThanOrEqualTo(65536));
      }
      expect(verifier.statistics.entries, lessThan(12));
      final retained = verifier.statistics;
      final body = jsonEncode({'text': '😀' * 4100});
      final signature = await sign(body);
      expect(await verify(verifier, body, signature), isTrue);
      expect(await verify(verifier, body, signature), isTrue);
      expect(verifier.statistics.entries, retained.entries);
      expect(verifier.statistics.codeUnits, retained.codeUnits);
      expect(verifier.statistics.hits, retained.hits);
    },
  );
}

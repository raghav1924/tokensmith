import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { ExploitSimulator } from '../core/simulator.js';
import { TokenCrypto } from '../core/crypto.js';

describe('Exploit Simulator Suite', () => {
  const legitToken = TokenCrypto.createJWT(
    { alg: 'HS256', typ: 'JWT' },
    { sub: 'usr_42', role: 'user' },
    'legit-secret-key-32-characters-tokensmith'
  );

  it('should simulate alg: "none" privilege escalation and verify naive vulnerability vs hardened block', () => {
    const res = ExploitSimulator.simulateAlgNone(legitToken);

    assert.strictEqual(res.attackType, 'alg-none-bypass');
    assert.strictEqual(res.vulnerableToNaiveVerifier, true);
    assert.strictEqual(res.blockedByHardenedVerifier, true);

    const parts = res.forgedToken.split('.');
    const header = JSON.parse(TokenCrypto.base64UrlDecode(parts[0]));
    const payload = JSON.parse(TokenCrypto.base64UrlDecode(parts[1]));

    assert.strictEqual(header.alg, 'none');
    assert.strictEqual(payload.role, 'superadmin');
    assert.strictEqual(parts[2], ''); // Empty signature
  });

  it('should simulate Algorithm Confusion attack (RS256 to HS256 key confusion)', () => {
    const rsToken = TokenCrypto.createJWT(
      { alg: 'RS256', typ: 'JWT' },
      { sub: 'usr_99', role: 'user' }
    );

    const res = ExploitSimulator.simulateAlgorithmConfusion(rsToken);
    assert.strictEqual(res.attackType, 'algorithm-confusion');
    assert.strictEqual(res.vulnerableToNaiveVerifier, true);
    assert.strictEqual(res.blockedByHardenedVerifier, true);
  });

  it('should detect and flag direct payload tampering', () => {
    const res = ExploitSimulator.simulatePayloadTampering(legitToken);
    assert.strictEqual(res.attackType, 'payload-tampering');
    assert.strictEqual(res.blockedByHardenedVerifier, true);
  });
});

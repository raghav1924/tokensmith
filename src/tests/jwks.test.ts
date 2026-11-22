import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { JwksInspector } from '../core/jwks.js';

describe('JWKS Inspector & Rotation Suite', () => {
  it('should validate standard RFC 7517 JWKS structure', () => {
    const mockJwks = JwksInspector.generateMockJWKS();
    const res = JwksInspector.validate(mockJwks);

    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.keyCount, 2);
    assert.strictEqual(res.issues.length, 0);
  });

  it('should flag invalid JWKS without keys array or missing kid', () => {
    const badJwks = { keys: [{ kty: 'RSA' }] } as any;
    const res = JwksInspector.validate(badJwks);

    assert.strictEqual(res.isValid, false);
    assert.ok(res.issues.some(i => i.includes('kid')));
  });

  it('should simulate zero-downtime key rotation stages accurately', () => {
    const current = JwksInspector.generateMockJWKS();
    const newKey = {
      kty: 'RSA',
      kid: 'tokensmith-2027-next-k3',
      use: 'sig',
      alg: 'RS256',
      n: 'new_modulus_123',
      e: 'AQAB'
    };

    const rotation = JwksInspector.simulateKeyRotation(current, newKey);
    assert.strictEqual(rotation.phase1_DualPublished.keys.length, 3);
    assert.strictEqual(rotation.phase2_ActiveSigningKid, 'tokensmith-2027-next-k3');
    assert.strictEqual(rotation.phase3_RetiredJwks.keys.length, 1);
    assert.strictEqual(rotation.instructions.length, 5);
  });
});

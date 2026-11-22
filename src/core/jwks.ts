/**
 * TokenSmith JWKS (JSON Web Key Set) Inspector & Rotation Simulator
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

import { JWKS, JWK } from '../types.js';

export class JwksInspector {
  /**
   * Validate RFC 7517 JSON Web Key Set structure and security parameters
   */
  static validate(jwks: JWKS): { isValid: boolean; issues: string[]; keyCount: number } {
    const issues: string[] = [];

    if (!jwks || !Array.isArray(jwks.keys)) {
      return { isValid: false, issues: ['JWKS root must contain a "keys" array.'], keyCount: 0 };
    }

    if (jwks.keys.length === 0) {
      issues.push('JWKS contains an empty "keys" array. Verification will fail for all incoming tokens.');
    }

    const seenKids = new Set<string>();

    for (let i = 0; i < jwks.keys.length; i++) {
      const key = jwks.keys[i];
      if (!key.kty) {
        issues.push(`Key #${i + 1} is missing the required "kty" (Key Type) parameter.`);
      }
      if (!key.kid) {
        issues.push(`Key #${i + 1} is missing "kid" (Key ID). Tokens cannot unambiguously select this key.`);
      } else {
        if (seenKids.has(key.kid)) {
          issues.push(`Duplicate "kid" found: "${key.kid}". Key IDs within a JWKS must be unique.`);
        }
        seenKids.add(key.kid);
      }
      if (key.use && key.use !== 'sig') {
        issues.push(`Key "${key.kid || i}" specifies use: "${key.use}". Expected "sig" (signature) for token verification.`);
      }
      if (key.kty === 'RSA' && (!key.n || !key.e)) {
        issues.push(`RSA Key "${key.kid || i}" is missing modulus "n" or exponent "e".`);
      }
    }

    return {
      isValid: issues.length === 0,
      issues,
      keyCount: jwks.keys.length
    };
  }

  /**
   * Simulate a Zero-Downtime Key Rotation across 3 phases:
   * Phase 1: Publish new public key to JWKS (Dual-key publication)
   * Phase 2: Switch token issuer active signing key to new key (Both valid)
   * Phase 3: Retire old key after token max TTL has elapsed
   */
  static simulateKeyRotation(currentJwks: JWKS, newKey: JWK): {
    phase1_DualPublished: JWKS;
    phase2_ActiveSigningKid: string;
    phase3_RetiredJwks: JWKS;
    instructions: string[];
  } {
    const primaryOldKid = currentJwks.keys[0]?.kid || 'legacy-key';
    const newKid = newKey.kid || `key-${Date.now()}`;

    // Phase 1: Dual publication (both old and new keys present in JWKS)
    const phase1: JWKS = {
      keys: [...currentJwks.keys, { ...newKey, kid: newKid }]
    };

    // Phase 3: Retirement (old key removed)
    const phase3: JWKS = {
      keys: [{ ...newKey, kid: newKid }]
    };

    return {
      phase1_DualPublished: phase1,
      phase2_ActiveSigningKid: newKid,
      phase3_RetiredJwks: phase3,
      instructions: [
        `Step 1: Deploy new public key "${newKid}" to .well-known/jwks.json alongside existing "${primaryOldKid}".`,
        `Step 2: Wait for CDN/cache TTL (e.g. 1 hour) to ensure all edge verifiers have cached the new JWKS.`,
        `Step 3: Update authentication service to begin signing new JWTs with private key "${newKid}".`,
        `Step 4: Allow max token expiration duration (e.g. 24 hours) for old tokens to naturally expire.`,
        `Step 5: Safely remove retired key "${primaryOldKid}" from .well-known/jwks.json.`
      ]
    };
  }

  /**
   * Generate sample mock JWKS for testing
   */
  static generateMockJWKS(): JWKS {
    return {
      keys: [
        {
          kty: 'RSA',
          kid: 'tokensmith-2026-prod-k1',
          use: 'sig',
          alg: 'RS256',
          n: 'u1lK_mock_rsa_modulus_tokensmith_production_key_01',
          e: 'AQAB'
        },
        {
          kty: 'RSA',
          kid: 'tokensmith-2026-canary-k2',
          use: 'sig',
          alg: 'RS256',
          n: 'w9xZ_mock_rsa_modulus_tokensmith_canary_key_02',
          e: 'AQAB'
        }
      ]
    };
  }
}

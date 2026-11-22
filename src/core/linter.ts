/**
 * TokenSmith JWT & JWKS Security Linter
 * Evaluates tokens against 16+ cryptographic, claim, and entropy heuristics.
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

import { TokenCrypto } from './crypto.js';
import { TokenAuditResult, AuditIssue, DecodedJWT } from '../types.js';

const WEAK_DICTIONARY_SECRETS = new Set([
  'secret',
  'password',
  'jwt_secret',
  'secret123',
  'development',
  'dev_secret',
  'admin',
  '123456',
  '12345678',
  'test',
  'testing',
  'supersecret',
  'mysecretkey',
  'changeme',
  'app_secret'
]);

const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /passwd/i,
  /secret/i,
  /private_key/i,
  /api_key/i,
  /apikey/i,
  /access_token/i,
  /bearer/i,
  /sk_live_[0-9a-zA-Z]+/i,
  /ghp_[0-9a-zA-Z]+/i,
  /AKIA[0-9A-Z]{16}/i
];

export class TokenLinter {
  /**
   * Audit a JWT string, optional HMAC secret, and reference timestamp
   */
  static audit(token: string, secret?: string, now = Math.floor(Date.now() / 1000)): TokenAuditResult {
    let decoded: DecodedJWT;
    try {
      decoded = TokenCrypto.parseJWT(token);
    } catch (e: any) {
      return {
        token,
        isValidFormat: false,
        score: 0,
        grade: 'F',
        algorithm: 'UNKNOWN',
        header: { alg: 'UNKNOWN' },
        payload: {},
        issues: [
          {
            code: 'JWT-000',
            severity: 'CRITICAL',
            section: 'HEADER',
            message: `Malformed JWT structure: ${e.message}`,
            recommendation: 'Ensure token follows the RFC 7519 standard: `base64url(header).base64url(payload).base64url(signature)`.'
          }
        ],
        isExpired: false,
        exploitVulnerabilities: {
          vulnerableToAlgNone: false,
          vulnerableToKeyConfusion: false,
          vulnerableToWeakSecret: false,
          hasSensitiveDataLeak: false
        }
      };
    }

    const issues: AuditIssue[] = [];
    const header = decoded.header;
    const payload = decoded.payload;
    const alg = (header.alg || '').toLowerCase();

    // 1. JWT-001: alg: "none"
    if (alg === 'none') {
      issues.push({
        code: 'JWT-001',
        severity: 'CRITICAL',
        section: 'HEADER',
        message: 'Token algorithm is explicitly set to "none". Unsigned tokens are vulnerable to arbitrary tampering and privilege escalation.',
        recommendation: 'Enforce a strict whitelist of cryptographic algorithms (e.g. HS256, RS256, ES256) and reject alg: "none".',
        detectedValue: 'alg: none'
      });
    }

    // 2. Secret entropy checks (if secret provided)
    let secretEntropyBits = 0;
    if (secret) {
      const entropy = TokenCrypto.calculateShannonEntropy(secret);
      secretEntropyBits = Math.round(entropy * secret.length);

      if (WEAK_DICTIONARY_SECRETS.has(secret.toLowerCase().trim())) {
        issues.push({
          code: 'JWT-003',
          severity: 'CRITICAL',
          section: 'SECRET',
          message: `HMAC secret "${secret}" is a common dictionary password easily cracked in milliseconds via offline dictionary attacks.`,
          recommendation: 'Generate a cryptographically secure random secret of at least 256 bits (32 random bytes) using `crypto.randomBytes(32).toString("hex")`.',
          detectedValue: secret
        });
      } else if (secret.length < 32 || entropy < 3.5) {
        issues.push({
          code: 'JWT-002',
          severity: 'HIGH',
          section: 'SECRET',
          message: `HMAC secret has low entropy (${entropy} per character, ${secret.length} characters). Standard RFC 7518 requires keys to be at least as long as the hash output (256 bits for HS256).`,
          recommendation: 'Use a high-entropy secret with at least 32 characters (256 bits) of random cryptographic material.',
          detectedValue: `${secret.length} chars, ${entropy} Shannon entropy`
        });
      }
    }

    // 3. JWT-004: Sensitive data leak in payload
    let hasSensitiveLeak = false;
    for (const [key, val] of Object.entries(payload)) {
      const strVal = String(val);
      for (const pattern of SENSITIVE_KEY_PATTERNS) {
        if (pattern.test(key) || pattern.test(strVal)) {
          hasSensitiveLeak = true;
          issues.push({
            code: 'JWT-004',
            severity: 'CRITICAL',
            section: 'PAYLOAD',
            message: `Sensitive credential or PII detected in payload claim "${key}". JWT payloads are only base64url encoded and can be read by anyone in possession of the token.`,
            recommendation: 'Never place passwords, database credentials, or secret API keys in a JWT payload. Store sensitive data in secure backend sessions.',
            detectedValue: `Claim: ${key}`
          });
          break;
        }
      }
    }

    // 4. JWT-005: Missing expiration claim
    if (payload.exp === undefined) {
      issues.push({
        code: 'JWT-005',
        severity: 'HIGH',
        section: 'CLAIMS',
        message: 'Token is missing the "exp" (expiration time) claim. The token will remain valid perpetually if leaked or stolen.',
        recommendation: 'Always set a finite expiration timestamp (`exp: Math.floor(Date.now() / 1000) + 3600`).'
      });
    }

    // 5. JWT-006: Excessive expiration lifespan
    let lifespanSeconds: number | undefined;
    let isExpired = false;
    let expiresInSeconds: number | undefined;

    if (payload.exp !== undefined) {
      if (payload.iat !== undefined) {
        lifespanSeconds = payload.exp - payload.iat;
        if (lifespanSeconds > 30 * 86400) {
          issues.push({
            code: 'JWT-006',
            severity: 'MEDIUM',
            section: 'CLAIMS',
            message: `Token lifespan is excessively long (${Math.round(lifespanSeconds / 86400)} days). Long-lived access tokens increase the blast radius of stolen credentials.`,
            recommendation: 'Issue short-lived access tokens (15 minutes to 1 hour) paired with secure refresh tokens.',
            detectedValue: `${lifespanSeconds} seconds`
          });
        }
      }

      // Check current expiration
      expiresInSeconds = payload.exp - now;
      if (expiresInSeconds < 0) {
        isExpired = true;
        issues.push({
          code: 'JWT-011',
          severity: 'HIGH',
          section: 'CLAIMS',
          message: `Token has expired (${Math.abs(expiresInSeconds)} seconds ago).`,
          recommendation: 'Reject expired tokens and require client refresh or re-authentication.',
          detectedValue: `exp: ${payload.exp}, now: ${now}`
        });
      }
    }

    // 6. JWT-007: Missing audience
    if (!payload.aud) {
      issues.push({
        code: 'JWT-007',
        severity: 'MEDIUM',
        section: 'CLAIMS',
        message: 'Token is missing the "aud" (audience) claim. Cross-service token reuse cannot be verified.',
        recommendation: 'Set the "aud" claim to your application\'s client ID or resource identifier.',
      });
    }

    // 7. JWT-008: Missing issuer
    if (!payload.iss) {
      issues.push({
        code: 'JWT-008',
        severity: 'MEDIUM',
        section: 'CLAIMS',
        message: 'Token is missing the "iss" (issuer) claim.',
        recommendation: 'Set the "iss" claim to identify your authentication authority (e.g. https://auth.example.com).'
      });
    }

    // 8. JWT-009: Issued in future (iat > now + 60s)
    if (payload.iat !== undefined && payload.iat > now + 60) {
      issues.push({
        code: 'JWT-009',
        severity: 'HIGH',
        section: 'CLAIMS',
        message: `Token "iat" (issued at) timestamp is in the future (${payload.iat - now}s ahead of server clock).`,
        recommendation: 'Check server time synchronization (NTP) or verify token origin.',
        detectedValue: `iat: ${payload.iat}`
      });
    }

    // 9. JWT-010: Not before in future
    if (payload.nbf !== undefined && payload.nbf > now) {
      issues.push({
        code: 'JWT-010',
        severity: 'HIGH',
        section: 'CLAIMS',
        message: `Token "nbf" (not before) timestamp is in the future (${payload.nbf - now}s remaining).`,
        recommendation: 'Reject token until nbf timestamp has elapsed.',
        detectedValue: `nbf: ${payload.nbf}`
      });
    }

    // 10. JWT-012: Missing kid in multi-key environment
    if (!header.kid && (alg.startsWith('rs') || alg.startsWith('es'))) {
      issues.push({
        code: 'JWT-012',
        severity: 'LOW',
        section: 'HEADER',
        message: 'Asymmetric token is missing "kid" (key ID) header. Automated zero-downtime key rotation is impaired.',
        recommendation: 'Include "kid" matching the key identifier in your JWKS endpoint.'
      });
    }

    // 11. JWT-014: Algorithm confusion hazard
    if (alg === 'hs256' && secret && secret.includes('BEGIN PUBLIC KEY')) {
      issues.push({
        code: 'JWT-014',
        severity: 'CRITICAL',
        section: 'HEADER',
        message: 'CRITICAL: Algorithm confusion vulnerability detected! Token specifies symmetric HS256 but secret appears to be an RSA Public Key.',
        recommendation: 'Separate symmetric and asymmetric verification pathways. Never allow HMAC algorithms to verify with public key credentials.',
        detectedValue: 'HS256 with Public Key PEM'
      });
    }

    // 12. JWT-015: Missing jti (JWT ID)
    if (!payload.jti) {
      issues.push({
        code: 'JWT-015',
        severity: 'LOW',
        section: 'CLAIMS',
        message: 'Token is missing "jti" (JWT ID) claim. Revocation lists and replay attack prevention cannot be enforced.',
        recommendation: 'Assign a unique UUID to the "jti" claim for one-time or revokable tokens.'
      });
    }

    // 13. JWT-016: Deprecated algorithm
    if (alg.includes('rs1') || alg.includes('sha1') || alg.includes('md5')) {
      issues.push({
        code: 'JWT-016',
        severity: 'HIGH',
        section: 'HEADER',
        message: `Deprecated and cryptographically weak signature algorithm "${header.alg}".`,
        recommendation: 'Migrate to modern SHA-256 or SHA-512 based algorithms (RS256, ES256, or EdDSA).'
      });
    }

    // Calculate score (0 to 100)
    let score = 100;
    for (const issue of issues) {
      switch (issue.severity) {
        case 'CRITICAL':
          score -= 35;
          break;
        case 'HIGH':
          score -= 20;
          break;
        case 'MEDIUM':
          score -= 10;
          break;
        case 'LOW':
          score -= 5;
          break;
        case 'INFO':
          break;
      }
    }
    score = Math.max(0, Math.min(100, score));

    // Grade assignment
    let grade: 'A+' | 'A' | 'B' | 'C' | 'F' = 'F';
    if (score >= 95) grade = 'A+';
    else if (score >= 85) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 50) grade = 'C';
    else grade = 'F';

    return {
      token,
      isValidFormat: true,
      score,
      grade,
      algorithm: header.alg || 'UNKNOWN',
      header,
      payload,
      issues,
      secretEntropyBits: secret ? secretEntropyBits : undefined,
      lifespanSeconds,
      isExpired,
      expiresInSeconds,
      exploitVulnerabilities: {
        vulnerableToAlgNone: alg === 'none',
        vulnerableToKeyConfusion: alg === 'hs256' && !!secret && secret.includes('BEGIN PUBLIC KEY'),
        vulnerableToWeakSecret: !!(secret && (WEAK_DICTIONARY_SECRETS.has(secret.toLowerCase().trim()) || secret.length < 32)),
        hasSensitiveDataLeak: hasSensitiveLeak
      }
    };
  }
}

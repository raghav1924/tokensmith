import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { TokenLinter } from '../core/linter.js';
import { TokenCrypto } from '../core/crypto.js';

describe('Token Security Linter Suite', () => {
  it('should flag alg: "none" as CRITICAL vulnerability (JWT-001)', () => {
    const noneToken = TokenCrypto.createJWT({ alg: 'none', typ: 'JWT' }, { sub: '123' });
    const audit = TokenLinter.audit(noneToken);

    assert.strictEqual(audit.exploitVulnerabilities.vulnerableToAlgNone, true);
    const jwt001 = audit.issues.find(i => i.code === 'JWT-001');
    assert.ok(jwt001, 'JWT-001 should be detected');
    assert.strictEqual(jwt001?.severity, 'CRITICAL');
  });

  it('should flag weak dictionary secret as CRITICAL (JWT-003)', () => {
    const token = TokenCrypto.createJWT({ alg: 'HS256' }, { sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 }, 'secret');
    const audit = TokenLinter.audit(token, 'secret');

    const jwt003 = audit.issues.find(i => i.code === 'JWT-003');
    assert.ok(jwt003, 'JWT-003 should be detected');
    assert.strictEqual(jwt003?.severity, 'CRITICAL');
  });

  it('should flag sensitive password/credential leak in payload (JWT-004)', () => {
    const leakToken = TokenCrypto.createJWT(
      { alg: 'HS256' },
      { sub: 'usr_1', password_hash: 'plain_secret_pass', exp: Math.floor(Date.now() / 1000) + 3600 },
      'secure-32-chars-long-secret-key-xyz'
    );
    const audit = TokenLinter.audit(leakToken, 'secure-32-chars-long-secret-key-xyz');

    assert.strictEqual(audit.exploitVulnerabilities.hasSensitiveDataLeak, true);
    const jwt004 = audit.issues.find(i => i.code === 'JWT-004');
    assert.ok(jwt004, 'JWT-004 should be detected');
    assert.strictEqual(jwt004?.severity, 'CRITICAL');
  });

  it('should detect expired tokens (JWT-011)', () => {
    const expiredToken = TokenCrypto.createJWT(
      { alg: 'HS256' },
      { sub: 'usr_2', exp: Math.floor(Date.now() / 1000) - 100 }
    );
    const audit = TokenLinter.audit(expiredToken);

    assert.strictEqual(audit.isExpired, true);
    const jwt011 = audit.issues.find(i => i.code === 'JWT-011');
    assert.ok(jwt011, 'JWT-011 should be detected');
  });

  it('should award A+ grade for production-hardened token and high-entropy secret', () => {
    const now = Math.floor(Date.now() / 1000);
    const strongSecret = 'f9a2e6b8c1d4e7f0a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9';
    const strongToken = TokenCrypto.createJWT(
      { alg: 'HS256', typ: 'JWT', kid: 'key-1' },
      {
        sub: 'usr_100',
        role: 'user',
        iss: 'https://auth.example.com',
        aud: 'https://api.example.com',
        iat: now,
        exp: now + 1800,
        jti: 'unique-jwt-id-123'
      },
      strongSecret
    );

    const audit = TokenLinter.audit(strongToken, strongSecret, now);
    assert.strictEqual(audit.score, 100);
    assert.strictEqual(audit.grade, 'A+');
    assert.strictEqual(audit.issues.length, 0);
  });
});

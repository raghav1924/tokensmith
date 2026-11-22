import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { TokenCrypto } from '../core/crypto.js';

describe('TokenSmith Cryptographic Engine Suite', () => {
  it('should encode and decode RFC 7515 Base64URL without padding or url-unsafe characters', () => {
    const raw = 'Hello World & Cryptography >> 2026';
    const encoded = TokenCrypto.base64UrlEncode(raw);
    assert.strictEqual(encoded.includes('='), false);
    assert.strictEqual(encoded.includes('+'), false);
    assert.strictEqual(encoded.includes('/'), false);

    const decoded = TokenCrypto.base64UrlDecode(encoded);
    assert.strictEqual(decoded, raw);
  });

  it('should sign and verify HMAC-SHA256 with timing-safe validation', () => {
    const secret = 'super-secret-key-32-chars-long-tokensmith';
    const payload = 'header.payload';
    const sig = TokenCrypto.signHmac('HS256', payload, secret);

    assert.strictEqual(typeof sig, 'string');
    assert.strictEqual(sig.length > 20, true);

    // Verify valid signature
    assert.strictEqual(TokenCrypto.verifyHmac('HS256', payload, sig, secret), true);

    // Verify invalid signature rejected
    assert.strictEqual(TokenCrypto.verifyHmac('HS256', payload, 'tamperedSig', secret), false);

    // Verify incorrect secret rejected
    assert.strictEqual(TokenCrypto.verifyHmac('HS256', payload, sig, 'wrong-secret'), false);
  });

  it('should calculate Shannon entropy accurately', () => {
    // Low entropy
    const low = TokenCrypto.calculateShannonEntropy('aaaaaa');
    assert.strictEqual(low, 0);

    // High entropy random string
    const high = TokenCrypto.calculateShannonEntropy('aZ9!bX2$qW8#kP1@');
    assert.strictEqual(high > 3.5, true);
  });

  it('should create and parse complete compact JWTs', () => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { sub: '123', name: 'Jatin' };
    const secret = 'test-secret-key-at-least-32-chars-ok';

    const token = TokenCrypto.createJWT(header, payload, secret);
    const parts = token.split('.');
    assert.strictEqual(parts.length, 3);

    const parsed = TokenCrypto.parseJWT(token);
    assert.strictEqual(parsed.header.alg, 'HS256');
    assert.strictEqual(parsed.payload.sub, '123');
    assert.strictEqual(parsed.payload.name, 'Jatin');
  });
});

/**
 * TokenSmith Cryptographic Engine
 * Zero-dependency RFC 7519 Base64URL, HMAC, Timing-Safe Equality, and Shannon Entropy.
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

import crypto from 'node:crypto';
import { DecodedJWT, JWTHeader, JWTPayload } from '../types.js';

export class TokenCrypto {
  /**
   * Encode string or Buffer into RFC 7515 Base64URL format (no padding, url-safe chars)
   */
  static base64UrlEncode(input: string | any): string {
    const buf = typeof input === 'string' ? Buffer.from(input, 'utf-8') : input;
    return buf.toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  /**
   * Decode RFC 7515 Base64URL format back into UTF-8 string
   */
  static base64UrlDecode(input: string): string {
    let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  /**
   * Decode RFC 7515 Base64URL format into binary Buffer
   */
  static base64UrlDecodeToBuffer(input: string): any {
    let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    return Buffer.from(base64, 'base64');
  }

  /**
   * Sign data string using HMAC algorithm and return Base64URL signature
   */
  static signHmac(algorithm: 'HS256' | 'HS384' | 'HS512', data: string, secret: string): string {
    const hashAlg = algorithm === 'HS256' ? 'sha256' : algorithm === 'HS384' ? 'sha384' : 'sha512';
    const hmac = crypto.createHmac(hashAlg, secret);
    hmac.update(data);
    const digestBuffer = hmac.digest();
    return this.base64UrlEncode(digestBuffer);
  }

  /**
   * Verify HMAC signature using constant-time comparison to prevent timing attacks
   */
  static verifyHmac(
    algorithm: 'HS256' | 'HS384' | 'HS512',
    data: string,
    signatureBase64Url: string,
    secret: string
  ): boolean {
    try {
      const expectedSig = this.signHmac(algorithm, data, secret);
      const expectedBuf = Buffer.from(expectedSig);
      const actualBuf = Buffer.from(signatureBase64Url);

      if (expectedBuf.length !== actualBuf.length) {
        return false;
      }

      return crypto.timingSafeEqual(expectedBuf, actualBuf);
    } catch {
      return false;
    }
  }

  /**
   * Calculate Shannon Entropy H of a string: H = -sum(p * log2(p))
   * Measures cryptographic randomness and strength of keys.
   */
  static calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;

    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }

    return parseFloat(entropy.toFixed(3));
  }

  /**
   * Construct and sign a compact JWT string
   */
  static createJWT(header: JWTHeader, payload: JWTPayload, secret?: string): string {
    const rawHeader = this.base64UrlEncode(JSON.stringify(header));
    const rawPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${rawHeader}.${rawPayload}`;

    if (header.alg === 'none' || !secret) {
      return `${signingInput}.`;
    }

    const alg = (header.alg || 'HS256') as 'HS256' | 'HS384' | 'HS512';
    const signature = this.signHmac(alg, signingInput, secret);
    return `${signingInput}.${signature}`;
  }

  /**
   * Parse compact JWT string into its 3 decoded sections
   */
  static parseJWT(token: string): DecodedJWT {
    const parts = (token || '').trim().split('.');
    if (parts.length < 2 || parts.length > 3) {
      throw new Error(`Invalid compact JWT format: expected 3 dot-separated segments, received ${parts.length}`);
    }

    const rawHeader = parts[0];
    const rawPayload = parts[1];
    const rawSignature = parts[2] || '';

    let header: JWTHeader;
    let payload: JWTPayload;

    try {
      header = JSON.parse(this.base64UrlDecode(rawHeader));
    } catch (e: any) {
      throw new Error(`Failed to parse JWT header: ${e.message}`);
    }

    try {
      payload = JSON.parse(this.base64UrlDecode(rawPayload));
    } catch (e: any) {
      throw new Error(`Failed to parse JWT payload: ${e.message}`);
    }

    return {
      header,
      payload,
      signature: rawSignature,
      rawHeader,
      rawPayload,
      rawSignature,
      rawToken: token
    };
  }
}

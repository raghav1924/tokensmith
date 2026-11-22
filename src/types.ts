/**
 * TokenSmith Core Type Definitions
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

export type JWTAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'none';

export interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
  crit?: string[];
  cty?: string;
  [key: string]: any;
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: any;
}

export interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
  rawHeader: string;
  rawPayload: string;
  rawSignature: string;
  rawToken: string;
}

export type IssueSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type TokenSection = 'HEADER' | 'PAYLOAD' | 'SIGNATURE' | 'SECRET' | 'CLAIMS';

export interface AuditIssue {
  code: string;
  severity: IssueSeverity;
  section: TokenSection;
  message: string;
  recommendation: string;
  detectedValue?: string;
}

export interface ExploitSimulationResult {
  attackType: 'alg-none-bypass' | 'algorithm-confusion' | 'clock-skew-spoof' | 'payload-tampering';
  name: string;
  description: string;
  forgedToken: string;
  vulnerableToNaiveVerifier: boolean;
  blockedByHardenedVerifier: boolean;
  technicalDetails: string;
}

export interface TokenAuditResult {
  token: string;
  isValidFormat: boolean;
  score: number; // 0 - 100
  grade: 'A+' | 'A' | 'B' | 'C' | 'F';
  algorithm: string;
  header: JWTHeader;
  payload: JWTPayload;
  issues: AuditIssue[];
  secretEntropyBits?: number;
  lifespanSeconds?: number;
  isExpired: boolean;
  expiresInSeconds?: number;
  exploitVulnerabilities: {
    vulnerableToAlgNone: boolean;
    vulnerableToKeyConfusion: boolean;
    vulnerableToWeakSecret: boolean;
    hasSensitiveDataLeak: boolean;
  };
}

export interface JWK {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
  [key: string]: any;
}

export interface JWKS {
  keys: JWK[];
}

export type FrameworkType = 'nextjs' | 'express' | 'fastify' | 'cloudflare' | 'hono' | 'fastapi';

export interface GeneratedMiddleware {
  framework: FrameworkType;
  title: string;
  filename: string;
  code: string;
  instructions: string;
}

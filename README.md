# TokenSmith 🔑⚡

> **Developer-First JWT & JWKS Security Linter, Cryptographic Exploit Simulator, Secret Entropy Auditor & Bento Grid Studio.**  
> Engineered natively in **TypeScript 5.9 on Node.js v22** with **zero external runtime dependencies**.
>
> **Author:** Jatin Sharma — [Website](https://jatinsh.netlify.app/) • [GitHub](https://github.com/raghav1924) • [LinkedIn](https://linkedin.com/in/raghav1924) • [X](https://x.com/raghav1924)

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-v22-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-success.svg)](#)
[![Tests Passing](https://img.shields.io/badge/Tests-18%2F18%20Passed-brightgreen.svg)](#)

---

## ⚡ Why TokenSmith?

In 2026, JSON Web Tokens (JWT) and JSON Web Key Sets (JWKS) form the bedrock of distributed microservice authentication, OAuth2 / OIDC handshakes, and Generative AI agent authorizations. Yet JWT misconfigurations remain among the top vulnerabilities on the OWASP API Security Top 10 (API2:2023 Broken Authentication):

1. **The `alg: "none"` Privilege Escalation (CVE-2015-9235):** Naive verification libraries parse `{"alg": "none"}` and skip cryptographic signature verification, allowing attackers to forge arbitrary claims (`role: "admin"`) by simply omitting the signature.
2. **Asymmetric-to-Symmetric Algorithm Confusion:** An attacker takes the server's public RSA key (often published openly on a `.well-known/jwks.json` endpoint), alters the header to HMAC `HS256`, and signs a forged payload using the public key string as the HMAC symmetric secret. Vulnerable backends verify the signature and accept the forged token!
3. **Weak HMAC Secrets & Low Entropy:** Developers configure weak secrets (`"secret"`, `"jwt_secret"`, or keys $< 256$ bits) that can be cracked in milliseconds via offline dictionary attacks.
4. **Dangerous Payload Leaks:** Developers mistakenly treat Base64URL encoding as encryption, exposing passwords, internal IDs, and cloud API keys in unencrypted token payloads.
5. **Missing Claim Constraints:** Omission of `exp`, `nbf`, `iss`, `aud`, or `jti`, allowing permanent token lifetimes, replay attacks, and cross-service token reuse.

**TokenSmith** is a zero-dependency developer security suite that lints, verifies, and exploit-tests your tokens in real time.

---

## 🏗️ Architecture Overview

```
======================================================================
                 TOKENSMITH SYSTEM ARCHITECTURE
======================================================================
  [ Base64URL & Crypto Engine ]      --> [ 16+ Security Heuristics ]
  • RFC 7515 Base64URL encode/decode     • JWT-001: alg "none" exploit
  • Native HMAC-SHA256/384/512           • JWT-002: Low secret entropy
  • Timing-safe equality comparisons     • JWT-004: Sensitive data leak
  • Shannon entropy H = -sum(p*log2 p)   • JWT-014: Algorithm confusion
                 │                                      │
                 ▼                                      ▼
  [ Exploit & Attack Simulator ]     --> [ JWKS Rotation Inspector ]
  • alg: "none" privilege escalation     • RFC 7517 JWKS validator
  • RS256 to HS256 Key Confusion         • Zero-downtime rotation model
  • Direct payload tampering test        • Dual-key transition staging
                 │                                      │
                 ▼                                      ▼
  [ Bento Grid Studio (Port 6868) ]  --> [ Multi-Framework Codegen ]
  • Pattern #12 Bento Grid layout        • Next.js 14/15 App Router
  • Pattern #20 Dark Mode Obsidian       • Express.js & Fastify
  • Pattern #24 Cybercore HUD Inspector  • Cloudflare Workers & Hono
  • Pattern #10 Glassmorphism Panels     • FastAPI (Python async stream)
======================================================================
```

---

## 🎨 Master Design Patterns Catalog Citations

TokenSmith incorporates core aesthetic paradigms from the Master Design System catalog:

1. **Pattern #12 — Bento Grid Architecture:** Modular asymmetric dashboard on port 6868 grouping the color-coded token inspector, circular health gauge, exploit simulation bench, and code generator.
2. **Pattern #20 — High-Contrast Dark Mode:** Deep obsidian canvas (`#070a0f`), subtle slate borders (`#1e293b`), and vibrant neon tokens (Rose `#f43f5e`, Indigo `#6366f1`, Cyan `#06b6d4`, Emerald `#10b981`).
3. **Pattern #24 — Cybercore Telemetry HUD:** Color-coded token inspection reticle (Header in Rose, Payload in Indigo, Signature in Cyan), Shannon Entropy meter, and live attack simulation terminal.
4. **Pattern #10 — Glassmorphism:** Translucent frosted metric cards with `backdrop-filter: blur(16px)` and subtle border highlights.
5. **Pattern #3 — Swiss Design Typography:** Strict typographical alignment, tabular monospace numeric readouts, and clear visual hierarchy.

---

## 🚀 Quick Start

### Installation & Run

```bash
# Clone and enter directory
git clone https://github.com/raghav1924/tokensmith.git
cd tokensmith

# Build and run tests
npm test

# Launch embedded Bento Grid Web Studio on Port 6868
npm run studio
```

---

## 💻 CLI Commands

### 1. Inspect & Decode JWT Chunks
```bash
tokensmith inspect <token>
```
Decodes and pretty-prints color-coded Header, Payload, and Signature with formatted JSON claims.

### 2. Audit Token for 16+ Security Heuristics
```bash
tokensmith audit <token> --secret "my-hmac-secret-key"
```
Evaluates token against 16+ security heuristics, computes Shannon entropy on the secret, checks for PII leaks, and awards a grade from **A+** to **F**.

### 3. Cryptographically Verify Signature
```bash
tokensmith verify <token> --secret "my-hmac-secret-key"
```
Performs constant-time timing-safe HMAC validation, verifying signature integrity and expiration status.

### 4. Simulate Real-World CVE Exploit Attacks
```bash
tokensmith attack <token>
```
Simulates `alg: "none"` privilege escalation and `RS256` to `HS256` Key Confusion attacks, demonstrating whether naive verifiers get bypassed versus TokenSmith's hardened verification.

### 5. Generate Multi-Framework Hardened Middleware
```bash
tokensmith generate --framework nextjs
tokensmith generate --framework express
tokensmith generate --framework fastify
tokensmith generate --framework cloudflare
tokensmith generate --framework hono
tokensmith generate --framework fastapi
```

### 6. Generate Valid Sample JWT
```bash
tokensmith sample
```

---

## 🧪 Test Suite

All 18 unit and integration tests run in under 200ms with zero runtime dependencies:

```bash
$ npm test

✔ should encode and decode RFC 7515 Base64URL without padding or url-unsafe characters
✔ should sign and verify HMAC-SHA256 with timing-safe validation
✔ should calculate Shannon entropy accurately
✔ should create and parse complete compact JWTs
✔ should simulate alg: "none" privilege escalation
✔ should simulate Algorithm Confusion attack (RS256 to HS256 key confusion)
✔ should detect and flag direct payload tampering
✔ should flag alg: "none" as CRITICAL vulnerability (JWT-001)
✔ should flag weak dictionary secret as CRITICAL (JWT-003)
✔ should flag sensitive password/credential leak in payload (JWT-004)
✔ should detect expired tokens (JWT-011)
✔ should award A+ grade for production-hardened token and high-entropy secret
✔ should validate standard RFC 7517 JWKS structure
✔ should flag invalid JWKS without keys array or missing kid
✔ should simulate zero-downtime key rotation stages accurately
✔ should synthesize production-hardened JWT middleware for nextjs
✔ should synthesize production-hardened JWT middleware for express
✔ should synthesize production-hardened JWT middleware for fastify
✔ should synthesize production-hardened JWT middleware for cloudflare
✔ should synthesize production-hardened JWT middleware for hono
✔ should synthesize production-hardened JWT middleware for fastapi

ℹ tests 18 | suites 5 | pass 18 | fail 0
```

---

## 👨‍💻 Author

**Jatin Sharma**  
Full Stack Developer & Product Engineer  
- **Portfolio:** [https://jatinsh.netlify.app/](https://jatinsh.netlify.app/)  
- **GitHub:** [@raghav1924](https://github.com/raghav1924)  
- **LinkedIn:** [linkedin.com/in/raghav1924](https://linkedin.com/in/raghav1924)  
- **X:** [@raghav1924](https://x.com/raghav1924)  

---

## 📄 License

MIT License. Designed and engineered by Jatin Sharma.

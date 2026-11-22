/**
 * TokenSmith Interactive Command-Line Interface (CLI)
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

import { TokenCrypto } from './core/crypto.js';
import { TokenLinter } from './core/linter.js';
import { ExploitSimulator } from './core/simulator.js';
import { MiddlewareGenerator } from './generators/middlewareGen.js';
import { StudioServer } from './studio/server.js';
import { FrameworkType } from './types.js';

const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const MAGENTA = '\x1b[35m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

function printBanner(): void {
  console.log(`
${RED}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║   TOKEN-SMITH — Developer-First JWT & JWKS Security Linter                   ║
║   Cryptographic Exploit Simulator, Secret Entropy & Bento Grid Studio        ║
╚══════════════════════════════════════════════════════════════════════════════╝${RESET}
${DIM}Author: Jatin Sharma (https://jatinsh.netlify.app/)${RESET}
`);
}

export async function runCli(argv = process.argv.slice(2)): Promise<void> {
  const cmd = argv[0] || 'help';

  switch (cmd) {
    case 'inspect':
      runInspectCmd(argv.slice(1));
      break;
    case 'audit':
      runAuditCmd(argv.slice(1));
      break;
    case 'verify':
      runVerifyCmd(argv.slice(1));
      break;
    case 'attack':
      runAttackCmd(argv.slice(1));
      break;
    case 'generate':
      runGenerateCmd(argv.slice(1));
      break;
    case 'sample':
      runSampleCmd();
      break;
    case 'studio':
      await runStudioCmd(argv.slice(1));
      break;
    case 'help':
    case '--help':
    case '-h':
    default:
      printHelp();
      break;
  }
}

function runInspectCmd(args: string[]): void {
  const token = args[0];
  if (!token) {
    console.error(`${RED}Error: Missing JWT token. Usage: tokensmith inspect <token>${RESET}`);
    return;
  }

  printBanner();
  try {
    const decoded = TokenCrypto.parseJWT(token);
    console.log(`${BOLD}DECODED JWT SECTIONS:${RESET}\n`);

    console.log(`${RED}${BOLD}[HEADER]${RESET}`);
    console.log(JSON.stringify(decoded.header, null, 2));

    console.log(`\n${MAGENTA}${BOLD}[PAYLOAD]${RESET}`);
    console.log(JSON.stringify(decoded.payload, null, 2));

    console.log(`\n${CYAN}${BOLD}[SIGNATURE (Base64URL)]${RESET}`);
    console.log(decoded.signature || `${DIM}(no signature)${RESET}`);

    console.log(`\n${DIM}Algorithm: ${decoded.header.alg} | Expiration: ${decoded.payload.exp ? new Date(decoded.payload.exp * 1000).toISOString() : 'None'}${RESET}`);
  } catch (e: any) {
    console.error(`${RED}Parse Error: ${e.message}${RESET}`);
  }
}

function runAuditCmd(args: string[]): void {
  const token = args[0];
  if (!token) {
    console.error(`${RED}Error: Missing JWT token. Usage: tokensmith audit <token> [--secret <key>]${RESET}`);
    return;
  }

  const secret = getArgValue(args, '--secret');
  printBanner();

  const audit = TokenLinter.audit(token, secret);
  const gradeColor = audit.grade === 'A+' || audit.grade === 'A' ? GREEN : audit.grade === 'B' ? YELLOW : RED;

  console.log(`Algorithm:         ${audit.algorithm}`);
  console.log(`Compliance Grade:  ${gradeColor}${BOLD}${audit.grade} (${audit.score}/100)${RESET}`);
  console.log(`Format Valid:      ${audit.isValidFormat ? `${GREEN}YES${RESET}` : `${RED}NO${RESET}`}`);
  console.log(`Expired:           ${audit.isExpired ? `${RED}YES${RESET}` : `${GREEN}NO${RESET}`}`);
  if (audit.lifespanSeconds !== undefined) {
    console.log(`Lifespan:          ${Math.round(audit.lifespanSeconds / 60)} minutes (${audit.lifespanSeconds}s)`);
  }
  if (secret) {
    console.log(`Secret Entropy:    ${audit.secretEntropyBits} bits (${audit.exploitVulnerabilities.vulnerableToWeakSecret ? `${RED}WEAK${RESET}` : `${GREEN}STRONG${RESET}`})`);
  }

  console.log(`\n${BOLD}SECURITY ISSUES FOUND (${audit.issues.length}):${RESET}`);
  if (audit.issues.length === 0) {
    console.log(`  ${GREEN}✔ Zero vulnerabilities or protocol violations detected. Perfect score.${RESET}`);
  } else {
    audit.issues.forEach(iss => {
      const sevColor = iss.severity === 'CRITICAL' ? RED : iss.severity === 'HIGH' ? YELLOW : CYAN;
      console.log(`  [${sevColor}${iss.severity}${RESET}] [${iss.section}] ${BOLD}${iss.code}${RESET}: ${iss.message}`);
      console.log(`    ${DIM}Remediation: ${iss.recommendation}${RESET}`);
    });
  }
}

function runVerifyCmd(args: string[]): void {
  const token = args[0];
  const secret = getArgValue(args, '--secret');

  if (!token || !secret) {
    console.error(`${RED}Error: Missing parameters. Usage: tokensmith verify <token> --secret <key>${RESET}`);
    return;
  }

  printBanner();
  try {
    const decoded = TokenCrypto.parseJWT(token);
    const alg = (decoded.header.alg || 'HS256') as 'HS256' | 'HS384' | 'HS512';

    if (!alg.startsWith('HS')) {
      console.log(`${YELLOW}Warning: Verification only natively supports HMAC algorithms (HS256, HS384, HS512). Token specifies ${decoded.header.alg}.${RESET}`);
      return;
    }

    const signingInput = `${decoded.rawHeader}.${decoded.rawPayload}`;
    const isValid = TokenCrypto.verifyHmac(alg, signingInput, decoded.signature, secret);

    if (isValid) {
      console.log(`${GREEN}✔ SIGNATURE VERIFIED: Cryptographically valid signature matched secret.${RESET}`);
      const now = Math.floor(Date.now() / 1000);
      if (decoded.payload.exp && decoded.payload.exp < now) {
        console.log(`${RED}⚠ WARNING: Signature is valid, BUT token has expired at ${new Date(decoded.payload.exp * 1000).toISOString()}.${RESET}`);
      }
    } else {
      console.log(`${RED}✘ VERIFICATION FAILED: Signature does not match secret or has been tampered with.${RESET}`);
    }
  } catch (e: any) {
    console.error(`${RED}Verification Error: ${e.message}${RESET}`);
  }
}

function runAttackCmd(args: string[]): void {
  const token = args[0];
  if (!token) {
    console.error(`${RED}Error: Missing token. Usage: tokensmith attack <token>${RESET}`);
    return;
  }

  printBanner();
  console.log(`${BOLD}SIMULATING REAL-WORLD EXPLOIT ATTACKS:${RESET}\n`);

  // 1. alg: "none"
  const noneSim = ExploitSimulator.simulateAlgNone(token);
  console.log(`1. ${BOLD}${noneSim.name}${RESET}`);
  console.log(`   Naive Verifier:     ${noneSim.vulnerableToNaiveVerifier ? `${RED}EXPLOITED (Bypassed)${RESET}` : `${GREEN}SECURE${RESET}`}`);
  console.log(`   TokenSmith Guard:   ${noneSim.blockedByHardenedVerifier ? `${GREEN}BLOCKED (Rejected)${RESET}` : `${RED}VULNERABLE${RESET}`}`);
  console.log(`   ${DIM}${noneSim.technicalDetails}${RESET}\n`);

  // 2. Algorithm confusion
  const confSim = ExploitSimulator.simulateAlgorithmConfusion(token);
  console.log(`2. ${BOLD}${confSim.name}${RESET}`);
  console.log(`   Naive Verifier:     ${confSim.vulnerableToNaiveVerifier ? `${RED}EXPLOITED (Bypassed)${RESET}` : `${GREEN}SECURE${RESET}`}`);
  console.log(`   TokenSmith Guard:   ${confSim.blockedByHardenedVerifier ? `${GREEN}BLOCKED (Rejected)${RESET}` : `${RED}VULNERABLE${RESET}`}`);
  console.log(`   ${DIM}${confSim.technicalDetails}${RESET}\n`);

  // 3. Payload tampering
  const tampSim = ExploitSimulator.simulatePayloadTampering(token);
  console.log(`3. ${BOLD}${tampSim.name}${RESET}`);
  console.log(`   Naive Verifier:     ${tampSim.vulnerableToNaiveVerifier ? `${RED}EXPLOITED${RESET}` : `${GREEN}BLOCKED${RESET}`}`);
  console.log(`   TokenSmith Guard:   ${tampSim.blockedByHardenedVerifier ? `${GREEN}BLOCKED (Rejected)${RESET}` : `${RED}VULNERABLE${RESET}`}`);
}

function runGenerateCmd(args: string[]): void {
  printBanner();
  const fw = (getArgValue(args, '--framework') || 'nextjs') as FrameworkType;
  const gen = MiddlewareGenerator.generate(fw, 'HS256');

  console.log(`${CYAN}Generated ${gen.title} (${gen.filename}):${RESET}\n`);
  console.log(gen.code);
  console.log(`\n${DIM}Integration: ${gen.instructions}${RESET}`);
}

function runSampleCmd(): void {
  printBanner();
  const now = Math.floor(Date.now() / 1000);
  const secret = 'super-secret-secure-tokensmith-key-2026-xyz';
  const token = TokenCrypto.createJWT(
    { alg: 'HS256', typ: 'JWT', kid: 'tokensmith-k1' },
    {
      sub: 'usr_7491823',
      name: 'Jatin Sharma',
      role: 'staff_engineer',
      iss: 'https://auth.tokensmith.dev',
      aud: 'https://api.tokensmith.dev',
      iat: now,
      exp: now + 3600,
      jti: 'a819b-7491-4e23-tokensmith'
    },
    secret
  );

  console.log(`${BOLD}Generated Sample JWT:${RESET}\n`);
  console.log(token);
  console.log(`\n${DIM}Secret used: ${secret}${RESET}`);
  console.log(`${DIM}Inspect with: tokensmith inspect "${token}"${RESET}`);
}

async function runStudioCmd(args: string[]): Promise<void> {
  printBanner();
  const port = parseInt(getArgValue(args, '--port') || '6868', 10);
  const studio = new StudioServer(port);
  await studio.start();

  console.log(`${GREEN}✔ TokenSmith Bento Grid Web Studio launched successfully!${RESET}`);
  console.log(`  ${BOLD}URL:${RESET} ${CYAN}http://localhost:${port}/${RESET}`);
  console.log(`  Interactive Token Debugger, Exploit Attack Bench, and Linter active.`);
  console.log(`  Press Ctrl+C to terminate studio session.`);
}

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return undefined;
}

function printHelp(): void {
  printBanner();
  console.log(`
${BOLD}USAGE:${RESET}
  $ tokensmith <command> [options]

${BOLD}COMMANDS:${RESET}
  ${CYAN}inspect <token>${RESET}           Decode and display color-coded JWT header, payload, and signature
  ${CYAN}audit <token> [options]${RESET}   Run 16+ security heuristics and grade compliance (0-100)
  ${CYAN}verify <token> [options]${RESET}  Cryptographically verify HMAC signature with timing-safe checks
  ${CYAN}attack <token>${RESET}            Simulate alg: "none" and Algorithm Confusion CVE exploits
  ${CYAN}sample${RESET}                    Generate a cryptographically valid sample JWT
  ${CYAN}generate [options]${RESET}        Synthesize hardened JWT verification middleware
  ${CYAN}studio [options]${RESET}          Launch the embedded Bento Grid Web Studio on port 6868
  ${CYAN}help${RESET}                      Display this help manual

${BOLD}OPTIONS:${RESET}
  --secret <key>        HMAC secret key to evaluate entropy or verify signature
  --framework <name>    Target framework for middleware generator (nextjs, express, fastify, cloudflare, hono, fastapi)
  --port <num>          Port to bind Web Studio (default: 6868)
`);
}

if (process.argv[1]?.endsWith('cli.js')) {
  runCli();
}

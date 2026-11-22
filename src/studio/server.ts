/**
 * TokenSmith Embedded Bento Grid Web Studio & JWT Security HUD
 * Runs locally on Port 6868 with zero external runtime dependencies.
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

import http from 'node:http';
import { URL } from 'node:url';
import { TokenCrypto } from '../core/crypto.js';
import { TokenLinter } from '../core/linter.js';
import { ExploitSimulator } from '../core/simulator.js';
import { MiddlewareGenerator } from '../generators/middlewareGen.js';
import { FrameworkType, JWTAlgorithm } from '../types.js';

export class StudioServer {
  private server: http.Server | null = null;
  readonly port: number;

  constructor(port = 6868) {
    this.port = port;
  }

  start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.route(req, res);
      });

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(this.port, () => {
        resolve(this.port);
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private route(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url || '/', `http://localhost:${this.port}`);

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(this.renderHtml());
      return;
    }

    if (url.pathname === '/api/sample') {
      const now = Math.floor(Date.now() / 1000);
      const token = TokenCrypto.createJWT(
        { alg: 'HS256', typ: 'JWT', kid: 'tokensmith-k1' },
        {
          sub: 'usr_9812471',
          name: 'Jatin Sharma',
          email: 'raghavjatin245@gmail.com',
          role: 'admin',
          iss: 'https://auth.tokensmith.dev',
          aud: 'https://api.tokensmith.dev',
          iat: now,
          exp: now + 3600,
          jti: 'b819a-9812-4f71-tokensmith'
        },
        'super-secret-secure-tokensmith-key-2026-xyz'
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token, secret: 'super-secret-secure-tokensmith-key-2026-xyz' }));
      return;
    }

    if (url.pathname === '/api/audit' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body || '{}');
          const token = parsed.token || '';
          const secret = parsed.secret || undefined;
          const audit = TokenLinter.audit(token, secret);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(audit));
        } catch (e: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    if (url.pathname === '/api/simulate-attack' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body || '{}');
          const token = parsed.token || '';
          const attack = parsed.attack || 'alg-none';

          let result;
          if (attack === 'alg-none') {
            result = ExploitSimulator.simulateAlgNone(token);
          } else if (attack === 'key-confusion') {
            result = ExploitSimulator.simulateAlgorithmConfusion(token);
          } else {
            result = ExploitSimulator.simulatePayloadTampering(token);
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e: any) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    if (url.pathname === '/api/codegen') {
      const framework = (url.searchParams.get('framework') || 'nextjs') as FrameworkType;
      const code = MiddlewareGenerator.generate(framework, 'HS256');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(code));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  }

  private renderHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TokenSmith Studio — JWT & JWKS Security HUD</title>
  <style>
    :root {
      --bg: #070a0f;
      --card-bg: rgba(15, 23, 42, 0.75);
      --card-border: rgba(51, 65, 85, 0.6);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --cyan: #06b6d4;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --indigo: #6366f1;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
      padding: 24px;
      line-height: 1.5;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-logo {
      width: 38px; height: 38px; border-radius: 8px;
      background: linear-gradient(135deg, var(--rose), var(--indigo));
      display: flex; align-items: center; justify-content: center;
      font-weight: 900; font-size: 20px; color: #fff;
    }
    .brand h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
    .badge {
      display: inline-block; padding: 3px 8px; border-radius: 4px;
      font-size: 11px; font-weight: 600; text-transform: uppercase;
      background: rgba(244, 63, 94, 0.15); color: var(--rose); border: 1px solid rgba(244, 63, 94, 0.3);
    }
    .author-badge {
      font-size: 13px; color: var(--text-muted); text-decoration: none;
      display: flex; align-items: center; gap: 6px;
    }
    .author-badge span { color: var(--emerald); font-weight: 600; }

    /* Bento Grid */
    .bento-grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 20px;
    }
    .cell {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 20px;
      backdrop-filter: blur(16px);
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    .cell-title {
      font-size: 13px; font-weight: 600; color: var(--text-muted);
      margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;
      text-transform: uppercase; letter-spacing: 0.5px;
    }

    .col-7 { grid-column: span 7; }
    .col-5 { grid-column: span 5; }
    .col-6 { grid-column: span 6; }
    .col-12 { grid-column: span 12; }

    /* Token Visualizer */
    .token-input {
      width: 100%; height: 90px; background: #000; border: 1px solid var(--card-border);
      border-radius: 8px; color: #f8fafc; font-family: monospace; font-size: 12px;
      padding: 10px; margin-bottom: 12px; resize: none; word-break: break-all;
    }
    .token-breakdown {
      display: flex; flex-direction: column; gap: 10px; margin-top: 10px;
    }
    .token-part {
      border-radius: 8px; padding: 12px; font-family: monospace; font-size: 12px;
    }
    .part-header { background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.3); color: #fda4af; }
    .part-payload { background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.3); color: #c7d2fe; }
    .part-sig { background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: #a5f3fc; }

    /* Score Gauge */
    .score-container {
      display: flex; align-items: center; gap: 24px; margin-bottom: 16px;
    }
    .score-circle {
      width: 90px; height: 90px; border-radius: 50%;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      border: 4px solid var(--emerald); background: rgba(16, 185, 129, 0.05);
    }
    .score-num { font-size: 26px; font-weight: 800; font-family: monospace; }
    .score-lbl { font-size: 10px; color: var(--text-muted); }

    /* Buttons */
    .btn-group { display: flex; gap: 8px; margin-top: 10px; }
    .btn {
      padding: 8px 14px; border-radius: 6px; font-weight: 600; font-size: 12px;
      cursor: pointer; border: 1px solid transparent; transition: all 0.2s;
    }
    .btn-primary { background: var(--cyan); color: #000; }
    .btn-secondary { background: rgba(255,255,255,0.08); color: var(--text-main); border-color: var(--card-border); }
    .btn-danger { background: rgba(244, 63, 94, 0.2); color: var(--rose); border-color: rgba(244, 63, 94, 0.4); }

    /* Tabs & Code */
    .tabs { display: flex; gap: 8px; margin-bottom: 12px; }
    .tab {
      padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 600;
      cursor: pointer; background: rgba(255,255,255,0.05); color: var(--text-muted);
    }
    .tab.active { background: rgba(244, 63, 94, 0.15); color: var(--rose); border: 1px solid rgba(244, 63, 94, 0.3); }
    pre {
      background: #000; border: 1px solid var(--card-border); border-radius: 8px;
      padding: 14px; font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12px; overflow-x: auto; color: #e2e8f0; max-height: 240px;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-logo">T</div>
      <div>
        <h1>TokenSmith <span class="badge">v1.0.0</span></h1>
        <p style="font-size: 12px; color: var(--text-muted);">JWT Security Linter, Exploit Simulator & Bento Grid Studio</p>
      </div>
    </div>
    <a href="https://jatinsh.netlify.app/" target="_blank" class="author-badge">
      Engineered by <span>Jatin Sharma</span>
    </a>
  </header>

  <div class="bento-grid">
    <!-- 1. Color-Coded Token Debugger -->
    <div class="cell col-7">
      <div class="cell-title">
        <span>COLOR-CODED JWT INSPECTOR</span>
        <span class="badge" id="alg-badge">HS256</span>
      </div>
      <textarea class="token-input" id="token-input" placeholder="Paste JWT token here..."></textarea>
      <div style="display: flex; gap: 10px;">
        <input type="text" id="secret-input" class="token-input" style="height: 38px; flex: 1;" placeholder="Optional HMAC Secret (e.g. key-xyz)">
        <button class="btn btn-primary" style="height: 38px;" onclick="runAudit()">Audit Token</button>
        <button class="btn btn-secondary" style="height: 38px;" onclick="loadSample()">Load Sample</button>
      </div>
      <div class="token-breakdown">
        <div class="token-part part-header">
          <div style="font-size: 10px; font-weight: 700; color: var(--rose);">HEADER (ALGORITHM & TOKEN TYPE)</div>
          <pre id="decoded-header" style="background: none; border: none; padding: 4px 0; color: #fda4af;">{}</pre>
        </div>
        <div class="token-part part-payload">
          <div style="font-size: 10px; font-weight: 700; color: var(--indigo);">PAYLOAD (DATA & CLAIMS)</div>
          <pre id="decoded-payload" style="background: none; border: none; padding: 4px 0; color: #c7d2fe;">{}</pre>
        </div>
        <div class="token-part part-sig">
          <div style="font-size: 10px; font-weight: 700; color: var(--cyan);">SIGNATURE (BASE64URL DIGEST)</div>
          <div id="decoded-sig" style="word-break: break-all; margin-top: 4px; color: #a5f3fc;">...</div>
        </div>
      </div>
    </div>

    <!-- 2. Security Health Score & 16+ Heuristics -->
    <div class="cell col-5">
      <div class="cell-title">
        <span>SECURITY HEALTH SCORE & 16+ HEURISTICS</span>
        <span class="badge" id="grade-badge">A+ GRADE</span>
      </div>
      <div class="score-container">
        <div class="score-circle" id="score-circle">
          <div class="score-num" id="score-num" style="color: var(--emerald);">100</div>
          <div class="score-lbl">SCORE</div>
        </div>
        <div>
          <div style="font-size: 13px; font-weight: 600;" id="score-status">Production-Ready (Zero Vulnerabilities)</div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="lifespan-info">Lifespan: 1 hour | Expired: No</div>
        </div>
      </div>
      <div style="font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px;">DETECTED ISSUES:</div>
      <div id="issues-list" style="max-height: 280px; overflow-y: auto; display: flex; flex-direction: column; gap: 8px;">
        <div style="font-size: 12px; color: var(--emerald);">✔ No cryptographic vulnerabilities or sensitive leaks detected.</div>
      </div>
    </div>

    <!-- 3. Exploit & Attack Bench -->
    <div class="cell col-6">
      <div class="cell-title">
        <span>1-CLICK EXPLOIT ATTACK BENCH</span>
        <span class="badge" style="color: var(--amber); border-color: var(--amber);">SIMULATOR</span>
      </div>
      <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
        Test how your token withstands real-world CVE exploits. See how naive verification libraries get bypassed while TokenSmith's hardened gate blocks them.
      </p>
      <div class="btn-group">
        <button class="btn btn-danger" onclick="triggerAttack('alg-none')">Launch alg: "none" Bypass</button>
        <button class="btn btn-danger" onclick="triggerAttack('key-confusion')">Launch Key Confusion</button>
        <button class="btn btn-secondary" onclick="triggerAttack('tamper')">Payload Tamper</button>
      </div>
      <div style="margin-top: 14px; background: rgba(0,0,0,0.4); border-radius: 8px; padding: 12px;">
        <div style="font-size: 12px; font-weight: 700; color: var(--rose);" id="attack-title">No attack simulated yet</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="attack-desc">Select an exploit above to test vulnerability boundaries.</div>
        <div style="display: flex; gap: 12px; margin-top: 8px; font-size: 11px;">
          <div>Naive Verifier: <strong id="attack-naive" style="color: var(--text-muted);">-</strong></div>
          <div>Hardened Verifier: <strong id="attack-hardened" style="color: var(--text-muted);">-</strong></div>
        </div>
      </div>
    </div>

    <!-- 4. Multi-Framework Middleware Generator -->
    <div class="cell col-6">
      <div class="cell-title">
        <span>HARDENED MIDDLEWARE GENERATOR</span>
        <span class="badge">PRODUCTION READY</span>
      </div>
      <div class="tabs">
        <div class="tab active" onclick="loadCode('nextjs', this)">Next.js 15</div>
        <div class="tab" onclick="loadCode('express', this)">Express.js</div>
        <div class="tab" onclick="loadCode('fastify', this)">Fastify</div>
        <div class="tab" onclick="loadCode('cloudflare', this)">Cloudflare</div>
        <div class="tab" onclick="loadCode('hono', this)">Hono</div>
        <div class="tab" onclick="loadCode('fastapi', this)">FastAPI</div>
      </div>
      <pre id="code-output">// Loading production middleware...</pre>
    </div>
  </div>

  <script>
    async function loadSample() {
      const res = await fetch('/api/sample');
      const data = await res.json();
      document.getElementById('token-input').value = data.token;
      document.getElementById('secret-input').value = data.secret;
      runAudit();
    }

    async function runAudit() {
      const token = document.getElementById('token-input').value.trim();
      const secret = document.getElementById('secret-input').value.trim();
      if (!token) return;

      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, secret })
      });
      const data = await res.json();

      document.getElementById('alg-badge').textContent = data.algorithm;
      document.getElementById('decoded-header').textContent = JSON.stringify(data.header, null, 2);
      document.getElementById('decoded-payload').textContent = JSON.stringify(data.payload, null, 2);
      const parts = token.split('.');
      document.getElementById('decoded-sig').textContent = parts[2] || '(no signature)';

      document.getElementById('score-num').textContent = data.score;
      document.getElementById('grade-badge').textContent = data.grade + ' GRADE';

      const circle = document.getElementById('score-circle');
      const scoreNum = document.getElementById('score-num');
      const color = data.grade === 'A+' || data.grade === 'A' ? 'var(--emerald)' : data.grade === 'B' ? 'var(--amber)' : 'var(--rose)';
      circle.style.borderColor = color;
      scoreNum.style.color = color;

      document.getElementById('lifespan-info').textContent = 'Lifespan: ' + (data.lifespanSeconds ? Math.round(data.lifespanSeconds/60) + ' min' : 'Undefined') + ' | Expired: ' + (data.isExpired ? 'YES' : 'NO');

      const issuesList = document.getElementById('issues-list');
      if (data.issues.length === 0) {
        issuesList.innerHTML = '<div style="font-size: 12px; color: var(--emerald);">✔ No cryptographic vulnerabilities or sensitive leaks detected.</div>';
      } else {
        issuesList.innerHTML = data.issues.map(iss => {
          const badgeColor = iss.severity === 'CRITICAL' ? 'var(--rose)' : iss.severity === 'HIGH' ? 'var(--amber)' : 'var(--cyan)';
          return '<div style="background: rgba(0,0,0,0.3); border-left: 3px solid ' + badgeColor + '; padding: 8px 10px; border-radius: 4px;">' +
            '<div style="font-size: 11px; font-weight: 700; color: ' + badgeColor + ';">[' + iss.code + '] ' + iss.severity + ' (' + iss.section + ')</div>' +
            '<div style="font-size: 11px; margin-top: 2px;">' + iss.message + '</div>' +
            '<div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">💡 ' + iss.recommendation + '</div>' +
          '</div>';
        }).join('');
      }
    }

    async function triggerAttack(type) {
      const token = document.getElementById('token-input').value.trim();
      if (!token) return;

      const res = await fetch('/api/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, attack: type })
      });
      const data = await res.json();

      document.getElementById('attack-title').textContent = data.name;
      document.getElementById('attack-desc').textContent = data.description;
      document.getElementById('attack-naive').textContent = data.vulnerableToNaiveVerifier ? 'EXPLOITED (BYPASSED)' : 'SECURE';
      document.getElementById('attack-naive').style.color = data.vulnerableToNaiveVerifier ? 'var(--rose)' : 'var(--emerald)';
      document.getElementById('attack-hardened').textContent = data.blockedByHardenedVerifier ? 'BLOCKED (REJECTED)' : 'VULNERABLE';
      document.getElementById('attack-hardened').style.color = data.blockedByHardenedVerifier ? 'var(--emerald)' : 'var(--rose)';
    }

    async function loadCode(framework, el) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      if (el) el.classList.add('active');
      const res = await fetch('/api/codegen?framework=' + framework);
      const data = await res.json();
      document.getElementById('code-output').textContent = data.code;
    }

    loadSample();
    loadCode('nextjs');
  </script>
</body>
</html>`;
  }
}

/**
 * Reporter module for TokenSentry.
 * Renders terminal colored output, exports JSON, and generates executive HTML audit reports.
 */

import fs from "node:fs";
import path from "node:path";

// ANSI Terminal Colors
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const RED = "\x1b[91m";
const GREEN = "\x1b[92m";
const YELLOW = "\x1b[93m";
const BLUE = "\x1b[94m";
const CYAN = "\x1b[96m";
const GRAY = "\x1b[90m";

export function printCliBanner() {
  console.log(`
${CYAN}${BOLD}  _______    _              _____            _              
 |__   __|  | |            / ____|          | |             
    | | ___ | | _____ _ __| (___   ___ _ __ | |_ _ __ _   _ 
    | |/ _ \\| |/ / _ \\ '_ \\\\___ \\ / _ \\ '_ \\| __| '__| | | |
    | | (_) |   <  __/ | | |___) |  __/ | | | |_| |  | |_| |
    |_|\\___/|_|\\_\\___|_| |_|_____/ \\___|_| |_|\\__|_|   \\__, |
                                                        __/ |
                                                       |___/ ${RESET}
${GRAY} JWT & API Security Exploitation Toolkit | OWASP API Security Standard${RESET}
`);
}

export function printCliSummary(audit) {
  const ratingColor =
    audit.riskRating === "CRITICAL" || audit.riskRating === "HIGH"
      ? RED
      : audit.riskRating === "MODERATE"
      ? YELLOW
      : GREEN;

  console.log(`${BOLD}==================== TOKEN SECURITY AUDIT ====================${RESET}`);
  console.log(`Algorithm:       ${BOLD}${audit.header.alg || "none"}${RESET}`);
  console.log(`Token Type:      ${audit.header.typ || "JWT"}`);
  console.log(`Security Score:  ${ratingColor}${BOLD}${audit.score}/100${RESET} (Risk Level: ${ratingColor}${audit.riskRating}${RESET})`);
  console.log(`Findings:        ${audit.findings.length} issue(s) identified`);
  console.log(`${BOLD}==============================================================${RESET}\n`);

  console.log(`${BOLD}DECODED TOKEN CLAIMS:${RESET}`);
  console.log(`${CYAN}Header:${RESET}  ${JSON.stringify(audit.header)}`);
  console.log(`${YELLOW}Payload:${RESET} ${JSON.stringify(audit.payload, null, 2)}\n`);

  if (audit.findings.length > 0) {
    console.log(`${BOLD}SECURITY VULNERABILITIES & EXPLOIT RISKS:${RESET}`);
    for (const f of audit.findings) {
      const sevColor = f.severity === "CRITICAL" ? RED : f.severity === "HIGH" ? RED : YELLOW;
      console.log(`  ${sevColor}[${f.severity}]${RESET} ${BOLD}${f.title}${RESET} (CVSS: ${f.cvss})`);
      console.log(`    ${GRAY}Classification:${RESET} ${f.cwe}`);
      console.log(`    ${GRAY}Description:${RESET}    ${f.description}`);
      console.log(`    ${GREEN}Remediation:${RESET}    ${f.remediation}`);
      if (f.exploitPoC) {
        console.log(`    ${CYAN}Forged Admin PoC Token:${RESET} ${f.exploitPoC.slice(0, 45)}...`);
      }
      console.log();
    }
  } else {
    console.log(`${GREEN}[+] Clean Token: No severe algorithmic or access control vulnerabilities detected.${RESET}\n`);
  }
}

export function exportJson(audit, outputPath) {
  fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(audit, null, 2), "utf-8");
}

export function generateHtmlReport(audit, outputPath) {
  fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });

  const score = audit.score;
  const dashArray = 283;
  const dashOffset = dashArray - (dashArray * score) / 100;

  const accentColor =
    score >= 90 ? "#10b981" : score >= 75 ? "#3b82f6" : score >= 50 ? "#f59e0b" : "#ef4444";

  const findingsHtml = audit.findings.length
    ? audit.findings
        .map(
          f => `
      <div class="vuln-card">
        <div class="vuln-top">
          <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
          <strong class="vuln-title">${f.title}</strong>
          <span class="vuln-cvss">CVSS: ${f.cvss}</span>
        </div>
        <div class="vuln-cwe">${f.cwe}</div>
        <p class="vuln-desc">${f.description}</p>
        <div class="rem-box">
          <strong>Recommended Fix:</strong>
          <p>${f.remediation}</p>
        </div>
        ${
          f.exploitPoC
            ? `<div class="exploit-box">
                <span class="exp-title">Forged Administrative Exploit Token (PoC):</span>
                <code>${f.exploitPoC}</code>
               </div>`
            : ""
        }
      </div>
    `
        )
        .join("")
    : `
      <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 2rem; text-align: center; color: #34d399;">
        <h3>✓ Robust Token Security</h3>
        <p>Token adheres to cryptographic best practices and access management policies.</p>
      </div>
    `;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TokenSentry - JWT Security Audit</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-surface: #101726;
            --bg-card: #1b2438;
            --border: #2e3c54;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --cyan: #38bdf8;
            --red: #ef4444;
            --amber: #f59e0b;
            --emerald: #10b981;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, sans-serif;
            padding: 2rem 1rem;
        }
        .container { max-width: 1080px; margin: 0 auto; }
        header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem;
        }
        .brand { display: flex; align-items: center; gap: 0.85rem; }
        .brand-icon {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, #0284c7, #38bdf8);
            border-radius: 10px; display: flex; align-items: center; justify-content: center;
            font-weight: 800; font-size: 1.3rem; color: #fff;
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.4);
        }
        .overview {
            display: grid; grid-template-columns: 280px 1fr; gap: 1.5rem; margin-bottom: 2rem;
        }
        @media (max-width: 768px) { .overview { grid-template-columns: 1fr; } }
        .card {
            background: var(--bg-surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .card-title {
            font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary);
            font-weight: 600; margin-bottom: 1rem;
        }
        .score-card { display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .gauge-svg { width: 140px; height: 140px; }
        .gauge-bg { fill: none; stroke: #1e293b; stroke-width: 8; }
        .gauge-fill {
            fill: none; stroke: ${accentColor}; stroke-width: 8; stroke-linecap: round;
            stroke-dasharray: ${dashArray}; stroke-dashoffset: ${dashOffset};
            transform: rotate(-90deg); transform-origin: 50% 50%;
        }
        .score-text { font-size: 2.2rem; font-weight: 800; fill: var(--text-primary); text-anchor: middle; dominant-baseline: central; }
        .score-desc { margin-top: 0.5rem; font-weight: 700; color: ${accentColor}; }

        /* Decoded Token Inspector */
        .token-inspector {
            display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;
        }
        @media (max-width: 650px) { .token-inspector { grid-template-columns: 1fr; } }
        .token-box {
            background: #050811; border: 1px solid var(--border); border-radius: 8px; padding: 1rem;
            font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;
        }
        .token-box pre { white-space: pre-wrap; word-break: break-all; color: #cbd5e1; }
        .tag-hdr { color: #f43f5e; font-weight: 700; }
        .tag-pay { color: #a855f7; font-weight: 700; }

        /* Vulnerabilities */
        .vuln-card {
            background: var(--bg-card); border-left: 4px solid var(--border); border-radius: 0 8px 8px 0;
            padding: 1.25rem; margin-bottom: 1rem;
        }
        .vuln-card:has(.badge-critical) { border-left-color: var(--red); }
        .vuln-card:has(.badge-high) { border-left-color: #f97316; }
        .vuln-card:has(.badge-low) { border-left-color: #3b82f6; }
        .vuln-top { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
        .vuln-cwe { font-size: 0.8rem; color: var(--cyan); font-family: 'JetBrains Mono', monospace; margin-bottom: 0.5rem; }
        .vuln-desc { font-size: 0.9rem; color: #cbd5e1; margin-bottom: 0.75rem; line-height: 1.5; }
        .rem-box {
            background: rgba(15, 23, 42, 0.8); border-radius: 6px; padding: 0.75rem 1rem;
            font-size: 0.85rem; border: 1px solid rgba(56, 189, 248, 0.2); margin-bottom: 0.5rem;
        }
        .rem-box strong { color: var(--emerald); }
        .exploit-box {
            background: #000; border-radius: 6px; padding: 0.75rem 1rem; border: 1px solid #334155;
            font-size: 0.8rem;
        }
        .exp-title { color: #fbbf24; font-weight: 600; display: block; margin-bottom: 0.25rem; }
        .exploit-box code { font-family: 'JetBrains Mono', monospace; color: #38bdf8; word-break: break-all; }

        .badge {
            display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px;
            font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
        .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
        .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }

        footer {
            margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border);
            text-align: center; font-size: 0.8rem; color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-icon">TS</div>
                <div>
                    <h1>TokenSentry Security Audit</h1>
                    <p>JSON Web Token (JWT) Vulnerability & Cryptographic Policy Engine</p>
                </div>
            </div>
            <div style="text-align: right; font-size: 0.85rem; color: var(--text-secondary);">
                <div>Algorithm: <strong>${audit.header.alg || "none"}</strong></div>
                <div>Risk Rating: <strong style="color: ${accentColor};">${audit.riskRating}</strong></div>
            </div>
        </header>

        <div class="overview">
            <div class="card score-card">
                <div class="card-title">Token Security Score</div>
                <svg class="gauge-svg" viewBox="0 0 100 100">
                    <circle class="gauge-bg" cx="50" cy="50" r="45"></circle>
                    <circle class="gauge-fill" cx="50" cy="50" r="45"></circle>
                    <text class="score-text" x="50" y="52">${score}</text>
                </svg>
                <div class="score-desc">${audit.riskRating} RISK</div>
            </div>
            <div class="card">
                <div class="card-title">Decoded JWT Token Artifacts (RFC 7519)</div>
                <div class="token-inspector">
                    <div class="token-box">
                        <div class="tag-hdr">HEADER (Metadata)</div>
                        <pre>${JSON.stringify(audit.header, null, 2)}</pre>
                    </div>
                    <div class="token-box">
                        <div class="tag-pay">PAYLOAD (Claims)</div>
                        <pre>${JSON.stringify(audit.payload, null, 2)}</pre>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Security Findings & Exploit Vulnerabilities (${audit.findings.length} Identified)</div>
            ${findingsHtml}
        </div>

        <footer>
            Generated by <strong>TokenSentry v1.0.0</strong> • Automated JWT & API Authentication Security Assessment.
        </footer>
    </div>
</body>
</html>`;

  fs.writeFileSync(outputPath, html, "utf-8");
}

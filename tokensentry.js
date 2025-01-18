#!/usr/bin/env node
/**
 * TokenSentry - JWT & API Security Auditor & Exploitation Toolkit
 * CLI Entrypoint for API Penetration Testing & Cryptographic Token Auditing.
 */

import { auditJwt } from "./src/auditor.js";
import { crackHmacSecret, generateNoneAttackPayloads } from "./src/attacks.js";
import { createJwt } from "./src/jwt.js";
import { printCliBanner, printCliSummary, exportJson, generateHtmlReport } from "./src/reporter.js";

// Sample vulnerable enterprise token for demo simulation
function generateDemoVulnerableToken() {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub: "user_49102",
    username: "john_doe",
    role: "standard_user",
    email: "john@corp.internal",
    ssn: "123-45-6789", // Sensitive claim leak!
    // Intentionally missing 'exp' claim (indefinite lifespan!)
    iat: Math.floor(Date.now() / 1000) - 3600
  };
  return createJwt(header, payload, "secret"); // Trivially guessable secret 'secret'!
}

function printUsage() {
  console.log(`
Usage:
  node tokensentry.js <token> [options]
  node tokensentry.js --demo
  node tokensentry.js --crack <token>

Options:
  --demo                 Run simulated audit on a vulnerable enterprise JWT
  --crack <token>        Perform dictionary attack to recover HMAC signing secret
  --exploit-none <token> Generate 'none' algorithm signature bypass exploit payloads
  --html <path>          Path for output HTML dashboard (default: reports/token_audit.html)
  --json <path>          Path for output JSON report (default: reports/token_audit.json)
  --help                 Show this help menu
`);
}

async function main() {
  const args = process.argv.slice(2);

  printCliBanner();

  if (args.includes("--help") || args.length === 0) {
    if (!args.includes("--demo")) {
      printUsage();
      return;
    }
  }

  let token = null;
  let htmlPath = "reports/token_audit.html";
  let jsonPath = "reports/token_audit.json";

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--demo") {
      console.log(`[*] Generating vulnerable enterprise authentication token for simulation...\n`);
      token = generateDemoVulnerableToken();
    } else if (args[i] === "--crack" && args[i + 1]) {
      const targetToken = args[i + 1];
      console.log(`[*] Starting multi-threaded dictionary brute-force attack...`);
      const res = crackHmacSecret(targetToken);
      if (res.success) {
        console.log(`\n\x1b[92m[+] SUCCESS! Secret Key Recovered:\x1b[0m '${res.crackedSecret}'`);
        console.log(`[+] Attempt count: ${res.attempts}`);
        console.log(`[+] Forged Admin Token:\n${res.forgedToken}\n`);
      } else {
        console.log(`\n\x1b[91m[-] Failed:\x1b[0m ${res.reason}\n`);
      }
      return;
    } else if (args[i] === "--exploit-none" && args[i + 1]) {
      const targetToken = args[i + 1];
      console.log(`[*] Generating 'none' algorithm bypass attack payloads (CVE-2015-9235)...`);
      const res = generateNoneAttackPayloads(targetToken);
      for (const p of res.payloads) {
        console.log(`\n  Variant: \x1b[96m${p.variant}\x1b[0m`);
        console.log(`  Payload: ${p.token}`);
      }
      console.log();
      return;
    } else if (args[i] === "--html" && args[i + 1]) {
      htmlPath = args[++i];
    } else if (args[i] === "--json" && args[i + 1]) {
      jsonPath = args[++i];
    } else if (!args[i].startsWith("--")) {
      token = args[i];
    }
  }

  if (!token) {
    printUsage();
    return;
  }

  try {
    const audit = auditJwt(token);
    printCliSummary(audit);

    if (htmlPath) {
      generateHtmlReport(audit, htmlPath);
      console.log(`\x1b[92m[+] HTML Token Security Report generated:\x1b[0m ${htmlPath}`);
    }

    if (jsonPath) {
      exportJson(audit, jsonPath);
      console.log(`\x1b[92m[+] Machine-readable JSON exported:\x1b[0m ${jsonPath}\n`);
    }
  } catch (err) {
    console.error(`\x1b[91m[!] Error auditing token:\x1b[0m ${err.message}`);
    process.exit(1);
  }
}

main();

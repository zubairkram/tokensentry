/**
 * JWT Security Posture & Compliance Auditor.
 * Evaluates tokens against OWASP API Security Top 10 and RFC 7519 standards.
 */

import { parseJwt } from "./jwt.js";
import { crackHmacSecret, generateNoneAttackPayloads } from "./attacks.js";

// Sensitive keys that should NEVER be stored in unencrypted JWT claims
const SENSITIVE_CLAIM_KEYS = [
  "password",
  "passwd",
  "pwd",
  "hash",
  "secret",
  "ssn",
  "credit_card",
  "cvv",
  "pin",
  "private_key",
  "apikey",
  "api_key"
];

/**
 * Conduct comprehensive security audit of a JWT token.
 */
export function auditJwt(token, options = {}) {
  const parsed = parseJwt(token);
  const { header, payload, signature } = parsed;

  const findings = [];
  const now = Math.floor(Date.now() / 1000);

  // 1. Audit Algorithm & Cryptographic Strength
  const alg = header.alg || "none";

  if (alg.toLowerCase() === "none") {
    findings.push({
      id: "SEC-JWT-001",
      severity: "CRITICAL",
      title: "Insecure 'none' Algorithm In Use (CVE-2015-9235)",
      cwe: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
      cvss: 9.8,
      description: "Token uses the 'none' algorithm, indicating signatures are not required or validated. An attacker can forge any claim.",
      remediation: "Disallow the 'none' algorithm in server verification libraries. Enforce strong cryptographic algorithms (RS256, ES256, or HS256 with 256-bit entropy)."
    });
  } else if (alg === "HS256") {
    // Attempt dictionary brute-force
    const crackResult = crackHmacSecret(token);
    if (crackResult.success) {
      findings.push({
        id: "SEC-JWT-002",
        severity: "CRITICAL",
        title: `Trivially Guessable HMAC Secret ('${crackResult.crackedSecret}')`,
        cwe: "CWE-522: Insufficiently Protected Credentials",
        cvss: 9.1,
        description: `The symmetric signing secret was cracked in ${crackResult.attempts} attempts using a standard wordlist: '${crackResult.crackedSecret}'. Anyone can forge valid tokens.`,
        remediation: "Rotate the JWT secret immediately. Use a cryptographically secure random string with at least 256 bits of entropy (e.g. `openssl rand -hex 32`).",
        exploitPoC: crackResult.forgedToken
      });
    }
  }

  // 2. Audit Expiration & Token Lifecycle
  if (!payload.exp) {
    findings.push({
      id: "SEC-JWT-003",
      severity: "HIGH",
      title: "Missing Token Expiration ('exp' Claim)",
      cwe: "CWE-613: Insufficient Session Expiration",
      cvss: 7.5,
      description: "The token does not specify an expiration timestamp. Once issued, stolen tokens remain valid indefinitely.",
      remediation: "Always configure a short lifespan (e.g. 15-60 minutes) in the 'exp' claim. Pair with refresh token rotation."
    });
  } else if (payload.exp < now) {
    findings.push({
      id: "SEC-JWT-004",
      severity: "LOW",
      title: "Token Has Expired",
      cwe: "CWE-298: Improper Validation of Certificate Expiration",
      cvss: 3.1,
      description: `Token expired at ${new Date(payload.exp * 1000).toISOString()} (${Math.round((now - payload.exp) / 60)} minutes ago).`,
      remediation: "Ensure backend verifies token expiration strictly and rejects expired tokens with HTTP 401 Unauthorized."
    });
  }

  if (!payload.iat) {
    findings.push({
      id: "SEC-JWT-005",
      severity: "LOW",
      title: "Missing Issued At ('iat' Claim)",
      cwe: "CWE-799: Improper Control of Interaction Frequency",
      cvss: 3.0,
      description: "Token does not record its issuance time, preventing age-based revocation and audit tracing.",
      remediation: "Include an 'iat' timestamp on every issued token."
    });
  }

  // 3. Audit Sensitive Claims & PII Exposure
  for (const [key, val] of Object.entries(payload)) {
    const keyLower = key.toLowerCase();
    if (SENSITIVE_CLAIM_KEYS.some(k => keyLower.includes(k))) {
      findings.push({
        id: "SEC-JWT-006",
        severity: "HIGH",
        title: `Sensitive Credential/PII Exposed in Claims: '${key}'`,
        cwe: "CWE-312: Cleartext Storage of Sensitive Information",
        cvss: 7.2,
        description: `The payload exposes sensitive field '${key}' in base64url plaintext. Standard JWT claims are readable by any client or proxy.`,
        remediation: "Remove confidential credentials from JWT claims. If sensitive data must be transmitted, use JWE (JSON Web Encryption) for payload confidentiality."
      });
    }
  }

  // 4. Calculate Posture Score
  let score = 100;
  const penalties = { CRITICAL: 35, HIGH: 20, MEDIUM: 10, LOW: 5 };
  for (const f of findings) {
    score -= penalties[f.severity] || 0;
  }
  score = Math.max(0, Math.min(100, score));

  let riskRating = "LOW";
  if (score < 50) riskRating = "CRITICAL";
  else if (score < 75) riskRating = "HIGH";
  else if (score < 90) riskRating = "MODERATE";

  // Generate exploit bypass tokens for penetration testers
  const exploitPayloads = generateNoneAttackPayloads(token);

  return {
    rawToken: token,
    header,
    payload,
    hasSignature: Boolean(signature),
    score,
    riskRating,
    findings,
    exploitPayloads
  };
}

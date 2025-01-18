# TokenSentry 🛡️🔑
### High-Performance JWT & API Security Exploitation & Auditing Toolkit

[![Node.js 18+](https://img.shields.io/badge/node.js-18%2B-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0%20(Standard%20Library)-success.svg)]()
[![Tests: 5 Passed](https://img.shields.io/badge/tests-5%2F5%20passed-brightgreen.svg)]()
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Security%20Aligned-orange.svg)]()

**TokenSentry** is a high-speed JSON Web Token (JWT) security auditor and penetration testing exploitation toolkit written in pure modern JavaScript (ES Modules) using **zero external npm dependencies**.

Designed around the **OWASP API Security Top 10** (API1: Broken Object Level Authorization, API2: Broken Authentication) and RFC 7519 standards, TokenSentry audits API authentication tokens for critical cryptographic flaws, brute-forces weak HMAC secrets, tests for signature bypass vulnerabilities, and generates executive HTML security reports.

---

## ⚡ Standards & Vulnerability Coverage

TokenSentry evaluates tokens against industry cryptographic baselines (RFC 7515/7519, NIST SP 800-63B, OWASP):

| Vulnerability Vector | Security Standard | TokenSentry Implementation |
| :--- | :--- | :--- |
| **Broken Authentication** | OWASP API2:2023 | Audits missing expiration (`exp`), missing issuance (`iat`), clock skew tolerance, and indefinite session validity. |
| **Algorithmic Cryptographic Flaws** | RFC 7515 / CWE-327 | Verifies HMAC-SHA signatures (`HS256`, `HS384`, `HS512`), exploits `none` algorithm bypass (CVE-2015-9235), and checks for algorithm confusion. |
| **Weak Secret & Credential Exposure** | CWE-522 / NIST SP 800-63B | High-speed dictionary brute-force attacking weak HMAC keys against top common developer secrets, auto-generating forged PoC tokens. |
| **Sensitive Data Exposure** | CWE-312 / OWASP API3:2023 | Deep-scans payload claims for unencrypted passwords, SSNs, credit card numbers, and internal infrastructure secrets. |
| **Privilege Escalation** | CWE-284 / OWASP API5:2023 | Tests for unauthorized administrative role modifications (`role: "admin"`) and signature tampering. |

---

## ⚡ Hacker Exploitation & Auditing Capabilities

1. **'none' Algorithm Signature Bypass (CVE-2015-9235):**
   - Detects servers that accept unsigned tokens.
   - Forges administrative exploit tokens across multiple casing variations (`none`, `None`, `NONE`, `nOnE`) with elevated privileges (`role: "admin"`).
2. **Algorithm Confusion / Key Confusion (CVE-2016-5431):**
   - Simulates asymmetric-to-symmetric downgrade (RS256 ➔ HS256) where the server verifies HMAC signatures using its own public RSA key.
3. **High-Speed Offline Dictionary Brute-Forcing:**
   - Rapidly audits HMAC secrets against curated wordlists of common developer passwords (`secret`, `jwtsecret`, `admin123`, etc.).
   - Recovers keys and auto-generates signed proof-of-concept exploit tokens.
4. **Token Lifecycle & Expiration Analysis:**
   - Detects tokens lacking `exp` claims that permit indefinite session hijacking.
   - Verifies clock skew tolerance and expired credentials.
5. **PII & Sensitive Claim Disclosure:**
   - Scans payload claims for cleartext passwords, SSNs, credit cards, or internal infrastructure secrets.
6. **Executive HTML Security Dashboard:**
   - Generates an interactive dark-themed HTML report featuring an SVG circular security score gauge, color-coded token inspector, and remediation instructions.

---

## 🏗️ Architecture & Project Structure

```text
tokensentry/
├── src/
│   ├── jwt.js             # Base64Url RFC 7515 codec, HMAC signing & signature validation
│   ├── attacks.js         # Exploit engines ('none' bypass, key confusion, dictionary cracking)
│   ├── auditor.js         # Security policy auditor, CVSS scoring & PII checks
│   ├── reporter.js        # ANSI CLI formatter, JSON exporter & HTML report generator
│   └── wordlist.js        # Curated dictionary of top weak JWT secrets
├── tests/
│   └── tokensentry.test.js # Automated test suite using Node.js native test runner
├── reports/
│   ├── demo_jwt_report.html # Generated executive HTML audit dashboard
│   └── demo_jwt_report.json # Generated machine-readable findings
├── tokensentry.js         # CLI entrypoint
├── package.json           # Project manifest (ES Modules)
├── LICENSE                # MIT License
└── README.md              # Documentation
```

---

## 🚀 Quickstart & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/zubairkram/tokensentry.git
cd tokensentry
```

### 2. Verify Prerequisites
Requires **Node.js 18+** (Node v24 recommended). **No `npm install` required!**
```bash
node -v
```

### 3. Run the Instant Demo
Audit a simulated vulnerable enterprise token:
```bash
node tokensentry.js --demo
```
This generates `reports/token_audit.html` and `reports/token_audit.json`.

---

## 💻 Usage & CLI Examples

### Basic Token Audit
```bash
node tokensentry.js eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Brute-Force HMAC Secret
```bash
node tokensentry.js --crack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Generate 'none' Algorithm Exploit Payloads
```bash
node tokensentry.js --exploit-none eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Custom Report Outputs
```bash
node tokensentry.js <token> --html reports/api_audit.html --json reports/api_audit.json
```

---

## 📊 Sample Output

### Terminal CLI Summary
```text
==================== TOKEN SECURITY AUDIT ====================
Algorithm:       HS256
Token Type:      JWT
Security Score:  25/100 (Risk Level: CRITICAL)
Findings:        3 issue(s) identified
==============================================================

DECODED TOKEN CLAIMS:
Header:  {"alg":"HS256","typ":"JWT"}
Payload: {
  "sub": "user_49102",
  "username": "john_doe",
  "role": "standard_user",
  "ssn": "123-45-6789"
}

SECURITY VULNERABILITIES & EXPLOIT RISKS:
  [CRITICAL] Trivially Guessable HMAC Secret ('secret') (CVSS: 9.1)
    Classification: CWE-522: Insufficiently Protected Credentials
    Description:    The symmetric signing secret was cracked in 1 attempts using wordlist: 'secret'.
    Forged Admin PoC Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

  [HIGH] Missing Token Expiration ('exp' Claim) (CVSS: 7.5)
    Classification: CWE-613: Insufficient Session Expiration
    Description:    Token has no expiration. Stolen tokens remain valid indefinitely.

  [HIGH] Sensitive Credential/PII Exposed in Claims: 'ssn' (CVSS: 7.2)
    Classification: CWE-312: Cleartext Storage of Sensitive Information
    Description:    The payload exposes sensitive field 'ssn' in base64url plaintext.

[+] HTML Token Security Report generated: reports/token_audit.html
```

---

## 🧪 Running Unit Tests

Run the test suite using Node.js's native test runner:

```bash
npm test
```

Output:
```text
✔ Base64Url encoding and decoding roundtrip (0.92ms)
✔ JWT creation, signing and verification (0.74ms)
✔ Cracking weak HMAC secret via dictionary brute-force (0.59ms)
✔ Generating 'none' algorithm bypass attack payloads (0.28ms)
✔ Auditing JWT with multiple security vulnerabilities (1.26ms)

ℹ pass 5 | fail 0 | duration_ms 100.64
```

---

## 🗺️ Cybersecurity Portfolio Suite

This project is part of a 3-part open-source security tool suite:

1. **[VigilScan (Python)](https://github.com/zubairkram/vigilscan)** — Network Vulnerability Scanner & SSL/TLS Audit Engine
2. **[TraceGuard SIEM (Python)](https://github.com/zubairkram/traceguard)** — Lightweight Log Analyzer & MITRE ATT&CK Threat Detector
3. **[TokenSentry (JavaScript)](https://github.com/zubairkram/tokensentry)** — JWT & API Security Exploitation & Auditing Toolkit

---

## ⚖️ License & Ethical Usage

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

> **Ethical Disclaimer:** TokenSentry is developed strictly for educational, defensive, and authorized penetration testing. Never audit or attack tokens from systems you do not own or have explicit written authorization to test.

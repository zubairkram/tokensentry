# TokenSentry 🛡️🔑
### High-Performance JWT & API Security Exploitation & Auditing Toolkit
> **Built in Modern JavaScript (Node.js) • Directly Aligned with Certiport IT Specialist: Cybersecurity (Domains 1.3, 1.4, 2.1, 4.1)**

[![Node.js 18+](https://img.shields.io/badge/node.js-18%2B-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0%20(Standard%20Library)-success.svg)]()
[![Tests: 5 Passed](https://img.shields.io/badge/tests-5%2F5%20passed-brightgreen.svg)]()
[![Certiport Aligned](https://img.shields.io/badge/Certiport-IT%20Specialist-orange.svg)]()

**TokenSentry** is a high-speed JSON Web Token (JWT) security auditor and penetration testing exploitation toolkit written in pure modern JavaScript (ES Modules) using **zero external npm dependencies**.

Engineered around **Certiport IT Specialist: Cybersecurity** standards and the **OWASP API Security Top 10**, TokenSentry audits API authentication tokens for critical cryptographic flaws, brute-forces weak HMAC secrets, tests for classic signature bypass vulnerabilities, and generates executive HTML security reports.

---

## 📋 Certiport Exam Objectives Alignment

| Certiport Exam Objective | Objective Description | TokenSentry Implementation |
| :--- | :--- | :--- |
| **Domain 1.3: Access Management Principles** | Authentication, authorization, token-based identity, password policies, MFA. | Audits token expiration (`exp`), missing issuance (`iat`), session replay windowing, and role-based privilege escalation. |
| **Domain 1.4: Encryption Methods & Applications** | Types of encryption, hashing, digital signatures, PKI, strong vs. weak algorithms, data at rest vs in transit. | Verifies HMAC-SHA signatures (`HS256`, `HS384`, `HS512`), flags broken algorithms (`none`), checks for cleartext PII/credentials, and demonstrates asymmetric-to-symmetric key confusion. |
| **Domain 2.1: TCP/IP & HTTP Protocol Vulnerabilities** | HTTP vs. HTTPS, session tokens, cleartext data leakage. | Intercepts unencrypted sensitive claims in bearer tokens (passwords, SSNs, internal roles) transmitted over HTTP APIs. |
| **Domain 4.1 & 4.2: Vulnerability Identification & Threat Intel** | Active reconnaissance, CVEs, CWE categorization, security reporting. | Maps findings directly to CVE-2015-9235, CVE-2016-5431, CWE-327, CWE-522, and CVSS v3.1 scores. |

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

## 🗺️ Certiport Cybersecurity Portfolio Roadmap

1. **Project 1: VigilScan (Python)** — Network Vulnerability Scanner & SSL/TLS Audit Engine *(Domains 1.4, 2.1, 2.2, 4.1, 4.2, 4.3)*
2. **Project 2: TraceGuard SIEM (Python)** — Lightweight Log Analyzer & MITRE ATT&CK Threat Detector *(Domains 1.2, 3.5, 5.1, 5.2, 5.3, 5.4)*
3. **Project 3 (This Repository): TokenSentry (JavaScript/Node.js)** — JWT & API Security Auditor & Exploit Toolkit *(Domains 1.3, 1.4, 2.1, 4.1)*

---

## ⚖️ License & Ethical Usage

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

> **Ethical Disclaimer:** TokenSentry is developed strictly for educational, defensive, and authorized penetration testing. Never audit or attack tokens from systems you do not own or have explicit written authorization to test.

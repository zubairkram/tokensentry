/**
 * Automated test suite for TokenSentry.
 * Built using Node.js native test runner (node:test) and assertions.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { base64UrlEncode, base64UrlDecode, parseJwt, createJwt, signHmac, verifyHmac } from "../src/jwt.js";
import { crackHmacSecret, generateNoneAttackPayloads } from "../src/attacks.js";
import { auditJwt } from "../src/auditor.js";

test("Base64Url encoding and decoding roundtrip", () => {
  const original = "Hello, Cybersecurity World! 12345";
  const encoded = base64UrlEncode(original);
  assert.equal(encoded.includes("+"), false);
  assert.equal(encoded.includes("/"), false);
  assert.equal(encoded.includes("="), false);

  const decoded = base64UrlDecode(encoded).toString("utf-8");
  assert.equal(decoded, original);
});

test("JWT creation, signing and verification", () => {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = { sub: "test_user", role: "admin" };
  const secret = "super-secret-key-1234567890-secure";

  const token = createJwt(header, payload, secret);
  const parsed = parseJwt(token);

  assert.equal(parsed.header.alg, "HS256");
  assert.equal(parsed.payload.sub, "test_user");
  assert.equal(parsed.payload.role, "admin");

  const isValid = verifyHmac("HS256", parsed.signingInput, parsed.signature, secret);
  assert.equal(isValid, true);
});

test("Cracking weak HMAC secret via dictionary brute-force", () => {
  const token = createJwt({ alg: "HS256" }, { sub: "victim" }, "password123");
  const result = crackHmacSecret(token);

  assert.equal(result.success, true);
  assert.equal(result.crackedSecret, "password123");
  assert.ok(result.forgedToken);
});

test("Generating 'none' algorithm bypass attack payloads", () => {
  const token = createJwt({ alg: "HS256" }, { sub: "user" }, "secret");
  const result = generateNoneAttackPayloads(token);

  assert.equal(result.payloads.length, 4);
  const noneToken = result.payloads[0].token;
  const parsed = parseJwt(noneToken);
  assert.equal(parsed.header.alg.toLowerCase(), "none");
  assert.equal(parsed.payload.role, "admin");
});

test("Auditing JWT with multiple security vulnerabilities", () => {
  const vulnerableToken = createJwt(
    { alg: "HS256" },
    { sub: "user1", password: "cleartext_password_123" }, // PII leak & no exp
    "secret" // weak secret
  );

  const audit = auditJwt(vulnerableToken);
  assert.equal(audit.riskRating, "CRITICAL");
  assert.ok(audit.findings.some(f => f.id === "SEC-JWT-002")); // cracked secret
  assert.ok(audit.findings.some(f => f.id === "SEC-JWT-003")); // missing exp
  assert.ok(audit.findings.some(f => f.id === "SEC-JWT-006")); // sensitive claim leak
});

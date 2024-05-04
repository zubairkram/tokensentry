/**
 * Core cryptographic JWT encoder, decoder, and signature engine.
 * Pure Node.js standard library - zero external dependencies.
 * Implements RFC 7519 (JWT) and RFC 7515 (JWS) cryptographic standards.
 */

import crypto from "node:crypto";

/**
 * Base64Url encode string or buffer (RFC 7515).
 */
export function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf-8");
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Base64Url decode to Buffer.
 */
export function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4 !== 0) {
    str += "=";
  }
  return Buffer.from(str, "base64");
}

/**
 * Parse a raw JWT string into header, payload, and signature.
 */
export function parseJwt(token) {
  if (!token || typeof token !== "string") {
    throw new Error("Invalid token: token must be a non-empty string");
  }

  const parts = token.trim().split(".");
  if (parts.length < 2 || parts.length > 3) {
    throw new Error(`Invalid JWT structure: expected 2 or 3 parts separated by dots, got ${parts.length}`);
  }

  let header, payload;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]).toString("utf-8"));
  } catch (err) {
    throw new Error(`Failed to parse JWT header: ${err.message}`);
  }

  try {
    payload = JSON.parse(base64UrlDecode(parts[1]).toString("utf-8"));
  } catch (err) {
    throw new Error(`Failed to parse JWT payload: ${err.message}`);
  }

  const signature = parts[2] || "";

  return {
    raw: token,
    header,
    payload,
    signature,
    signingInput: `${parts[0]}.${parts[1]}`
  };
}

/**
 * Compute HMAC signature using specified algorithm (HS256, HS384, HS512).
 */
export function signHmac(algorithm, signingInput, secret) {
  const hashAlg = algorithm.replace("HS", "sha");
  return crypto
    .createHmac(hashAlg, secret)
    .update(signingInput)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Verify HMAC signature.
 */
export function verifyHmac(algorithm, signingInput, signature, secret) {
  const expected = signHmac(algorithm, signingInput, secret);
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

/**
 * Create a new signed or forged JWT.
 */
export function createJwt(header, payload, secret = "", signature = null) {
  const h = base64UrlEncode(JSON.stringify(header));
  const p = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;

  if (signature !== null) {
    return `${signingInput}.${signature}`;
  }

  if (header.alg && header.alg.toLowerCase() === "none") {
    return `${signingInput}.`;
  }

  const sig = signHmac(header.alg || "HS256", signingInput, secret);
  return `${signingInput}.${sig}`;
}

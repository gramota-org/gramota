import { createHash, randomBytes } from "node:crypto";
import { Oid4vciError } from "./types.js";

/**
 * PKCE primitives per RFC 7636.
 *
 * The wallet generates a random `code_verifier`, hashes it to produce a
 * `code_challenge` (S256), sends the challenge with the auth request, and
 * sends the verifier with the token request. The issuer derives the
 * challenge from the verifier and confirms they match.
 *
 * This protects against authorization-code interception attacks — a
 * stolen `code` is useless without the verifier.
 */

/** Generate a code verifier per RFC 7636 §4.1.
 * Length: 43–128 chars; charset: [A-Za-z0-9_~.-] (unreserved per RFC 3986). */
export function generateCodeVerifier(byteLength = 32): string {
  if (byteLength < 32 || byteLength > 96) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "PKCE code verifier byte length must be in [32, 96] (RFC 7636 § 4.1)",
    );
  }
  return randomBytes(byteLength).toString("base64url");
}

/** Compute the S256 code challenge from a verifier per RFC 7636 §4.2. */
export function codeChallenge(verifier: string): string {
  if (typeof verifier !== "string" || verifier.length < 43) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "code verifier must be at least 43 characters (RFC 7636 §4.1)",
    );
  }
  return createHash("sha256").update(verifier).digest("base64url");
}

/** Generate a CSRF state parameter — unique per auth flow. */
export function generateState(byteLength = 16): string {
  return randomBytes(byteLength).toString("base64url");
}

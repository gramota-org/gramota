/**
 * Opaque code generators for the OAuth + OID4VCI flows.
 *
 * Two flavors:
 *
 *   - {@link generateAuthorizationCode} — RFC 6749 §4.1.2 authorization
 *     codes for the auth-code grant. 32 random bytes by default
 *     (`AUTHORIZATION_CODE_BYTES`); base64url-encoded so the wallet can
 *     embed it in a URL without escaping.
 *
 *   - {@link generatePreAuthorizedCode} — OID4VCI §4.1.1 pre-authorized
 *     codes embedded in credential offers. Identical entropy profile
 *     (`PRE_AUTHORIZED_CODE_BYTES = 32`) — both are single-use, both
 *     get redeemed at /token.
 *
 * Both helpers are pure factory functions. State (binding the code to
 * a merchant org, a credential offer, an expiry) lives in the stores
 * (`AuthCodeStore`, the offer table) — not on the code string itself.
 *
 * Why two helpers when the implementation is identical: the two grant
 * types have different security postures (pre-auth is end-user-out-of-band;
 * auth-code is through the browser with PKCE) and may diverge in entropy /
 * format requirements over time. Keeping them separate now means callers
 * pick the semantically correct one at call sites and we can tighten
 * either independently.
 */

import { randomBytes } from "node:crypto";

/** Default entropy for `generateAuthorizationCode`. 32 bytes ≫ RFC 6749's
 * "sufficiently random" bar; base64url of 32 bytes is 43 chars. */
export const AUTHORIZATION_CODE_BYTES = 32;

/** Default entropy for `generatePreAuthorizedCode`. Same as above. */
export const PRE_AUTHORIZED_CODE_BYTES = 32;

export interface GenerateCodeOptions {
  /** Number of random bytes to draw. Default: 32. */
  byteLength?: number;
}

/**
 * Generate an opaque authorization code (RFC 6749 §4.1.2) — single-use,
 * exchanged at /token together with the PKCE verifier.
 */
export function generateAuthorizationCode(
  options: GenerateCodeOptions = {},
): string {
  return randomCode(options.byteLength ?? AUTHORIZATION_CODE_BYTES);
}

/**
 * Generate an opaque pre-authorized code (OID4VCI §4.1.1) — embedded in
 * a credential offer, redeemed at /token under the
 * `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant.
 */
export function generatePreAuthorizedCode(
  options: GenerateCodeOptions = {},
): string {
  return randomCode(options.byteLength ?? PRE_AUTHORIZED_CODE_BYTES);
}

function randomCode(byteLength: number): string {
  if (
    !Number.isFinite(byteLength) ||
    byteLength < 16 ||
    byteLength > 128 ||
    !Number.isInteger(byteLength)
  ) {
    // 16 bytes is the floor (~128 bits of entropy, the OAuth norm).
    // 128 bytes is a defensive ceiling — anything more is a misuse.
    throw new Error(
      `generateAuthorizationCode / generatePreAuthorizedCode: byteLength must be an integer in [16, 128], got ${byteLength}`,
    );
  }
  return randomBytes(byteLength).toString("base64url");
}

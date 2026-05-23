/**
 * Cryptographic randomness helpers for OID4VP authorization requests.
 *
 * Per OID4VP Final 1.0 §5.3 + §11.2 — verifier-supplied opaque values
 * (`state`, `nonce`) MUST carry at least 128 bits of entropy. Even when
 * holder binding (KB-JWT) is present, these fields are reused for CSRF
 * stitching, replay protection and small values invite brute force in
 * edge cases where the value leaks externally (e.g. via referer headers
 * in poorly-implemented universal-link handling).
 *
 * Both helpers draw 16 random bytes (128 bits) from `node:crypto` and
 * encode them in the form the spec prefers for that field:
 *
 *  - `state` → hex (RFC 6648 implementation hint, also what the EU
 *    reference wallet's emulator build sends back verbatim — using hex
 *    keeps the value safe across URL-encoded transports).
 *  - `nonce` → base64url no-pad (matches what the wallet's KB-JWT
 *    `nonce` claim will echo, per OID4VP §5.5 + SD-JWT VC §4.3).
 */

import { randomBytes } from "node:crypto";

/**
 * 128-bit random `state` value, hex-encoded.
 *
 * `state` is the verifier-controlled correlation token the wallet
 * echoes back unchanged in the Authorization Response. Verifiers MUST
 * generate this with enough entropy that a third party cannot guess a
 * pending session id (OID4VP §5.3 + §11.2).
 *
 * 16 bytes → 128 bits → 32 hex chars. Use `generateNonce` for the
 * cryptographic challenge in the same request — they serve different
 * purposes and MUST NOT be reused for one another.
 */
export function generateState(): string {
  return randomBytes(16).toString("hex");
}

/**
 * 128-bit random `nonce` value, base64url-encoded (no padding).
 *
 * `nonce` is the cryptographic challenge the wallet binds into its
 * KB-JWT to prove possession of the holder key. It MUST be unique per
 * request and at least 128 bits (OID4VP §5.3 + §11.2). 16 bytes →
 * 128 bits → 22 base64url chars (no padding).
 *
 * Use `generateState` for the verifier's correlation token in the same
 * request — they serve different purposes and MUST NOT be reused.
 */
export function generateNonce(): string {
  return randomBytes(16).toString("base64url");
}

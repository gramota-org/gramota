/**
 * RFC 9101 JAR (JWT-Secured Authorization Request) signing for OID4VP.
 *
 *   verifier ─── builds AuthorizationRequest object ──►
 *           ─── wraps as compact-serialised JWS    ──►
 *           ─── sets x5c header = [leaf cert DER]  ──►
 *                                                     wallet
 *
 * The wallet:
 *   1. Fetches the JAR (inline `request=<jwt>` or via `request_uri=<url>`)
 *   2. Sees `application/oauth-authz-req+jwt`, parses as a JWS
 *   3. Reads the `x5c` header → leaf cert
 *   4. Validates: cert chain trusted? SAN matches `client_id` value?
 *   5. Verifies the JWS signature with the leaf cert's public key
 *   6. Decodes the payload as the AuthorizationRequest, processes it
 *
 * For the EUDIW HAIP profile + the EU reference wallet's demo build,
 * `x509_san_dns` (with this signed JAR shape) is the only `client_id_prefix`
 * the wallet accepts. Production verifiers MUST sign their requests.
 */

import { SignJWT, importPKCS8 } from "jose";
import {
  Oid4vpError,
  type AuthorizationRequest,
  type SigningCert,
} from "./types.js";

export interface SignAuthorizationRequestOptions {
  /** The verifier's Authorization Request to sign. Must already include
   * the verifier-side fields (`client_id`, `nonce`, `response_uri`, etc).
   * The signer doesn't validate semantic content — only wire-encodes. */
  readonly request: AuthorizationRequest;
  /** The verifier's signing material — produced by `generateSigningCert`
   * or supplied externally. */
  readonly cert: SigningCert;
}

/**
 * Sign an OID4VP Authorization Request as a compact-serialised JWS,
 * formatted per RFC 9101 + OID4VP §5.10.
 *
 * The JWS header carries:
 *   - `alg: "ES256"` (the only algorithm the EU wallet currently accepts
 *     for x509_san_dns prefix; future iterations can lift this)
 *   - `typ: "oauth-authz-req+jwt"` per RFC 9101
 *   - `x5c: [<base64-DER leaf cert>]` so the wallet doesn't need a
 *     separate key-discovery step
 *
 * The JWS payload IS the request object — claims at the top level, not
 * wrapped in some envelope (RFC 9101 §10.2). Caller serves the result
 * with content type `application/oauth-authz-req+jwt`.
 *
 * @throws {@link Oid4vpError} with `oid4vp.jar_signing_failed` if the
 *   private key is malformed or signing fails.
 */
export async function signAuthorizationRequest(
  options: SignAuthorizationRequestOptions,
): Promise<string> {
  if (
    options.cert === null ||
    typeof options.cert !== "object" ||
    typeof options.cert.privateKeyPem !== "string"
  ) {
    throw new Oid4vpError(
      "oid4vp.jar_signing_failed",
      "signAuthorizationRequest: cert.privateKeyPem is required",
    );
  }
  if (!Array.isArray(options.cert.x5c) || options.cert.x5c.length === 0) {
    throw new Oid4vpError(
      "oid4vp.jar_signing_failed",
      "signAuthorizationRequest: cert.x5c must be a non-empty array",
    );
  }

  let privateKey;
  try {
    privateKey = await importPKCS8(options.cert.privateKeyPem, "ES256");
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.jar_signing_failed",
      `signAuthorizationRequest: failed to import private key: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  try {
    // Spread into a fresh mutable object — `jose.SignJWT` wants
    // `JWTPayload` (mutable, index-signature) while `AuthorizationRequest`
    // is strict-readonly. The spread copies own enumerable props and
    // produces a value of structurally-compatible type without an
    // `as unknown as` double-cast.
    const payload: Record<string, unknown> = { ...options.request };
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: "ES256",
        typ: "oauth-authz-req+jwt",
        x5c: [...options.cert.x5c],
      })
      .sign(privateKey);
    return jwt;
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.jar_signing_failed",
      `signAuthorizationRequest: JWS signing failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

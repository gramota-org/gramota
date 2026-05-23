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
 *
 * In addition to the OID4VP request claims, the signer always emits the
 * standard JWT claims `aud`, `iat`, `exp` on the JAR payload (RFC 9101
 * §4 recommends them; OID4VP §5.8 mandates `aud`; HAIP-strict wallets
 * reject when any of the three is absent). The audience defaults to the
 * static pseudo-issuer `https://self-issued.me/v2` and the lifetime
 * defaults to 5 minutes — both are configurable per call.
 */

import { SignJWT, importPKCS8 } from "jose";
import {
  Oid4vpError,
  type AuthorizationRequest,
  type SigningCert,
} from "./types.js";

/** OID4VP §5.8 — default `aud` for the signed JAR. Wallets check `aud`
 * against either their own issuer URL (dynamic discovery) or the static
 * pseudo-issuer `https://self-issued.me/v2`. We don't do dynamic wallet
 * discovery — so the static value is the right default per the HAIP
 * convention. Callers can override via `SignAuthorizationRequestOptions.aud`
 * when targeting wallets that announce themselves via `wallet_metadata`. */
export const DEFAULT_JAR_AUDIENCE = "https://self-issued.me/v2";

/** Default JAR lifetime — 5 minutes. RFC 9101 §4 doesn't fix a value but
 * recommends a "short" lifetime; HAIP doesn't pin one either. 5 min
 * matches OID4VCI's c_nonce window for symmetry across endpoints, and is
 * the audit-recommended default (EUDI compliance audit, 2026-05). */
export const DEFAULT_JAR_LIFETIME_SECONDS = 5 * 60;

export interface SignAuthorizationRequestOptions {
  /** The verifier's Authorization Request to sign. Must already include
   * the verifier-side fields (`client_id`, `nonce`, `response_uri`, etc).
   * The signer doesn't validate semantic content — only wire-encodes. */
  readonly request: AuthorizationRequest;
  /** The verifier's signing material — produced by `generateSigningCert`
   * or supplied externally. */
  readonly cert: SigningCert;
  /** Audience for the signed JAR. Defaults to {@link DEFAULT_JAR_AUDIENCE}
   * (`https://self-issued.me/v2`) per HAIP convention (RFC 9101 §2.1 +
   * OID4VP §5.8). Pass `undefined` explicitly to fall through to the
   * default — a JAR is never emitted without an `aud` claim. */
  readonly aud?: string;
  /** JAR lifetime in seconds. `iat = now`, `exp = now + lifetime`.
   * Defaults to {@link DEFAULT_JAR_LIFETIME_SECONDS} (300 = 5 min).
   * (OID4VP §5.8 + RFC 9101 §4) */
  readonly jarLifetimeSeconds?: number;
  /** Override `iat` source — useful for deterministic tests. Defaults
   * to `() => Math.floor(Date.now() / 1000)`. Returned value is treated
   * as the unix-seconds timestamp written to `iat`; `exp` is
   * `now() + jarLifetimeSeconds`. */
  readonly now?: () => number;
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
 * wrapped in some envelope (RFC 9101 §10.2). On top of the request
 * claims the signer always overlays:
 *   - `aud` — defaults to `https://self-issued.me/v2`
 *   - `iat` — set to `now()` (unix seconds)
 *   - `exp` — set to `iat + jarLifetimeSeconds` (default 300 s)
 *
 * If the request payload already carries any of `aud`/`iat`/`exp`, those
 * payload-level values win — the signer is non-destructive. Caller
 * serves the result with content type `application/oauth-authz-req+jwt`.
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

  // Resolve the JWT timing claims. `options.aud === undefined` falls
  // through to the default (per the option's contract) — callers cannot
  // suppress the claim, only override its value.
  const aud = options.aud ?? DEFAULT_JAR_AUDIENCE;
  const lifetime =
    options.jarLifetimeSeconds ?? DEFAULT_JAR_LIFETIME_SECONDS;
  const nowFn = options.now ?? (() => Math.floor(Date.now() / 1000));
  const iat = nowFn();
  const exp = iat + lifetime;

  try {
    // Spread into a fresh mutable object — `jose.SignJWT` wants
    // `JWTPayload` (mutable, index-signature) while `AuthorizationRequest`
    // is strict-readonly. The spread copies own enumerable props and
    // produces a value of structurally-compatible type without an
    // `as unknown as` double-cast.
    //
    // The OID4VP request fields go in first; if the caller has already
    // set `aud`/`iat`/`exp` at the request level (unusual but legal),
    // those payload-level values win. Otherwise we apply the resolved
    // defaults below. Either way the JAR carries all three claims.
    const payload: Record<string, unknown> = { ...options.request };
    if (payload["aud"] === undefined) payload["aud"] = aud;
    if (payload["iat"] === undefined) payload["iat"] = iat;
    if (payload["exp"] === undefined) payload["exp"] = exp;

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

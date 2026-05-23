/**
 * Authorization-code grant store for OID4VCI §3.4 (HAIP-conformant
 * PID issuance).
 *
 * Background
 * ──────────
 * HAIP §6 mandates auth-code + PKCE + PAR + wallet attestation for PID.
 * This file owns the auth-code half: an opaque code minted by the
 * authorize endpoint, exchanged at the token endpoint with a PKCE
 * `code_verifier` that hashes back to the recorded `code_challenge`
 * (RFC 7636 §4.6).
 *
 * Lifecycle
 * ─────────
 *   1. Authorize endpoint validates the request (incl. PKCE challenge
 *      + optional wallet attestation), then `put()`s a code bound to
 *      the OAuth params (client_id, redirect_uri, PKCE challenge) plus
 *      whatever issuer-specific context (org id, offer id, wallet
 *      instance id) the host needs at /token time.
 *   2. Token endpoint accepts `grant_type=authorization_code` +
 *      `code=<value>` + `code_verifier=<verifier>`. `consume()` returns
 *      the bound request; the host then validates the verifier against
 *      the recorded challenge with {@link verifyPkceChallenge}.
 *
 * TTL is 60s — auth codes have a tight window per OAuth 2.0 §10.5.
 *
 * Storage
 * ───────
 * The default in-memory impl ({@link AuthCodeStore}) is fine for single-
 * replica deployments. Production scale-out wants Redis-backed; the host
 * plugs that in by satisfying {@link AuthCodeStoreLike}.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const AUTH_CODE_TTL_SECONDS = 60;

/** PKCE method per RFC 7636 §4.2. S256 is the only one HAIP mandates;
 * `plain` is included for non-HAIP generic OAuth clients but every HAIP
 * route MUST reject it upstream. */
export type CodeChallengeMethod = "S256" | "plain";

export interface AuthCodeRequest {
  /** OAuth client_id from the original /authorize request. */
  clientId: string;
  /** Redirect URI from the original /authorize request. Token endpoint
   *  rejects mismatches per RFC 6749 §4.1.3. */
  redirectUri: string;
  /** PKCE code_challenge per RFC 7636 §4.2. */
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  /** OID4VCI `issuer_state` from the original /authorize, if any. */
  issuerState?: string;
  /** OID4VCI `authorization_details` from the original /authorize, if any. */
  authorizationDetails?: readonly unknown[];
  /** When the wallet attached DPoP at /authorize, the JWK thumbprint so
   *  the access token issued later can carry the same sender-constraint. */
  dpopJkt?: string;
  /** When wallet attestation is wired, the attestation's `sub` (wallet
   *  instance id) for audit logs. */
  walletInstanceId?: string;
  /** Tenant binding (org id, merchant id, etc.) — opaque to the SDK. */
  organizationId?: string;
  /** Issuance binding — credential offer id, configuration id, etc. The
   *  store doesn't interpret; it just persists for the /token leg. */
  offerId?: string;
  /** Free-form extras for host-specific binding context. */
  extra?: Readonly<Record<string, unknown>>;
}

export interface AuthCodePutOptions {
  ttlSeconds?: number;
}

export interface AuthCodePutResult {
  /** Opaque code — single-use, redeem at /token. */
  code: string;
  /** Lifetime in seconds. */
  expiresInSeconds: number;
}

export interface AuthCodeStoreLike {
  /** Mint an auth code bound to the original PAR request + the issuance
   *  context. Returns the opaque code + lifetime. */
  put(request: AuthCodeRequest, options?: AuthCodePutOptions): Promise<AuthCodePutResult>;
  /** Single-use consume. Returns undefined for unknown, expired, or
   *  previously-consumed codes. */
  consume(code: string): Promise<AuthCodeRequest | undefined>;
  prune(): void;
}

export interface AuthCodeStoreOptions {
  ttlSeconds?: number;
}

interface StoredAuthCode {
  request: AuthCodeRequest;
  expiresAtMs: number;
}

export class AuthCodeStore implements AuthCodeStoreLike {
  private readonly byCode = new Map<string, StoredAuthCode>();
  private readonly defaultTtlSeconds: number;

  constructor(options: AuthCodeStoreOptions = {}) {
    this.defaultTtlSeconds = options.ttlSeconds ?? AUTH_CODE_TTL_SECONDS;
  }

  async put(
    request: AuthCodeRequest,
    options: AuthCodePutOptions = {},
  ): Promise<AuthCodePutResult> {
    const ttl = options.ttlSeconds ?? this.defaultTtlSeconds;
    const code = randomBytes(32).toString("base64url");
    const expiresAtMs = Date.now() + ttl * 1000;
    this.byCode.set(code, { request, expiresAtMs });
    return { code, expiresInSeconds: ttl };
  }

  /**
   * Resolve + consume. Returns undefined for unknown, expired, or
   * previously-consumed codes. Single-use per OAuth 2.0 §4.1.2.
   */
  async consume(code: string): Promise<AuthCodeRequest | undefined> {
    const entry = this.byCode.get(code);
    if (!entry) return undefined;
    this.byCode.delete(code);
    if (Date.now() > entry.expiresAtMs) return undefined;
    return entry.request;
  }

  prune(): void {
    const now = Date.now();
    for (const [code, entry] of this.byCode) {
      if (now > entry.expiresAtMs) this.byCode.delete(code);
    }
  }
}

/**
 * RFC 7636 §4.6 — verify a code_verifier against a recorded challenge.
 *
 * S256 path: `BASE64URL(SHA256(verifier)) == challenge`.
 * plain path: `verifier == challenge` (HAIP forbids; we accept for
 * generic OAuth clients but every HAIP route MUST reject `plain` upstream).
 *
 * Returns true iff verification passes. Errors are absorbed into `false`
 * so the route can treat the boolean as a simple gate without leaking
 * which validation step failed. Equality uses
 * {@link crypto.timingSafeEqual} to remove a (very mild) timing oracle.
 */
export function verifyPkceChallenge(
  verifier: string,
  challenge: string,
  method: CodeChallengeMethod,
): boolean {
  if (typeof verifier !== "string" || typeof challenge !== "string") {
    return false;
  }
  // RFC 7636 §4.1 — code_verifier MUST be 43–128 chars.
  if (verifier.length < 43 || verifier.length > 128) {
    return false;
  }
  if (!/^[A-Za-z0-9_\-.~]+$/.test(verifier)) {
    // RFC 7636 §4.1 unreserved charset.
    return false;
  }
  if (method === "plain") {
    return constantTimeEqual(verifier, challenge);
  }
  if (method !== "S256") {
    return false;
  }
  try {
    const computed = createHash("sha256").update(verifier).digest("base64url");
    return constantTimeEqual(computed, challenge);
  } catch {
    return false;
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf-8");
  const bb = Buffer.from(b, "utf-8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

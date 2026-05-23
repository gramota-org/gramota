/**
 * Pushed Authorization Request (PAR) store — RFC 9126.
 *
 * Background
 * ──────────
 * HAIP 1.0 §6.2 mandates PAR for the auth-code flow on PID issuance. The
 * wallet pushes the authorization parameters to `POST /oid4vci/par` and
 * receives back a one-shot `request_uri`
 * (`urn:ietf:params:oauth:request_uri:<id>`). The wallet then redirects
 * the user to the authorize endpoint with just
 * `client_id=...&request_uri=<urn:...>` rather than spelling the params
 * out in the URL — improves privacy (params don't sit in logs) and lets
 * the issuer pre-validate the request before the browser hop.
 *
 * Lifetime
 * ────────
 * Per RFC 9126 §2.2 the response includes `expires_in` (default 60s in
 * our impl per the HAIP profile note). Single-use: the authorize endpoint
 * consumes the entry on first resolution.
 *
 * Storage
 * ───────
 * The default implementation is an in-process `Map`. Production scale-out
 * across multiple replicas wants a Redis-backed impl — the host plugs that
 * in by satisfying {@link ParStoreLike}.
 */

import { randomBytes } from "node:crypto";

export const PAR_DEFAULT_TTL_SECONDS = 60;

/** URN prefix per RFC 9126 §2.2. */
const REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

/**
 * The PKCE code-challenge method. HAIP §6.2 mandates `S256`.
 * Re-exported from `auth-code-store` for callers that import everything
 * from this module.
 */
export type CodeChallengeMethod = "S256";

/**
 * Headers from `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`
 * captured on the original /par call so the authorize endpoint can replay
 * them through the wallet-attestation verifier. The two values travel as
 * compact-serialised JWTs.
 */
export interface PushedClientAttestation {
  /** `OAuth-Client-Attestation` header value (the JWT). */
  header: string;
  /** `OAuth-Client-Attestation-PoP` header value (the JWT). */
  pop: string;
}

/**
 * The set of parameters the wallet pushed. Captured verbatim — the
 * authorize endpoint does the semantic validation; the store only persists.
 *
 * Per RFC 9126 §2.1 every parameter normally on the auth URL appears here.
 * The shape below is the OID4VCI-conformant superset.
 */
export interface ParRequestPayload {
  clientId: string;
  /** Almost always `"code"` in OID4VCI. */
  responseType: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  /** OAuth scope, optional companion to authorization_details. */
  scope?: string;
  /** CSRF token from the wallet — the AS reflects it back on redirect. */
  state?: string;
  /** OID4VCI `issuer_state` from the credential offer (optional). */
  issuerState?: string;
  /** OID4VCI `authorization_details` — the JSON array spec-shaped by
   *  the wallet. We persist it as-is. */
  authorizationDetails?: readonly unknown[];
  /** HAIP §6.3 wallet attestation pair the wallet attached via headers. */
  attestation?: PushedClientAttestation;
  /** Tenant binding — when the host is multi-tenant, this is the org id
   *  the request was scoped to. Strings keep the interface storage-agnostic
   *  (Postgres pkey, UUID, free-form). */
  organizationId?: string;
  /** Any additional request parameters the wallet pushed, preserved
   *  verbatim. Useful for vendor extensions / future spec params. */
  extra?: Readonly<Record<string, string>>;
}

export interface ParPutOptions {
  ttlSeconds?: number;
}

export interface ParPutResult {
  /** Opaque URN per RFC 9126 §2.2 — `urn:ietf:params:oauth:request_uri:...`. */
  requestUri: string;
  /** Lifetime in seconds — surface as `expires_in` in the response. */
  expiresInSeconds: number;
}

export interface ParStoreLike {
  /** Store a pushed authorization request payload + return its request_uri. */
  put(payload: ParRequestPayload, options?: ParPutOptions): Promise<ParPutResult>;
  /** Resolve + single-use-consume a request_uri. Returns undefined if not
   *  found, expired, or already used. */
  consume(requestUri: string): Promise<ParRequestPayload | undefined>;
  /** Periodic sweep of expired entries. */
  prune(): void;
}

export interface ParStoreOptions {
  /** Default TTL applied when `put()` doesn't override. Default: 60s. */
  ttlSeconds?: number;
}

interface StoredPushedRequest {
  payload: ParRequestPayload;
  expiresAtMs: number;
}

/**
 * In-memory default implementation of {@link ParStoreLike}. Map-backed.
 */
export class ParStore implements ParStoreLike {
  private readonly byUri = new Map<string, StoredPushedRequest>();
  private readonly defaultTtlSeconds: number;

  constructor(options: ParStoreOptions = {}) {
    this.defaultTtlSeconds = options.ttlSeconds ?? PAR_DEFAULT_TTL_SECONDS;
  }

  async put(
    payload: ParRequestPayload,
    options: ParPutOptions = {},
  ): Promise<ParPutResult> {
    const ttl = options.ttlSeconds ?? this.defaultTtlSeconds;
    const requestUri = `${REQUEST_URI_PREFIX}${randomBytes(24).toString("base64url")}`;
    const expiresAtMs = Date.now() + ttl * 1000;
    this.byUri.set(requestUri, { payload, expiresAtMs });
    return { requestUri, expiresInSeconds: ttl };
  }

  /**
   * Resolve + consume. Single-use: success removes the entry so the
   * `request_uri` can't be replayed against a second authorize call.
   */
  async consume(requestUri: string): Promise<ParRequestPayload | undefined> {
    const entry = this.byUri.get(requestUri);
    if (!entry) return undefined;
    this.byUri.delete(requestUri);
    if (Date.now() > entry.expiresAtMs) return undefined;
    return entry.payload;
  }

  prune(): void {
    const now = Date.now();
    for (const [uri, entry] of this.byUri) {
      if (now > entry.expiresAtMs) this.byUri.delete(uri);
    }
  }
}

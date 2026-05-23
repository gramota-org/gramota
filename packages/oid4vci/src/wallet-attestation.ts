/**
 * Wallet attestation per HAIP §6.3 — OAuth 2.0 Attestation-Based Client
 * Authentication (draft-ietf-oauth-attestation-based-client-auth).
 *
 * Background
 * ──────────
 * HAIP-conformant PID issuance requires the wallet to prove it's a
 * legitimate EUDI wallet instance. Two headers travel on `/par` and on
 * `/token` for the auth-code flow:
 *
 *   - `OAuth-Client-Attestation`: a JWT signed by the wallet *vendor's*
 *     attester (Apple, Google, EU CAB, …). Carries the wallet instance's
 *     public key in `cnf.jwk` and a `sub` identifying the wallet provider.
 *   - `OAuth-Client-Attestation-PoP`: a second JWT signed by the wallet
 *     *instance* itself with the cnf.jwk from above. Proves the wallet
 *     actually holds the private key, not just the attestation. Carries
 *     `aud = issuer URL` to bind the PoP to this issuer.
 *
 * Validation
 * ──────────
 *   1. Attestation JWT signature against the configured attester key(s).
 *   2. PoP JWT signature against the `cnf.jwk` from the attestation.
 *   3. PoP `aud` MUST equal the configured audience (issuer URL).
 *   4. PoP `nonce` MUST equal the configured nonce, when one is required.
 *   5. Both JWTs MUST be non-expired (jose default + small skew).
 *   6. PoP `iss` (when present) MUST equal the attestation `sub` — the
 *      PoP issuer is the wallet instance the attestation identifies.
 *
 * Returns the wallet instance JWK (the same key the cnf.jwk identifies)
 * for downstream binding (DPoP / proof JWT cnf checks) plus the
 * attestation's `jti` and `iat` for audit logs.
 *
 * Out of scope here
 * ─────────────────
 * - LoTL/LoTE resolution of trusted attesters (the regulatory track).
 * - Wallet-key attestation chains (`x5c` on the cnf.jwk) — we accept
 *   the bare JWK form the draft also describes.
 * - Revocation of attestations (CRL / status list).
 */

import {
  createRemoteJWKSet,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
  type KeyLike,
  type ResolvedKey,
} from "jose";

/**
 * Configuration for {@link verifyWalletAttestation}.
 *
 * Provide exactly one of `attesterJwks` or `attesterJwksUrl`. When
 * neither is set and `sandboxMode` is true, verification is skipped
 * (for local dev only — never enable in production).
 */
export interface WalletAttestationConfig {
  /** Inline JWK Set. Convenient for tests + small static-key deployments. */
  attesterJwks?: { keys: readonly JWK[] };
  /** Remote JWKS URL — preferred for production. Resolved + cached by jose. */
  attesterJwksUrl?: string;
  /**
   * Allow zero-config sandbox mode where missing headers + missing
   * config = pass-through (no attestation validated; the function still
   * throws when headers ARE present but invalid). Default: false.
   *
   * Intended only for local dev environments where the wallet vendor's
   * attester key isn't yet provisioned. Routes should still gate the
   * production flow with a 503 if neither config nor sandbox is set.
   */
  sandboxMode?: boolean;
  /**
   * Required `aud` claim on the PoP JWT. Usually the issuer's URL. The
   * spec mandates the PoP binds to its target audience.
   */
  expectedAudience: string;
  /**
   * Required `nonce` claim on the PoP. Usually a fresh server-issued
   * nonce. When omitted, the nonce check is skipped (compatible with
   * dev wallets that don't yet round-trip a nonce).
   */
  expectedNonce?: string;
  /**
   * Maximum clock skew tolerated when validating JWT iat/exp.
   * Default: 60 seconds.
   */
  clockToleranceSeconds?: number;
}

export interface WalletAttestationResult {
  /** Wallet instance public key — same key that signed the PoP and that
   *  is/will-be embedded in DPoP / proof JWT cnf.jwk for this session. */
  clientInstanceJwk: JWK;
  attestation: {
    /** JTI from the attestation JWT, when present (for audit dedup). */
    jti: string;
    /** IAT from the attestation JWT, when present (for audit). */
    iat: number;
  };
  /** The wallet provider / instance identifier — the `sub` claim of
   *  the attestation. Useful for audit + tenant policy checks. */
  walletInstanceId: string;
}

/** Stable error codes mapping onto the OAuth Attestation-Based Client
 *  Authentication draft's error responses. */
export type WalletAttestationErrorCode =
  | "invalid_client_attestation"
  | "invalid_client_attestation_pop"
  | "client_attestation_not_configured"
  | "client_attestation_missing";

export class WalletAttestationError extends Error {
  readonly code: WalletAttestationErrorCode;

  constructor(code: WalletAttestationErrorCode, message: string) {
    super(message);
    this.name = "WalletAttestationError";
    this.code = code;
  }
}

export interface WalletAttestationHeaders {
  /** `OAuth-Client-Attestation` request header. */
  attestation?: string;
  /** `OAuth-Client-Attestation-PoP` request header. */
  pop?: string;
}

/**
 * Validate the OAuth-Client-Attestation + PoP pair per HAIP §6.3.
 *
 * @throws {WalletAttestationError} on any validation failure. Codes map
 *   to the draft's OAuth error responses so the host can pass them
 *   through.
 */
export async function verifyWalletAttestation(
  headers: WalletAttestationHeaders,
  config: WalletAttestationConfig,
): Promise<WalletAttestationResult> {
  // ── 0. Header presence + config presence checks.
  const haveHeaders =
    typeof headers.attestation === "string" &&
    headers.attestation.length > 0 &&
    typeof headers.pop === "string" &&
    headers.pop.length > 0;

  const resolver = getAttesterKeyResolver(config);

  if (!resolver) {
    if (config.sandboxMode) {
      // Sandbox: headers absent + no config → return a synthetic result
      // so the route can continue. Production MUST NOT use this branch.
      if (!haveHeaders) {
        return synthesizeSandboxResult();
      }
      // Headers present but no attester configured — still reject.
      throw new WalletAttestationError(
        "client_attestation_not_configured",
        "wallet attestation provided but no attester key configured",
      );
    }
    throw new WalletAttestationError(
      "client_attestation_not_configured",
      "no trusted wallet attester configured",
    );
  }

  if (!haveHeaders) {
    throw new WalletAttestationError(
      "client_attestation_missing",
      "OAuth-Client-Attestation and -PoP headers are both required",
    );
  }

  const clockTolerance =
    config.clockToleranceSeconds !== undefined
      ? `${config.clockToleranceSeconds}s`
      : "60s";

  // ── 1. Verify the attestation JWT against the attester key(s).
  let attestationPayload: JWTPayload;
  try {
    const result = await jwtVerify(headers.attestation!, resolver, {
      clockTolerance,
    });
    attestationPayload = result.payload;
  } catch (err) {
    throw new WalletAttestationError(
      "invalid_client_attestation",
      `attestation verification failed: ${describe(err)}`,
    );
  }

  const walletInstanceId =
    typeof attestationPayload.sub === "string"
      ? attestationPayload.sub
      : undefined;
  if (!walletInstanceId) {
    throw new WalletAttestationError(
      "invalid_client_attestation",
      "attestation missing sub claim",
    );
  }

  const cnf = attestationPayload["cnf"] as
    | Record<string, unknown>
    | undefined;
  const clientInstanceJwk = cnf?.["jwk"] as JWK | undefined;
  if (
    !clientInstanceJwk ||
    typeof clientInstanceJwk !== "object" ||
    Array.isArray(clientInstanceJwk)
  ) {
    throw new WalletAttestationError(
      "invalid_client_attestation",
      "attestation missing cnf.jwk",
    );
  }

  // ── 2. Verify the PoP signed by the cnf.jwk; check aud + nonce.
  let popPayload: JWTPayload;
  try {
    const popKey = (await importJWK(
      clientInstanceJwk,
      typeof clientInstanceJwk.alg === "string" ? clientInstanceJwk.alg : "ES256",
    )) as KeyLike | Uint8Array;
    const result = await jwtVerify(headers.pop!, popKey, {
      audience: config.expectedAudience,
      clockTolerance,
    });
    popPayload = result.payload;
  } catch (err) {
    throw new WalletAttestationError(
      "invalid_client_attestation_pop",
      `pop verification failed: ${describe(err)}`,
    );
  }

  if (config.expectedNonce !== undefined) {
    if (popPayload["nonce"] !== config.expectedNonce) {
      throw new WalletAttestationError(
        "invalid_client_attestation_pop",
        "pop nonce mismatch",
      );
    }
  }

  // PoP `iss` (when present) should equal the attestation `sub` per
  // §3.2.3 of the draft.
  if (
    typeof popPayload.iss === "string" &&
    popPayload.iss !== walletInstanceId
  ) {
    throw new WalletAttestationError(
      "invalid_client_attestation_pop",
      "pop iss does not match attestation sub",
    );
  }

  return {
    clientInstanceJwk,
    attestation: {
      jti: typeof attestationPayload.jti === "string" ? attestationPayload.jti : "",
      iat: typeof attestationPayload.iat === "number" ? attestationPayload.iat : 0,
    },
    walletInstanceId,
  };
}

/**
 * Helper that reads attester config from an env-like object. Returns
 * undefined when neither `WALLET_ATTESTER_JWK` nor `WALLET_ATTESTER_JWKS_URL`
 * is set; the caller decides whether to opt-into sandbox mode or 503 the
 * dependent route.
 *
 * Recognised env vars:
 *   - `WALLET_ATTESTER_JWKS_URL` — preferred for production.
 *   - `WALLET_ATTESTER_JWK` — single JWK serialised as JSON.
 *   - `WALLET_ATTESTER_JWKS` — JWK Set as JSON `{ "keys": [...] }`.
 *   - `WALLET_ATTESTATION_SANDBOX` — `"1"` / `"true"` to enable sandbox.
 *   - `WALLET_ATTESTATION_NONCE` — when set, applied as expectedNonce.
 *
 * `expectedAudience` is always supplied by the caller (usually the
 * tenant issuer URL) since env vars rarely encode per-tenant URLs.
 */
export function loadWalletAttestationConfigFromEnv(
  env: NodeJS.ProcessEnv,
  expectedAudience: string,
): WalletAttestationConfig | undefined {
  const jwksUrl = env["WALLET_ATTESTER_JWKS_URL"];
  const jwkJson = env["WALLET_ATTESTER_JWK"];
  const jwksJson = env["WALLET_ATTESTER_JWKS"];
  const sandbox = isTruthyEnv(env["WALLET_ATTESTATION_SANDBOX"]);
  const expectedNonce = env["WALLET_ATTESTATION_NONCE"];

  let attesterJwks: { keys: JWK[] } | undefined;
  if (typeof jwksJson === "string" && jwksJson.length > 0) {
    try {
      const parsed = JSON.parse(jwksJson) as { keys: JWK[] };
      if (parsed && Array.isArray(parsed.keys)) {
        attesterJwks = { keys: parsed.keys };
      }
    } catch {
      // Malformed JSON — fall through to other env paths.
    }
  } else if (typeof jwkJson === "string" && jwkJson.length > 0) {
    try {
      const parsed = JSON.parse(jwkJson) as JWK;
      attesterJwks = { keys: [parsed] };
    } catch {
      // Malformed JSON — fall through.
    }
  }

  if (!jwksUrl && !attesterJwks && !sandbox) {
    return undefined;
  }

  const config: WalletAttestationConfig = { expectedAudience };
  if (jwksUrl) config.attesterJwksUrl = jwksUrl;
  if (attesterJwks) config.attesterJwks = attesterJwks;
  if (sandbox) config.sandboxMode = true;
  if (expectedNonce) config.expectedNonce = expectedNonce;
  return config;
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

type KeyResolver = Parameters<typeof jwtVerify>[1];

function getAttesterKeyResolver(
  config: WalletAttestationConfig,
): KeyResolver | undefined {
  if (config.attesterJwksUrl) {
    return createRemoteJWKSet(new URL(config.attesterJwksUrl));
  }
  if (config.attesterJwks && config.attesterJwks.keys.length > 0) {
    const keys = config.attesterJwks.keys;
    // Resolver receives the JWS header + token; pick the JWK whose `kid`
    // matches, otherwise fall back to the first key. Bare-JWK deployments
    // typically have a single key.
    return (async (header) => {
      const kid = header["kid"];
      const match =
        (typeof kid === "string"
          ? keys.find((k) => k.kid === kid)
          : undefined) ?? keys[0];
      if (!match) {
        throw new WalletAttestationError(
          "invalid_client_attestation",
          "no matching attester key for the attestation kid",
        );
      }
      return (await importJWK(
        match,
        typeof match.alg === "string" ? match.alg : "ES256",
      )) as ResolvedKey["key"];
    }) as KeyResolver;
  }
  return undefined;
}

function isTruthyEnv(v: string | undefined): boolean {
  if (typeof v !== "string") return false;
  const norm = v.trim().toLowerCase();
  return norm === "1" || norm === "true" || norm === "yes" || norm === "on";
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function synthesizeSandboxResult(): WalletAttestationResult {
  return {
    clientInstanceJwk: {} as JWK,
    attestation: { jti: "", iat: 0 },
    walletInstanceId: "sandbox",
  };
}

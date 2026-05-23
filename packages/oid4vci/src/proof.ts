import { verifyJws, type JsonWebKey, type Signer } from "@gramota/jose";
import { Oid4vciError } from "./types.js";

/** JOSE `typ` header value that OID4VCI §7.2.1.1 mandates for proof JWTs. */
export const PROOF_JWT_TYP = "openid4vci-proof+jwt";

/**
 * Build a Proof of Possession JWT per OID4VCI §7.2.1.
 *
 * The wallet signs this JWT with its holder-binding signer. The issuer
 * uses the embedded `jwk` to bind the issued credential to the holder.
 *
 * Header:
 *   - alg: matches the signer
 *   - typ: "openid4vci-proof+jwt"
 *   - jwk: the holder's public JWK (the issuer puts this in cnf.jwk)
 *
 * Payload:
 *   - aud: the credential_issuer URL (audience binding)
 *   - iat: now
 *   - nonce: c_nonce from the issuer's token response (replay protection)
 *
 * Takes a {@link Signer} rather than a raw private JWK so production
 * wallets can plug in WebAuthn / iOS Secure Enclave / HSM backed signers
 * that never materialize the private key in JS heap.
 */
export interface BuildProofOptions {
  /** The audience — typically `credentialIssuer` from the metadata. */
  audience: string;
  /** Holder's signer — produces the proof JWT signature. The signer's
   * `publicKey` is embedded as the JOSE header `jwk` parameter. */
  signer: Signer;
  /** Optional issuer-supplied nonce (`c_nonce`). Recommended; many
   * issuers require it. */
  nonce?: string;
  /** Override iat — for tests. */
  iat?: number;
  /** Optional client_id of the wallet — `iss` claim of the proof. */
  iss?: string;
}

export async function buildProofJwt(
  options: BuildProofOptions,
): Promise<string> {
  const iat = options.iat ?? Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    aud: options.audience,
    iat,
  };
  if (options.nonce !== undefined) payload["nonce"] = options.nonce;
  if (options.iss !== undefined) payload["iss"] = options.iss;

  const header: Record<string, unknown> = {
    alg: options.signer.alg,
    typ: PROOF_JWT_TYP,
    jwk: options.signer.publicKey,
  };

  // Compose the JWS canonical "header.payload" and hand it to the signer.
  // The signer returns just the base64url signature segment.
  const headerB64 = Buffer.from(JSON.stringify(header), "utf-8").toString(
    "base64url",
  );
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString(
    "base64url",
  );
  const signedPayload = `${headerB64}.${payloadB64}`;
  const signature = await options.signer.sign(signedPayload);
  return `${signedPayload}.${signature}`;
}

// ---------------------------------------------------------------------------
// Server-side: verify an inbound Proof of Possession JWT (OID4VCI §7.2.1.1)
// ---------------------------------------------------------------------------

/** Default freshness window for proof JWT `iat`, in seconds. The spec
 * does not pin a value; we follow the same conservative bracket the
 * spec authors use in informative examples (60 s past, 5 s clock-skew
 * future) — wide enough for normal wallet latency, tight enough to
 * shrink the replay window when {@link VerifyProofJwtOptions.nonce}
 * isn't supplied. Override via {@link VerifyProofJwtOptions.maxAgeSeconds}
 * / {@link VerifyProofJwtOptions.maxFutureSkewSeconds}. */
export const PROOF_JWT_DEFAULT_MAX_AGE_SECONDS = 60;
export const PROOF_JWT_DEFAULT_MAX_FUTURE_SKEW_SECONDS = 5;

/** OID4VCI §7.2.1.1: the only HAIP-blessed proof signing alg is ES256.
 * The verifier still accepts any caller-allowed alg; pass an explicit
 * `algorithms` allowlist to narrow. */
const PROOF_JWT_DEFAULT_ALGS = ["ES256"] as const;

export interface VerifyProofJwtOptions {
  /** Compact-serialized proof JWT from the `proof.jwt` / `proofs.jwt[]`
   * field of the credential request. */
  jwt: string;
  /** Expected audience — the Credential Issuer Identifier per §7.2.1.1.
   * Required: this is the binding that prevents a proof minted against
   * issuer A being replayed against issuer B. */
  audience: string;
  /** Expected nonce — the `c_nonce` the issuer minted (Draft 13: in the
   * token response; Final 1.0: from the Nonce Endpoint). When set, the
   * proof's `nonce` claim MUST equal this. When omitted, no nonce check
   * runs — appropriate only when the issuer doesn't issue c_nonces at all. */
  nonce?: string;
  /** Allowed signing algorithms. Default `["ES256"]` per HAIP §7. */
  algorithms?: readonly string[];
  /** Max age of the proof, in seconds. Default 60 — anything older is
   * rejected. */
  maxAgeSeconds?: number;
  /** Max future clock-skew tolerance, in seconds. Default 5. */
  maxFutureSkewSeconds?: number;
  /** Clock override for tests, in seconds-since-epoch. Default `Date.now()`. */
  now?: number;
}

export interface VerifyProofJwtResult {
  /** Public JWK extracted from the proof's JWS `jwk` header. Bind this
   * into the issued credential's `cnf.jwk` claim. */
  publicJwk: JsonWebKey;
  /** Verified payload — includes `aud`, `iat`, optionally `nonce`, `iss`. */
  payload: Readonly<Record<string, unknown>>;
  /** Verified protected header — includes `alg`, `typ`, `jwk`. */
  header: Readonly<Record<string, unknown>>;
}

/**
 * Verify an inbound Proof of Possession JWT per OID4VCI §7.2.1.1.
 *
 * The verifier:
 *   1. Parses the protected header — requires `typ: "openid4vci-proof+jwt"`
 *      and an embedded `jwk` (self-attesting proof; no external key
 *      resolution needed).
 *   2. Verifies the JWS signature against the embedded JWK (alg pinned
 *      via {@link VerifyProofJwtOptions.algorithms}, default `["ES256"]`).
 *      `verifyJws` enforces the alg allowlist and rejects `alg=none`.
 *   3. Validates payload claims: `aud` matches the expected Credential
 *      Issuer Identifier, `iat` is within the freshness window, and
 *      (when {@link VerifyProofJwtOptions.nonce} is supplied) `nonce`
 *      equals the expected `c_nonce`.
 *
 * Returns the verified public JWK (for binding into `cnf.jwk` on the
 * issued credential) along with the payload + header.
 *
 * @throws {@link Oid4vciError} with stable codes:
 *   - `oid4vci.invalid_input` — malformed JWT or header
 *   - `oid4vci.unsupported_proof_type` — header `typ` is not
 *     `openid4vci-proof+jwt` (§7.2.1.1 MUST)
 *   - `oid4vci.invalid_proof` — semantic violation (aud, nonce, iat,
 *     signature, or missing `jwk` in header)
 */
export async function verifyProofJwt(
  options: VerifyProofJwtOptions,
): Promise<VerifyProofJwtResult> {
  if (typeof options.jwt !== "string" || options.jwt.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyProofJwt: jwt is required",
    );
  }
  if (typeof options.audience !== "string" || options.audience.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyProofJwt: audience is required (Credential Issuer Identifier)",
    );
  }

  // Parse the protected header to read `typ` + `jwk` before signature
  // verification — the `jwk` is the verification key (self-attesting
  // proof per §7.2.1.1).
  const segments = options.jwt.split(".");
  if (segments.length !== 3) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyProofJwt: malformed JWT (expected 3 segments)",
    );
  }
  let header: Record<string, unknown>;
  try {
    const json = Buffer.from(segments[0]!, "base64url").toString("utf-8");
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("header is not a JSON object");
    }
    header = parsed as Record<string, unknown>;
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyProofJwt: malformed header: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  // OID4VCI §7.2.1.1: the proof's JOSE header `typ` MUST be
  // "openid4vci-proof+jwt". Without this check a generic JWT (e.g. an
  // ID Token reused by a malicious or non-conformant client) would
  // pass — typ-binding is the line that says "this JWT is a proof".
  if (header["typ"] !== PROOF_JWT_TYP) {
    throw new Oid4vciError(
      "oid4vci.unsupported_proof_type",
      `verifyProofJwt: header typ must be ${JSON.stringify(
        PROOF_JWT_TYP,
      )} (OID4VCI §7.2.1.1), got ${JSON.stringify(header["typ"])}`,
    );
  }

  const jwk = header["jwk"];
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new Oid4vciError(
      "oid4vci.invalid_proof",
      "verifyProofJwt: header is missing jwk (OID4VCI §7.2.1.1 requires holder key embedding)",
    );
  }
  const publicJwk = jwk as JsonWebKey;

  // verifyJws enforces the alg allowlist and rejects `alg=none`.
  // Default to ES256 per HAIP §7 — narrow further via options.algorithms.
  const algorithms = options.algorithms ?? PROOF_JWT_DEFAULT_ALGS;
  let verified;
  try {
    verified = await verifyJws(options.jwt, publicJwk, {
      algorithms: algorithms as Parameters<typeof verifyJws>[2] extends
        | { algorithms?: infer A }
        | undefined
        ? A
        : never,
    });
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_proof",
      `verifyProofJwt: signature verification failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const payload = verified.payload;

  // Audience check — §7.2.1.1: aud MUST be the Credential Issuer
  // Identifier. The proof is bound to one issuer; cross-issuer replay
  // is rejected here.
  const aud = payload["aud"];
  if (aud !== options.audience) {
    throw new Oid4vciError(
      "oid4vci.invalid_proof",
      `verifyProofJwt: aud mismatch (proof=${JSON.stringify(aud)}, expected=${JSON.stringify(options.audience)})`,
    );
  }

  // iat freshness — §7.2.1.1 doesn't pin a window; the audit calls for
  // "reasonable, e.g., 60s past, 5s future". jose's `jwtVerify` ignores
  // `iat` unless `maxTokenAge` is set — easy footgun. We re-implement
  // the check here so callers can't accidentally accept a stale proof
  // by omitting an option.
  const iat = payload["iat"];
  if (typeof iat !== "number" || !Number.isFinite(iat)) {
    throw new Oid4vciError(
      "oid4vci.invalid_proof",
      "verifyProofJwt: payload is missing iat or iat is not numeric",
    );
  }
  const nowSec = options.now ?? Math.floor(Date.now() / 1000);
  const maxAge = options.maxAgeSeconds ?? PROOF_JWT_DEFAULT_MAX_AGE_SECONDS;
  const maxFutureSkew =
    options.maxFutureSkewSeconds ?? PROOF_JWT_DEFAULT_MAX_FUTURE_SKEW_SECONDS;
  if (iat > nowSec + maxFutureSkew) {
    throw new Oid4vciError(
      "oid4vci.invalid_proof",
      `verifyProofJwt: iat is in the future (iat=${iat}, now=${nowSec}, allowedSkew=${maxFutureSkew}s)`,
    );
  }
  if (iat < nowSec - maxAge) {
    throw new Oid4vciError(
      "oid4vci.invalid_proof",
      `verifyProofJwt: iat is too old (iat=${iat}, now=${nowSec}, maxAge=${maxAge}s)`,
    );
  }

  // Nonce — §7.2.1.1: REQUIRED when the issuer has a Nonce Endpoint
  // (OID4VCI 1.0 Final §7). When the caller doesn't supply an expected
  // nonce, we skip the check — appropriate for legacy Draft 13 flows
  // that don't mint c_nonces, or for callers that have already validated
  // nonce out-of-band. When the caller does supply one, the proof's
  // `nonce` claim MUST match.
  if (options.nonce !== undefined) {
    const proofNonce = payload["nonce"];
    if (proofNonce !== options.nonce) {
      throw new Oid4vciError(
        "oid4vci.invalid_proof",
        `verifyProofJwt: nonce mismatch (proof=${JSON.stringify(proofNonce)}, expected=${JSON.stringify(options.nonce)})`,
      );
    }
  }

  return {
    publicJwk,
    payload,
    header: verified.header,
  };
}

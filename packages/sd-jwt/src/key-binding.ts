import {
  signJws,
  verifyJws,
  type JsonWebKey,
  type Signer,
  type SupportedAlg,
} from "@gateway/jose";
import { computeSdHash } from "./sd-hash.js";
import type { HashAlg } from "./issue.js";
import type { ParsedSdJwt, VerifiedKeyBinding } from "./types.js";

/** Stable codes for `SdJwtKeyBindingError`. Each maps to one of the 9 rules
 * enforced by `verifyKeyBinding`. */
export type SdJwtKeyBindingErrorCode =
  | "sd_jwt.kb.invalid_input"
  | "sd_jwt.kb.absent"
  | "sd_jwt.kb.cnf_missing"
  | "sd_jwt.kb.cnf_jwk_missing"
  | "sd_jwt.kb.malformed"
  | "sd_jwt.kb.malformed_header"
  | "sd_jwt.kb.typ_mismatch"
  | "sd_jwt.kb.signature_invalid"
  | "sd_jwt.kb.required_claim_missing"
  | "sd_jwt.kb.invalid_claim_type"
  | "sd_jwt.kb.audience_mismatch"
  | "sd_jwt.kb.nonce_mismatch"
  | "sd_jwt.kb.iat_too_future"
  | "sd_jwt.kb.iat_too_old"
  | "sd_jwt.kb.transcript_mismatch"
  | "sd_jwt.kb.sd_hash_compute_failed";

/** All KB-JWT failures funnel through this single error type — easier for
 * verifiers to catch and log uniformly. */
export class SdJwtKeyBindingError extends Error {
  override readonly name = "SdJwtKeyBindingError";
  readonly code: SdJwtKeyBindingErrorCode;
  constructor(
    code: SdJwtKeyBindingErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.code = code;
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

// ---------------------------------------------------------------------------
// Builder (holder side)
// ---------------------------------------------------------------------------

/** KB-JWT signing input — accepts either raw keys (shorthand for tests
 * and dev) or a {@link Signer} (production wallets with HSM/WebAuthn/
 * Secure Enclave backing). */
export type KbJwtSignerInput =
  | {
      /** JWS algorithm matching the holder JWK's capabilities. */
      alg: SupportedAlg;
      /** Holder's PRIVATE JWK. Public part must equal `cnf.jwk`. */
      privateKey: JsonWebKey;
    }
  | {
      /** Holder's Signer Strategy. Public side must equal `cnf.jwk`. */
      signer: Signer;
    };

export type BuildKbJwtOptions = {
  /** Verifier identifier — bound into KB-JWT to prevent cross-verifier replay. */
  aud: string;
  /** Verifier challenge — bound into KB-JWT to prevent within-verifier replay. */
  nonce: string;
  /** Issued-at (Unix seconds). Default: now. */
  iat?: number;
  /** Hash algorithm for sd_hash. Default `sha-256`. Must equal the parent
   * SD-JWT's `_sd_alg` to be verifiable. */
  hashAlg?: HashAlg;
} & KbJwtSignerInput;

/**
 * Build and sign a Key Binding JWT for a given presentation prefix.
 *
 * The presentation prefix is `<issuer-jws>~<d1>~...~<dN>~` — every byte the
 * KB-JWT must commit to. Pass `parsed.presentationPrefix` from the parser, or
 * reconstruct it from the SD-JWT you're presenting.
 */
export async function buildKeyBindingJwt(
  presentationPrefix: string,
  options: BuildKbJwtOptions,
): Promise<string> {
  if (typeof presentationPrefix !== "string" || presentationPrefix.length === 0) {
    throw new SdJwtKeyBindingError("sd_jwt.kb.invalid_input", "presentationPrefix must be a non-empty string");
  }
  if (!presentationPrefix.endsWith("~")) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.invalid_input",
      "presentationPrefix must end with '~' per IETF SD-JWT §4.3",
    );
  }
  if (typeof options.aud !== "string" || options.aud.length === 0) {
    throw new SdJwtKeyBindingError("sd_jwt.kb.invalid_input", "aud is required");
  }
  if (typeof options.nonce !== "string" || options.nonce.length === 0) {
    throw new SdJwtKeyBindingError("sd_jwt.kb.invalid_input", "nonce is required");
  }

  const hashAlg = options.hashAlg ?? "sha-256";
  const sdHash = computeSdHash(presentationPrefix, hashAlg);
  const iat = options.iat ?? Math.floor(Date.now() / 1000);

  const payload = {
    iat,
    aud: options.aud,
    nonce: options.nonce,
    sd_hash: sdHash,
  };

  // Normalize input: Signer Strategy in production, raw JWK shorthand
  // for tests/dev. Both paths produce a compact-serialized JWS with
  // typ=kb+jwt — the wire format the verifier reads.
  if ("signer" in options) {
    const signer = options.signer;
    const headerB64 = Buffer.from(
      JSON.stringify({ alg: signer.alg, typ: "kb+jwt" }),
      "utf-8",
    ).toString("base64url");
    const payloadB64 = Buffer.from(
      JSON.stringify(payload),
      "utf-8",
    ).toString("base64url");
    const signed = `${headerB64}.${payloadB64}`;
    const signature = await signer.sign(signed);
    return `${signed}.${signature}`;
  }
  return await signJws(payload, options.privateKey, {
    alg: options.alg,
    typ: "kb+jwt",
  });
}

// ---------------------------------------------------------------------------
// Verifier (relying-party side)
// ---------------------------------------------------------------------------

export interface VerifyKbJwtOptions {
  /** Required. The verifier's identifier; the KB-JWT's `aud` must equal this. */
  expectedAudience: string;
  /** Required. The challenge the verifier issued; the KB-JWT's `nonce` must equal this. */
  expectedNonce: string;
  /** Maximum acceptable age of the KB-JWT in seconds. Default 60. */
  maxAgeSeconds?: number;
  /** Maximum acceptable clock skew in seconds (iat in the future). Default 30. */
  maxClockSkewSeconds?: number;
  /** Algorithm allowlist for the KB-JWT signature. Default: all asymmetric. */
  algorithms?: readonly SupportedAlg[];
  /** Override "now" for tests. Returns Unix seconds. */
  now?: () => number;
}

/**
 * Verify a Key Binding JWT against IETF SD-JWT §4.3.
 *
 * Hard rules enforced:
 *   1. KB-JWT must be present.
 *   2. Parent SD-JWT must contain a `cnf.jwk` claim.
 *   3. KB-JWT header `typ` MUST be `kb+jwt`.
 *   4. KB-JWT signature MUST verify against `cnf.jwk` using an allowlisted alg.
 *   5. KB-JWT payload MUST contain `iat`, `aud`, `nonce`, `sd_hash`.
 *   6. `aud` MUST equal `expectedAudience`.
 *   7. `nonce` MUST equal `expectedNonce`.
 *   8. `iat` MUST be within (-maxAge, +clockSkew) of now.
 *   9. `sd_hash` MUST equal the verifier's own computation over `presentationPrefix`.
 */
export async function verifyKeyBinding(
  parsed: ParsedSdJwt,
  options: VerifyKbJwtOptions,
): Promise<VerifiedKeyBinding> {
  // Rule 1: KB-JWT must be present
  if (parsed.keyBindingJwt === undefined) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.absent",
      "KB-JWT required but absent — presentation lacks holder binding proof",
    );
  }

  // Rule 2: cnf.jwk must be in the parent SD-JWT
  const cnf = parsed.payload["cnf"];
  if (cnf === null || typeof cnf !== "object" || Array.isArray(cnf)) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.cnf_missing",
      "parent SD-JWT has no cnf claim — issuer never bound a holder key",
    );
  }
  const cnfJwk = (cnf as Record<string, unknown>)["jwk"];
  if (cnfJwk === null || typeof cnfJwk !== "object" || Array.isArray(cnfJwk)) {
    throw new SdJwtKeyBindingError("sd_jwt.kb.cnf_jwk_missing", "cnf.jwk is missing or malformed");
  }

  // Rule 3: typ MUST be "kb+jwt" — pre-flight before invoking crypto
  const headerB64 = parsed.keyBindingJwt.split(".")[0];
  if (headerB64 === undefined || headerB64.length === 0) {
    throw new SdJwtKeyBindingError("sd_jwt.kb.malformed", "KB-JWT is malformed");
  }
  let kbHeader: Record<string, unknown>;
  try {
    kbHeader = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf-8"),
    );
  } catch {
    throw new SdJwtKeyBindingError("sd_jwt.kb.malformed_header", "KB-JWT header is not valid base64url JSON");
  }
  if (kbHeader["typ"] !== "kb+jwt") {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.typ_mismatch",
      `KB-JWT 'typ' must be 'kb+jwt', got ${JSON.stringify(kbHeader["typ"])}`,
    );
  }

  // Rule 4: signature verification (alg allowlisting + alg=none rejection are
  // built into verifyJws).
  let verified;
  try {
    const verifyOpts: { algorithms?: readonly SupportedAlg[] } = {};
    if (options.algorithms !== undefined) {
      verifyOpts.algorithms = options.algorithms;
    }
    verified = await verifyJws(
      parsed.keyBindingJwt,
      cnfJwk as JsonWebKey,
      verifyOpts,
    );
  } catch (err) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.signature_invalid",
      `KB-JWT signature verification failed: ${describe(err)}`,
    );
  }

  // Rule 5: required payload claims
  const p = verified.payload;
  for (const claim of ["iat", "aud", "nonce", "sd_hash"] as const) {
    if (p[claim] === undefined) {
      throw new SdJwtKeyBindingError("sd_jwt.kb.required_claim_missing", `KB-JWT is missing required claim: ${claim}`);
    }
  }
  if (typeof p["iat"] !== "number") {
    throw new SdJwtKeyBindingError("sd_jwt.kb.invalid_claim_type", "KB-JWT iat must be a number");
  }
  if (typeof p["aud"] !== "string") {
    throw new SdJwtKeyBindingError("sd_jwt.kb.invalid_claim_type", "KB-JWT aud must be a string");
  }
  if (typeof p["nonce"] !== "string") {
    throw new SdJwtKeyBindingError("sd_jwt.kb.invalid_claim_type", "KB-JWT nonce must be a string");
  }
  if (typeof p["sd_hash"] !== "string") {
    throw new SdJwtKeyBindingError("sd_jwt.kb.invalid_claim_type", "KB-JWT sd_hash must be a string");
  }

  // Rule 6: aud
  if (p["aud"] !== options.expectedAudience) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.audience_mismatch",
      `KB-JWT aud mismatch — expected '${options.expectedAudience}', got '${p["aud"]}'`,
    );
  }

  // Rule 7: nonce
  if (p["nonce"] !== options.expectedNonce) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.nonce_mismatch",
      "KB-JWT nonce mismatch — possible replay or wrong challenge",
    );
  }

  // Rule 8: time validation
  const now = options.now ? options.now() : Math.floor(Date.now() / 1000);
  const maxAge = options.maxAgeSeconds ?? 60;
  const maxSkew = options.maxClockSkewSeconds ?? 30;
  const iat = p["iat"];
  if (iat > now + maxSkew) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.iat_too_future",
      `KB-JWT iat is too far in the future (iat=${iat}, now=${now}, maxSkew=${maxSkew}s)`,
    );
  }
  if (iat < now - maxAge) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.iat_too_old",
      `KB-JWT iat is too old (iat=${iat}, now=${now}, maxAge=${maxAge}s)`,
    );
  }

  // Rule 9: sd_hash matches the transcript
  const hashAlg =
    typeof parsed.payload["_sd_alg"] === "string"
      ? (parsed.payload["_sd_alg"] as HashAlg)
      : "sha-256";
  let expectedSdHash: string;
  try {
    expectedSdHash = computeSdHash(parsed.presentationPrefix, hashAlg);
  } catch (err) {
    throw new SdJwtKeyBindingError("sd_jwt.kb.sd_hash_compute_failed", `failed to compute sd_hash: ${describe(err)}`);
  }
  if (p["sd_hash"] !== expectedSdHash) {
    throw new SdJwtKeyBindingError(
      "sd_jwt.kb.transcript_mismatch",
      "KB-JWT sd_hash does not match the transcript — disclosures may have been tampered with, added, removed, or reordered",
    );
  }

  return {
    header: { typ: "kb+jwt", alg: verified.alg },
    payload: {
      iat: p["iat"],
      aud: p["aud"],
      nonce: p["nonce"],
      sd_hash: p["sd_hash"],
    },
    holderKey: cnfJwk as Record<string, unknown>,
  };
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

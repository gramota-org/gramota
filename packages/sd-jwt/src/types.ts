/**
 * Stable identifiers for every failure mode in `@gramota/sd-jwt`.
 *
 * Codes are namespaced by the operation that raised them:
 *   - `sd_jwt.parse.*` — `parseSdJwt` (structural decoding)
 *   - `sd_jwt.verify.*` — `verifyHashBinding` (disclosure ↔ digest match)
 *   - `sd_jwt.kb.*` — `verifyKeyBinding` / `buildKeyBindingJwt` (KB-JWT)
 *   - `sd_jwt.issue.*` — `issueSdJwt` (signing path)
 *
 * Use the code (not the message) for stable log filtering, dashboards,
 * and per-error programmatic handling. Messages are human-readable and
 * may change.
 */
export type SdJwtErrorCode =
  // parse.ts
  | "sd_jwt.parse.invalid_input"
  | "sd_jwt.parse.missing_separator"
  | "sd_jwt.parse.malformed_jwt"
  | "sd_jwt.parse.malformed_header"
  | "sd_jwt.parse.malformed_payload"
  | "sd_jwt.parse.malformed_disclosure"
  // verify-hash-binding.ts
  | "sd_jwt.verify.unsupported_hash_alg"
  // key-binding.ts
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
  | "sd_jwt.kb.sd_hash_compute_failed"
  // issue.ts
  | "sd_jwt.issue.signer_required"
  | "sd_jwt.issue.alg_required"
  | "sd_jwt.issue.signer_returned_empty"
  | "sd_jwt.issue.unsupported_hash_alg"
  | "sd_jwt.issue.salt_generator_exhausted";

/**
 * Single error class for every failure mode in `@gramota/sd-jwt`.
 *
 * Discriminator is the `code` field — handlers branch on the prefix
 * (`sd_jwt.parse.*` / `sd_jwt.kb.*` / ...) rather than `instanceof` on
 * a per-operation class. Replaces the older per-operation classes
 * (`SdJwtParseError`, `SdJwtVerificationError`, `SdJwtIssuanceError`,
 * `SdJwtKeyBindingError`).
 */
export class SdJwtError extends Error {
  override readonly name = "SdJwtError";
  readonly code: SdJwtErrorCode;
  constructor(
    code: SdJwtErrorCode,
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

export interface SdJwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  x5c?: string[];
  [key: string]: unknown;
}

export interface SdJwtPayload {
  iss?: string;
  sub?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  cnf?: { jwk?: unknown; kid?: string };
  vct?: string;
  status?: unknown;
  _sd?: string[];
  _sd_alg?: string;
  [key: string]: unknown;
}

export interface SdJwtDisclosure {
  raw: string;
  salt: string;
  name: string | null;
  value: unknown;
}

export interface ParsedSdJwt {
  header: SdJwtHeader;
  payload: SdJwtPayload;
  signature: string;
  signedPayload: string;
  disclosures: SdJwtDisclosure[];
  keyBindingJwt?: string;
  /** The exact bytes the KB-JWT's `sd_hash` is computed over: the issuer JWS
   * plus every presented disclosure plus separator tildes, ending with `~`.
   * Per IETF SD-JWT §4.3: `sd_hash = base64url(SHA-256(presentationPrefix))`. */
  presentationPrefix: string;
}

/** Verified Key Binding JWT contents per IETF SD-JWT §4.3. */
export interface VerifiedKeyBinding {
  header: { typ: "kb+jwt"; alg: string };
  payload: {
    iat: number;
    aud: string;
    nonce: string;
    sd_hash: string;
  };
  /** The holder JWK extracted from the parent SD-JWT's `cnf.jwk` claim. */
  holderKey: Record<string, unknown>;
}

export interface VerifiedSdJwt {
  parsed: ParsedSdJwt;
  /** The JWT payload with `_sd` arrays expanded into their disclosed claims and
   * `_sd_alg` stripped. Withheld digests and decoys disappear silently — that
   * is the privacy property of selective disclosure. */
  claims: Record<string, unknown>;
  /** Disclosures whose digest matched some `_sd` entry in the payload. */
  matchedDisclosures: SdJwtDisclosure[];
  /** Disclosures presented by the holder that did NOT match any digest. A
   * non-empty array here is a verification failure: the holder is presenting
   * material the issuer never signed. */
  unmatchedDisclosures: SdJwtDisclosure[];
  /** The hash algorithm used (from `_sd_alg`, defaults to "sha-256"). */
  hashAlgorithm: string;
}

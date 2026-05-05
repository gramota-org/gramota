import type { JsonWebKey, Signer, SupportedAlg } from "@gramota/jose";
import type { HashAlg, SdJwtDisclosure } from "@gramota/sd-jwt";

/**
 * Two equivalent ways to give the Issuer its signing capability:
 *
 *   - Raw form (shorthand for tests/dev):
 *       { privateKey, publicKey, alg }
 *   - Signer form (production with KMS / HSM / signing service):
 *       { signer: Signer }
 *
 * Production issuers nearly always use the Signer form: their root-of-
 * trust private key lives in an HSM / KMS and is RPC-signed.
 */
export type IssuerSignerInput =
  | {
      /** Issuer's PRIVATE JWK used to sign credentials. */
      privateKey: JsonWebKey;
      /** Issuer's PUBLIC JWK — used by holders to verify. */
      publicKey: JsonWebKey;
      /** JWS algorithm. Must be compatible with `privateKey`. */
      alg: SupportedAlg;
    }
  | {
      /** Production-grade signer Strategy (KMS, HSM, custom). */
      signer: Signer;
    };

/** Configuration for an Issuer instance — set once, used per `issue()`. */
export type IssuerConfig = IssuerSignerInput & {
  /** Issuer identifier (a stable URL). Becomes the `iss` claim. */
  issuerId: string;
  /** Hash algorithm for selective-disclosure digests. Default `sha-256`. */
  hashAlg?: HashAlg;
  /** JOSE `kid` header to set on every issued credential. Optional. */
  kid?: string;
  /** JOSE `typ` header. Default `vc+sd-jwt` (per SD-JWT-VC spec). */
  typ?: string;
};

export interface IssueOptions {
  /** All claims that will go into the credential. Top-level keys become
   * either selectively-disclosable disclosures or directly-visible payload
   * claims, controlled by `selectivelyDisclosable`. */
  subject: Readonly<Record<string, unknown>>;
  /** Names of `subject` keys to make selectively disclosable. Names that
   * don't appear in `subject` cause an error. Default: empty (no SD). */
  selectivelyDisclosable?: readonly string[];
  /** Holder's PUBLIC JWK — bound into `cnf.jwk`. Required by SD-JWT-VC for
   * holder-binding (the security model collapses without it). */
  holderKey: JsonWebKey;
  /** SD-JWT-VC credential type identifier — required by the spec. Customers
   * who really know what they're doing can pass an empty string to skip,
   * but the default behaviour rejects missing `vct`. */
  vct: string;
  /** Seconds-until-expiry, relative to `issuedAt`. Mutually exclusive with
   * `expiresAt`. */
  expiresIn?: number;
  /** Absolute expiry as Unix seconds. Mutually exclusive with `expiresIn`. */
  expiresAt?: number;
  /** Optional `nbf` (not-before) claim. */
  notBefore?: number;
  /** Override `iat` — defaults to `floor(Date.now()/1000)` at call time. */
  issuedAt?: number;
  /** Optional `status` claim for revocation tracking (Token Status List). */
  status?: Readonly<Record<string, unknown>>;
  /** Override the generated credential ID (default: random UUID v4). */
  credentialId?: string;
}

/** Result of `issuer.issue()`. */
export interface IssueResult {
  /** The compact-serialised SD-JWT-VC token to send to the holder. */
  token: string;
  /** Issuer-side identifier for tracking. */
  credentialId: string;
  /** Disclosure objects — useful for the issuer's own records / audit logs. */
  disclosures: readonly SdJwtDisclosure[];
  /** Computed expiry (if `expiresIn` or `expiresAt` was set). */
  expiresAt: number | undefined;
}

/**
 * Per-credential binding for `issueBatch`. Everything that varies *across*
 * credentials in the batch goes here; everything shared (subject, vct,
 * expiry, …) sits at the top level of {@link BatchIssueOptions}.
 */
export interface BatchIssueEntry {
  /** Holder's PUBLIC JWK — bound into this credential's `cnf.jwk`. Each
   * entry must have a distinct holder key for one-time-use unlinkability. */
  holderKey: JsonWebKey;
  /** Override the generated credential ID (default: random UUID v4 per entry). */
  credentialId?: string;
  /** Per-credential `status` claim — typical use is to allocate a distinct
   * Token Status List index for each one-time credential so they can be
   * revoked independently. */
  status?: Readonly<Record<string, unknown>>;
}

/**
 * Options for `issuer.issueBatch()` (OID4VCI Draft 14/15 batch issuance).
 *
 * Shared across the batch: subject, vct, expiry, notBefore, issuedAt,
 * selectivelyDisclosable.
 *
 * Per-credential: `credentials[i]` (holderKey, optional credentialId,
 * optional status).
 */
export interface BatchIssueOptions {
  /** Claims shared by every credential in the batch. Same semantics as
   * {@link IssueOptions.subject}. */
  subject: Readonly<Record<string, unknown>>;
  /** SD-JWT-VC type identifier — shared across the batch. */
  vct: string;
  /** Names of `subject` keys to make selectively disclosable. Validated
   * once against `subject`; applies to every credential. Each credential
   * gets fresh random salts (so two credentials over the same data are
   * unlinkable on the wire). */
  selectivelyDisclosable?: readonly string[];
  /** Shared `expiresIn`. Mutually exclusive with `expiresAt`. */
  expiresIn?: number;
  /** Shared absolute `expiresAt`. Mutually exclusive with `expiresIn`. */
  expiresAt?: number;
  /** Shared `nbf`. */
  notBefore?: number;
  /** Shared `iat`. Defaults to `floor(Date.now()/1000)` evaluated *once*
   * for the whole batch (so every credential reports the same iat). */
  issuedAt?: number;
  /** One entry per credential to issue. Length ≥ 1. */
  credentials: readonly BatchIssueEntry[];
}

/** Stable codes for `IssuerError`. */
export type IssuerErrorCode =
  | "issuer.subject_invalid"
  | "issuer.holder_key_required"
  | "issuer.vct_required"
  | "issuer.expiry_conflict"
  | "issuer.expiry_invalid"
  | "issuer.disclosable_missing"
  | "issuer.reserved_claim_in_subject"
  | "issuer.batch_empty";

export class IssuerError extends Error {
  override readonly name = "IssuerError";
  readonly code: IssuerErrorCode;
  constructor(
    code: IssuerErrorCode,
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

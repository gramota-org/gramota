import type { JsonWebKey, SupportedAlg } from "@gateway/jose";
import type { HashAlg, SdJwtDisclosure } from "@gateway/sd-jwt";

/** Configuration for an Issuer instance — set once, used per `issue()`. */
export interface IssuerConfig {
  /** Issuer's PRIVATE JWK used to sign credentials. */
  privateKey: JsonWebKey;
  /** Issuer's PUBLIC JWK — used by holders to verify, and by us for sanity
   * checks (e.g. confirm the keypair is consistent). */
  publicKey: JsonWebKey;
  /** JWS algorithm. Must be compatible with `privateKey`. */
  alg: SupportedAlg;
  /** Issuer identifier (a stable URL). Becomes the `iss` claim. */
  issuerId: string;
  /** Hash algorithm for selective-disclosure digests. Default `sha-256`. */
  hashAlg?: HashAlg;
  /** JOSE `kid` header to set on every issued credential. Optional. */
  kid?: string;
  /** JOSE `typ` header. Default `vc+sd-jwt` (per SD-JWT-VC spec). */
  typ?: string;
}

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

export class IssuerError extends Error {
  override readonly name = "IssuerError";
}

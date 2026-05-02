import type { JsonWebKey, SupportedAlg } from "@gramota/jose";
import type { TrustResolver } from "@gramota/trust";
import type {
  CredentialStatusResult,
  StatusResolver,
} from "@gramota/status-list";

/** Configuration for a Verifier instance. */
export interface VerifierConfig {
  /** The verifier's identifier. The KB-JWT's `aud` claim MUST equal this.
   * Cross-verifier replay protection — pick a stable, app-specific URL. */
  audience: string;

  /** Exactly one of `issuerKey` (shorthand) OR `trust` (full resolver) is
   * required. */
  issuerKey?: JsonWebKey;

  /** Pluggable trust resolution. Use `StaticTrustResolver` for hard-coded
   * keys, `JwksUrlTrustResolver` for runtime JWKS fetching, or any custom
   * implementation of the `TrustResolver` interface. */
  trust?: TrustResolver;

  /**
   * Pluggable revocation/suspension resolution (Strategy pattern).
   *
   * When set, the verifier runs a 10th security check ("status.check")
   * after all crypto checks pass. Default: omitted — no status check.
   *
   * Use `StatusListResolver` for IETF Token Status List (the typical EU
   * choice). Custom resolvers (CRL, OCSP, EU Trusted Issuers Registry,
   * deny-lists) implement the `StatusResolver` interface and plug in here.
   */
  statusResolver?: StatusResolver;

  /** JWS algorithm allowlist for both issuer and KB-JWT signatures.
   * Default: every IETF asymmetric algorithm we support.
   * `alg=none` is *never* permitted, regardless of this list. */
  algorithms?: readonly SupportedAlg[];

  /** Maximum acceptable age of the KB-JWT, in seconds. Default 60. */
  maxKbJwtAgeSeconds?: number;

  /** Maximum acceptable clock skew (KB-JWT `iat` in the future), in seconds.
   * Default 30. */
  maxClockSkewSeconds?: number;
}

/** Per-call options for `verifier.verify(...)`. */
export interface VerifyOptions {
  /** The challenge the verifier sent to the wallet. The KB-JWT's `nonce`
   * claim MUST equal this. Within-verifier replay protection. */
  nonce: string;

  /** Override "now" — used for tests and time-frozen environments. Returns
   * Unix seconds. Default: `Math.floor(Date.now() / 1000)`. */
  now?: () => number;

  /**
   * Status-check policy for THIS verification.
   *
   * - When `false`/omitted, the configured `statusResolver` (if any)
   *   is still consulted; "skipped" is acceptable.
   * - When `true`, a credential with no resolvable status fails the
   *   "status.check" gate. Useful for high-assurance flows where
   *   non-revocable credentials are unacceptable.
   *
   * Has no effect when no `statusResolver` is configured on the Verifier.
   */
  requireStatus?: boolean;
}

/** A single security check, recorded for observability. Every check is
 * present in the result regardless of pass/fail, so customers can build
 * audit dashboards. */
export interface SecurityCheck {
  /** Stable identifier — useful for logs and dashboards. */
  name: SecurityCheckName;
  passed: boolean;
  /** Human-readable detail when the check fails. */
  message?: string;
}

/** Stable identifiers for the security checks we run, in execution order. */
export type SecurityCheckName =
  | "structure.parse"
  | "trust.resolution"
  | "issuer.signature"
  | "hash-binding.disclosures"
  | "kb-jwt.present"
  | "kb-jwt.cnf-binding"
  | "kb-jwt.signature"
  | "kb-jwt.audience"
  | "kb-jwt.nonce"
  | "kb-jwt.time"
  | "kb-jwt.transcript"
  | "status.check";

/** Protocol metadata extracted alongside the user-facing claims. */
export interface VerificationMetadata {
  issuer: string;
  audience: string;
  issuedAt: number | undefined;
  expiresAt: number | undefined;
  /** The holder's bound public JWK from cnf.jwk in the parent SD-JWT. After
   * verification this is guaranteed to be a well-formed JWK that successfully
   * verified the KB-JWT signature. */
  holderKey: Readonly<Record<string, unknown>>;
}

export type VerifyResult<TClaims = Record<string, unknown>> =
  | SuccessResult<TClaims>
  | FailureResult;

export interface SuccessResult<TClaims = Record<string, unknown>> {
  ok: true;
  /** The selectively-disclosed user claims with `_sd` / `_sd_alg` / `cnf`
   * stripped — this is what the application actually consumes. */
  claims: TClaims;
  /** Protocol-level metadata that's not part of the user claims. */
  metadata: VerificationMetadata;
  /** Every check we ran, all passed. Useful for audit trails. */
  checks: readonly SecurityCheck[];
  /** When `options.status` was supplied, the resolved status (or
   * "skipped" if the credential carried no status reference). Absent
   * when status checking wasn't requested. */
  status?: CredentialStatusResult | "skipped";
  /** Returns claims; never throws on success. */
  unwrap(): TClaims;
}

export interface FailureResult {
  ok: false;
  /** Human-readable reason — surfaces the message from the failed check. */
  reason: string;
  /** Stable identifier of the first check that failed. */
  failedCheck: SecurityCheckName;
  /** Every check up to and including the one that failed. */
  checks: readonly SecurityCheck[];
  /** Throws `VerificationError` carrying this result. */
  unwrap(): never;
}

export class VerificationError extends Error {
  override readonly name = "VerificationError";
  /** Equal to `result.failedCheck` — stable identifier for log filters,
   * alerts, and dashboards. Same shape as the codes used by other packages. */
  readonly code: SecurityCheckName;
  constructor(
    message: string,
    /** The full failure record — stable for logging. */
    readonly result: FailureResult,
  ) {
    super(message);
    this.code = result.failedCheck;
  }
}

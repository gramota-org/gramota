import type { JsonWebKey, SupportedAlg } from "@gramota/jose";
import type { TrustResolver } from "@gramota/trust";
import type {
  CredentialStatusResult,
  StatusResolver,
} from "@gramota/status-list";

/** Configuration for a Verifier instance. */
export interface VerifierConfig {
  /** The verifier's identifier. The KB-JWT's `aud` claim MUST equal this
   * (or any of `additionalAudiences`). Cross-verifier replay protection —
   * pick a stable, app-specific URL. */
  audience: string;

  /** Additional accepted `aud` values. Useful when wallets in the wild
   * disagree about what the KB-JWT audience should be. The OID4VP
   * `x509_san_dns:<host>` client_id is a common alternate form some
   * wallets (the EU reference wallet's eudi-app-android-wallet-ui) put
   * in `aud` instead of the verifier audience URL. */
  additionalAudiences?: readonly string[];

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

/** Input passed to {@link VerifyOptions.require} predicates. */
export interface RequireInput<TClaims = Record<string, unknown>> {
  /** The disclosed claims — same shape as `result.claims` on success. */
  readonly claims: TClaims;
  /** Protocol metadata — same shape as `result.metadata` on success. */
  readonly metadata: VerificationMetadata;
}

/**
 * Return shape for {@link VerifyOptions.require} when the caller wants
 * to attach a human-readable reason. Plain `boolean` is also accepted
 * for the common case.
 */
export interface RequireResult {
  readonly passed: boolean;
  /** Shown in `result.reason` and the audit trail when `passed: false`.
   * Default: `"require predicate returned false"`. */
  readonly reason?: string;
}

/** Per-call options for `verifier.verify(...)`. */
export interface VerifyOptions<TClaims = Record<string, unknown>> {
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

  /**
   * Application-level predicate. Runs AFTER all crypto + status checks
   * pass; receives the disclosed claims + protocol metadata; returns
   * a boolean (or `{ passed, reason }` for a custom failure reason).
   *
   * If the predicate returns `false` (or `{ passed: false }`), the
   * verification fails with `failedCheck: "require.predicate"` and the
   * predicate's `reason` (or a default) becomes `result.reason`. The
   * `require.predicate` entry is appended to `result.checks` either
   * way, so audit dashboards see the same shape as for any other check.
   *
   * If the predicate throws, the throw propagates — the verifier does
   * NOT silently treat exceptions as "passed: false". This is so
   * caller bugs surface as crashes during dev, not as accepted
   * presentations in production.
   *
   * @example
   * ```ts
   * await verifier.verify(token, {
   *   nonce,
   *   require: ({ claims }) =>
   *     claims.age_over_18 === true &&
   *     EU_COUNTRIES.has(claims.nationality as string),
   * });
   * ```
   */
  require?: (
    input: RequireInput<TClaims>,
  ) => boolean | RequireResult | Promise<boolean | RequireResult>;
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
  | "status.check"
  /** Application-level predicate from {@link VerifyOptions.require}.
   * Runs last; not part of the cryptographic protocol — semantically
   * a customer business rule that determines whether the (already
   * crypto-valid) presentation is acceptable for THIS endpoint. */
  | "require.predicate";

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
  /** Throws `VerifierError` carrying this result. */
  unwrap(): never;
}

export class VerifierError extends Error {
  override readonly name = "VerifierError";
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

/**
 * Base error for everything thrown out of `@gramota/*` packages.
 *
 * Every per-package error class extends this. Two reasons:
 *
 *   1. **One catch site.** Telemetry, logging, and error boundaries
 *      can use `instanceof GramotaError` instead of importing every
 *      package's error class. Particularly important for app-level
 *      Sentry integration where you want to tag SDK errors uniformly.
 *
 *   2. **Stable error code surface.** Each subclass narrows `code` to
 *      its own union (`SecurityCheckName` for verifier, `IssuerErrorCode`
 *      for issuer, etc.) but `error.code` is always a string at runtime,
 *      so generic logs / metrics keys work without type gymnastics.
 *
 * Subclasses **should**:
 *   - Set `name` to the subclass name (improves stack traces)
 *   - Pass a structured `code` for programmatic branching
 *   - Pass `cause` when wrapping a thrown error from a dependency
 *
 * @example
 * ```ts
 * try {
 *   await verifier.presentations.verify(token, { nonce });
 * } catch (err) {
 *   if (err instanceof GramotaError) {
 *     telemetry.recordError(err.name, err.code);
 *     throw err;
 *   }
 *   throw err;
 * }
 * ```
 */
export class GramotaError extends Error {
  /** Stable string that identifies the failure mode. Subclasses narrow
   * the type; at runtime it's always a string. Use for branching, logs,
   * and metrics labels — never serialize {@link GramotaError.message}
   * for that purpose, message strings drift across versions. */
  readonly code: string;

  /** Optional original error that caused this one. Always set when the
   * Gramota package is wrapping a thrown exception from a dependency
   * (Web Crypto, JOSE, fetch). Survives `JSON.stringify(err)` only via
   * the `cause` property — Node 16.9+ logs it natively. */
  override readonly cause?: unknown;

  constructor(message: string, code: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "GramotaError";
    this.code = code;
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}

/**
 * Type guard — narrows a caught `unknown` to {@link GramotaError}.
 *
 * Particularly useful at app-level catch sites where you want to log
 * SDK errors uniformly without losing type information about where
 * they came from.
 */
export function isGramotaError(err: unknown): err is GramotaError {
  return err instanceof GramotaError;
}

import { GramotaError } from "@gramota/core";

import type { JsonWebKey } from "@gramota/jose";

/** Inputs the resolver gets to make a decision. */
export interface TrustContext {
  /** The `iss` claim from the JWT payload, if any. */
  iss: string | undefined;
  /** The `kid` claim from the JWT protected header, if any. */
  kid: string | undefined;
  /** The full protected header — useful for `x5c`, `jwk`, custom params. */
  header: Readonly<Record<string, unknown>>;
}

/** A pluggable strategy for figuring out which JWK(s) should verify an
 * issuer's JWS. Strategy + Repository pattern: implementations can be a
 * static list, a JWKS URL fetch, an EU Trusted List, or anything custom. */
export interface TrustResolver {
  /** Return all candidate JWKs that might verify this issuer's JWS. The
   * verifier will try each in order until one succeeds. Throw if no candidate
   * can be produced — that's a trust-resolution failure. */
  resolveIssuerKeys(context: TrustContext): Promise<readonly JsonWebKey[]>;
}

/** Stable codes for `TrustResolutionError`. */
export type TrustErrorCode =
  | "trust.iss_required"
  | "trust.issuer_not_configured"
  | "trust.fetch_failed"
  | "trust.http_error"
  | "trust.malformed_jwks"
  | "trust.invalid_input";

export class TrustResolutionError extends GramotaError {
  override readonly code: TrustErrorCode;

  constructor(
    code: TrustErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, code, options);
    this.name = "TrustResolutionError";
    this.code = code;
  }
}

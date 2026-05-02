import type { JsonWebKey } from "@gramota/jose";
import {
  TrustResolutionError,
  type TrustContext,
  type TrustResolver,
} from "./types.js";

/** Constructor input forms for StaticTrustResolver. */
export type StaticTrustInput =
  | readonly JsonWebKey[]
  | Readonly<Record<string, readonly JsonWebKey[]>>;

/**
 * Trust a fixed set of public keys, optionally keyed by issuer URL.
 *
 * Two configuration shapes:
 *
 *   // Flat list — every key is trusted for every issuer.
 *   new StaticTrustResolver([key1, key2])
 *
 *   // Per-issuer map — strict isolation between issuers.
 *   new StaticTrustResolver({
 *     "https://issuer-a.example.com": [keyA1, keyA2],
 *     "https://issuer-b.example.com": [keyB],
 *   })
 *
 * `kid` matching: if both the JWT header and a configured key carry a `kid`,
 * the resolver returns only matching keys; otherwise it returns all keys for
 * the issuer (verifier will try them in order).
 */
export class StaticTrustResolver implements TrustResolver {
  private readonly mode: "flat" | "byIssuer";
  private readonly flat: readonly JsonWebKey[];
  private readonly byIssuer: ReadonlyMap<string, readonly JsonWebKey[]>;

  constructor(input: StaticTrustInput) {
    if (Array.isArray(input)) {
      this.mode = "flat";
      this.flat = input;
      this.byIssuer = new Map();
    } else if (input !== null && typeof input === "object") {
      this.mode = "byIssuer";
      this.flat = [];
      this.byIssuer = new Map(Object.entries(input));
    } else {
      throw new TypeError(
        "StaticTrustResolver requires an array of JWKs or an iss→keys map",
      );
    }
    if (this.mode === "flat" && this.flat.length === 0) {
      throw new TypeError("StaticTrustResolver requires at least one key");
    }
    if (this.mode === "byIssuer" && this.byIssuer.size === 0) {
      throw new TypeError("StaticTrustResolver issuer map is empty");
    }
  }

  async resolveIssuerKeys(
    context: TrustContext,
  ): Promise<readonly JsonWebKey[]> {
    let candidates: readonly JsonWebKey[];

    if (this.mode === "flat") {
      candidates = this.flat;
    } else {
      if (context.iss === undefined) {
        throw new TrustResolutionError(
          "trust.iss_required",
          "issuer-keyed StaticTrustResolver requires iss to resolve, but JWT has no iss claim",
        );
      }
      const forIss = this.byIssuer.get(context.iss);
      if (forIss === undefined) {
        throw new TrustResolutionError(
          "trust.issuer_not_configured",
          `issuer ${context.iss} is not in the static trust list`,
        );
      }
      candidates = forIss;
    }

    // Filter by kid if specified on both sides; otherwise pass everything through.
    if (context.kid !== undefined) {
      const matching = candidates.filter((k) => {
        const ckid = (k as Record<string, unknown>)["kid"];
        return typeof ckid === "string" && ckid === context.kid;
      });
      if (matching.length > 0) {
        return matching;
      }
      // No kid match → fall back to returning all candidates. Some issuers
      // publish unkeyed JWKs while still using kid in headers; we'd rather
      // try than reject.
    }

    return candidates;
  }
}

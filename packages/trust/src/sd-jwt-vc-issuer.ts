/**
 * SD-JWT-VC Issuer trust resolver per IETF draft-ietf-oauth-sd-jwt-vc.
 *
 * Resolves issuer keys via the standardized SD-JWT-VC well-known
 * endpoint:
 *
 *     <iss>/.well-known/jwt-vc-issuer
 *
 * The response shape is wrapped (different from a plain RFC 7517 JWKS):
 *
 *     {
 *       "issuer": "<canonical issuer URL>",
 *       "jwks": { "keys": [...] }      OR  "jwks_uri": "<URL>"
 *     }
 *
 * The `issuer` field MUST equal the `iss` we resolved on, otherwise
 * an attacker could host a benign discovery doc at one URL and
 * reference it from another. We enforce this check.
 *
 * If the response uses `jwks_uri` (indirection), we fetch one more
 * level. Both forms are spec-compliant.
 *
 * Implements `TrustResolver` — drops in anywhere a `TrustResolver`
 * is expected (Verifier, Holder via custom config, etc.). This is
 * the resolver to use against EU dev infrastructure.
 */

import type { JsonWebKey } from "@gramota/jose";
import {
  TrustResolutionError,
  type TrustContext,
  type TrustResolver,
} from "./types.js";

export type Fetcher = (
  url: string,
  init?: { signal?: AbortSignal; headers?: Record<string, string> },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

export interface SdJwtVcIssuerResolverOptions {
  /** Override the well-known URL builder. Default: `<iss>/.well-known/jwt-vc-issuer`. */
  metadataUrl?: (iss: string) => string;
  /** Cache TTL in milliseconds. Default: 5 minutes. */
  cacheMs?: number;
  /** Override `fetch`. */
  fetcher?: Fetcher;
  /** Override `Date.now()` — for tests. */
  now?: () => number;
}

interface CacheEntry {
  expiresAt: number;
  keys: readonly JsonWebKey[];
}

export class SdJwtVcIssuerTrustResolver implements TrustResolver {
  private readonly buildMetadataUrl: (iss: string) => string;
  private readonly cacheMs: number;
  private readonly fetcher: Fetcher;
  private readonly nowFn: () => number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: SdJwtVcIssuerResolverOptions = {}) {
    this.buildMetadataUrl =
      options.metadataUrl ??
      ((iss) => `${stripTrailingSlash(iss)}/.well-known/jwt-vc-issuer`);
    this.cacheMs = options.cacheMs ?? 5 * 60_000;
    this.fetcher =
      options.fetcher ??
      ((url, init) =>
        fetch(url, init).then((r) => ({
          ok: r.ok,
          status: r.status,
          json: () => r.json(),
        })));
    this.nowFn = options.now ?? Date.now;
  }

  async resolveIssuerKeys(
    context: TrustContext,
  ): Promise<readonly JsonWebKey[]> {
    if (context.iss === undefined) {
      throw new TrustResolutionError(
        "trust.iss_required",
        "SdJwtVcIssuerTrustResolver requires iss but JWT has no iss claim",
      );
    }

    const keys = await this.fetchKeysCached(context.iss);

    // kid filtering — same semantics as JwksUrlTrustResolver. When the
    // header carries a kid, prefer keys that match. If none match, fall
    // back to the full set so verifyJws can try each.
    if (context.kid !== undefined) {
      const matching = keys.filter((k) => {
        const ckid = (k as Record<string, unknown>)["kid"];
        return typeof ckid === "string" && ckid === context.kid;
      });
      if (matching.length > 0) return matching;
    }

    return keys;
  }

  /** Force-clear cache for one issuer. */
  invalidate(iss: string): void {
    this.cache.delete(iss);
  }

  // ---- internal --------------------------------------------------------

  private async fetchKeysCached(
    iss: string,
  ): Promise<readonly JsonWebKey[]> {
    const cached = this.cache.get(iss);
    if (cached !== undefined && cached.expiresAt > this.nowFn()) {
      return cached.keys;
    }

    const metadataUrl = this.buildMetadataUrl(iss);
    const metadata = await this.fetchJson(metadataUrl);

    if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
      throw new TrustResolutionError(
        "trust.malformed_jwks",
        `SD-JWT-VC issuer metadata at ${metadataUrl} is not a JSON object`,
      );
    }
    const m = metadata as Record<string, unknown>;

    // SECURITY: `issuer` field MUST equal the iss we resolved on. Without
    // this, an attacker hosts a valid discovery doc at one URL and points
    // at it from a malicious issuer URL.
    if (m["issuer"] !== iss) {
      throw new TrustResolutionError(
        "trust.malformed_jwks",
        `SD-JWT-VC issuer metadata 'issuer' field (${String(m["issuer"])}) does not match resolved iss (${iss})`,
      );
    }

    let keys: readonly JsonWebKey[];
    if (
      m["jwks"] !== null &&
      typeof m["jwks"] === "object" &&
      !Array.isArray(m["jwks"])
    ) {
      // Embedded JWKS form: { jwks: { keys: [...] } }
      keys = parseJwksObject(m["jwks"] as Record<string, unknown>, metadataUrl);
    } else if (typeof m["jwks_uri"] === "string" && m["jwks_uri"].length > 0) {
      // Indirection form: { jwks_uri: "<URL>" } — fetch one more level.
      const jwksBody = await this.fetchJson(m["jwks_uri"]);
      if (jwksBody === null || typeof jwksBody !== "object" || Array.isArray(jwksBody)) {
        throw new TrustResolutionError(
          "trust.malformed_jwks",
          `JWKS at ${m["jwks_uri"]} is not a JSON object`,
        );
      }
      keys = parseJwksObject(jwksBody as Record<string, unknown>, m["jwks_uri"]);
    } else {
      throw new TrustResolutionError(
        "trust.malformed_jwks",
        `SD-JWT-VC issuer metadata at ${metadataUrl} has neither 'jwks' nor 'jwks_uri'`,
      );
    }

    this.cache.set(iss, {
      expiresAt: this.nowFn() + this.cacheMs,
      keys,
    });
    return keys;
  }

  private async fetchJson(url: string): Promise<unknown> {
    let response: Awaited<ReturnType<Fetcher>>;
    try {
      response = await this.fetcher(url, {
        headers: { Accept: "application/json" },
      });
    } catch (err) {
      throw new TrustResolutionError(
        "trust.fetch_failed",
        `failed to fetch ${url}: ${describe(err)}`,
      );
    }
    if (!response.ok) {
      throw new TrustResolutionError(
        "trust.http_error",
        `${url} returned HTTP ${response.status}`,
      );
    }
    try {
      return await response.json();
    } catch (err) {
      throw new TrustResolutionError(
        "trust.malformed_jwks",
        `body at ${url} is not valid JSON: ${describe(err)}`,
      );
    }
  }
}

function parseJwksObject(
  jwks: Record<string, unknown>,
  source: string,
): readonly JsonWebKey[] {
  const keys = jwks["keys"];
  if (!Array.isArray(keys)) {
    throw new TrustResolutionError(
      "trust.malformed_jwks",
      `JWKS at ${source} is missing a "keys" array (RFC 7517 §5)`,
    );
  }
  for (const k of keys) {
    if (k === null || typeof k !== "object" || Array.isArray(k)) {
      throw new TrustResolutionError(
        "trust.malformed_jwks",
        `JWKS at ${source} contains a non-object entry`,
      );
    }
  }
  return keys as readonly JsonWebKey[];
}

function stripTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

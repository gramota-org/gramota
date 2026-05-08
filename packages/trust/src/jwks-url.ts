import type { JsonWebKey } from "@gramota/jose";
import type { Fetcher } from "@gramota/core";
import {
  TrustResolutionError,
  type TrustContext,
  type TrustResolver,
} from "./types.js";

// Re-export so existing consumers of `@gramota/trust` keep working
// without a separate import from `@gramota/jose`. The canonical home of
// the type is `@gramota/jose`.
export type { Fetcher };

export interface JwksUrlResolverOptions {
  /** Build the JWKS URL from the issuer's `iss` claim. Default: appends
   * `/.well-known/jwks.json`. SD-JWT-VC §5.1 also defines a different scheme
   * via `/.well-known/jwt-issuer/...`; pass a custom builder for that. */
  jwksUrl?: (iss: string) => string;
  /** Cache TTL in milliseconds. Default: 5 minutes. */
  cacheMs?: number;
  /** Override the global `fetch` — useful for tests + custom transports. */
  fetcher?: Fetcher;
  /** Override `Date.now()` — used for cache expiry tests. */
  now?: () => number;
}

interface CacheEntry {
  expiresAt: number;
  keys: readonly JsonWebKey[];
}

/**
 * Resolve issuer keys by fetching a JWK Set (RFC 7517 §5) from the issuer's
 * well-known URL. Caches per-issuer for `cacheMs`.
 */
export class JwksUrlTrustResolver implements TrustResolver {
  private readonly buildUrl: (iss: string) => string;
  private readonly cacheMs: number;
  private readonly fetcher: Fetcher;
  private readonly nowFn: () => number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: JwksUrlResolverOptions = {}) {
    this.buildUrl =
      options.jwksUrl ?? ((iss) => `${stripTrailingSlash(iss)}/.well-known/jwks.json`);
    this.cacheMs = options.cacheMs ?? 5 * 60_000;
    this.fetcher =
      options.fetcher ??
      ((url, init) =>
        fetch(url, init).then((r) => ({
          ok: r.ok,
          status: r.status,
          headers: r.headers,
          json: () => r.json(),
          text: () => r.text(),
        })));
    this.nowFn = options.now ?? Date.now;
  }

  async resolveIssuerKeys(
    context: TrustContext,
  ): Promise<readonly JsonWebKey[]> {
    if (context.iss === undefined) {
      throw new TrustResolutionError(
        "trust.iss_required",
        "JwksUrlTrustResolver requires iss but JWT has no iss claim",
      );
    }

    const keys = await this.fetchKeysCached(context.iss);

    if (context.kid !== undefined) {
      const matching = keys.filter((k) => {
        const ckid = (k as Record<string, unknown>)["kid"];
        return typeof ckid === "string" && ckid === context.kid;
      });
      if (matching.length > 0) return matching;
    }

    return keys;
  }

  /** Manually invalidate the cache for a given issuer. Useful when keys
   * rotate and the consumer knows about it out of band. */
  invalidate(iss: string): void {
    this.cache.delete(iss);
  }

  private async fetchKeysCached(
    iss: string,
  ): Promise<readonly JsonWebKey[]> {
    const cached = this.cache.get(iss);
    if (cached !== undefined && cached.expiresAt > this.nowFn()) {
      return cached.keys;
    }

    const url = this.buildUrl(iss);
    let response: Awaited<ReturnType<Fetcher>>;
    try {
      response = await this.fetcher(url);
    } catch (err) {
      throw new TrustResolutionError(
        "trust.fetch_failed",
        `failed to fetch JWKS from ${url}: ${describe(err)}`,
      );
    }
    if (!response.ok) {
      throw new TrustResolutionError(
        "trust.http_error",
        `JWKS fetch returned HTTP ${response.status} from ${url}`,
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (err) {
      throw new TrustResolutionError(
        "trust.malformed_jwks",
        `JWKS at ${url} is not valid JSON: ${describe(err)}`,
      );
    }

    const keys = parseJwksResponse(body, url);

    this.cache.set(iss, {
      expiresAt: this.nowFn() + this.cacheMs,
      keys,
    });

    return keys;
  }
}

function parseJwksResponse(body: unknown, url: string): readonly JsonWebKey[] {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new TrustResolutionError(
      "trust.malformed_jwks",
      `JWKS at ${url} is not a JSON object`,
    );
  }
  const keys = (body as Record<string, unknown>)["keys"];
  if (!Array.isArray(keys)) {
    throw new TrustResolutionError(
      "trust.malformed_jwks",
      `JWKS at ${url} is missing a "keys" array (RFC 7517 §5)`,
    );
  }
  for (const k of keys) {
    if (k === null || typeof k !== "object" || Array.isArray(k)) {
      throw new TrustResolutionError(
        "trust.malformed_jwks",
        `JWKS at ${url} contains a non-object entry`,
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

/**
 * Minimal HTTP-client surface used by every Gramota package that makes
 * outbound calls (issuer metadata, JWKS resolution, status-list fetch).
 *
 * Why a custom type instead of just `typeof fetch`:
 *
 *   - Adapter friendly. Any function with this shape works — global
 *     `fetch`, `node-fetch`, `undici`, an in-memory mock for tests, a
 *     fetch-with-retry wrapper. Callers don't have to monkey-patch
 *     `globalThis.fetch` to inject a test transport.
 *   - Tiny surface. We need at most `{ ok, status, headers.get, json,
 *     text }`. Forcing every adapter to implement the full `Response`
 *     interface (streams, blob, formData, ...) is gratuitous.
 *   - Stable across runtimes. The Web `fetch` types ship in DOM lib;
 *     pinning to that pulls DOM types into Node-only consumers. Our
 *     {@link Fetcher} is a self-contained interface.
 *
 * If you have a `globalThis.fetch`, it satisfies this type structurally —
 * just pass it directly: `new JwksUrlTrustResolver({ fetcher: fetch })`.
 *
 * Lives in `@gramota/core` because every transport-touching package
 * (jose, oid4vci, oid4vp, status-list, holder, issuer, verifier) needs
 * the same shape. Putting it in `@gramota/jose` was a historical
 * accident — `@gramota/jose` is for crypto, not HTTP.
 */

/** Subset of the Web `Response` shape that Gramota libraries actually
 * consume.
 *
 * Both `json()` and `text()` are required — every real-world `fetch`
 * impl (Web platform, undici, node-fetch) supplies both, and forcing
 * adapters to implement both keeps library call sites clean (no
 * `if (!response.text) throw` guards on the hot path). Test mocks
 * use the {@link mockFetcherResponse} helper to satisfy the contract
 * without typing out every method. */
export interface FetcherResponse {
  readonly ok: boolean;
  readonly status: number;
  /** Optional, but if present must support case-insensitive header
   * lookup per HTTP §3.2. Required by RFC 9449 §8 (DPoP-Nonce) and
   * a few other "look at the header on a non-success response" paths. */
  readonly headers?: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
}

/** Adapter-friendly HTTP fetcher. Compatible with global `fetch`,
 * `node-fetch`, `undici`, and test mocks. */
export type Fetcher = (
  url: string,
  init?: RequestInit,
) => Promise<FetcherResponse>;

/**
 * Build a {@link FetcherResponse} for tests / in-process adapters with
 * minimal boilerplate. Both `json()` and `text()` are derived from the
 * supplied body so the strict contract is satisfied without forcing
 * mock authors to spell every method out.
 *
 *   mockFetcherResponse({ json: { keys: [...] } })
 *   mockFetcherResponse({ text: "compact-jws" })
 *   mockFetcherResponse({ ok: false, status: 404, text: "not found" })
 */
export function mockFetcherResponse(input: {
  ok?: boolean;
  status?: number;
  /** Provide either `json` or `text`. If both, `json` wins for `json()`,
   * `text` wins for `text()`. If neither, the body is the empty string. */
  json?: unknown;
  text?: string;
  headers?: Readonly<Record<string, string>>;
}): FetcherResponse {
  const ok = input.ok ?? true;
  const status = input.status ?? (ok ? 200 : 500);
  const text =
    input.text !== undefined
      ? input.text
      : input.json !== undefined
        ? JSON.stringify(input.json)
        : "";
  const json = input.json !== undefined ? input.json : safeParse(text);
  const headerEntries = input.headers ?? {};
  return {
    ok,
    status,
    headers: {
      get(name: string): string | null {
        const lower = name.toLowerCase();
        for (const [k, v] of Object.entries(headerEntries)) {
          if (k.toLowerCase() === lower) return v;
        }
        return null;
      },
    },
    json: async () => json,
    text: async () => text,
  };
}

function safeParse(text: string): unknown {
  if (text.length === 0) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

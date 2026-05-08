import type { Fetcher, FetcherResponse } from "@gramota/core";
import { Oid4vciError, type IssuerMetadata } from "./types.js";

// Re-export so existing consumers of `@gramota/oid4vci` keep working
// without a separate import from `@gramota/jose`. The canonical home of
// these types is `@gramota/jose`; re-exporting is purely a convenience.
export type { Fetcher, FetcherResponse };

/**
 * Fetch + validate Issuer Metadata from
 * `<credential_issuer>/.well-known/openid-credential-issuer`.
 */
export async function fetchIssuerMetadata(
  credentialIssuer: string,
  options: { fetcher?: Fetcher } = {},
): Promise<IssuerMetadata> {
  if (
    typeof credentialIssuer !== "string" ||
    credentialIssuer.length === 0
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "credentialIssuer must be a non-empty URL",
    );
  }
  const url =
    stripTrailingSlash(credentialIssuer) +
    "/.well-known/openid-credential-issuer";

  const fetcher = options.fetcher ?? defaultFetcher;
  let response: Awaited<ReturnType<Fetcher>>;
  try {
    response = await fetcher(url, {
      headers: { Accept: "application/json" },
    });
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.metadata_fetch_failed",
      `failed to fetch issuer metadata from ${url}: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!response.ok) {
    throw new Oid4vciError(
      "oid4vci.metadata_fetch_failed",
      `issuer metadata fetch returned HTTP ${response.status} from ${url}`,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.metadata_invalid",
      `issuer metadata at ${url} is not valid JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  return validateMetadata(body, url);
}

/** Validate already-loaded metadata JSON (e.g. for tests or pre-fetched data). */
export function validateMetadata(
  body: unknown,
  source = "<inline>",
): IssuerMetadata {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new Oid4vciError(
      "oid4vci.metadata_invalid",
      `issuer metadata at ${source} must be a JSON object`,
    );
  }
  const m = body as Record<string, unknown>;

  if (typeof m["credential_issuer"] !== "string") {
    throw new Oid4vciError(
      "oid4vci.metadata_invalid",
      `metadata.credential_issuer must be a string URL`,
    );
  }
  if (typeof m["credential_endpoint"] !== "string") {
    throw new Oid4vciError(
      "oid4vci.metadata_invalid",
      `metadata.credential_endpoint must be a string URL`,
    );
  }
  if (
    m["credential_configurations_supported"] === null ||
    typeof m["credential_configurations_supported"] !== "object" ||
    Array.isArray(m["credential_configurations_supported"])
  ) {
    throw new Oid4vciError(
      "oid4vci.metadata_invalid",
      `metadata.credential_configurations_supported must be a JSON object`,
    );
  }

  return m as unknown as IssuerMetadata;
}

/** Resolve which token endpoint to use for an issuer. Per OID4VCI §11.2,
 * the metadata may delegate to a separate authorization server. */
export function resolveTokenEndpoint(
  metadata: IssuerMetadata,
): string {
  if (typeof metadata.token_endpoint === "string") {
    return metadata.token_endpoint;
  }
  // Fallback: same origin as credential_issuer + /token
  return stripTrailingSlash(metadata.credential_issuer) + "/token";
}

/**
 * Authorization Server metadata. Combines the relevant fields from RFC 8414
 * (oauth-authorization-server) and OpenID Connect Discovery — both formats
 * publish the same `authorization_endpoint` / `token_endpoint` we need.
 */
export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  /** RFC 9126 — when present, the wallet must POST auth params here to
   * receive a `request_uri`, then redirect with just client_id+request_uri.
   * Some clients (notably the EU's `wallet-dev`) require PAR per-client
   * even when the AS-wide policy doesn't enforce it. */
  pushed_authorization_request_endpoint?: string;
  /** RFC 9126 — when true, the AS rejects auth requests not pushed via PAR. */
  require_pushed_authorization_requests?: boolean;
  /** RFC 9449 §5.1 — algorithms the AS accepts for DPoP proofs. When
   * present and the wallet's signing alg is in the list, our SDK
   * auto-attaches DPoP proofs to token + credential requests. */
  dpop_signing_alg_values_supported?: readonly string[];
  /** RFC 7636 — must include "S256" for our PKCE-only flow to work. */
  code_challenge_methods_supported?: readonly string[];
  /** Useful for diagnostics — should include "authorization_code". */
  grant_types_supported?: readonly string[];
  [key: string]: unknown;
}

/**
 * Resolve the authorization server for an issuer per OID4VCI §11.2.2.
 *
 *   1. If the issuer publishes `authorization_endpoint` + `token_endpoint`
 *      directly on its credential-issuer metadata, treat the issuer as its
 *      own AS — return a synthetic metadata object.
 *   2. Else if `authorization_servers` is set, fetch metadata from the
 *      first entry. Tries OIDC discovery first (`openid-configuration`)
 *      then RFC 8414 (`oauth-authorization-server`).
 *   3. Else fall back to `<credential_issuer>/{authorize,token}`.
 *
 * The wallet must use the AS's endpoints — not the issuer's — for the
 * auth-code flow, otherwise the EU Keycloak-backed dev issuer will 404.
 */
export async function fetchAuthorizationServerMetadata(
  issuerMetadata: IssuerMetadata,
  options: { fetcher?: Fetcher } = {},
): Promise<AuthorizationServerMetadata> {
  const fetcher = options.fetcher ?? defaultFetcher;

  // Case 1: issuer is its own AS (test/dev mocks, simple issuers).
  // Triggered when token_endpoint is on the issuer metadata directly —
  // authorization_endpoint may be absent (pre-auth-only issuers don't
  // need it) and we synthesize a sensible default.
  const issuerObj = issuerMetadata as Record<string, unknown>;
  const directAuthz = issuerObj["authorization_endpoint"];
  const directToken = issuerMetadata.token_endpoint;
  if (typeof directToken === "string") {
    const result: AuthorizationServerMetadata = {
      issuer: issuerMetadata.credential_issuer,
      authorization_endpoint:
        typeof directAuthz === "string"
          ? directAuthz
          : stripTrailingSlash(issuerMetadata.credential_issuer) + "/authorize",
      token_endpoint: directToken,
    };
    // Self-hosting issuers may also expose PAR — propagate it.
    if (
      typeof issuerObj["pushed_authorization_request_endpoint"] === "string"
    ) {
      result.pushed_authorization_request_endpoint = issuerObj[
        "pushed_authorization_request_endpoint"
      ] as string;
    }
    if (
      typeof issuerObj["require_pushed_authorization_requests"] === "boolean"
    ) {
      result.require_pushed_authorization_requests = issuerObj[
        "require_pushed_authorization_requests"
      ] as boolean;
    }
    if (Array.isArray(issuerObj["dpop_signing_alg_values_supported"])) {
      result.dpop_signing_alg_values_supported = issuerObj[
        "dpop_signing_alg_values_supported"
      ] as readonly string[];
    }
    return result;
  }

  // Case 2: delegated AS (production EU dev issuer, EUDIW reference impl).
  const ases = issuerMetadata.authorization_servers;
  if (Array.isArray(ases) && ases.length > 0) {
    const asUrl = ases[0]!;
    const candidates = [
      stripTrailingSlash(asUrl) + "/.well-known/openid-configuration",
      stripTrailingSlash(asUrl) + "/.well-known/oauth-authorization-server",
    ];
    let lastError: string | undefined;
    for (const url of candidates) {
      try {
        const res = await fetcher(url, {
          headers: { Accept: "application/json" },
        });
        if (!res.ok) {
          lastError = `HTTP ${res.status} from ${url}`;
          continue;
        }
        const body = (await res.json()) as Record<string, unknown>;
        const authzEndpoint = body["authorization_endpoint"];
        const tokenEndpoint = body["token_endpoint"];
        if (
          typeof authzEndpoint !== "string" ||
          typeof tokenEndpoint !== "string"
        ) {
          lastError = `AS metadata at ${url} missing endpoints`;
          continue;
        }
        return {
          issuer: typeof body["issuer"] === "string" ? body["issuer"] : asUrl,
          authorization_endpoint: authzEndpoint,
          token_endpoint: tokenEndpoint,
          ...(typeof body["pushed_authorization_request_endpoint"] === "string"
            ? {
                pushed_authorization_request_endpoint:
                  body["pushed_authorization_request_endpoint"] as string,
              }
            : {}),
          ...(typeof body["require_pushed_authorization_requests"] === "boolean"
            ? {
                require_pushed_authorization_requests:
                  body["require_pushed_authorization_requests"] as boolean,
              }
            : {}),
          ...(Array.isArray(body["dpop_signing_alg_values_supported"])
            ? {
                dpop_signing_alg_values_supported:
                  body["dpop_signing_alg_values_supported"] as readonly string[],
              }
            : {}),
          ...(Array.isArray(body["code_challenge_methods_supported"])
            ? {
                code_challenge_methods_supported:
                  body["code_challenge_methods_supported"] as readonly string[],
              }
            : {}),
          ...(Array.isArray(body["grant_types_supported"])
            ? {
                grant_types_supported:
                  body["grant_types_supported"] as readonly string[],
              }
            : {}),
        };
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
      }
    }
    throw new Oid4vciError(
      "oid4vci.metadata_fetch_failed",
      `failed to fetch authorization server metadata for ${asUrl}: ${lastError ?? "unknown"}`,
    );
  }

  // Case 3: no AS info — assume the issuer hosts both endpoints itself.
  const base = stripTrailingSlash(issuerMetadata.credential_issuer);
  return {
    issuer: issuerMetadata.credential_issuer,
    authorization_endpoint: base + "/authorize",
    token_endpoint: base + "/token",
  };
}

function stripTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

const defaultFetcher: Fetcher = (url, init) =>
  fetch(url, init).then((r) => ({
    ok: r.ok,
    status: r.status,
    headers: r.headers,
    json: () => r.json(),
    text: () => r.text(),
  }));

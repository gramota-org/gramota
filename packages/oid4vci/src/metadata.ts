import { Oid4vciError, type IssuerMetadata } from "./types.js";

export type Fetcher = (
  url: string,
  init?: RequestInit,
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

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
  const directAuthz = (issuerMetadata as Record<string, unknown>)[
    "authorization_endpoint"
  ];
  const directToken = issuerMetadata.token_endpoint;
  if (typeof directAuthz === "string" && typeof directToken === "string") {
    return {
      issuer: issuerMetadata.credential_issuer,
      authorization_endpoint: directAuthz,
      token_endpoint: directToken,
    };
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
    json: () => r.json(),
    text: () => r.text(),
  }));

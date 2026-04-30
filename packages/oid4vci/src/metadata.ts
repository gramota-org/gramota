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

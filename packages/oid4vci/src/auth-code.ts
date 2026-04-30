import { Oid4vciError, type TokenResponse } from "./types.js";
import { codeChallenge, generateCodeVerifier, generateState } from "./pkce.js";
import type { Fetcher } from "./metadata.js";

/** OAuth authorization-code grant identifier. */
export const AUTHORIZATION_CODE_GRANT = "authorization_code";

export interface BuildAuthorizationUrlOptions {
  /** Authorization server's `authorization_endpoint` — resolve via
   * `fetchAuthorizationServerMetadata` to handle delegated AS correctly. */
  authorizationEndpoint: string;
  /** OAuth `client_id`. Often the wallet's identifier or a registered ID. */
  clientId: string;
  /** Where the issuer should redirect after consent. */
  redirectUri: string;
  /** Credential configuration id from the offer / metadata. */
  credentialConfigurationId: string;
  /** Optional pre-existing PKCE verifier — useful for tests. Default: random. */
  codeVerifier?: string;
  /** Optional pre-existing CSRF state — useful for tests. Default: random. */
  state?: string;
  /** OAuth scope (alternative/companion to authorization_details). */
  scope?: string;
  /** OID4VCI `issuer_state` parameter from the offer (optional). */
  issuerState?: string;
}

export interface BuiltAuthorizationUrl {
  /** Send the user here. */
  authorizationUrl: string;
  /** Keep this — needed for `requestTokenAuthCode`. NEVER expose to issuer. */
  codeVerifier: string;
  /** Verify against `?state=` on the callback to prevent CSRF. */
  state: string;
}

/**
 * Build the authorization URL for OID4VCI auth-code flow + PKCE per
 * OID4VCI §4 + RFC 7636.
 *
 * The wallet redirects the user to this URL. The user authenticates at
 * the issuer, consents to credential issuance, and the issuer redirects
 * back to `redirectUri` with `?code=...&state=...`.
 */
export function buildAuthorizationUrl(
  options: BuildAuthorizationUrlOptions,
): BuiltAuthorizationUrl {
  validateRequiredFields(options);

  const codeVerifier = options.codeVerifier ?? generateCodeVerifier();
  const state = options.state ?? generateState();

  const url = new URL(options.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");

  // OID4VCI §5.1.2: authorization_details signals the credential being requested.
  url.searchParams.set(
    "authorization_details",
    JSON.stringify([
      {
        type: "openid_credential",
        credential_configuration_id: options.credentialConfigurationId,
      },
    ]),
  );

  if (options.scope !== undefined) url.searchParams.set("scope", options.scope);
  if (options.issuerState !== undefined) {
    url.searchParams.set("issuer_state", options.issuerState);
  }

  return {
    authorizationUrl: url.toString(),
    codeVerifier,
    state,
  };
}

export interface RequestTokenAuthCodeOptions {
  /** Token endpoint URL — typically `resolveTokenEndpoint(metadata)`. */
  tokenEndpoint: string;
  /** Authorization code from the issuer's redirect. */
  code: string;
  /** PKCE verifier saved from `buildAuthorizationUrl`. */
  codeVerifier: string;
  /** Same redirect_uri sent in the auth request — issuer enforces match. */
  redirectUri: string;
  /** Same client_id used in the auth request. */
  clientId: string;
  /** Optional fetcher override. */
  fetcher?: Fetcher;
}

/**
 * Exchange the authorization code for an access token per RFC 6749 §4.1.3
 * + RFC 7636 §4.5.
 */
export async function requestTokenAuthCode(
  options: RequestTokenAuthCodeOptions,
): Promise<TokenResponse> {
  if (typeof options.code !== "string" || options.code.length === 0) {
    throw new Oid4vciError("oid4vci.invalid_input", "code is required");
  }
  if (
    typeof options.codeVerifier !== "string" ||
    options.codeVerifier.length < 43
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "codeVerifier is required and must be ≥43 characters (RFC 7636)",
    );
  }
  if (typeof options.redirectUri !== "string" || options.redirectUri.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "redirectUri is required",
    );
  }
  if (typeof options.clientId !== "string" || options.clientId.length === 0) {
    throw new Oid4vciError("oid4vci.invalid_input", "clientId is required");
  }

  const body = new URLSearchParams();
  body.set("grant_type", AUTHORIZATION_CODE_GRANT);
  body.set("code", options.code);
  body.set("code_verifier", options.codeVerifier);
  body.set("redirect_uri", options.redirectUri);
  body.set("client_id", options.clientId);

  const fetcher = options.fetcher ?? defaultFetcher;
  let response: Awaited<ReturnType<Fetcher>>;
  try {
    response = await fetcher(options.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: body.toString(),
    });
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.token_request_failed",
      `auth-code token request failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!response.ok) {
    let detail = "";
    try {
      detail = await response.text();
    } catch {
      detail = "<no body>";
    }
    throw new Oid4vciError(
      "oid4vci.token_request_failed",
      `token endpoint returned HTTP ${response.status}: ${detail.slice(0, 500)}`,
    );
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.token_response_invalid",
      `token response is not valid JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (json === null || typeof json !== "object" || Array.isArray(json)) {
    throw new Oid4vciError(
      "oid4vci.token_response_invalid",
      "token response must be a JSON object",
    );
  }
  const t = json as Record<string, unknown>;
  if (typeof t["access_token"] !== "string") {
    throw new Oid4vciError(
      "oid4vci.token_response_invalid",
      "token response missing access_token",
    );
  }
  if (typeof t["token_type"] !== "string") {
    throw new Oid4vciError(
      "oid4vci.token_response_invalid",
      "token response missing token_type",
    );
  }
  return t as unknown as TokenResponse;
}

/** Parse a callback URL from the issuer's redirect: extract `code`, `state`,
 * and any error params. Throws on error responses. */
export interface ParsedAuthCallback {
  code: string;
  state: string;
  /** OID4VCI may pass through this when the offer included issuer_state. */
  issuerState?: string;
}

export function parseAuthCallback(callbackUrl: string): ParsedAuthCallback {
  let url: URL;
  try {
    url = new URL(callbackUrl);
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_url",
      `auth callback URL is not valid: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  const error = url.searchParams.get("error");
  if (error !== null) {
    const desc = url.searchParams.get("error_description") ?? "";
    throw new Oid4vciError(
      "oid4vci.token_request_failed",
      `issuer returned auth error: ${error}${desc ? ` (${desc})` : ""}`,
    );
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (code === null || code.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "callback URL is missing the `code` parameter",
    );
  }
  if (state === null || state.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "callback URL is missing the `state` parameter",
    );
  }

  const result: ParsedAuthCallback = { code, state };
  const issuerState = url.searchParams.get("issuer_state");
  if (issuerState !== null) result.issuerState = issuerState;
  return result;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function validateRequiredFields(opts: BuildAuthorizationUrlOptions): void {
  for (const f of [
    "authorizationEndpoint",
    "clientId",
    "redirectUri",
    "credentialConfigurationId",
  ] as const) {
    const v = opts[f];
    if (typeof v !== "string" || v.length === 0) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        `buildAuthorizationUrl: ${f} is required`,
      );
    }
  }
}

const defaultFetcher: Fetcher = (url, init) =>
  fetch(url, init).then((r) => ({
    ok: r.ok,
    status: r.status,
    json: () => r.json(),
    text: () => r.text(),
  }));

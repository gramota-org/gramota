import type { Signer } from "@gramota/jose";
import { Oid4vciError, type TokenResponse } from "./types.js";
import { codeChallenge, generateCodeVerifier, generateState } from "./pkce.js";
import { postWithDpopRetry } from "./dpop.js";
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
 * Build the canonical authorization parameters (OAuth + PKCE + OID4VCI
 * `authorization_details`). Shared between the direct auth-URL path and
 * the PAR (RFC 9126) path so they're guaranteed identical.
 */
export function buildAuthorizationParams(
  options: BuildAuthorizationUrlOptions,
): {
  params: Record<string, string>;
  codeVerifier: string;
  state: string;
} {
  validateRequiredFields(options);

  const codeVerifier = options.codeVerifier ?? generateCodeVerifier();
  const state = options.state ?? generateState();

  const params: Record<string, string> = {
    response_type: "code",
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    state,
    code_challenge: codeChallenge(codeVerifier),
    code_challenge_method: "S256",
    // OID4VCI §5.1.2: authorization_details signals the credential being requested.
    authorization_details: JSON.stringify([
      {
        type: "openid_credential",
        credential_configuration_id: options.credentialConfigurationId,
      },
    ]),
  };
  if (options.scope !== undefined) params["scope"] = options.scope;
  if (options.issuerState !== undefined) {
    params["issuer_state"] = options.issuerState;
  }

  return { params, codeVerifier, state };
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
  const { params, codeVerifier, state } = buildAuthorizationParams(options);

  const url = new URL(options.authorizationEndpoint);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  return {
    authorizationUrl: url.toString(),
    codeVerifier,
    state,
  };
}

/**
 * Build the post-PAR authorization URL (RFC 9126 §4): once the wallet has
 * pushed its parameters and received a `request_uri`, the redirect URL
 * carries only `client_id` + `request_uri`. No PKCE, no `redirect_uri`,
 * no `state` — the AS already has them, bound to the URN.
 */
export function buildPostParAuthorizationUrl(
  authorizationEndpoint: string,
  clientId: string,
  requestUri: string,
): string {
  if (
    typeof authorizationEndpoint !== "string" ||
    authorizationEndpoint.length === 0
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "buildPostParAuthorizationUrl: authorizationEndpoint is required",
    );
  }
  if (typeof clientId !== "string" || clientId.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "buildPostParAuthorizationUrl: clientId is required",
    );
  }
  if (typeof requestUri !== "string" || requestUri.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "buildPostParAuthorizationUrl: requestUri is required",
    );
  }
  const url = new URL(authorizationEndpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("request_uri", requestUri);
  return url.toString();
}

// ---------------------------------------------------------------------------
// Pushed Authorization Requests (RFC 9126)
// ---------------------------------------------------------------------------

export interface PushAuthorizationRequestOptions {
  /** AS's `pushed_authorization_request_endpoint` from its metadata. */
  parEndpoint: string;
  /** Every authorization parameter, exactly as it would have appeared on
   * the auth URL. PAR is a transport substitution, not a content change. */
  params: Readonly<Record<string, string>>;
  /** Optional fetcher override. */
  fetcher?: Fetcher;
}

export interface PushAuthorizationRequestResult {
  /** The opaque URN the AS bound our parameters to. The wallet redirects
   * the user with this in `?request_uri=` per RFC 9126 §4. */
  requestUri: string;
  /** AS's recommended freshness window for `request_uri`. RFC 9126 §2.2
   * RECOMMENDS but doesn't require it. */
  expiresIn?: number;
}

/**
 * Push authorization parameters to the AS's PAR endpoint per RFC 9126.
 *
 * The AS validates the parameters, mints a `request_uri` URN bound to
 * them, and returns it. The wallet then redirects the user to the
 * authorization endpoint with just `client_id` + `request_uri`.
 *
 * Why this exists: the EU dev issuer's `wallet-dev` client requires PAR
 * (per-client policy). Without it, the EU AS rejects with
 * "Pushed Authorization Request is only allowed".
 */
export async function pushAuthorizationRequest(
  options: PushAuthorizationRequestOptions,
): Promise<PushAuthorizationRequestResult> {
  if (typeof options.parEndpoint !== "string" || options.parEndpoint.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "pushAuthorizationRequest: parEndpoint is required",
    );
  }
  if (
    options.params === null ||
    typeof options.params !== "object" ||
    typeof options.params["client_id"] !== "string" ||
    options.params["client_id"].length === 0
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "pushAuthorizationRequest: params.client_id is required",
    );
  }

  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(options.params)) {
    body.set(k, v);
  }

  const fetcher = options.fetcher ?? defaultFetcher;
  let response: Awaited<ReturnType<Fetcher>>;
  try {
    response = await fetcher(options.parEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: body.toString(),
    });
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.par_request_failed",
      `PAR request failed: ${
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
      "oid4vci.par_request_failed",
      `PAR endpoint returned HTTP ${response.status}: ${detail.slice(0, 500)}`,
    );
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.par_response_invalid",
      `PAR response is not valid JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (json === null || typeof json !== "object" || Array.isArray(json)) {
    throw new Oid4vciError(
      "oid4vci.par_response_invalid",
      "PAR response must be a JSON object",
    );
  }
  const obj = json as Record<string, unknown>;
  if (typeof obj["request_uri"] !== "string" || obj["request_uri"].length === 0) {
    throw new Oid4vciError(
      "oid4vci.par_response_invalid",
      "PAR response missing request_uri",
    );
  }
  const result: PushAuthorizationRequestResult = {
    requestUri: obj["request_uri"],
  };
  if (typeof obj["expires_in"] === "number") {
    result.expiresIn = obj["expires_in"];
  }
  return result;
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
  /** When set, attach a DPoP proof (RFC 9449) to the token request. */
  dpopSigner?: Signer;
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
  const response = await postWithDpopRetry({
    fetcher,
    url: options.tokenEndpoint,
    body: body.toString(),
    contentType: "application/x-www-form-urlencoded",
    accept: "application/json",
    ...(options.dpopSigner !== undefined ? { dpopSigner: options.dpopSigner } : {}),
  });
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
    headers: r.headers,
    json: () => r.json(),
    text: () => r.text(),
  }));

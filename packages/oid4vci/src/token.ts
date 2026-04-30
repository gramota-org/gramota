import { Oid4vciError, type TokenResponse } from "./types.js";
import type { Fetcher } from "./metadata.js";

/** Pre-authorized code grant identifier per OID4VCI §4.1.1. */
export const PRE_AUTHORIZED_CODE_GRANT =
  "urn:ietf:params:oauth:grant-type:pre-authorized_code";

export interface RequestTokenOptions {
  tokenEndpoint: string;
  preAuthorizedCode: string;
  /** Transaction code (PIN) when the offer requires one. */
  txCode?: string;
  fetcher?: Fetcher;
}

/**
 * Exchange a pre-authorized code for an access token at the issuer's
 * authorization-server token endpoint.
 *
 * On success, returns the TokenResponse including any `c_nonce` the issuer
 * requires the wallet to embed in the next proof JWT.
 */
export async function requestToken(
  options: RequestTokenOptions,
): Promise<TokenResponse> {
  if (
    typeof options.tokenEndpoint !== "string" ||
    options.tokenEndpoint.length === 0
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "tokenEndpoint is required",
    );
  }
  if (
    typeof options.preAuthorizedCode !== "string" ||
    options.preAuthorizedCode.length === 0
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "preAuthorizedCode is required",
    );
  }

  const body = new URLSearchParams();
  body.set("grant_type", PRE_AUTHORIZED_CODE_GRANT);
  body.set("pre-authorized_code", options.preAuthorizedCode);
  if (options.txCode !== undefined) {
    body.set("tx_code", options.txCode);
  }

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
      `token request failed: ${
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

const defaultFetcher: Fetcher = (url, init) =>
  fetch(url, init).then((r) => ({
    ok: r.ok,
    status: r.status,
    json: () => r.json(),
    text: () => r.text(),
  }));

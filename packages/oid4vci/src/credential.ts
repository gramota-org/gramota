import {
  Oid4vciError,
  type CredentialRequest,
  type CredentialResponse,
} from "./types.js";
import type { Fetcher } from "./metadata.js";

export interface RequestCredentialOptions {
  credentialEndpoint: string;
  accessToken: string;
  /** Either `credential_configuration_id` (preferred) or `format`+`vct`. */
  request: CredentialRequest;
  fetcher?: Fetcher;
}

/**
 * Send a Credential Request to the issuer's credential endpoint per
 * OID4VCI §7. The request must include a proof JWT — see `buildProofJwt`.
 */
export async function requestCredential(
  options: RequestCredentialOptions,
): Promise<CredentialResponse> {
  if (
    typeof options.credentialEndpoint !== "string" ||
    options.credentialEndpoint.length === 0
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "credentialEndpoint is required",
    );
  }
  if (
    typeof options.accessToken !== "string" ||
    options.accessToken.length === 0
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "accessToken is required",
    );
  }
  if (options.request === null || typeof options.request !== "object") {
    throw new Oid4vciError("oid4vci.invalid_input", "request is required");
  }

  const fetcher = options.fetcher ?? defaultFetcher;
  let response: Awaited<ReturnType<Fetcher>>;
  try {
    response = await fetcher(options.credentialEndpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${options.accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(options.request),
    });
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.credential_request_failed",
      `credential request failed: ${
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
      "oid4vci.credential_request_failed",
      `credential endpoint returned HTTP ${response.status}: ${detail.slice(0, 500)}`,
    );
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.credential_response_invalid",
      `credential response is not valid JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (json === null || typeof json !== "object" || Array.isArray(json)) {
    throw new Oid4vciError(
      "oid4vci.credential_response_invalid",
      "credential response must be a JSON object",
    );
  }
  const r = json as Record<string, unknown>;

  // Either `credential` (single) or `credentials` (batch — newer spec) must be present.
  const hasSingle = typeof r["credential"] === "string";
  const hasBatch = Array.isArray(r["credentials"]);
  if (!hasSingle && !hasBatch) {
    throw new Oid4vciError(
      "oid4vci.credential_response_invalid",
      "credential response missing both `credential` and `credentials`",
    );
  }
  return r as unknown as CredentialResponse;
}

const defaultFetcher: Fetcher = (url, init) =>
  fetch(url, init).then((r) => ({
    ok: r.ok,
    status: r.status,
    json: () => r.json(),
    text: () => r.text(),
  }));

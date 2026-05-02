import type { Signer } from "@gramota/jose";
import {
  Oid4vciError,
  type CredentialRequest,
  type CredentialResponse,
} from "./types.js";
import type { Fetcher } from "./metadata.js";
import { postWithDpopRetry } from "./dpop.js";

export interface RequestCredentialOptions {
  credentialEndpoint: string;
  accessToken: string;
  /** Either `credential_configuration_id` (preferred) or `format`+`vct`. */
  request: CredentialRequest;
  fetcher?: Fetcher;
  /** When set, the request is sent as `Authorization: DPoP <token>` with
   * a DPoP proof JWT (RFC 9449) bound to the access token via the `ath`
   * claim. The proof is signed by this signer. */
  dpopSigner?: Signer;
}

/**
 * Send a Credential Request to the issuer's credential endpoint per
 * OID4VCI §7. The request must include a proof JWT — see `buildProofJwt`.
 *
 * When `dpopSigner` is supplied, the request is sender-constrained per
 * RFC 9449: the access token is presented under the `DPoP` scheme and a
 * `DPoP:` proof header binds the request to the holder's signing key.
 * The proof's `ath` claim is the SHA-256 of the access token, so a
 * stolen token can't be replayed by a different key.
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
  const response = await postWithDpopRetry({
    fetcher,
    url: options.credentialEndpoint,
    body: JSON.stringify(options.request),
    contentType: "application/json",
    accept: "application/json",
    bearerToken: options.accessToken,
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
    headers: r.headers,
    json: () => r.json(),
    text: () => r.text(),
  }));

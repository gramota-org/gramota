import { Oid4vciError, type CredentialOffer } from "./types.js";

/**
 * Parse a Credential Offer URL per OID4VCI §4.1.
 *
 * Two URL forms are accepted:
 *
 *   1. **By value** — `openid-credential-offer://?credential_offer=<url-encoded JSON>`
 *      The offer is inline; this function returns it parsed.
 *   2. **By reference** — `openid-credential-offer://?credential_offer_uri=<URL>`
 *      The wallet must fetch the offer JSON from the URL itself. This
 *      function does NOT make HTTP calls; it surfaces a structured error
 *      so callers can branch on the code and run their fetcher.
 *
 * Custom schemes are common (`openid-credential-offer://`, `haip://`,
 * `eudi-openid4vci://`) — we don't enforce a specific scheme, just parse
 * the query string. The offer's own `credential_issuer` URL is what
 * grounds the wallet, not the deep-link scheme.
 *
 * @example
 * ```ts
 * const offer = parseCredentialOffer(
 *   "openid-credential-offer://?credential_offer=" +
 *   encodeURIComponent(JSON.stringify({
 *     credential_issuer: "https://acme.gramota.dev",
 *     credential_configuration_ids: ["urn:eudi:pid:1_sd_jwt_vc"],
 *     grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "..." } },
 *   })),
 * );
 * ```
 *
 * @throws {@link Oid4vciError} with `oid4vci.invalid_input` (empty/non-string),
 *   `oid4vci.invalid_url` (malformed URL), or `oid4vci.invalid_offer`
 *   (mutually-exclusive params, missing params, by-reference form).
 */
export function parseCredentialOffer(url: string): CredentialOffer {
  if (typeof url !== "string" || url.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "credential offer URL must be a non-empty string",
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_url",
      `not a valid URL: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const inline = parsed.searchParams.get("credential_offer");
  const byRef = parsed.searchParams.get("credential_offer_uri");

  if (inline !== null && byRef !== null) {
    throw new Oid4vciError(
      "oid4vci.invalid_offer",
      "credential_offer and credential_offer_uri are mutually exclusive (OID4VCI §4.1)",
    );
  }
  if (inline === null && byRef === null) {
    throw new Oid4vciError(
      "oid4vci.invalid_offer",
      "URL has neither credential_offer nor credential_offer_uri parameter",
    );
  }

  if (inline !== null) return parseOfferJson(inline);

  // Offer-by-reference is a different code path (caller must fetch). Surface
  // a structured error so callers can differentiate.
  throw new Oid4vciError(
    "oid4vci.invalid_offer",
    `credential_offer_uri requires a separate fetch step; got reference: ${byRef}`,
  );
}

/**
 * Parse the JSON body of a credential offer.
 *
 * Use this when you've already fetched the offer body (e.g. you handled
 * the `credential_offer_uri` HTTP call in your own code). The validation
 * matches `parseCredentialOffer` for consistency.
 *
 * @throws {@link Oid4vciError} with `oid4vci.invalid_offer` if the JSON
 *   is malformed, not an object, or missing required fields.
 */
export function parseOfferJson(json: string): CredentialOffer {
  let offer: unknown;
  try {
    offer = JSON.parse(json);
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_offer",
      `credential_offer is not valid JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (offer === null || typeof offer !== "object" || Array.isArray(offer)) {
    throw new Oid4vciError(
      "oid4vci.invalid_offer",
      "credential_offer must be a JSON object",
    );
  }

  const obj = offer as Record<string, unknown>;
  if (typeof obj["credential_issuer"] !== "string") {
    throw new Oid4vciError(
      "oid4vci.invalid_offer",
      "credential_offer.credential_issuer must be a string URL",
    );
  }
  if (
    !Array.isArray(obj["credential_configuration_ids"]) ||
    obj["credential_configuration_ids"].length === 0 ||
    !obj["credential_configuration_ids"].every((s) => typeof s === "string")
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_offer",
      "credential_offer.credential_configuration_ids must be a non-empty array of strings",
    );
  }

  return obj as unknown as CredentialOffer;
}

/**
 * Extract the pre-authorized code from a parsed offer.
 *
 * @returns the code string when the offer carries the pre-authorized
 *   code grant (OID4VCI §4.1.1), or `null` when only authorization-code
 *   flow is available.
 */
export function extractPreAuthorizedCode(offer: CredentialOffer): string | null {
  const grant =
    offer.grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  return grant?.["pre-authorized_code"] ?? null;
}

/**
 * Extract the `tx_code` requirement from a parsed offer.
 *
 * `tx_code` (transaction code) is the in-band PIN/OTP some issuers
 * require alongside the pre-auth code — the wallet must collect it from
 * the user and submit it with the token request.
 *
 * @returns the requirement object (input mode, length, description) or
 *   `null` when no tx_code is required (the common case).
 */
export function extractTxCodeRequirement(
  offer: CredentialOffer,
): { input_mode?: "numeric" | "text"; length?: number; description?: string } | null {
  const grant =
    offer.grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  return grant?.tx_code ?? null;
}

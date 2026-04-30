import { Oid4vciError, type CredentialOffer } from "./types.js";

/**
 * Parse a Credential Offer URL per OID4VCI §4.1.
 *
 * Two URL forms are accepted:
 *
 *   1. `openid-credential-offer://?credential_offer=<url-encoded JSON>`
 *      (offer-by-value — the offer is inline)
 *   2. `openid-credential-offer://?credential_offer_uri=<URL>`
 *      (offer-by-reference — wallet fetches the offer JSON from the URL)
 *
 * Custom schemes are common (`openid-credential-offer://`, `haip://`,
 * `eudi-openid4vci://`) — we don't enforce a specific scheme, just parse
 * the query string.
 *
 * Returns the parsed CredentialOffer. For offer-by-reference, callers must
 * fetch the URL themselves and pass the JSON through `parseOfferJson`.
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

/** Parse the JSON body of a credential offer (whether inline or fetched). */
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

/** Helper: extract the pre-authorized code from a parsed offer, or null
 * if the offer doesn't grant pre-authorized access. */
export function preAuthorizedCodeFrom(offer: CredentialOffer): string | null {
  const grant =
    offer.grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  return grant?.["pre-authorized_code"] ?? null;
}

/** Helper: extract tx_code requirements from the offer, or null if not required. */
export function txCodeRequirementFrom(
  offer: CredentialOffer,
): { input_mode?: "numeric" | "text"; length?: number; description?: string } | null {
  const grant =
    offer.grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
  return grant?.tx_code ?? null;
}

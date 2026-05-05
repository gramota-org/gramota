/**
 * Server-side OID4VCI helpers — for credential issuers wrapping
 * `@gramota/issuer` with an HTTP layer.
 *
 * Companion to the client-side helpers in this package (`requestToken`,
 * `requestCredential`, etc). Issuers don't *have* to use these — the
 * spec is fully described — but every implementation needs to do
 * roughly the same parsing/validation, so we factor it out.
 *
 * Currently exported:
 *
 *   - {@link parseCredentialRequest} — accepts a credential-request body
 *     in either Draft 13 (legacy `format`+`vct`+`proof`) or Draft 14/15
 *     (`credential_configuration_id` + `proofs.jwt[]`) form and returns
 *     a canonical {@link ParsedCredentialRequest}.
 *
 * Why a normaliser instead of one types-strict-per-draft parser: real
 * wallets in the wild straddle drafts. The EU reference wallet's stack
 * (eudi-lib-jvm-openid4vci-kt 0.9.x) sends Draft 14/15 shape; older
 * wallets and our own synthetic-holder test send Draft 13. Issuers
 * that accept both work with the entire ecosystem.
 */

import {
  Oid4vciError,
  type CredentialRequest,
  type IssuerMetadata,
  type ParsedCredentialRequest,
} from "./types.js";

export interface ParseCredentialRequestOptions {
  /** Raw request body (already JSON-parsed). */
  body: unknown;
  /** Issuer metadata — used to look up the format from a
   * `credential_configuration_id` when the wallet uses Draft 14/15
   * shape. Optional: if omitted, we accept the request without
   * format validation as long as the configuration id is set. */
  issuerMetadata?: IssuerMetadata;
}

/**
 * Parse + normalise a credential-request body into the canonical shape.
 *
 * Throws {@link Oid4vciError} with a stable error code on:
 *   - body is not an object → `oid4vci.invalid_input`
 *   - both Draft 13 and Draft 14/15 shapes missing → `oid4vci.invalid_input`
 *   - configuration id present but not in metadata → `oid4vci.config_not_found`
 *   - proof missing entirely → `oid4vci.invalid_input`
 */
export function parseCredentialRequest(
  options: ParseCredentialRequestOptions,
): ParsedCredentialRequest {
  const body = options.body;
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "credential request body must be a JSON object",
    );
  }
  const req = body as CredentialRequest;

  // Resolve format + configuration id. Three paths:
  //   1. Draft 14/15: credential_configuration_id + metadata lookup.
  //   2. Draft 13: format (+ vct for sd-jwt) supplied directly.
  //   3. Hybrid: both supplied — accept and prefer the configuration id.
  let credentialConfigurationId = req.credential_configuration_id;
  let format = req.format;
  let vct = req.vct;

  if (credentialConfigurationId !== undefined && options.issuerMetadata) {
    const cfg =
      options.issuerMetadata.credential_configurations_supported?.[
        credentialConfigurationId
      ];
    if (!cfg) {
      throw new Oid4vciError(
        "oid4vci.config_not_found",
        `credential_configuration_id ${credentialConfigurationId} is not in issuer metadata`,
      );
    }
    format = format ?? cfg.format;
    vct = vct ?? (typeof cfg["vct"] === "string" ? (cfg["vct"] as string) : undefined);
  }

  if (
    credentialConfigurationId === undefined &&
    format === undefined
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "credential request must include either credential_configuration_id (Draft 14+) or format (Draft 13)",
    );
  }

  // Normalise proofs. Draft 13 single → array of length 1; Draft 14/15
  // batch → array as-is. Reject empty proofs entirely.
  const proofJwts: string[] = [];
  if (req.proof?.proof_type === "jwt" && typeof req.proof.jwt === "string") {
    proofJwts.push(req.proof.jwt);
  }
  if (Array.isArray(req.proofs?.jwt)) {
    for (const jwt of req.proofs!.jwt!) {
      if (typeof jwt === "string" && jwt.length > 0) proofJwts.push(jwt);
    }
  }
  if (proofJwts.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "credential request must include proof.jwt (Draft 13) or proofs.jwt[] (Draft 14/15)",
    );
  }

  // Build the result with conditional spreads — `exactOptionalPropertyTypes`
  // makes `parsed.foo = undefined` distinct from "no foo property", so we
  // assemble at construction time.
  const firstProof = proofJwts[0]!; // length >= 1 enforced above
  const parsed: ParsedCredentialRequest = {
    proofJwts,
    proofJwt: firstProof,
    ...(credentialConfigurationId !== undefined
      ? { credentialConfigurationId }
      : {}),
    ...(format !== undefined ? { format } : {}),
    ...(vct !== undefined ? { vct } : {}),
  };
  return parsed;
}

/**
 * Compose a per-tenant Credential Issuer URL by injecting `subdomain` as
 * the leftmost DNS label of `baseUrl`'s host.
 *
 *   buildSubdomainIssuerUrl("https://gramota.dev", "acme")
 *     → "https://acme.gramota.dev"
 *   buildSubdomainIssuerUrl("https://localtest.me:4444", "demo")
 *     → "https://demo.localtest.me:4444"
 *
 * The trailing slash that `URL.toString()` adds is stripped — issuer
 * identifiers are commonly compared byte-for-byte (RFC 8414 §2 ties the
 * `iss` claim to the metadata-fetch URL) and a stray `/` is a footgun.
 *
 * @throws if `baseUrl` is not a valid URL or `subdomain` is empty / not
 *   a valid DNS label (RFC 1035: lowercase alphanumeric + hyphen, no
 *   leading/trailing hyphen, ≤ 63 chars).
 */
export function buildSubdomainIssuerUrl(
  baseUrl: string,
  subdomain: string,
): string {
  if (typeof subdomain !== "string" || subdomain.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "buildSubdomainIssuerUrl: subdomain is required",
    );
  }
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(subdomain)) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `buildSubdomainIssuerUrl: ${JSON.stringify(subdomain)} is not a valid DNS label`,
    );
  }
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_url",
      `buildSubdomainIssuerUrl: baseUrl is not a valid URL: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  url.hostname = `${subdomain}.${url.hostname}`;
  return url.toString().replace(/\/$/, "");
}

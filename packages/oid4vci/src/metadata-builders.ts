/**
 * Spec-shaped metadata builders for the issuer's `.well-known/*`
 * endpoints.
 *
 * Two builders, mirroring the two well-known docs every OID4VCI issuer
 * publishes:
 *
 *   - {@link buildIssuerMetadata} — `/.well-known/openid-credential-issuer`
 *     per OID4VCI 1.0 Final §11.2.
 *   - {@link buildAuthorizationServerMetadata} —
 *     `/.well-known/oauth-authorization-server` per RFC 8414, with the
 *     OAuth + OID4VCI fields (PAR, DPoP, PKCE) the wallet checks.
 *
 * Why builders instead of letting routes hand-roll JSON: the JSON shape is
 * spec-mandated, evolving across drafts, and easy to get wrong. Drift
 * between issuers + tests is a real source of wallet interop bugs. The
 * builders take a small typed input shape and return the canonical
 * spec-shaped object; routes just send it.
 *
 * The output is `Record<string, unknown>` rather than the strict-typed
 * `IssuerMetadata` because the well-known docs include
 * vendor/profile-specific extension fields the SDK type intentionally
 * doesn't model. Callers that want a typed view can `as` to
 * `IssuerMetadata` after the call — the structural shape matches.
 */

import type { CodeChallengeMethod } from "./auth-code-store.js";

export interface BuildIssuerMetadataInput {
  /** Tenant credential-issuer URL — the canonical issuer identifier.
   *  Per OID4VCI §11.2 this MUST equal `metadata.credential_issuer` and
   *  is also the basis of the `.well-known/...` URL the wallet fetches. */
  credentialIssuer: string;
  /** Credential endpoint URL (typically `<issuer>/oid4vci/credential`). */
  credentialEndpoint: string;
  /** OID4VCI 1.0 Final §11.2 — dedicated Nonce Endpoint. Required when
   *  the issuer accepts key proofs (we always do). */
  nonceEndpoint: string;
  /** Optional jwt-vc-issuer document URL (IETF SD-JWT-VC §3.5). When set,
   *  surfaced so wallets know where the SD-JWT-VC public key sits. */
  jwtVcIssuerEndpoint?: string;
  /** Spec-shaped `credential_configurations_supported` map. The SDK
   *  doesn't validate the inner shape — callers spell out the config per
   *  OID4VCI §11.2.3. */
  credentialConfigurationsSupported: Readonly<Record<string, unknown>>;
  /** OID4VCI Draft 14/15 §11.2.3 batch_credential_issuance.
   *  When omitted, the field is dropped — wallets fall back to single-
   *  credential mode. */
  batchCredentialIssuance?: { batchSize: number };
  /** When the issuer delegates to an external AS, list it here. Empty /
   *  omitted means "issuer is its own AS"; the SDK populates a self-
   *  reference automatically when this is omitted. */
  authorizationServers?: readonly string[];
  /** Free-form display info per OID4VCI §11.2.1. */
  display?: readonly Readonly<Record<string, unknown>>[];
  /** Extra top-level fields, merged after the spec ones. Useful for
   *  vendor extensions / profile-specific metadata. */
  extra?: Readonly<Record<string, unknown>>;
}

/**
 * Build the OID4VCI Issuer Metadata document.
 *
 * The output is JSON-serialisable and conforms to OID4VCI 1.0 Final §11.2.
 */
export function buildIssuerMetadata(
  input: BuildIssuerMetadataInput,
): Record<string, unknown> {
  if (typeof input.credentialIssuer !== "string" || input.credentialIssuer.length === 0) {
    throw new Error("buildIssuerMetadata: credentialIssuer is required");
  }
  if (typeof input.credentialEndpoint !== "string" || input.credentialEndpoint.length === 0) {
    throw new Error("buildIssuerMetadata: credentialEndpoint is required");
  }
  if (typeof input.nonceEndpoint !== "string" || input.nonceEndpoint.length === 0) {
    throw new Error("buildIssuerMetadata: nonceEndpoint is required");
  }
  if (
    input.credentialConfigurationsSupported === null ||
    typeof input.credentialConfigurationsSupported !== "object" ||
    Array.isArray(input.credentialConfigurationsSupported)
  ) {
    throw new Error(
      "buildIssuerMetadata: credentialConfigurationsSupported must be an object",
    );
  }

  const out: Record<string, unknown> = {
    credential_issuer: input.credentialIssuer,
    authorization_servers:
      input.authorizationServers && input.authorizationServers.length > 0
        ? [...input.authorizationServers]
        : [input.credentialIssuer],
    credential_endpoint: input.credentialEndpoint,
    nonce_endpoint: input.nonceEndpoint,
    credential_configurations_supported: input.credentialConfigurationsSupported,
  };

  if (input.batchCredentialIssuance) {
    out["batch_credential_issuance"] = {
      batch_size: input.batchCredentialIssuance.batchSize,
    };
  }
  if (input.jwtVcIssuerEndpoint) {
    out["jwt_vc_issuer"] = input.jwtVcIssuerEndpoint;
  }
  if (input.display && input.display.length > 0) {
    out["display"] = input.display;
  }
  if (input.extra) {
    for (const [k, v] of Object.entries(input.extra)) {
      out[k] = v;
    }
  }
  return out;
}

export interface BuildAuthzServerMetadataInput {
  /** AS issuer identifier — for OID4VCI this matches the credential_issuer. */
  issuer: string;
  /** Authorization endpoint. Required when grant_types includes
   *  `authorization_code`; omit on pre-auth-only deployments. */
  authorizationEndpoint?: string;
  /** Token endpoint URL. */
  tokenEndpoint: string;
  /** Pushed Authorization Request endpoint per RFC 9126. Optional. */
  pushedAuthorizationRequestEndpoint?: string;
  /** When true, the AS rejects auth requests not pushed via PAR.
   *  HAIP §6.2 mandates this for HAIP-conformant deployments. */
  requirePushedAuthorizationRequests?: boolean;
  /** Spec-shaped grant_types_supported. Order is wire-irrelevant. */
  grantTypesSupported: readonly string[];
  /** Spec-shaped response_types_supported. Defaults to `["code"]`
   *  when the auth-code grant is on the menu, `[]` otherwise. */
  responseTypesSupported?: readonly string[];
  /** PKCE methods supported. HAIP mandates `["S256"]` when auth-code is
   *  enabled; defaults to `["S256"]` when omitted. */
  codeChallengeMethodsSupported?: readonly CodeChallengeMethod[];
  /** RFC 9449 §5.1 — algorithms the AS accepts on DPoP proofs. */
  dpopSigningAlgValuesSupported?: readonly string[];
  /** Token endpoint client-auth methods. Defaults to `["none"]` (OID4VCI
   *  pre-auth flow uses no client auth). HAIP-conformant deployments
   *  override with `["attest_jwt_client_auth"]` or similar. */
  tokenEndpointAuthMethodsSupported?: readonly string[];
  /** Extra top-level fields, merged after the spec ones. */
  extra?: Readonly<Record<string, unknown>>;
}

/**
 * Build the OAuth Authorization Server Metadata document.
 *
 * The output conforms to RFC 8414 with the OID4VCI + HAIP additions
 * (PAR, DPoP, PKCE) wallets check.
 */
export function buildAuthorizationServerMetadata(
  input: BuildAuthzServerMetadataInput,
): Record<string, unknown> {
  if (typeof input.issuer !== "string" || input.issuer.length === 0) {
    throw new Error("buildAuthorizationServerMetadata: issuer is required");
  }
  if (typeof input.tokenEndpoint !== "string" || input.tokenEndpoint.length === 0) {
    throw new Error("buildAuthorizationServerMetadata: tokenEndpoint is required");
  }
  if (!Array.isArray(input.grantTypesSupported) || input.grantTypesSupported.length === 0) {
    throw new Error(
      "buildAuthorizationServerMetadata: grantTypesSupported must be a non-empty array",
    );
  }

  const hasAuthCode = input.grantTypesSupported.includes("authorization_code");

  const out: Record<string, unknown> = {
    issuer: input.issuer,
    token_endpoint: input.tokenEndpoint,
    grant_types_supported: [...input.grantTypesSupported],
    token_endpoint_auth_methods_supported:
      input.tokenEndpointAuthMethodsSupported &&
      input.tokenEndpointAuthMethodsSupported.length > 0
        ? [...input.tokenEndpointAuthMethodsSupported]
        : ["none"],
    response_types_supported:
      input.responseTypesSupported !== undefined
        ? [...input.responseTypesSupported]
        : hasAuthCode
          ? ["code"]
          : [],
  };

  if (
    input.dpopSigningAlgValuesSupported &&
    input.dpopSigningAlgValuesSupported.length > 0
  ) {
    out["dpop_signing_alg_values_supported"] = [
      ...input.dpopSigningAlgValuesSupported,
    ];
  } else {
    // RFC 9449 §5.1 — even when the host doesn't override, advertise the
    // SDK's default DPoP alg so wallets sender-constrain automatically.
    out["dpop_signing_alg_values_supported"] = ["ES256"];
  }

  if (hasAuthCode) {
    if (input.authorizationEndpoint) {
      out["authorization_endpoint"] = input.authorizationEndpoint;
    }
    if (input.pushedAuthorizationRequestEndpoint) {
      out["pushed_authorization_request_endpoint"] =
        input.pushedAuthorizationRequestEndpoint;
    }
    if (input.requirePushedAuthorizationRequests !== undefined) {
      out["require_pushed_authorization_requests"] =
        input.requirePushedAuthorizationRequests;
    }
    out["code_challenge_methods_supported"] =
      input.codeChallengeMethodsSupported &&
      input.codeChallengeMethodsSupported.length > 0
        ? [...input.codeChallengeMethodsSupported]
        : ["S256"];
  }

  if (input.extra) {
    for (const [k, v] of Object.entries(input.extra)) {
      out[k] = v;
    }
  }
  return out;
}

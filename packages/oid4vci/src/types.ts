/**
 * OID4VCI Final 1.0 wire-format types.
 * Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 *
 * Scope of this package:
 *   - Credential Offer parsing (§4)
 *   - Issuer Metadata (§11)
 *   - Pre-authorized code flow (§4.1.1)
 *   - Token + Credential endpoints
 *
 * Deferred:
 *   - Authorization code flow
 *   - Deferred issuance, batch, DPoP, notifications
 *   - mso_mdoc credential format (we focus on vc+sd-jwt)
 */

/** A Credential Offer the issuer hands to the wallet, typically as a URL
 * the wallet scans or follows. Per OID4VCI §4.1. */
export interface CredentialOffer {
  /** Issuer base URL (used as the audience for proofs). */
  credential_issuer: string;
  /** Identifiers of the credential configurations the issuer is offering. */
  credential_configuration_ids: readonly string[];
  /** Which grant types are available. We support pre-authorized_code only. */
  grants?: {
    "authorization_code"?: {
      issuer_state?: string;
      authorization_server?: string;
    };
    "urn:ietf:params:oauth:grant-type:pre-authorized_code"?: {
      "pre-authorized_code": string;
      tx_code?: TxCodeRequirement;
      authorization_server?: string;
    };
  };
}

/** When the issuer requires a transaction code (e.g. PIN), this describes
 * how the wallet should collect it from the user. */
export interface TxCodeRequirement {
  input_mode?: "numeric" | "text";
  length?: number;
  description?: string;
}

/** Issuer metadata published at `<issuer>/.well-known/openid-credential-issuer`. */
export interface IssuerMetadata {
  credential_issuer: string;
  credential_endpoint: string;
  /** OAuth 2.0 token endpoint. May live on a separate authorization_server. */
  token_endpoint?: string;
  /** Authorization servers — when token_endpoint isn't on the issuer itself. */
  authorization_servers?: readonly string[];
  /** Map of configuration id → details. The wallet picks one to request. */
  credential_configurations_supported: Readonly<
    Record<string, CredentialConfiguration>
  >;
  /** Display info for the issuer (name, logo, locale). */
  display?: readonly Readonly<Record<string, unknown>>[];
  [key: string]: unknown;
}

export interface CredentialConfiguration {
  /** "vc+sd-jwt" or similar. Must match what we can handle. */
  format: string;
  /** OAuth scope for this credential, when using auth-code flow. */
  scope?: string;
  /** "jwk" / "did:..." — for SD-JWT-VC, "jwk" is standard. */
  cryptographic_binding_methods_supported?: readonly string[];
  /** Algorithms the issuer can sign credentials with. */
  credential_signing_alg_values_supported?: readonly string[];
  /** Proof types the issuer accepts (we use jwt). */
  proof_types_supported?: Readonly<
    Record<string, { proof_signing_alg_values_supported: readonly string[] }>
  >;
  /** vc+sd-jwt-specific: the credential type identifier. */
  vct?: string;
  display?: readonly Readonly<Record<string, unknown>>[];
  [key: string]: unknown;
}

/** Token endpoint response per RFC 6749 + OID4VCI extensions. */
export interface TokenResponse {
  access_token: string;
  token_type: "Bearer" | (string & {});
  expires_in?: number;
  /** Issuer-supplied nonce — bound into the proof JWT. */
  c_nonce?: string;
  c_nonce_expires_in?: number;
  scope?: string;
}

/** Credential request payload per OID4VCI §7.2.
 *
 * The wire format evolved across drafts. We accept any of these shapes
 * and `parseCredentialRequest` normalises them into a single canonical
 * form for issuers to consume:
 *
 *   - **Draft 13 (legacy)**: top-level `format`/`vct`, single `proof`.
 *   - **Draft 14/15**: `credential_configuration_id` (preferred) or
 *     `credential_identifier` (Draft 15+ deferred-credential flow), with
 *     either single `proof` or batch `proofs.jwt[]`.
 */
export interface CredentialRequest {
  /** Draft 14+: identifies a row in `credential_configurations_supported`. */
  credential_configuration_id?: string;
  /** Draft 15+: server-issued credential identifier (deferred / per-token). */
  credential_identifier?: string;
  /** Draft 13 (legacy): explicit format string. */
  format?: string;
  /** Draft 13 (legacy): vc+sd-jwt type. */
  vct?: string;
  /** Single proof of possession — Draft 13 form. Wallet signs a JWT
   * with the cnf-bound key. */
  proof?: {
    proof_type: "jwt";
    jwt: string;
  };
  /** Batch proofs of possession — Draft 14/15 form. The EU wallet
   * (eudi-lib-jvm-openid4vci-kt 0.9+) sends this. Each entry is a
   * separate proof JWT for one credential in the batch; for non-batch
   * issuance the array has length 1. */
  proofs?: {
    jwt?: readonly string[];
  };
}

/** Canonical form returned by `parseCredentialRequest` — one shape for
 * issuers to consume regardless of which OID4VCI draft the wallet uses. */
export interface ParsedCredentialRequest {
  /** Always present. Either echoes the wallet-provided value or is
   * derived from `format` (Draft 13 fallback). */
  credentialConfigurationId?: string;
  /** Always present (defaulted to "dc+sd-jwt" if the wallet only sent
   * a credential_configuration_id and the issuer's metadata says so). */
  format?: string;
  /** SD-JWT-VC type (only set when format is `dc+sd-jwt`). */
  vct?: string;
  /** Always present when proof was supplied — the first JWT from
   * `proofs.jwt[]` or the singular `proof.jwt`. */
  proofJwt?: string;
  /** All proof JWTs (length 1 for non-batch) so issuers that support
   * batch issuance can iterate. */
  proofJwts: readonly string[];
}

/** Credential response per OID4VCI §7.3. */
export interface CredentialResponse {
  /** The credential, format-specific. For vc+sd-jwt this is the SD-JWT-VC string. */
  credential?: string;
  credentials?: readonly { credential: string; [key: string]: unknown }[];
  /** Fresh nonce for the next request, if any. */
  c_nonce?: string;
  c_nonce_expires_in?: number;
  /** Optional notification id for the wallet to acknowledge issuance. */
  notification_id?: string;
}

/** Stable codes for `Oid4vciError`. */
export type Oid4vciErrorCode =
  | "oid4vci.invalid_url"
  | "oid4vci.invalid_offer"
  | "oid4vci.unsupported_grant"
  | "oid4vci.unsupported_format"
  | "oid4vci.unsupported_proof_type"
  | "oid4vci.metadata_fetch_failed"
  | "oid4vci.metadata_invalid"
  | "oid4vci.token_request_failed"
  | "oid4vci.token_response_invalid"
  | "oid4vci.credential_request_failed"
  | "oid4vci.credential_response_invalid"
  | "oid4vci.config_not_found"
  | "oid4vci.tx_code_required"
  | "oid4vci.invalid_input"
  | "oid4vci.par_request_failed"
  | "oid4vci.par_response_invalid"
  | "oid4vci.par_endpoint_missing";

export class Oid4vciError extends Error {
  override readonly name = "Oid4vciError";
  readonly code: Oid4vciErrorCode;
  constructor(
    code: Oid4vciErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.code = code;
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

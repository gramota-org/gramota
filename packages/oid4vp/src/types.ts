/**
 * OID4VP Final 1.0 wire-format types.
 * Spec: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 *
 * Scope of this package: §5 Authorization Request, §6 Authorization Response.
 * Presentation Definition (§5.4) is modelled but not yet matched/queried —
 * downstream packages will add DIF Presentation Exchange JSONPath support.
 */

/** OID4VP §5.4 — `client_id_scheme` enumerated values. */
export type ClientIdScheme =
  | "pre-registered"
  | "redirect_uri"
  | "https"
  | "did"
  | "x509_san_dns"
  | "x509_san_uri"
  | "verifier_attestation"
  | (string & {});

/** OID4VP §6.2 — `response_mode` for the authorization response. */
export type ResponseMode =
  | "direct_post"
  | "direct_post.jwt"
  | "fragment"
  | "query";

/** OID4VP §5 — Authorization Request, the bundle a verifier sends to a wallet.
 *
 * In production this is delivered as a query string, a `request_uri` (signed
 * JWT), or via a custom URI scheme like `openid4vp://`. We model the parsed
 * structure once and let serialisation handle the rest. */
export interface AuthorizationRequest {
  /** MUST be `vp_token` per OID4VP §5. */
  response_type: "vp_token";
  /** Identifier of the verifier — meaning depends on `client_id_scheme`. */
  client_id: string;
  /** How the wallet should resolve and trust `client_id`. Default
   * `pre-registered` — for HAIP/EUDIW the spec mandates explicit. */
  client_id_scheme?: ClientIdScheme;
  /** How the wallet returns the response. HAIP requires `direct_post`. */
  response_mode?: ResponseMode;
  /** Where to POST the response when `response_mode=direct_post`. */
  response_uri?: string;
  /** Where to redirect the response for legacy modes. */
  redirect_uri?: string;
  /** Cryptographic challenge — bound into KB-JWT to prevent replay. */
  nonce: string;
  /** Opaque verifier-controlled correlation token, echoed back unchanged. */
  state?: string;
  /** Inline DIF Presentation Definition JSON — what the verifier wants. */
  presentation_definition?: Readonly<Record<string, unknown>>;
  /** Or a URL the wallet can fetch the PD from. Mutually exclusive with above. */
  presentation_definition_uri?: string;
  /** Wallet metadata transparency parameter. */
  client_metadata?: Readonly<Record<string, unknown>>;
  /** Subset of the wallet's supported response formats / curves the verifier
   * is willing to accept. */
  scope?: string;
}

/** OID4VP §6 — Authorization Response from wallet to verifier. */
export interface AuthorizationResponse {
  /** The presentation(s) — a single SD-JWT-VC or an array for multi-credential. */
  vp_token: string | readonly string[];
  /** DIF Presentation Submission mapping descriptors → vp_token positions. */
  presentation_submission: Readonly<Record<string, unknown>>;
  /** Echoes the verifier's `state` from the request. */
  state?: string;
  /** OID4VP §6.4 — the wallet's identifier (e.g. issuer URL). */
  iss?: string;
}

export class Oid4vpError extends Error {
  override readonly name = "Oid4vpError";
}

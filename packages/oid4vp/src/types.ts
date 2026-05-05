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
  /** Inline DIF Presentation Definition JSON — what the verifier wants
   * (OID4VP 1.0 query shape). */
  presentation_definition?: Readonly<Record<string, unknown>>;
  /** Or a URL the wallet can fetch the PD from. Mutually exclusive with above. */
  presentation_definition_uri?: string;
  /** DCQL query (OID4VP 2.0 — Digital Credentials Query Language).
   * Mutually exclusive with `presentation_definition`. */
  dcql_query?: Readonly<Record<string, unknown>>;
  /** Wallet metadata transparency parameter. */
  client_metadata?: Readonly<Record<string, unknown>>;
  /** Subset of the wallet's supported response formats / curves the verifier
   * is willing to accept. */
  scope?: string;
}

/** OID4VP §6 — Authorization Response from wallet to verifier.
 *
 * The wire shape depends on which query language the request used:
 *
 *   - **Presentation Exchange (DIF PEX)**: `vp_token` is a string or
 *     string[], paired with `presentation_submission` mapping descriptors
 *     to vp_token positions.
 *   - **DCQL** (OID4VP Final 1.0): `vp_token` is a JSON OBJECT keyed by
 *     the DCQL credential `id` (e.g. `{"pid": "<sd-jwt-vc>"}`). No
 *     `presentation_submission` is sent — the keys ARE the mapping.
 *
 * Verifiers should accept whichever shape the wallet sends; production EU
 * wallets (eudi-lib-android-wallet-ui 0.26+) use DCQL exclusively.
 */
export interface AuthorizationResponse {
  /** The presentation(s).
   *
   *   - String / string[] form (PEX response).
   *   - Object form (DCQL response) — keys are the DCQL credential ids
   *     and values are the credential strings.
   */
  vp_token: string | readonly string[] | Readonly<Record<string, string>>;
  /** DIF Presentation Submission mapping descriptors → vp_token positions.
   * Required for PEX responses; absent for DCQL responses. */
  presentation_submission?: Readonly<Record<string, unknown>>;
  /** Echoes the verifier's `state` from the request. */
  state?: string;
  /** OID4VP §6.4 — the wallet's identifier (e.g. issuer URL). */
  iss?: string;
}

/**
 * X.509 signing material for an OID4VP verifier.
 *
 * Bundles together the four artefacts a verifier needs to produce signed
 * Authorization Requests (RFC 9101 JAR) and prove its identity to wallets
 * via the `x509_san_dns` client_id_prefix:
 *
 *   - `privateKeyPem` — PKCS#8 private key, used to sign the JAR
 *   - `certificatePem` — leaf cert, served when the wallet asks for proof
 *   - `x5c` — base64 DER cert(s) embedded in the JWS `x5c` header
 *   - `sanDns` — the SAN-DNS hostname the wallet matches against `client_id`
 *
 * Generation: see `generateSigningCert` for self-signed certs (local dev,
 * pinned-trust-store deployments). Production typically uses an externally
 * issued cert (ACME, corporate CA) — same shape, different origin.
 */
export interface SigningCert {
  /** PEM-encoded PKCS#8 private key. */
  readonly privateKeyPem: string;
  /** PEM-encoded leaf certificate. */
  readonly certificatePem: string;
  /** Base64-encoded DER certs in chain order, suitable for the JWS `x5c`
   * header per RFC 7515 §4.1.6. Length 1 for self-signed leaves. */
  readonly x5c: readonly string[];
  /** DNS name in the cert's Subject Alternative Name. The wallet
   * compares this against the OID4VP `client_id` value (with the
   * `x509_san_dns:` prefix stripped). */
  readonly sanDns: string;
}

/** Stable codes for `Oid4vpError`. */
export type Oid4vpErrorCode =
  | "oid4vp.invalid_url"
  | "oid4vp.required_field_missing"
  | "oid4vp.unsupported_response_type"
  | "oid4vp.mutually_exclusive_fields"
  | "oid4vp.response_uri_required"
  | "oid4vp.invalid_json"
  | "oid4vp.invalid_value_type"
  | "oid4vp.malformed_body"
  | "oid4vp.malformed_submission"
  | "oid4vp.cert_generation_failed"
  | "oid4vp.jar_signing_failed";

export class Oid4vpError extends Error {
  override readonly name = "Oid4vpError";
  readonly code: Oid4vpErrorCode;

  constructor(
    code: Oid4vpErrorCode,
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

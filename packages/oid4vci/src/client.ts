import {
  asSigner,
  type JsonWebKey,
  type Signer,
  type SupportedAlg,
} from "@gateway/jose";
import {
  CredentialFormatError,
  CredentialFormatRegistry,
  createDefaultCredentialFormatRegistry,
} from "@gateway/credential-format";
import {
  parseCredentialOffer,
  preAuthorizedCodeFrom,
  txCodeRequirementFrom,
} from "./offer.js";
import {
  fetchAuthorizationServerMetadata,
  fetchIssuerMetadata,
  resolveTokenEndpoint,
  type AuthorizationServerMetadata,
  type Fetcher,
} from "./metadata.js";
import { buildProofJwt } from "./proof.js";
import { requestToken } from "./token.js";
import { requestCredential } from "./credential.js";
import {
  buildAuthorizationParams,
  parseAuthCallback,
  requestTokenAuthCode,
} from "./auth-code.js";
import {
  ParAuthorizationTransport,
  type AuthorizationTransport,
} from "./transport.js";
import {
  Oid4vciError,
  type CredentialOffer,
  type IssuerMetadata,
} from "./types.js";

/**
 * Two equivalent ways to give the client signing capability:
 *
 *   - Raw form:  { holderPublicKey, holderPrivateKey, alg } — shorthand
 *     for tests/dev. Internally normalized to a {@link JwkSigner}.
 *   - Signer form: { signer: Signer } — for production wallets where
 *     the private key lives in WebAuthn / iOS Secure Enclave / HSM /
 *     KMS and is never materialized in JS heap.
 *
 * Pass exactly one shape. Mixing both is a programmer error.
 */
export type Oid4vciClientSignerInput =
  | {
      /** Holder's public JWK (embedded in the proof JWT header `jwk`). */
      holderPublicKey: JsonWebKey;
      /** Holder's private JWK (used to sign the proof). */
      holderPrivateKey: JsonWebKey;
      /** JWS algorithm matching the holder's key. */
      alg: SupportedAlg;
    }
  | {
      /** A Signer Strategy — production-grade alternative to raw keys. */
      signer: Signer;
    };

export type Oid4vciClientConfig = Oid4vciClientSignerInput & {
  /** Override fetch — for tests. */
  fetcher?: Fetcher;
  /**
   * How authorization parameters reach the AS during `authorize()`.
   * Default: {@link ParAuthorizationTransport} (RFC 9126 PAR).
   *
   * Pass a different strategy to opt into another transport — e.g.
   * `new DirectAuthorizationTransport()` for classic-OAuth issuers
   * that don't support PAR. Custom transports (e.g. JAR/RFC 9101)
   * implement {@link AuthorizationTransport} and plug in here.
   *
   * Strategy pattern: this is the abstraction `authorize()` depends
   * on, so adding a new transport doesn't require touching the
   * orchestrator (Open/Closed Principle).
   */
  authorizationTransport?: AuthorizationTransport;
  /**
   * Pluggable credential-format registry.
   *
   * `acceptOffer()` and `authorize()` consult this registry to gate
   * which formats they're willing to drive — instead of hardcoding
   * `if format === "vc+sd-jwt"`. Add an `MDocFormatHandler` to the
   * registry and the client suddenly handles mDoc credentials.
   *
   * Default: a registry with `SdJwtVcFormatHandler` pre-registered.
   */
  credentialFormats?: CredentialFormatRegistry;
  /**
   * DPoP (RFC 9449) policy. Default: `"auto"` — attach DPoP proofs
   * when the AS metadata advertises `dpop_signing_alg_values_supported`
   * including the wallet's signing alg.
   *
   * Set `false` to disable DPoP entirely (Bearer tokens only). Set
   * `true` to force DPoP regardless of metadata — useful when an AS
   * supports DPoP but doesn't advertise it (rare but spec-allowed).
   */
  dpop?: boolean | "auto";
};

export interface AcceptOfferOptions {
  /** Transaction code (PIN) — supplied when the offer's tx_code requires it. */
  txCode?: string;
  /** Override which credential_configuration_id to request. Default: first. */
  credentialConfigurationId?: string;
  /** Override iat in the proof JWT — for tests. */
  proofIat?: number;
  /** Override fetcher per-call. */
  fetcher?: Fetcher;
}

export interface AcceptOfferResult {
  /** The compact-serialised credential string the issuer returned. */
  credential: string;
  /** The credential_configuration_id that was requested. */
  credentialConfigurationId: string;
  /** Issuer metadata fetched during the flow. */
  metadata: IssuerMetadata;
  /** Original parsed offer. */
  offer: CredentialOffer;
}

/**
 * High-level OID4VCI client. The Holder uses this to receive credentials
 * from issuers; advanced users can construct it directly.
 *
 * Flow (pre-authorized code):
 *   1. parseCredentialOffer(url) → offer
 *   2. fetchIssuerMetadata(offer.credential_issuer) → metadata
 *   3. requestToken(metadata, offer, opts) → access_token + c_nonce
 *   4. buildProofJwt(holderKey, audience, c_nonce) → proof
 *   5. requestCredential(metadata, accessToken, proof) → credential string
 */
export class Oid4vciClient {
  /** The authorization-transport Strategy. Defaults to PAR; override via
   * `Oid4vciClientConfig.authorizationTransport` for non-PAR issuers
   * or to inject custom transports (e.g. JAR/RFC 9101). */
  private readonly authorizationTransport: AuthorizationTransport;
  /** Registry the client consults to decide which credential formats it
   * will drive. Defaults to a registry with SdJwtVcFormatHandler. */
  private readonly credentialFormats: CredentialFormatRegistry;
  /** The Signer the client uses for proof JWTs. Either supplied
   * directly via `config.signer` (production wallets with HSM/WebAuthn)
   * or built from raw `{ holderPublicKey, holderPrivateKey, alg }` keys
   * via {@link asSigner} (tests, dev). */
  private readonly signer: Signer;
  /** Captured fetcher override for ergonomics. */
  private readonly defaultFetcher: Fetcher | undefined;
  /** DPoP policy: `"auto"` (default), `true`, or `false`. */
  private readonly dpopPolicy: boolean | "auto";

  constructor(config: Oid4vciClientConfig) {
    this.signer = normalizeSignerInput(config);
    this.authorizationTransport =
      config.authorizationTransport ?? new ParAuthorizationTransport();
    this.credentialFormats =
      config.credentialFormats ?? createDefaultCredentialFormatRegistry();
    this.defaultFetcher = config.fetcher;
    this.dpopPolicy = config.dpop ?? "auto";
  }

  /**
   * Decide whether to attach DPoP proofs to a flow. Respects the policy
   * setting; in `"auto"` mode, checks the AS metadata for
   * `dpop_signing_alg_values_supported` and confirms the wallet's
   * signing alg is in the list.
   */
  private shouldUseDpop(asMetadata: AuthorizationServerMetadata): boolean {
    if (this.dpopPolicy === false) return false;
    if (this.dpopPolicy === true) return true;
    // auto
    const supported = asMetadata.dpop_signing_alg_values_supported;
    return (
      Array.isArray(supported) &&
      supported.includes(this.signer.alg as string)
    );
  }

  /** Pure: parse a credential offer URL without any network I/O. */
  parseOffer(url: string): CredentialOffer {
    return parseCredentialOffer(url);
  }

  /** Run the full pre-authorized code flow against the issuer in the offer. */
  async acceptOffer(
    url: string,
    options: AcceptOfferOptions = {},
  ): Promise<AcceptOfferResult> {
    const offer = parseCredentialOffer(url);

    const preAuth = preAuthorizedCodeFrom(offer);
    if (preAuth === null) {
      throw new Oid4vciError(
        "oid4vci.unsupported_grant",
        "offer does not include a pre-authorized_code grant; auth-code flow not yet supported",
      );
    }

    const txReq = txCodeRequirementFrom(offer);
    if (txReq !== null && options.txCode === undefined) {
      throw new Oid4vciError(
        "oid4vci.tx_code_required",
        `offer requires a tx_code (${
          txReq.input_mode ?? "text"
        }${txReq.length !== undefined ? `, length=${txReq.length}` : ""}); pass options.txCode`,
      );
    }

    const fetcher = options.fetcher ?? this.defaultFetcher;
    const metadata = await fetchIssuerMetadata(offer.credential_issuer, {
      ...(fetcher !== undefined ? { fetcher } : {}),
    });

    const configId =
      options.credentialConfigurationId ??
      offer.credential_configuration_ids[0];
    if (configId === undefined) {
      throw new Oid4vciError(
        "oid4vci.invalid_offer",
        "offer has no credential_configuration_ids",
      );
    }
    const config = metadata.credential_configurations_supported[configId];
    if (config === undefined) {
      throw new Oid4vciError(
        "oid4vci.config_not_found",
        `credential_configuration_id '${configId}' is not in issuer metadata`,
      );
    }

    // Consult the format registry — the client drives whatever the
    // registry has handlers for. Default registry knows SD-JWT-VC; add
    // an MDocFormatHandler to drive mDoc credentials too.
    const formatHandler = this.requireIssuanceHandler(config.format);

    // Resolve AS metadata so we can auto-detect DPoP support. (For
    // self-hosting issuers this is a synthetic object, no extra fetch.)
    const asMetadata = await fetchAuthorizationServerMetadata(metadata, {
      ...(fetcher !== undefined ? { fetcher } : {}),
    });
    const useDpop = this.shouldUseDpop(asMetadata);

    // Token request
    const tokenEndpoint = resolveTokenEndpoint(metadata);
    const tokenOpts: Parameters<typeof requestToken>[0] = {
      tokenEndpoint,
      preAuthorizedCode: preAuth,
    };
    if (options.txCode !== undefined) tokenOpts.txCode = options.txCode;
    if (fetcher !== undefined) tokenOpts.fetcher = fetcher;
    if (useDpop) tokenOpts.dpopSigner = this.signer;
    const tokenResponse = await requestToken(tokenOpts);

    // Build proof — delegates the actual signing to the configured Signer.
    const proofOpts: Parameters<typeof buildProofJwt>[0] = {
      audience: metadata.credential_issuer,
      signer: this.signer,
    };
    if (tokenResponse.c_nonce !== undefined) {
      proofOpts.nonce = tokenResponse.c_nonce;
    }
    if (options.proofIat !== undefined) proofOpts.iat = options.proofIat;
    const proofJwt = await buildProofJwt(proofOpts);

    // Credential request — DPoP-bound when auto-detection said so.
    const credOpts: Parameters<typeof requestCredential>[0] = {
      credentialEndpoint: metadata.credential_endpoint,
      accessToken: tokenResponse.access_token,
      request: {
        credential_configuration_id: configId,
        proof: { proof_type: "jwt", jwt: proofJwt },
      },
    };
    if (fetcher !== undefined) credOpts.fetcher = fetcher;
    if (useDpop) credOpts.dpopSigner = this.signer;
    const credResponse = await requestCredential(credOpts);

    const credential =
      credResponse.credential ?? credResponse.credentials?.[0]?.credential;
    if (typeof credential !== "string") {
      throw new Oid4vciError(
        "oid4vci.credential_response_invalid",
        "issuer did not return a credential string",
      );
    }

    // Format-specific issuance-token sanity check (e.g. SD-JWT-VC must
    // contain `~`). The handler decides what "well-formed for this
    // format" means.
    try {
      formatHandler.validateIssuanceToken(credential);
    } catch (err) {
      throw new Oid4vciError(
        "oid4vci.credential_response_invalid",
        `issuer returned a credential that doesn't validate as '${config.format}': ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }

    return {
      credential,
      credentialConfigurationId: configId,
      metadata,
      offer,
    };
  }

  // -------------------------------------------------------------------------
  // Auth-code flow (interactive, two-step)
  // -------------------------------------------------------------------------

  /**
   * Step 1 of OID4VCI auth-code flow.
   *
   * Parses the offer, fetches issuer metadata, generates PKCE + state,
   * builds the URL the wallet must navigate the user to. Returns the
   * URL plus secrets the wallet must keep until step 2.
   */
  async authorize(
    offerUrl: string,
    options: AuthorizeOfferOptions,
  ): Promise<AuthorizeOfferResult> {
    if (
      typeof options.clientId !== "string" ||
      options.clientId.length === 0
    ) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        "authorize: clientId is required",
      );
    }
    if (
      typeof options.redirectUri !== "string" ||
      options.redirectUri.length === 0
    ) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        "authorize: redirectUri is required",
      );
    }

    const offer = parseCredentialOffer(offerUrl);
    const fetcher = options.fetcher ?? this.defaultFetcher;
    const metadata = await fetchIssuerMetadata(offer.credential_issuer, {
      ...(fetcher !== undefined ? { fetcher } : {}),
    });

    const configId =
      options.credentialConfigurationId ??
      offer.credential_configuration_ids[0];
    if (configId === undefined) {
      throw new Oid4vciError(
        "oid4vci.invalid_offer",
        "offer has no credential_configuration_ids",
      );
    }
    const config = metadata.credential_configurations_supported[configId];
    if (config === undefined) {
      throw new Oid4vciError(
        "oid4vci.config_not_found",
        `credential_configuration_id '${configId}' is not in issuer metadata`,
      );
    }
    // Registry gate (replaces hardcoded if-format).
    this.requireIssuanceHandler(config.format);

    // OID4VCI §11.2.2: resolve the authorization server. The EU dev issuer
    // delegates to a Keycloak realm; the issuer's own URL has no /authorize.
    const asMetadata = await fetchAuthorizationServerMetadata(metadata, {
      ...(fetcher !== undefined ? { fetcher } : {}),
    });

    // OID4VCI may pass through an issuer_state from the offer.
    const issuerState =
      offer.grants?.["authorization_code"]?.issuer_state;

    const buildOpts: Parameters<typeof buildAuthorizationParams>[0] = {
      authorizationEndpoint: asMetadata.authorization_endpoint,
      clientId: options.clientId,
      redirectUri: options.redirectUri,
      credentialConfigurationId: configId,
    };
    if (options.codeVerifier !== undefined) {
      buildOpts.codeVerifier = options.codeVerifier;
    }
    if (options.state !== undefined) buildOpts.state = options.state;
    if (options.scope !== undefined) buildOpts.scope = options.scope;
    if (issuerState !== undefined) buildOpts.issuerState = issuerState;

    // Build canonical params + verifier + state, then hand off to the
    // configured transport Strategy. The default is PAR (RFC 9126) but
    // callers can inject DirectAuthorizationTransport, a custom JAR
    // implementation, etc. — Open/Closed via Strategy pattern.
    const { params, codeVerifier, state } = buildAuthorizationParams(buildOpts);
    const deliverInput: Parameters<AuthorizationTransport["deliver"]>[0] = {
      authorizationServerMetadata: asMetadata,
      params,
      clientId: options.clientId,
    };
    if (fetcher !== undefined) deliverInput.fetcher = fetcher;
    const authorizationUrl =
      await this.authorizationTransport.deliver(deliverInput);

    return {
      authorizationUrl,
      codeVerifier,
      state,
      offer,
      metadata,
      authorizationServerMetadata: asMetadata,
      credentialConfigurationId: configId,
    };
  }

  /**
   * Step 2 of OID4VCI auth-code flow.
   *
   * Given the issuer's redirect-callback URL plus the secrets returned by
   * `authorize`, exchange the code for a token, build a proof JWT, request
   * the credential, and return the credential string + metadata.
   */
  async claim(options: ClaimOfferOptions): Promise<AcceptOfferResult> {
    if (
      typeof options.callbackUrl !== "string" ||
      options.callbackUrl.length === 0
    ) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        "claim: callbackUrl is required",
      );
    }

    const callback = parseAuthCallback(options.callbackUrl);

    // CSRF: state from callback must match what we got at start.
    if (callback.state !== options.state) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        "auth callback state does not match — possible CSRF attack",
      );
    }

    const fetcher = options.fetcher ?? this.defaultFetcher;
    // Use the AS's token_endpoint — for delegated AS (EU/Keycloak), the
    // issuer doesn't host /token itself.
    const tokenEndpoint = options.authorizationServerMetadata.token_endpoint;
    const useDpop = this.shouldUseDpop(options.authorizationServerMetadata);

    const tokenOpts: Parameters<typeof requestTokenAuthCode>[0] = {
      tokenEndpoint,
      code: callback.code,
      codeVerifier: options.codeVerifier,
      redirectUri: options.redirectUri,
      clientId: options.clientId,
    };
    if (fetcher !== undefined) tokenOpts.fetcher = fetcher;
    if (useDpop) tokenOpts.dpopSigner = this.signer;
    const tokenResponse = await requestTokenAuthCode(tokenOpts);

    // Build proof JWT — same Signer for the auth-code path.
    const proofOpts: Parameters<typeof buildProofJwt>[0] = {
      audience: options.metadata.credential_issuer,
      signer: this.signer,
    };
    if (tokenResponse.c_nonce !== undefined) {
      proofOpts.nonce = tokenResponse.c_nonce;
    }
    if (options.proofIat !== undefined) proofOpts.iat = options.proofIat;
    const proofJwt = await buildProofJwt(proofOpts);

    // Credential request — DPoP-bound when auto-detection said so.
    const credOpts: Parameters<typeof requestCredential>[0] = {
      credentialEndpoint: options.metadata.credential_endpoint,
      accessToken: tokenResponse.access_token,
      request: {
        credential_configuration_id: options.credentialConfigurationId,
        proof: { proof_type: "jwt", jwt: proofJwt },
      },
    };
    if (fetcher !== undefined) credOpts.fetcher = fetcher;
    if (useDpop) credOpts.dpopSigner = this.signer;
    const credResponse = await requestCredential(credOpts);

    const credential =
      credResponse.credential ?? credResponse.credentials?.[0]?.credential;
    if (typeof credential !== "string") {
      throw new Oid4vciError(
        "oid4vci.credential_response_invalid",
        "issuer did not return a credential string",
      );
    }

    // Format-specific issuance-token validation via the registry.
    const claimedFormat =
      options.metadata.credential_configurations_supported[
        options.credentialConfigurationId
      ]?.format;
    if (typeof claimedFormat === "string") {
      const handler = this.requireIssuanceHandler(claimedFormat);
      try {
        handler.validateIssuanceToken(credential);
      } catch (err) {
        throw new Oid4vciError(
          "oid4vci.credential_response_invalid",
          `issuer returned a credential that doesn't validate as '${claimedFormat}': ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }

    return {
      credential,
      credentialConfigurationId: options.credentialConfigurationId,
      metadata: options.metadata,
      offer: options.offer,
    };
  }

  /**
   * Look up an issuance-capable handler in the registry. Translates
   * the registry's CredentialFormatError into our Oid4vciError code
   * surface so callers see one error vocabulary.
   */
  private requireIssuanceHandler(format: string) {
    try {
      return this.credentialFormats.requireIssuance(format);
    } catch (err) {
      if (err instanceof CredentialFormatError) {
        throw new Oid4vciError("oid4vci.unsupported_format", err.message);
      }
      throw err;
    }
  }
}

/**
 * Normalize the dual-input config (raw JWKs OR Signer) into a Signer.
 * Throws TypeError if neither shape is satisfied.
 */
function normalizeSignerInput(config: Oid4vciClientSignerInput): Signer {
  if (
    "signer" in config &&
    config.signer !== undefined &&
    typeof (config.signer as Signer).sign === "function"
  ) {
    return config.signer;
  }
  if (
    "holderPublicKey" in config &&
    "holderPrivateKey" in config &&
    "alg" in config &&
    config.holderPublicKey !== null &&
    typeof config.holderPublicKey === "object" &&
    config.holderPrivateKey !== null &&
    typeof config.holderPrivateKey === "object" &&
    typeof config.alg === "string" &&
    config.alg.length > 0
  ) {
    return asSigner({
      publicKey: config.holderPublicKey,
      privateKey: config.holderPrivateKey,
      alg: config.alg,
    });
  }
  throw new TypeError(
    "Oid4vciClient: pass either { holderPublicKey, holderPrivateKey, alg } (raw shorthand) or { signer } (production)",
  );
}

// ---------------------------------------------------------------------------
// Auth-code option types
// ---------------------------------------------------------------------------

export interface AuthorizeOfferOptions {
  /** OAuth client_id — registered with the issuer or the wallet's identifier. */
  clientId: string;
  /** Where the issuer should redirect the user after consent. */
  redirectUri: string;
  /** Override which credential to request. Default: first id from the offer. */
  credentialConfigurationId?: string;
  /** Optional pre-existing PKCE verifier — for tests. Default: random. */
  codeVerifier?: string;
  /** Optional pre-existing CSRF state — for tests. Default: random. */
  state?: string;
  /** Optional OAuth scope. */
  scope?: string;
  /** Optional fetcher override per-call. */
  fetcher?: Fetcher;
}

export interface AuthorizeOfferResult {
  /** Open this URL in the user's browser. */
  authorizationUrl: string;
  /** Persist this with the user's session — needed for `claim`. */
  codeVerifier: string;
  /** Persist this and verify against `?state=` on the callback. */
  state: string;
  /** Carry these to step 2 unchanged. */
  offer: CredentialOffer;
  metadata: IssuerMetadata;
  /** Authorization server metadata resolved per OID4VCI §11.2.2. The token
   * endpoint here is what `claim` exchanges the code against. */
  authorizationServerMetadata: AuthorizationServerMetadata;
  credentialConfigurationId: string;
}

export interface ClaimOfferOptions {
  /** The full callback URL the issuer redirected to (with ?code=&state=). */
  callbackUrl: string;
  /** From step 1's AuthorizeOfferResult. */
  codeVerifier: string;
  state: string;
  metadata: IssuerMetadata;
  authorizationServerMetadata: AuthorizationServerMetadata;
  offer: CredentialOffer;
  credentialConfigurationId: string;
  /** Same redirect_uri / client_id used at step 1 — issuer enforces match. */
  redirectUri: string;
  clientId: string;
  /** Optional fetcher override per-call. */
  fetcher?: Fetcher;
  /** Override iat in the proof JWT — for tests. */
  proofIat?: number;
}

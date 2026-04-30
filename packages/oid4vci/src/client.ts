import type { JsonWebKey, SupportedAlg } from "@gateway/jose";
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
  buildAuthorizationUrl,
  parseAuthCallback,
  requestTokenAuthCode,
} from "./auth-code.js";
import {
  Oid4vciError,
  type CredentialOffer,
  type IssuerMetadata,
} from "./types.js";

export interface Oid4vciClientConfig {
  /** Holder's public JWK (embedded in the proof JWT header `jwk`). */
  holderPublicKey: JsonWebKey;
  /** Holder's private JWK (used to sign the proof). */
  holderPrivateKey: JsonWebKey;
  /** JWS algorithm matching the holder's key. */
  alg: SupportedAlg;
  /** Override fetch — for tests. */
  fetcher?: Fetcher;
}

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
  constructor(private readonly config: Oid4vciClientConfig) {
    if (
      config.holderPublicKey === null ||
      typeof config.holderPublicKey !== "object"
    ) {
      throw new TypeError(
        "Oid4vciClient: holderPublicKey is required",
      );
    }
    if (
      config.holderPrivateKey === null ||
      typeof config.holderPrivateKey !== "object"
    ) {
      throw new TypeError(
        "Oid4vciClient: holderPrivateKey is required",
      );
    }
    if (typeof config.alg !== "string" || config.alg.length === 0) {
      throw new TypeError("Oid4vciClient: alg is required");
    }
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

    const fetcher = options.fetcher ?? this.config.fetcher;
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

    // We only handle vc+sd-jwt in v1.
    if (config.format !== "vc+sd-jwt" && config.format !== "dc+sd-jwt") {
      throw new Oid4vciError(
        "oid4vci.unsupported_format",
        `credential format '${config.format}' is not supported (v1 supports vc+sd-jwt only)`,
      );
    }

    // Token request
    const tokenEndpoint = resolveTokenEndpoint(metadata);
    const tokenOpts: Parameters<typeof requestToken>[0] = {
      tokenEndpoint,
      preAuthorizedCode: preAuth,
    };
    if (options.txCode !== undefined) tokenOpts.txCode = options.txCode;
    if (fetcher !== undefined) tokenOpts.fetcher = fetcher;
    const tokenResponse = await requestToken(tokenOpts);

    // Build proof
    const proofOpts: Parameters<typeof buildProofJwt>[0] = {
      audience: metadata.credential_issuer,
      publicKey: this.config.holderPublicKey,
      privateKey: this.config.holderPrivateKey,
      alg: this.config.alg,
    };
    if (tokenResponse.c_nonce !== undefined) {
      proofOpts.nonce = tokenResponse.c_nonce;
    }
    if (options.proofIat !== undefined) proofOpts.iat = options.proofIat;
    const proofJwt = await buildProofJwt(proofOpts);

    // Credential request
    const credOpts: Parameters<typeof requestCredential>[0] = {
      credentialEndpoint: metadata.credential_endpoint,
      accessToken: tokenResponse.access_token,
      request: {
        credential_configuration_id: configId,
        proof: { proof_type: "jwt", jwt: proofJwt },
      },
    };
    if (fetcher !== undefined) credOpts.fetcher = fetcher;
    const credResponse = await requestCredential(credOpts);

    const credential =
      credResponse.credential ?? credResponse.credentials?.[0]?.credential;
    if (typeof credential !== "string") {
      throw new Oid4vciError(
        "oid4vci.credential_response_invalid",
        "issuer did not return a credential string",
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
    const fetcher = options.fetcher ?? this.config.fetcher;
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
    if (config.format !== "vc+sd-jwt" && config.format !== "dc+sd-jwt") {
      throw new Oid4vciError(
        "oid4vci.unsupported_format",
        `credential format '${config.format}' is not supported (v1: vc+sd-jwt only)`,
      );
    }

    // OID4VCI §11.2.2: resolve the authorization server. The EU dev issuer
    // delegates to a Keycloak realm; the issuer's own URL has no /authorize.
    const asMetadata = await fetchAuthorizationServerMetadata(metadata, {
      ...(fetcher !== undefined ? { fetcher } : {}),
    });

    // OID4VCI may pass through an issuer_state from the offer.
    const issuerState =
      offer.grants?.["authorization_code"]?.issuer_state;

    const buildOpts: Parameters<typeof buildAuthorizationUrl>[0] = {
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

    const built = buildAuthorizationUrl(buildOpts);

    return {
      authorizationUrl: built.authorizationUrl,
      codeVerifier: built.codeVerifier,
      state: built.state,
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

    const fetcher = options.fetcher ?? this.config.fetcher;
    // Use the AS's token_endpoint — for delegated AS (EU/Keycloak), the
    // issuer doesn't host /token itself.
    const tokenEndpoint = options.authorizationServerMetadata.token_endpoint;

    const tokenOpts: Parameters<typeof requestTokenAuthCode>[0] = {
      tokenEndpoint,
      code: callback.code,
      codeVerifier: options.codeVerifier,
      redirectUri: options.redirectUri,
      clientId: options.clientId,
    };
    if (fetcher !== undefined) tokenOpts.fetcher = fetcher;
    const tokenResponse = await requestTokenAuthCode(tokenOpts);

    // Build proof JWT
    const proofOpts: Parameters<typeof buildProofJwt>[0] = {
      audience: options.metadata.credential_issuer,
      publicKey: this.config.holderPublicKey,
      privateKey: this.config.holderPrivateKey,
      alg: this.config.alg,
    };
    if (tokenResponse.c_nonce !== undefined) {
      proofOpts.nonce = tokenResponse.c_nonce;
    }
    if (options.proofIat !== undefined) proofOpts.iat = options.proofIat;
    const proofJwt = await buildProofJwt(proofOpts);

    // Credential request
    const credOpts: Parameters<typeof requestCredential>[0] = {
      credentialEndpoint: options.metadata.credential_endpoint,
      accessToken: tokenResponse.access_token,
      request: {
        credential_configuration_id: options.credentialConfigurationId,
        proof: { proof_type: "jwt", jwt: proofJwt },
      },
    };
    if (fetcher !== undefined) credOpts.fetcher = fetcher;
    const credResponse = await requestCredential(credOpts);

    const credential =
      credResponse.credential ?? credResponse.credentials?.[0]?.credential;
    if (typeof credential !== "string") {
      throw new Oid4vciError(
        "oid4vci.credential_response_invalid",
        "issuer did not return a credential string",
      );
    }

    return {
      credential,
      credentialConfigurationId: options.credentialConfigurationId,
      metadata: options.metadata,
      offer: options.offer,
    };
  }
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

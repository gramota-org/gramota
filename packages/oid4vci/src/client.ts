import type { JsonWebKey, SupportedAlg } from "@gateway/jose";
import {
  parseCredentialOffer,
  preAuthorizedCodeFrom,
  txCodeRequirementFrom,
} from "./offer.js";
import {
  fetchIssuerMetadata,
  resolveTokenEndpoint,
  type Fetcher,
} from "./metadata.js";
import { buildProofJwt } from "./proof.js";
import { requestToken } from "./token.js";
import { requestCredential } from "./credential.js";
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
}

export {
  Oid4vciError,
  type CredentialConfiguration,
  type CredentialOffer,
  type CredentialRequest,
  type CredentialResponse,
  type IssuerMetadata,
  type Oid4vciErrorCode,
  type TokenResponse,
  type TxCodeRequirement,
} from "./types.js";

export {
  parseCredentialOffer,
  parseOfferJson,
  preAuthorizedCodeFrom,
  txCodeRequirementFrom,
} from "./offer.js";

export {
  fetchIssuerMetadata,
  validateMetadata,
  resolveTokenEndpoint,
  type Fetcher,
} from "./metadata.js";

export { buildProofJwt, type BuildProofOptions } from "./proof.js";

export {
  requestToken,
  PRE_AUTHORIZED_CODE_GRANT,
  type RequestTokenOptions,
} from "./token.js";

export {
  requestCredential,
  type RequestCredentialOptions,
} from "./credential.js";

export {
  Oid4vciClient,
  type AcceptOfferOptions,
  type AcceptOfferResult,
  type Oid4vciClientConfig,
} from "./client.js";

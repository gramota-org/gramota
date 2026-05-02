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
  fetchAuthorizationServerMetadata,
  fetchIssuerMetadata,
  resolveTokenEndpoint,
  validateMetadata,
  type AuthorizationServerMetadata,
  type Fetcher,
  type FetcherResponse,
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
  type AuthorizeOfferOptions,
  type AuthorizeOfferResult,
  type ClaimOfferOptions,
  type Oid4vciClientConfig,
} from "./client.js";

export {
  AUTHORIZATION_CODE_GRANT,
  buildAuthorizationParams,
  buildAuthorizationUrl,
  buildPostParAuthorizationUrl,
  parseAuthCallback,
  pushAuthorizationRequest,
  requestTokenAuthCode,
  type BuildAuthorizationUrlOptions,
  type BuiltAuthorizationUrl,
  type ParsedAuthCallback,
  type PushAuthorizationRequestOptions,
  type PushAuthorizationRequestResult,
  type RequestTokenAuthCodeOptions,
} from "./auth-code.js";

export {
  DirectAuthorizationTransport,
  ParAuthorizationTransport,
  type AuthorizationTransport,
  type DeliverInput,
} from "./transport.js";

export {
  buildDpopJwt,
  computeAccessTokenHash,
  type BuildDpopJwtOptions,
} from "./dpop.js";

export {
  codeChallenge,
  generateCodeVerifier,
  generateState,
} from "./pkce.js";

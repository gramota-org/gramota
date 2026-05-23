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
  buildCredentialOfferUrl,
  extractPreAuthorizedCode,
  extractTxCodeRequirement,
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

export {
  buildProofJwt,
  verifyProofJwt,
  PROOF_JWT_TYP,
  PROOF_JWT_DEFAULT_MAX_AGE_SECONDS,
  PROOF_JWT_DEFAULT_MAX_FUTURE_SKEW_SECONDS,
  type BuildProofOptions,
  type VerifyProofJwtOptions,
  type VerifyProofJwtResult,
} from "./proof.js";

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
  verifyDpopJwt,
  type BuildDpopJwtOptions,
  type VerifyDpopJwtOptions,
  type VerifyDpopJwtResult,
} from "./dpop.js";

export {
  buildSubdomainIssuerUrl,
  parseCredentialRequest,
  type ParseCredentialRequestOptions,
} from "./server.js";

export {
  codeChallenge,
  generateCodeVerifier,
  generateState,
} from "./pkce.js";

export {
  CNonceStore,
  C_NONCE_TTL_SECONDS,
  type CNonceStoreLike,
  type CNonceStoreOptions,
  type CNonceMintOptions,
  type CNonceMintResult,
} from "./c-nonce-store.js";

export {
  ParStore,
  PAR_DEFAULT_TTL_SECONDS,
  type ParStoreLike,
  type ParStoreOptions,
  type ParRequestPayload,
  type ParPutOptions,
  type ParPutResult,
  type PushedClientAttestation,
} from "./par-store.js";

export {
  AuthCodeStore,
  AUTH_CODE_TTL_SECONDS,
  verifyPkceChallenge,
  type AuthCodeStoreLike,
  type AuthCodeStoreOptions,
  type AuthCodeRequest,
  type AuthCodePutOptions,
  type AuthCodePutResult,
  type CodeChallengeMethod,
} from "./auth-code-store.js";

export {
  WalletAttestationError,
  loadWalletAttestationConfigFromEnv,
  verifyWalletAttestation,
  type WalletAttestationConfig,
  type WalletAttestationErrorCode,
  type WalletAttestationHeaders,
  type WalletAttestationResult,
} from "./wallet-attestation.js";

export {
  InMemoryDpopJtiStore,
  type DpopJtiStoreLike,
  type InMemoryDpopJtiStoreOptions,
} from "./dpop-jti-store.js";

export {
  buildAuthorizationServerMetadata,
  buildIssuerMetadata,
  type BuildAuthzServerMetadataInput,
  type BuildIssuerMetadataInput,
} from "./metadata-builders.js";

export {
  AUTHORIZATION_CODE_BYTES,
  PRE_AUTHORIZED_CODE_BYTES,
  generateAuthorizationCode,
  generatePreAuthorizedCode,
  type GenerateCodeOptions,
} from "./codes.js";

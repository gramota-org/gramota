export { verifyJws } from "./verify.js";
export { verifyJwsWithX5c } from "./verify-x5c.js";
export { computeJwkThumbprint } from "./thumbprint.js";
// Re-export the transport types from @gramota/core. They lived here
// historically; moved to core in 0.3.0 so non-crypto packages don't
// need a jose dep just to type their fetch adapter. The re-export
// stays so existing `import { Fetcher } from "@gramota/jose"` keeps
// working — schedule its removal for 1.0.
export {
  mockFetcherResponse,
  type Fetcher,
  type FetcherResponse,
} from "@gramota/core";
export type {
  VerifyJwsX5cOptions,
  VerifiedJwsWithX5c,
} from "./verify-x5c.js";
export { signJws } from "./sign.js";
export { makeSigner } from "./make-signer.js";
export type { SignJwsOptions } from "./sign.js";
export {
  JwkSigner,
  asSigner,
  type JwkSignerOptions,
  type Signer,
} from "./signer.js";
export {
  extractPublicKeyFromX5c,
  parseX5cEntry,
  validateX5cChain,
  x5cToPem,
} from "./x5c.js";
export type {
  ChainValidationOptions,
  ChainValidationResult,
} from "./x5c.js";
export type {
  JoseErrorCode,
  JsonWebKey,
  SupportedAlg,
  VerifyJwsOptions,
  VerifiedJws,
} from "./types.js";
export { JoseError } from "./types.js";

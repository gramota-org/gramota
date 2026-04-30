export { parseSdJwt, SdJwtParseError } from "./parse.js";
export {
  verifyHashBinding,
  SdJwtVerificationError,
} from "./verify-hash-binding.js";
export {
  issueSdJwt,
  stubSignature,
  deterministicSalts,
  SdJwtIssuanceError,
} from "./issue.js";
export type {
  IssueSdJwtOptions,
  IssuanceResult,
  HashAlg,
} from "./issue.js";
export type {
  SdJwtHeader,
  SdJwtPayload,
  SdJwtDisclosure,
  ParsedSdJwt,
  VerifiedSdJwt,
} from "./types.js";

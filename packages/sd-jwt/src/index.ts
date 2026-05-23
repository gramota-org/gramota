// Single error class + code union for the whole package.
export { SdJwtError } from "./types.js";
export type { SdJwtErrorCode } from "./types.js";

// Domain types.
export type {
  SdJwtHeader,
  SdJwtPayload,
  SdJwtDisclosure,
  ParsedSdJwt,
  VerifiedSdJwt,
  VerifiedKeyBinding,
} from "./types.js";

// Primary API — grouped by operation.
export { parseSdJwt } from "./parse.js";

export { verifyHashBinding } from "./verify-hash-binding.js";

export {
  buildKeyBindingJwt,
  verifyKeyBinding,
  type BuildKbJwtOptions,
  type VerifyKbJwtOptions,
} from "./key-binding.js";

export {
  issueSdJwt,
  stubSignature,
  deterministicSalts,
  sd,
  type SdValue,
  type IssueSdJwtOptions,
  type IssuanceResult,
  type HashAlg,
} from "./issue.js";

// Helpers.
export { computeSdHash } from "./sd-hash.js";

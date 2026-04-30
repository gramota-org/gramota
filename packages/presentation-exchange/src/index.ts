export {
  PresentationExchangeError,
  type Constraints,
  type DescriptorMap,
  type Field,
  type FormatMap,
  type InputDescriptor,
  type PresentationDefinition,
  type PresentationExchangeErrorCode,
  type PresentationSubmission,
} from "./types.js";

export {
  evaluateJsonPath,
  leafClaimName,
  parseJsonPath,
  type JsonPathSegment,
} from "./jsonpath.js";

export type { CredentialMatcher, MatchResult } from "./matcher.js";

export {
  SdJwtVcMatcher,
  SD_JWT_VC_FORMAT,
  type SdJwtVcCredentialView,
} from "./sd-jwt-vc-matcher.js";

export {
  buildPresentationSubmission,
  selectForDefinition,
  type Selection,
  type SelectionFailure,
  type SelectionMatch,
  type SelectInput,
} from "./select.js";

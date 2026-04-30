export {
  DcqlError,
  type DcqlClaimQuery,
  type DcqlCredentialQuery,
  type DcqlCredentialSet,
  type DcqlErrorCode,
  type DcqlQuery,
} from "./types.js";

export {
  evaluateDcqlPath,
  leafPropertyName,
  validateDcqlPath,
  type DcqlPathSegment,
} from "./path.js";

export {
  DC_SD_JWT_VC_FORMAT,
  DcqlSdJwtVcMatcher,
  SD_JWT_VC_FORMAT,
  type DcqlMatchResult,
  type SdJwtVcCredentialView,
} from "./sd-jwt-vc-matcher.js";

export {
  selectForDcql,
  type DcqlMatcher,
  type DcqlSelection,
  type DcqlSelectionFailure,
  type DcqlSelectionMatch,
  type DcqlSelectInput,
} from "./select.js";

export { Issuer, type IssuerCredentialsApi } from "./issuer.js";
export {
  IssuerError,
  type BatchIssueEntry,
  type BatchIssueOptions,
  type IssuerConfig,
  type IssuerErrorCode,
  type IssueOptions,
  type IssueResult,
} from "./types.js";

// EU PID claim helpers — constants for canonical claim names + a default
// subject builder. Importing from `@gramota/issuer` keeps callers from
// hand-typing `birthdate` vs `birth_date` (the Rulebook spelling differs
// from common OIDC custom).
export {
  EU_PID_VCT,
  EU_PID_CREDENTIAL_CONFIGURATION_ID,
  PidClaim,
  PID_MANDATORY_CLAIM_NAMES,
  defaultPidSubject,
  statusListReference,
  type PidSubject,
  type DefaultPidSubjectOptions,
  type StatusListReference,
} from "./pid.js";

import type { JsonWebKey } from "@gateway/jose";
import type { ParsedSdJwt } from "@gateway/sd-jwt";
import { fetchStatusList, type Fetcher } from "./fetch.js";
import { getStatus } from "./parse.js";
import {
  STATUS_INVALID,
  STATUS_SUSPENDED,
  STATUS_VALID,
  StatusListError,
  type CredentialStatusResult,
  type StatusList,
  type StatusReference,
  type StatusState,
} from "./types.js";

export interface CheckCredentialStatusOptions {
  /** Trusted issuer JWKs — the status list's signature must verify
   * against one. Same semantics as everywhere else in the SDK. */
  trustedIssuers: readonly JsonWebKey[];
  /** Override fetch — for tests. */
  fetcher?: Fetcher;
  /** Override "now" — for expiry checks. */
  now?: () => number;
  /** Pre-fetched / cached list — skip the network if supplied. The list
   * is still validated (`sub` match, expiry) before use. */
  list?: StatusList;
}

/**
 * Resolve a credential's status per IETF Token Status List.
 *
 *   1. Read the credential's `status.status_list = { uri, idx }`.
 *   2. Fetch the list (or use one passed in via `options.list`).
 *   3. Verify its signature against `trustedIssuers`.
 *   4. Read the bit(s) at `idx`.
 *   5. Return a structured result with code + state.
 *
 * Throws `StatusListError("status_list.no_status_reference")` if the
 * credential has no `status` claim — callers should treat that as
 * "issuer didn't opt into revocation" (not as a verification failure).
 */
export async function checkCredentialStatus(
  credential: ParsedSdJwt,
  options: CheckCredentialStatusOptions,
): Promise<CredentialStatusResult> {
  const ref = readStatusReference(credential);

  let list: StatusList;
  if (options.list !== undefined) {
    if (options.list.subject !== ref.uri) {
      throw new StatusListError(
        "status_list.subject_mismatch",
        `pre-fetched list.subject (${options.list.subject}) doesn't match credential ref (${ref.uri})`,
      );
    }
    list = options.list;
  } else {
    const fetchOpts: Parameters<typeof fetchStatusList>[1] = {
      trustedIssuers: options.trustedIssuers,
    };
    if (options.fetcher !== undefined) fetchOpts.fetcher = options.fetcher;
    if (options.now !== undefined) fetchOpts.now = options.now;
    list = await fetchStatusList(ref.uri, fetchOpts);
  }

  const code = getStatus(list, ref.idx);
  return {
    code,
    state: stateFor(code, list.bits),
    list,
    reference: ref,
  };
}

/** Pull `status.status_list = { uri, idx }` out of a parsed credential. */
export function readStatusReference(
  credential: ParsedSdJwt,
): StatusReference {
  const status = credential.payload["status"];
  if (status === null || status === undefined) {
    throw new StatusListError(
      "status_list.no_status_reference",
      "credential has no `status` claim — issuer did not opt into status checks",
    );
  }
  if (typeof status !== "object" || Array.isArray(status)) {
    throw new StatusListError(
      "status_list.invalid_payload",
      "credential `status` claim must be an object",
    );
  }
  const sl = (status as Record<string, unknown>)["status_list"];
  if (sl === null || typeof sl !== "object" || Array.isArray(sl)) {
    throw new StatusListError(
      "status_list.invalid_payload",
      "credential `status.status_list` must be an object",
    );
  }
  const slObj = sl as Record<string, unknown>;
  const uri = slObj["uri"];
  const idx = slObj["idx"];
  if (typeof uri !== "string" || uri.length === 0) {
    throw new StatusListError(
      "status_list.invalid_payload",
      "credential `status.status_list.uri` must be a non-empty string",
    );
  }
  if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 0) {
    throw new StatusListError(
      "status_list.invalid_payload",
      "credential `status.status_list.idx` must be a non-negative integer",
    );
  }
  return { uri, idx };
}

function stateFor(code: number, bits: number): StatusState {
  if (code === STATUS_VALID) return "valid";
  if (code === STATUS_INVALID) return "invalid";
  if (code === STATUS_SUSPENDED) return "suspended";
  // Codes 3..15 are application-specific (only meaningful when bits >= 4).
  if (bits >= 4 && code >= 3) return "application_specific";
  return "unknown";
}

import { GramotaError } from "@gramota/core";

/**
 * IETF Token Status List wire-format types.
 * Spec: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
 *
 * Issuers publish a status list (a signed JWT/SD-JWT containing a
 * compressed bitstring) and embed a `status.status_list = { uri, idx }`
 * reference into each credential they sign. Verifiers fetch the list,
 * read the bit(s) at `idx`, and decide whether the credential is valid.
 *
 * Status values per the spec:
 *   0 = VALID
 *   1 = INVALID  (revoked — terminal)
 *   2 = SUSPENDED (temporary)
 *   3..15 = APPLICATION_SPECIFIC (only meaningful with bits >= 4)
 *
 * Bit packing: lists pack `bits` bits per status (1, 2, 4, or 8). Within
 * a byte, the LEAST-significant bits hold the lowest indices. Example
 * for bits=2:
 *   byte 0 = b7 b6 b5 b4 b3 b2 b1 b0
 *           [idx3] [idx2] [idx1] [idx0]
 */

/** A reference to a credential's status — embedded as `status.status_list`
 * in the credential payload. */
export interface StatusReference {
  /** URL where the wallet/verifier fetches the status list token. */
  uri: string;
  /** 0-based index into the list. */
  idx: number;
}

/** Permitted bit-widths per status (RFC requires one of these). */
export type StatusBits = 1 | 2 | 4 | 8;

/** A parsed (decoded + decompressed) status list. */
export interface StatusList {
  /** Bit-width of each status entry. */
  bits: StatusBits;
  /** Decompressed raw bitstring. Each byte holds 8/bits statuses
   * (for bits=1, 8 statuses; bits=2, 4 statuses; etc.). */
  bytes: Uint8Array;
  /** Total number of statuses encoded — derived from `bytes.length`. */
  length: number;
  /** Issuer of the list (`iss` claim of the status list token). */
  issuer: string;
  /** The list's own URL / subject (`sub` claim — should match the URI
   * used to fetch it). */
  subject: string;
  /** Issued-at, unix seconds. */
  issuedAt: number;
  /** Expiry (unix seconds), if the issuer set one. */
  expiresAt?: number;
  /** Caching hint (seconds), if set. */
  ttl?: number;
}

/** Status code values defined by the spec. */
export const STATUS_VALID = 0;
export const STATUS_INVALID = 1;
export const STATUS_SUSPENDED = 2;

/** Friendly label for a status code. */
export type StatusState =
  | "valid"
  | "invalid"
  | "suspended"
  | "application_specific"
  | "unknown";

/** Result of resolving a credential's status. */
export interface CredentialStatusResult {
  /** Numeric status code. */
  code: number;
  /** Human-readable label. */
  state: StatusState;
  /** The list that was consulted. */
  list: StatusList;
  /** The reference that pointed at the list. */
  reference: StatusReference;
}

/** Stable error codes for `StatusListError`. */
export type StatusListErrorCode =
  | "status_list.invalid_input"
  | "status_list.invalid_token"
  | "status_list.invalid_payload"
  | "status_list.invalid_compression"
  | "status_list.invalid_bits"
  | "status_list.index_out_of_range"
  | "status_list.fetch_failed"
  | "status_list.signature_invalid"
  | "status_list.subject_mismatch"
  | "status_list.expired"
  | "status_list.no_status_reference";

export class StatusListError extends GramotaError {
  override readonly code: StatusListErrorCode;

  constructor(
    code: StatusListErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, code, options);
    this.name = "StatusListError";
    this.code = code;
  }
}

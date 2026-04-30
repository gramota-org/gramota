import { inflateSync } from "node:zlib";
import {
  StatusListError,
  type StatusBits,
  type StatusList,
} from "./types.js";

/**
 * Parse a Status List token (compact JWS form).
 *
 * Expected payload claims per the IETF spec:
 *   iss         — issuer URL (string)
 *   sub         — list URL (string, MUST equal the URL used to fetch it)
 *   iat         — issued-at, unix seconds (number)
 *   exp         — optional expiry (unix seconds)
 *   ttl         — optional caching hint (seconds)
 *   status_list — { bits, lst }
 *     bits      — 1 | 2 | 4 | 8
 *     lst       — base64url(zlib_compressed_bitstring)
 *
 * NOTE: this function does NOT verify the JWS signature. Use
 * `verifyStatusListToken` (in fetch.ts / a separate wrapper) when
 * trust matters — i.e., before relying on the result for verification.
 */
export function parseStatusListToken(token: string): StatusList {
  if (typeof token !== "string" || token.length === 0) {
    throw new StatusListError(
      "status_list.invalid_input",
      "status list token must be a non-empty string",
    );
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new StatusListError(
      "status_list.invalid_token",
      `status list token must be a compact JWS with 3 segments, got ${parts.length}`,
    );
  }

  let payload: Record<string, unknown>;
  try {
    const json = Buffer.from(parts[1]!, "base64url").toString("utf-8");
    payload = JSON.parse(json) as Record<string, unknown>;
  } catch (err) {
    throw new StatusListError(
      "status_list.invalid_token",
      `status list payload is not valid base64url-encoded JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  return parseStatusListPayload(payload);
}

/** Parse a status list from an already-decoded JWT payload object. */
export function parseStatusListPayload(
  payload: Record<string, unknown>,
): StatusList {
  if (typeof payload["iss"] !== "string") {
    throw new StatusListError(
      "status_list.invalid_payload",
      "status list payload missing string `iss`",
    );
  }
  if (typeof payload["sub"] !== "string") {
    throw new StatusListError(
      "status_list.invalid_payload",
      "status list payload missing string `sub`",
    );
  }
  if (typeof payload["iat"] !== "number") {
    throw new StatusListError(
      "status_list.invalid_payload",
      "status list payload missing number `iat`",
    );
  }

  const sl = payload["status_list"];
  if (sl === null || typeof sl !== "object" || Array.isArray(sl)) {
    throw new StatusListError(
      "status_list.invalid_payload",
      "status list payload missing object `status_list`",
    );
  }
  const slObj = sl as Record<string, unknown>;

  const bitsRaw = slObj["bits"];
  if (
    bitsRaw !== 1 &&
    bitsRaw !== 2 &&
    bitsRaw !== 4 &&
    bitsRaw !== 8
  ) {
    throw new StatusListError(
      "status_list.invalid_bits",
      `status_list.bits must be 1, 2, 4, or 8 — got ${String(bitsRaw)}`,
    );
  }
  const bits = bitsRaw as StatusBits;

  const lst = slObj["lst"];
  if (typeof lst !== "string" || lst.length === 0) {
    throw new StatusListError(
      "status_list.invalid_payload",
      "status_list.lst must be a non-empty base64url string",
    );
  }

  let compressed: Buffer;
  try {
    compressed = Buffer.from(lst, "base64url");
  } catch (err) {
    throw new StatusListError(
      "status_list.invalid_payload",
      `status_list.lst is not valid base64url: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(inflateSync(compressed));
  } catch (err) {
    throw new StatusListError(
      "status_list.invalid_compression",
      `status_list.lst zlib decompression failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  const length = (bytes.length * 8) / bits;
  const result: StatusList = {
    bits,
    bytes,
    length,
    issuer: payload["iss"],
    subject: payload["sub"],
    issuedAt: payload["iat"],
  };
  if (typeof payload["exp"] === "number") {
    result.expiresAt = payload["exp"];
  }
  if (typeof payload["ttl"] === "number") {
    result.ttl = payload["ttl"];
  }
  return result;
}

/**
 * Read the status code at `index` from a parsed list.
 *
 * Bit ordering per spec: within a byte, the lowest-numbered indices live
 * in the LSBs. For bits=2:
 *   byte 0 = b7 b6 b5 b4 b3 b2 b1 b0
 *           [idx3][idx2][idx1][idx0]
 */
export function getStatus(list: StatusList, index: number): number {
  if (!Number.isInteger(index) || index < 0) {
    throw new StatusListError(
      "status_list.invalid_input",
      `status index must be a non-negative integer, got ${index}`,
    );
  }
  if (index >= list.length) {
    throw new StatusListError(
      "status_list.index_out_of_range",
      `status index ${index} >= list length ${list.length}`,
    );
  }

  const { bits, bytes } = list;
  const statusesPerByte = 8 / bits; // 8, 4, 2, or 1
  const byteIdx = Math.floor(index / statusesPerByte);
  const inByte = index % statusesPerByte; // 0..(statusesPerByte-1)
  const shift = inByte * bits; // 0, bits, 2*bits, ...
  const mask = (1 << bits) - 1;
  return (bytes[byteIdx]! >> shift) & mask;
}

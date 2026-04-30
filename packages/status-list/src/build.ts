import { deflateSync } from "node:zlib";
import { signJws, type JsonWebKey, type SupportedAlg } from "@gateway/jose";
import { StatusListError, type StatusBits } from "./types.js";

export interface BuildStatusListOptions {
  /** Issuer URL (= `iss` claim). */
  issuer: string;
  /** Public list URL (= `sub` claim, MUST equal the URL the list will be
   * fetched from — the verifier enforces match). */
  subject: string;
  /** Number of statuses to encode. The packed bytes are sized to fit. */
  length: number;
  /** Bit-width per status. Default: 1 (valid/invalid only). */
  bits?: StatusBits;
  /** Issued-at, unix seconds. Default: now. */
  issuedAt?: number;
  /** Optional expiry, unix seconds. */
  expiresAt?: number;
  /** Optional caching TTL hint. */
  ttl?: number;
  /** Initial statuses — index → code. Codes default to 0 (valid). */
  initial?: Readonly<Record<number, number>>;
  /** Issuer's signing JWK. */
  privateKey: JsonWebKey;
  /** JWS algorithm — must match the key. */
  alg: SupportedAlg;
  /** Key id for the JWS header (so verifiers can pick the right JWK). */
  kid?: string;
}

/**
 * Build a signed Status List token (compact JWS) per the IETF spec.
 *
 * Returns the compact JWS string. Hosting it at the URL passed as
 * `subject` makes it a real, fetchable status list.
 */
export async function buildStatusListToken(
  options: BuildStatusListOptions,
): Promise<string> {
  const bits: StatusBits = options.bits ?? 1;
  const length = options.length;
  if (!Number.isInteger(length) || length <= 0) {
    throw new StatusListError(
      "status_list.invalid_input",
      `buildStatusListToken: length must be a positive integer, got ${length}`,
    );
  }
  const statusesPerByte = 8 / bits;
  const byteCount = Math.ceil(length / statusesPerByte);
  const bytes = new Uint8Array(byteCount);

  if (options.initial !== undefined) {
    const mask = (1 << bits) - 1;
    for (const [idxRaw, codeRaw] of Object.entries(options.initial)) {
      const idx = Number(idxRaw);
      if (!Number.isInteger(idx) || idx < 0 || idx >= length) {
        throw new StatusListError(
          "status_list.invalid_input",
          `initial[${idxRaw}]: index out of range`,
        );
      }
      if (
        !Number.isInteger(codeRaw) ||
        codeRaw < 0 ||
        codeRaw > mask
      ) {
        throw new StatusListError(
          "status_list.invalid_input",
          `initial[${idxRaw}]: code ${codeRaw} doesn't fit in ${bits} bits`,
        );
      }
      const byteIdx = Math.floor(idx / statusesPerByte);
      const inByte = idx % statusesPerByte;
      const shift = inByte * bits;
      bytes[byteIdx] = (bytes[byteIdx]! & ~(mask << shift)) | (codeRaw << shift);
    }
  }

  const compressed = deflateSync(Buffer.from(bytes));
  const lst = compressed.toString("base64url");

  const iat = options.issuedAt ?? Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: options.issuer,
    sub: options.subject,
    iat,
    status_list: { bits, lst },
  };
  if (options.expiresAt !== undefined) payload["exp"] = options.expiresAt;
  if (options.ttl !== undefined) payload["ttl"] = options.ttl;

  const signOpts: Parameters<typeof signJws>[2] = {
    alg: options.alg,
    typ: "statuslist+jwt",
  };
  if (options.kid !== undefined) signOpts.kid = options.kid;

  return await signJws(payload, options.privateKey, signOpts);
}

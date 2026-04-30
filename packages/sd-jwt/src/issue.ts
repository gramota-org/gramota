import { createHash, randomBytes } from "node:crypto";
import type { SdJwtDisclosure, SdJwtHeader } from "./types.js";

export interface IssueSdJwtOptions {
  /** Non-selectively-disclosable claims placed directly in the JWT payload. */
  payload: Record<string, unknown>;
  /** Claims to make selectively disclosable as object properties. */
  sdClaims?: Record<string, unknown>;
  /** JWT signing algorithm (placed in header `alg`). The signature itself is
   * produced by `signer` — this library does not perform cryptographic signing
   * (that is `@gateway/jose`'s job). */
  alg: string;
  /** Optional `typ` header claim (e.g. "vc+sd-jwt", "dc+sd-jwt"). */
  typ?: string;
  /** Async (or sync) signer. Receives `header.payload` (the bytes to sign) and
   * returns the base64url-encoded signature. Use `stubSignature` for tests. */
  signer: (signedPayload: string) => Promise<string> | string;
  /** Hash algorithm (default "sha-256"). Sets `_sd_alg` when sdClaims present. */
  hashAlg?: HashAlg;
  /** Salt generator returning a base64url string. Pluggable for deterministic
   * testing. Default: 128-bit random salt. */
  saltGenerator?: () => string;
  /** Additional header parameters (kid, x5c, etc.). */
  extraHeader?: Record<string, unknown>;
}

export type HashAlg = "sha-256" | "sha-384" | "sha-512";

export interface IssuanceResult {
  token: string;
  disclosures: SdJwtDisclosure[];
}

export class SdJwtIssuanceError extends Error {
  override readonly name = "SdJwtIssuanceError";
}

/** Constant placeholder for tests where the signature is not verified. */
export const stubSignature = (): string => "stub-signature";

/**
 * Build a compact-serialized SD-JWT-VC.
 *
 * The encoder:
 *  - Serialises each (salt, name, value) as a JSON array, base64url-encodes it,
 *    and SHA-256 hashes the encoded form to produce a digest.
 *  - Places the digests in `_sd` (only at top level for now), and `_sd_alg` in
 *    the JWT payload.
 *  - Concatenates JWT + disclosures + trailing `~`.
 *
 * Limitations of this version:
 *  - Object-property selective disclosure only (no nested SD, no array-element
 *    disclosures). Those are tracked for follow-up packages.
 *  - No cryptographic signing — signer is pluggable but `@gateway/jose` will
 *    provide the real ES256/EdDSA/RS256 implementations.
 */
export async function issueSdJwt(
  opts: IssueSdJwtOptions,
): Promise<IssuanceResult> {
  const hashAlg = opts.hashAlg ?? "sha-256";
  const nodeHashAlg = toNodeHashAlg(hashAlg);
  const salt = opts.saltGenerator ?? defaultSaltGenerator;

  if (typeof opts.signer !== "function") {
    throw new SdJwtIssuanceError("signer is required");
  }
  if (typeof opts.alg !== "string" || opts.alg.length === 0) {
    throw new SdJwtIssuanceError("alg is required");
  }

  // Build disclosures + digests.
  const disclosures: SdJwtDisclosure[] = [];
  const digests: string[] = [];
  for (const [name, value] of Object.entries(opts.sdClaims ?? {})) {
    const saltStr = salt();
    const json = JSON.stringify([saltStr, name, value]);
    const raw = Buffer.from(json, "utf-8").toString("base64url");
    const digest = createHash(nodeHashAlg).update(raw).digest("base64url");
    disclosures.push({ raw, salt: saltStr, name, value });
    digests.push(digest);
  }

  // Build header.
  const header: SdJwtHeader = { alg: opts.alg, ...opts.extraHeader };
  if (opts.typ !== undefined) {
    header.typ = opts.typ;
  }
  const headerB64 = Buffer.from(JSON.stringify(header), "utf-8").toString(
    "base64url",
  );

  // Build payload.
  const payload: Record<string, unknown> = { ...opts.payload };
  if (digests.length > 0) {
    payload["_sd"] = digests;
    payload["_sd_alg"] = hashAlg;
  }
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString(
    "base64url",
  );

  // Sign.
  const signedPayload = `${headerB64}.${payloadB64}`;
  const signature = await opts.signer(signedPayload);
  if (typeof signature !== "string" || signature.length === 0) {
    throw new SdJwtIssuanceError("signer returned an empty signature");
  }

  // Concatenate JWT + disclosures + trailing tilde.
  const jwt = `${signedPayload}.${signature}`;
  const token =
    disclosures.length === 0
      ? `${jwt}~`
      : `${jwt}~${disclosures.map((d) => d.raw).join("~")}~`;

  return { token, disclosures };
}

function toNodeHashAlg(alg: HashAlg): string {
  switch (alg) {
    case "sha-256":
      return "sha256";
    case "sha-384":
      return "sha384";
    case "sha-512":
      return "sha512";
    default: {
      const exhaustive: never = alg;
      throw new SdJwtIssuanceError(`unsupported hash alg: ${exhaustive}`);
    }
  }
}

function defaultSaltGenerator(): string {
  return randomBytes(16).toString("base64url");
}

/** Build a deterministic salt generator from an array of pre-chosen salts.
 *  Useful for tests that need byte-stable output. */
export function deterministicSalts(salts: readonly string[]): () => string {
  let i = 0;
  return () => {
    const s = salts[i++];
    if (s === undefined) {
      throw new SdJwtIssuanceError("deterministic salt generator exhausted");
    }
    return s;
  };
}

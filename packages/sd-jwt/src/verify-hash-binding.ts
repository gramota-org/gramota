import { createHash } from "node:crypto";
import {
  SdJwtError,
  type ParsedSdJwt,
  type SdJwtDisclosure,
  type VerifiedSdJwt,
} from "./types.js";

const DEFAULT_HASH_ALG = "sha-256";

// Failure codes raised by `verifyHashBinding` are namespaced
// `sd_jwt.verify.*`. See `SdJwtErrorCode` in `./types.ts` for the full
// union of codes raised across the package.

/**
 * Verify the hash binding between disclosures and the issuer's `_sd` digests,
 * and reconstruct the disclosed claims.
 *
 * This is the SD-JWT security primitive: it proves that every disclosed claim
 * was authorised by the issuer at signing time, and that no extra claims have
 * been smuggled in by the holder.
 *
 * Note: this verifies the *hash binding* only. Issuer-signature verification
 * (`@gramota/jose`) and key-binding-JWT verification are separate layers above.
 */
export function verifyHashBinding(parsed: ParsedSdJwt): VerifiedSdJwt {
  const hashAlgorithm =
    typeof parsed.payload._sd_alg === "string"
      ? parsed.payload._sd_alg
      : DEFAULT_HASH_ALG;
  const nodeHashAlg = toNodeHashAlgorithm(hashAlgorithm);

  // Map digest → disclosure for O(1) lookup during the walk.
  const byDigest = new Map<string, SdJwtDisclosure>();
  for (const d of parsed.disclosures) {
    const digest = createHash(nodeHashAlg).update(d.raw).digest("base64url");
    byDigest.set(digest, d);
  }

  const matched = new Set<string>();
  const claims = expand(parsed.payload, byDigest, matched, nodeHashAlg);
  // Strip `_sd_alg` from the top level (it's metadata, not a real claim).
  delete (claims as Record<string, unknown>)._sd_alg;

  const matchedDisclosures: SdJwtDisclosure[] = [];
  const unmatchedDisclosures: SdJwtDisclosure[] = [];
  for (const d of parsed.disclosures) {
    const digest = createHash(nodeHashAlg).update(d.raw).digest("base64url");
    if (matched.has(digest)) {
      matchedDisclosures.push(d);
    } else {
      unmatchedDisclosures.push(d);
    }
  }

  return {
    parsed,
    claims: claims as Record<string, unknown>,
    matchedDisclosures,
    unmatchedDisclosures,
    hashAlgorithm,
  };
}

function expand(
  node: unknown,
  byDigest: Map<string, SdJwtDisclosure>,
  matched: Set<string>,
  nodeHashAlg: string,
): unknown {
  if (Array.isArray(node)) {
    const out: unknown[] = [];
    for (const el of node) {
      if (isArrayElementDigest(el)) {
        const digest = el["..."];
        const disc = byDigest.get(digest);
        if (disc !== undefined && disc.name === null) {
          matched.add(digest);
          out.push(expand(disc.value, byDigest, matched, nodeHashAlg));
        }
        // If unmatched, the array element is selectively withheld — drop it.
        continue;
      }
      out.push(expand(el, byDigest, matched, nodeHashAlg));
    }
    return out;
  }

  if (node !== null && typeof node === "object") {
    const obj = node as Record<string, unknown>;
    const out: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      if (key === "_sd" && Array.isArray(value)) {
        for (const digest of value) {
          if (typeof digest !== "string") continue;
          const disc = byDigest.get(digest);
          if (disc !== undefined && disc.name !== null) {
            out[disc.name] = expand(disc.value, byDigest, matched, nodeHashAlg);
            matched.add(digest);
          }
          // Unmatched digests are withheld claims or decoys — drop silently.
        }
        continue;
      }
      if (key === "_sd_alg") {
        continue;
      }
      out[key] = expand(value, byDigest, matched, nodeHashAlg);
    }
    return out;
  }

  return node;
}

function isArrayElementDigest(
  el: unknown,
): el is { "...": string } {
  return (
    el !== null &&
    typeof el === "object" &&
    !Array.isArray(el) &&
    Object.keys(el).length === 1 &&
    typeof (el as Record<string, unknown>)["..."] === "string"
  );
}

function toNodeHashAlgorithm(alg: string): string {
  switch (alg.toLowerCase()) {
    case "sha-256":
      return "sha256";
    case "sha-384":
      return "sha384";
    case "sha-512":
      return "sha512";
    default:
      throw new SdJwtError(
        "sd_jwt.verify.unsupported_hash_alg",
        `unsupported _sd_alg: ${alg}`,
      );
  }
}

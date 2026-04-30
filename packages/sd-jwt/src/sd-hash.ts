import { createHash } from "node:crypto";
import type { HashAlg } from "./issue.js";

/**
 * Compute `sd_hash` per IETF SD-JWT §4.3.
 *
 * Input: the presentation prefix — issuer JWS + all presented disclosures +
 * separator tildes, ending with `~`. NEVER include the KB-JWT.
 *
 * Output: base64url-encoded hash of the input bytes.
 *
 * This binds the KB-JWT to the exact disclosures presented; tampering with
 * any disclosure or reordering them invalidates the hash.
 */
export function computeSdHash(
  presentationPrefix: string,
  hashAlg: HashAlg = "sha-256",
): string {
  return createHash(toNodeHashAlg(hashAlg))
    .update(presentationPrefix)
    .digest("base64url");
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
      throw new Error(`unsupported hash alg: ${exhaustive}`);
    }
  }
}

import { verifyJws } from "./verify.js";
import {
  extractPublicKeyFromX5c,
  validateX5cChain,
  type ChainValidationOptions,
  type ChainValidationResult,
} from "./x5c.js";
import {
  JoseError,
  type VerifiedJws,
  type VerifyJwsOptions,
} from "./types.js";

export interface VerifyJwsX5cOptions extends VerifyJwsOptions {
  /** Optional cert-chain validation. When provided, the chain is verified
   * against the supplied trust anchors before signature verification. */
  trustAnchors?: readonly string[];
  /** Override "now" — for chain-validity tests. */
  now?: Date;
}

export interface VerifiedJwsWithX5c extends VerifiedJws {
  /** Set when `trustAnchors` were supplied and the chain validated. */
  chain?: ChainValidationResult;
}

/**
 * Verify a JWS where the public key is supplied via the `x5c` JOSE header
 * (RFC 7515 §4.1.6) — common for OID4VP authorization requests under the
 * EUDI HAIP profile and any deployment using x509 trust.
 *
 * Two modes:
 *   - **Signature only** — extract key from x5c[0], verify the JWS. This
 *     proves cryptographic integrity but NOT that you trust the issuer.
 *   - **With trust anchors** — additionally validate the cert chain leads
 *     to one of `options.trustAnchors`. This proves authenticity to the
 *     extent your trust anchors are correct.
 *
 * Errors:
 *   - `jose.x5c_missing`         — header has no x5c
 *   - `jose.x5c_empty`           — x5c is an empty array
 *   - `jose.x5c_parse_failed`    — a cert in x5c is malformed
 *   - `jose.x5c_chain_invalid`   — chain check failed (validity, signature)
 *   - `jose.x5c_no_trust_anchor` — last cert doesn't lead to a trusted root
 *   - `jose.signature_invalid`   — JWS signature didn't verify against x5c[0]
 *   - all the standard `jose.*` codes from `verifyJws`
 */
export async function verifyJwsWithX5c(
  jws: string,
  options: VerifyJwsX5cOptions = {},
): Promise<VerifiedJwsWithX5c> {
  if (typeof jws !== "string" || jws.length === 0) {
    throw new JoseError(
      "jose.invalid_input",
      "jws must be a non-empty string",
    );
  }

  // Extract x5c from the JOSE header before invoking crypto.
  const headerB64 = jws.split(".")[0];
  if (headerB64 === undefined || headerB64.length === 0) {
    throw new JoseError(
      "jose.malformed_jws",
      "malformed JWS: missing header segment",
    );
  }
  let header: { x5c?: unknown };
  try {
    const json = Buffer.from(headerB64, "base64url").toString("utf-8");
    header = JSON.parse(json) as { x5c?: unknown };
  } catch {
    throw new JoseError(
      "jose.malformed_header",
      "JWS header is not valid base64url JSON",
    );
  }
  if (!Array.isArray(header.x5c)) {
    throw new JoseError(
      "jose.x5c_missing",
      "JWS header has no x5c array",
    );
  }
  if (header.x5c.length === 0) {
    throw new JoseError(
      "jose.x5c_empty",
      "JWS header x5c is an empty array",
    );
  }
  const x5c = header.x5c as string[];

  // Optionally validate the chain BEFORE accepting the public key.
  let chain: ChainValidationResult | undefined;
  if (options.trustAnchors !== undefined) {
    const chainOpts: ChainValidationOptions = {
      trustAnchors: options.trustAnchors,
    };
    if (options.now !== undefined) chainOpts.now = options.now;
    chain = validateX5cChain(x5c, chainOpts);
  }

  // Extract the public key from x5c[0] and run signature verification.
  const publicKey = extractPublicKeyFromX5c(x5c);

  const verifyOpts: VerifyJwsOptions = {};
  if (options.algorithms !== undefined) verifyOpts.algorithms = options.algorithms;
  const verified = await verifyJws(jws, publicKey, verifyOpts);

  const result: VerifiedJwsWithX5c = { ...verified };
  if (chain !== undefined) result.chain = chain;
  return result;
}

import { X509Certificate } from "node:crypto";
import {
  JoseVerificationError,
  type JsonWebKey,
} from "./types.js";

/**
 * Convert a single `x5c` entry to PEM format.
 *
 * Per RFC 7515 §4.1.6, x5c entries are base64-encoded (NOT base64url) DER
 * certificates. We just wrap them in standard PEM headers.
 */
export function x5cToPem(x5cEntry: string): string {
  if (typeof x5cEntry !== "string" || x5cEntry.length === 0) {
    throw new JoseVerificationError(
      "jose.x5c_parse_failed",
      "x5c entry must be a non-empty base64 string",
    );
  }
  // Standard PEM has 64-char lines; node accepts other widths but we
  // produce the canonical form for clarity.
  const lines = x5cEntry.match(/.{1,64}/g) ?? [x5cEntry];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/** Parse a single `x5c` entry as an X.509 certificate. */
export function parseX5cEntry(x5cEntry: string): X509Certificate {
  try {
    return new X509Certificate(x5cToPem(x5cEntry));
  } catch (err) {
    throw new JoseVerificationError(
      "jose.x5c_parse_failed",
      `failed to parse x5c entry: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/**
 * Extract the public JWK from `x5c[0]` (the leaf signing certificate).
 *
 * This produces a JWK suitable for passing to `verifyJws`. It does not
 * validate the chain or the cert's trust — use `validateX5cChain` for that.
 */
export function extractPublicKeyFromX5c(
  x5c: readonly string[],
): JsonWebKey {
  if (!Array.isArray(x5c)) {
    throw new JoseVerificationError(
      "jose.x5c_missing",
      "x5c is missing or not an array",
    );
  }
  if (x5c.length === 0) {
    throw new JoseVerificationError(
      "jose.x5c_empty",
      "x5c is an empty array",
    );
  }
  const cert = parseX5cEntry(x5c[0]!);
  const jwk = cert.publicKey.export({ format: "jwk" });
  return jwk as JsonWebKey;
}

// ---------------------------------------------------------------------------
// Chain validation
// ---------------------------------------------------------------------------

export interface ChainValidationOptions {
  /** PEM-encoded trust anchor certificates the chain must lead to. */
  trustAnchors: readonly string[];
  /** Override "now" — useful for tests. */
  now?: Date;
}

export interface ChainValidationResult {
  /** The leaf (x5c[0]) certificate, parsed. */
  leaf: X509Certificate;
  /** Every certificate in the chain, in x5c order. */
  chain: readonly X509Certificate[];
  /** The trust anchor that ultimately validated the chain. */
  anchor: X509Certificate;
}

/**
 * Validate an `x5c` chain against trust anchors.
 *
 * Rules enforced:
 *   1. Every cert in `x5c` is currently within its validity window.
 *   2. Each cert is cryptographically signed by the next in `x5c`.
 *   3. The last cert in `x5c` is signed by (or equal to) one of `trustAnchors`.
 *
 * Throws `JoseVerificationError` with `code: "jose.x5c_chain_invalid"` or
 * `"jose.x5c_no_trust_anchor"` if validation fails.
 *
 * Returns the leaf certificate (for further inspection) and the trust anchor
 * that validated the chain.
 */
export function validateX5cChain(
  x5c: readonly string[],
  options: ChainValidationOptions,
): ChainValidationResult {
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new JoseVerificationError(
      "jose.x5c_empty",
      "x5c is empty",
    );
  }
  if (
    !Array.isArray(options.trustAnchors) ||
    options.trustAnchors.length === 0
  ) {
    throw new JoseVerificationError(
      "jose.invalid_input",
      "validateX5cChain: trustAnchors must be a non-empty array of PEM strings",
    );
  }

  const certs = x5c.map(parseX5cEntry);
  const now = options.now ?? new Date();

  // Rule 1: validity windows
  for (const c of certs) {
    const notBefore = new Date(c.validFrom);
    const notAfter = new Date(c.validTo);
    if (notBefore > now) {
      throw new JoseVerificationError(
        "jose.x5c_chain_invalid",
        `certificate not yet valid: ${c.subject} (validFrom=${c.validFrom})`,
      );
    }
    if (notAfter < now) {
      throw new JoseVerificationError(
        "jose.x5c_chain_invalid",
        `certificate expired: ${c.subject} (validTo=${c.validTo})`,
      );
    }
  }

  // Rule 2: each cert cryptographically signed by next
  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i]!;
    const parent = certs[i + 1]!;
    if (!child.verify(parent.publicKey)) {
      throw new JoseVerificationError(
        "jose.x5c_chain_invalid",
        `certificate at x5c[${i}] is not signed by x5c[${i + 1}]`,
      );
    }
  }

  // Rule 3: last cert leads to a trust anchor (either equal-to or signed-by)
  const lastCert = certs[certs.length - 1]!;
  const anchorCerts = options.trustAnchors.map(
    (pem) => new X509Certificate(pem),
  );

  for (const anchor of anchorCerts) {
    if (lastCert.fingerprint256 === anchor.fingerprint256) {
      return { leaf: certs[0]!, chain: certs, anchor };
    }
    if (lastCert.verify(anchor.publicKey)) {
      return { leaf: certs[0]!, chain: certs, anchor };
    }
  }

  throw new JoseVerificationError(
    "jose.x5c_no_trust_anchor",
    `chain does not lead to any of the ${anchorCerts.length} trust anchor(s)`,
  );
}

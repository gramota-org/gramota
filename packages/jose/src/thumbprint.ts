/**
 * RFC 7638 — JSON Web Key (JWK) Thumbprint.
 *
 * Used by:
 *   - DPoP (RFC 9449): the `jkt` claim in access tokens binds them to a
 *     specific JWK. Verifiers compute the inbound DPoP key's thumbprint
 *     and compare against the token's `cnf.jkt`.
 *   - SD-JWT-VC: the holder-binding key cnf claim can carry `jkt`
 *     instead of the full key.
 *   - Wallet attestation flows where keys are referenced compactly.
 *
 * The thumbprint is `base64url(sha256(canonicalJSON(requiredJwkFields)))`.
 * "Required fields" depends on the key type — we implement the three
 * curves wallets actually use (RSA, EC, OKP). RFC 7638 §3.2 explicitly
 * forbids extra members in the canonical input, so we strip everything
 * but the type-specific required keys.
 */

import { createHash } from "node:crypto";
import { JoseError, type JsonWebKey } from "./types.js";

/**
 * Compute the SHA-256 JWK Thumbprint per RFC 7638.
 *
 *   computeJwkThumbprint({ kty: "EC", crv: "P-256", x: "...", y: "..." })
 *     → "G7B0w8...22 chars total"
 *
 * Returns the thumbprint in base64url encoding (the canonical form
 * referenced by `jkt` claims). Throws {@link JoseError}
 * with `jose.invalid_input` for unsupported `kty` values or missing
 * required members.
 */
export function computeJwkThumbprint(jwk: JsonWebKey): string {
  if (jwk === null || typeof jwk !== "object") {
    throw new JoseError(
      "jose.invalid_input",
      "computeJwkThumbprint: jwk must be an object",
    );
  }
  const kty = (jwk as { kty?: unknown }).kty;
  if (typeof kty !== "string" || kty.length === 0) {
    throw new JoseError(
      "jose.invalid_input",
      "computeJwkThumbprint: jwk.kty is required",
    );
  }

  const required = requiredMembers(kty, jwk as Record<string, unknown>);
  // RFC 7638 §3.3 — members must appear in lexicographic order, with
  // RFC 8259 canonical JSON (no whitespace, lowercase escapes).
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(required).sort()) {
    ordered[key] = required[key];
  }
  const canonical = JSON.stringify(ordered);
  const digest = createHash("sha256").update(canonical, "utf-8").digest();
  return Buffer.from(digest).toString("base64url");
}

function requiredMembers(
  kty: string,
  jwk: Record<string, unknown>,
): Record<string, string> {
  switch (kty) {
    case "EC": {
      const crv = jwk["crv"];
      const x = jwk["x"];
      const y = jwk["y"];
      requireString(kty, "crv", crv);
      requireString(kty, "x", x);
      requireString(kty, "y", y);
      return { kty, crv: crv as string, x: x as string, y: y as string };
    }
    case "RSA": {
      const n = jwk["n"];
      const e = jwk["e"];
      requireString(kty, "n", n);
      requireString(kty, "e", e);
      return { kty, e: e as string, n: n as string };
    }
    case "OKP": {
      const crv = jwk["crv"];
      const x = jwk["x"];
      requireString(kty, "crv", crv);
      requireString(kty, "x", x);
      return { kty, crv: crv as string, x: x as string };
    }
    case "oct": {
      const k = jwk["k"];
      requireString(kty, "k", k);
      return { kty, k: k as string };
    }
    default:
      throw new JoseError(
        "jose.invalid_input",
        `computeJwkThumbprint: unsupported kty '${kty}'`,
      );
  }
}

function requireString(kty: string, name: string, value: unknown): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new JoseError(
      "jose.invalid_input",
      `computeJwkThumbprint: jwk.${name} is required for kty=${kty}`,
    );
  }
}

import type { JsonWebKey } from "@gramota/jose";

/**
 * Compare two JWKs for equality of the *public key material only*.
 * Ignores optional metadata (`kid`, `alg`, `use`, etc.) that varies across
 * issuers but doesn't change cryptographic identity.
 *
 * Per RFC 7638 the canonical way is JWK Thumbprint, but for cnf-binding
 * verification within a trusted runtime, direct field-wise comparison of the
 * kty-required fields is equivalent and avoids hashing.
 */
export function publicJwksEqual(a: unknown, b: unknown): boolean {
  if (
    a === null ||
    b === null ||
    typeof a !== "object" ||
    typeof b !== "object" ||
    Array.isArray(a) ||
    Array.isArray(b)
  ) {
    return false;
  }

  const ka = a as Record<string, unknown>;
  const kb = b as Record<string, unknown>;

  if (ka["kty"] !== kb["kty"]) return false;

  switch (ka["kty"]) {
    case "RSA":
      return ka["n"] === kb["n"] && ka["e"] === kb["e"];
    case "EC":
      return (
        ka["crv"] === kb["crv"] && ka["x"] === kb["x"] && ka["y"] === kb["y"]
      );
    case "OKP":
      return ka["crv"] === kb["crv"] && ka["x"] === kb["x"];
    default:
      return false;
  }
}

/** Best-effort cast for ergonomic call sites that already know the input is
 * a JWK shape. Returns the same value typed as JsonWebKey. */
export function asJwk(value: unknown): JsonWebKey {
  return value as JsonWebKey;
}

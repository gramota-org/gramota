/**
 * RFC 7638 — JWK Thumbprint conformance.
 *
 * Test vectors:
 *   - The canonical RSA example from RFC 7638 §3.1 (the one in the spec
 *     itself), giving the known thumbprint
 *     "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".
 *   - An EC P-256 key generated via WebCrypto and round-tripped through
 *     `jose`'s exportJWK to check our P-256 path matches the reference
 *     `jose` library's thumbprint.
 *   - Defensive guards: missing kty, missing required member per kty,
 *     unsupported kty.
 *
 * What we don't test here: edge curves we don't support (Ed448, P-521 OKP).
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair, calculateJwkThumbprint } from "jose";
import {
  JoseError,
  computeJwkThumbprint,
  type JsonWebKey,
} from "../src/index.js";

// RFC 7638 §3.1 — the canonical RSA test vector.
const RFC_7638_RSA_JWK: JsonWebKey = {
  kty: "RSA",
  n:
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbf" +
    "AAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknj" +
    "hMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65" +
    "YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQ" +
    "vRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lF" +
    "d2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzK" +
    "nqDKgw",
  e: "AQAB",
};

describe("computeJwkThumbprint — RFC 7638 §3.1 canonical RSA", () => {
  it("matches the spec's published thumbprint", () => {
    const expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    expect(computeJwkThumbprint(RFC_7638_RSA_JWK)).toBe(expected);
  });
});

describe("computeJwkThumbprint — EC P-256 cross-check vs jose lib", () => {
  it("matches `jose.calculateJwkThumbprint` for a freshly-generated EC key", async () => {
    const { publicKey } = await generateKeyPair("ES256", { extractable: true });
    const pub = (await exportJWK(publicKey)) as JsonWebKey;
    const expected = await calculateJwkThumbprint(
      pub as Parameters<typeof calculateJwkThumbprint>[0],
    );
    expect(computeJwkThumbprint(pub)).toBe(expected);
  });
});

describe("computeJwkThumbprint — OKP (Ed25519) cross-check vs jose lib", () => {
  it("matches `jose.calculateJwkThumbprint` for a freshly-generated Ed25519 key", async () => {
    const { publicKey } = await generateKeyPair("EdDSA", {
      crv: "Ed25519",
      extractable: true,
    });
    const pub = (await exportJWK(publicKey)) as JsonWebKey;
    const expected = await calculateJwkThumbprint(
      pub as Parameters<typeof calculateJwkThumbprint>[0],
    );
    expect(computeJwkThumbprint(pub)).toBe(expected);
  });
});

describe("computeJwkThumbprint — input validation", () => {
  it("throws on missing kty", () => {
    expect(() =>
      computeJwkThumbprint({} as JsonWebKey),
    ).toThrow(JoseError);
  });

  it("throws on unsupported kty", () => {
    expect(() =>
      computeJwkThumbprint({ kty: "totally-fake" } as unknown as JsonWebKey),
    ).toThrow(JoseError);
  });

  it("throws on EC missing crv/x/y", () => {
    expect(() =>
      computeJwkThumbprint({ kty: "EC", crv: "P-256", x: "abc" } as JsonWebKey),
    ).toThrow(JoseError);
  });

  it("throws on RSA missing n/e", () => {
    expect(() =>
      computeJwkThumbprint({ kty: "RSA", n: "abc" } as JsonWebKey),
    ).toThrow(JoseError);
  });
});

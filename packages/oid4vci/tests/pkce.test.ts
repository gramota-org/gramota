/**
 * PKCE primitives — RFC 7636.
 *
 * The verifier is a high-entropy random string. The challenge is its
 * SHA-256 hash, base64url-encoded. The issuer derives the challenge from
 * the verifier and confirms they match — that's what defeats authorization-
 * code interception.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  codeChallenge,
  generateCodeVerifier,
  generateState,
  Oid4vciError,
} from "../src/index.js";

describe("PKCE — generateCodeVerifier", () => {
  it("returns a base64url string of the expected length (default 32 bytes → 43 chars)", () => {
    const v = generateCodeVerifier();
    // base64url(32 bytes) = 43 chars (no padding)
    expect(v).toHaveLength(43);
    // RFC 7636 unreserved chars: [A-Za-z0-9-._~]; base64url uses [A-Za-z0-9_-].
    expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("yields fresh randomness on every call", () => {
    const a = generateCodeVerifier();
    const b = generateCodeVerifier();
    expect(a).not.toBe(b);
  });

  it("respects custom byte lengths within RFC bounds", () => {
    // 64 bytes → 86 chars base64url
    const v = generateCodeVerifier(64);
    expect(v).toHaveLength(86);
    // Verifier of length 86 is valid per RFC 7636 §4.1 (43..128).
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
  });

  it("rejects byte lengths below 32 (would yield < 43 chars)", () => {
    expect(() => generateCodeVerifier(16)).toThrowError(Oid4vciError);
  });

  it("rejects byte lengths above 96 (would exceed RFC max 128 chars)", () => {
    expect(() => generateCodeVerifier(128)).toThrowError(Oid4vciError);
  });
});

describe("PKCE — codeChallenge (S256)", () => {
  it("matches the canonical RFC 7636 §B.1 vector", () => {
    // RFC 7636 Appendix B.1: verifier dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
    // → challenge E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    expect(codeChallenge(verifier)).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
  });

  it("is deterministic (same verifier → same challenge)", () => {
    const v = generateCodeVerifier();
    expect(codeChallenge(v)).toBe(codeChallenge(v));
  });

  it("differs from the verifier (i.e. it actually hashes)", () => {
    const v = generateCodeVerifier();
    expect(codeChallenge(v)).not.toBe(v);
  });

  it("produces 43-char base64url SHA-256 digests", () => {
    const v = generateCodeVerifier();
    const c = codeChallenge(v);
    // base64url(SHA-256 = 32 bytes) = 43 chars
    expect(c).toHaveLength(43);
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("matches an independent SHA-256 + base64url computation", () => {
    const v = generateCodeVerifier();
    const expected = createHash("sha256").update(v).digest("base64url");
    expect(codeChallenge(v)).toBe(expected);
  });

  it("rejects verifiers shorter than 43 characters (RFC 7636 §4.1)", () => {
    expect(() => codeChallenge("too-short")).toThrowError(Oid4vciError);
  });
});

describe("PKCE — generateState", () => {
  it("returns a base64url string of expected default length (16 bytes → 22 chars)", () => {
    const s = generateState();
    expect(s).toHaveLength(22);
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("yields fresh randomness on every call", () => {
    expect(generateState()).not.toBe(generateState());
  });

  it("respects custom byte lengths", () => {
    expect(generateState(8)).toHaveLength(11);
    expect(generateState(32)).toHaveLength(43);
  });
});

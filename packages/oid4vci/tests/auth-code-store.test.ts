/**
 * AuthCodeStore + verifyPkceChallenge — auth-code grant primitives.
 *
 * The verifyPkceChallenge tests use the RFC 7636 Appendix B.1 vector to
 * pin S256 conformance.
 */

import { describe, it, expect } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import {
  AUTH_CODE_TTL_SECONDS,
  AuthCodeStore,
  verifyPkceChallenge,
  type AuthCodeRequest,
} from "../src/index.js";

const sample: AuthCodeRequest = {
  clientId: "wallet-dev",
  redirectUri: "https://wallet.example.com/cb",
  codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  codeChallengeMethod: "S256",
  issuerState: "offer-42",
  organizationId: "org_abc",
  offerId: "offer_xyz",
};

describe("AuthCodeStore — put + consume", () => {
  it("mints an opaque code with the default TTL", async () => {
    const store = new AuthCodeStore();
    const { code, expiresInSeconds } = await store.put(sample);
    expect(typeof code).toBe("string");
    expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(expiresInSeconds).toBe(AUTH_CODE_TTL_SECONDS);
  });

  it("round-trips the exact bound request", async () => {
    const store = new AuthCodeStore();
    const { code } = await store.put(sample);
    const got = await store.consume(code);
    expect(got).toEqual(sample);
  });

  it("rejects a double-consume (single-use per OAuth §4.1.2)", async () => {
    const store = new AuthCodeStore();
    const { code } = await store.put(sample);
    expect(await store.consume(code)).toEqual(sample);
    expect(await store.consume(code)).toBeUndefined();
  });

  it("rejects an unknown code", async () => {
    const store = new AuthCodeStore();
    expect(await store.consume("nope")).toBeUndefined();
  });

  it("rejects an expired code", async () => {
    const store = new AuthCodeStore();
    const { code } = await store.put(sample, { ttlSeconds: 0 });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(await store.consume(code)).toBeUndefined();
  });

  it("mints distinct codes on every call", async () => {
    const store = new AuthCodeStore();
    const a = await store.put(sample);
    const b = await store.put(sample);
    expect(a.code).not.toBe(b.code);
  });
});

describe("AuthCodeStore — prune", () => {
  it("removes expired entries without touching live ones", async () => {
    const store = new AuthCodeStore();
    const fresh = await store.put(sample, { ttlSeconds: 60 });
    const stale = await store.put(sample, { ttlSeconds: 0 });
    await new Promise((resolve) => setTimeout(resolve, 10));
    store.prune();
    expect(await store.consume(stale.code)).toBeUndefined();
    expect(await store.consume(fresh.code)).toEqual(sample);
  });
});

describe("verifyPkceChallenge — RFC 7636 §4.6 (S256)", () => {
  it("accepts the canonical Appendix B.1 vector", () => {
    // RFC 7636 Appendix B.1
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(verifyPkceChallenge(verifier, challenge, "S256")).toBe(true);
  });

  it("rejects a verifier that hashes to a different challenge", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = "wrongchallenge-xxxxxxxxxxxxxxxxxxxxxxxxxxx";
    expect(verifyPkceChallenge(verifier, challenge, "S256")).toBe(false);
  });

  it("matches an independent SHA-256 + base64url computation", () => {
    const verifier = randomBytes(32).toString("base64url");
    const expected = createHash("sha256").update(verifier).digest("base64url");
    expect(verifyPkceChallenge(verifier, expected, "S256")).toBe(true);
  });

  it("rejects verifiers shorter than 43 characters (RFC 7636 §4.1)", () => {
    // 'short' is below the floor; even with a hash-matching challenge it
    // must be rejected by the length gate.
    const shortVerifier = "tooshort";
    const challenge = createHash("sha256")
      .update(shortVerifier)
      .digest("base64url");
    expect(verifyPkceChallenge(shortVerifier, challenge, "S256")).toBe(false);
  });

  it("rejects verifiers longer than 128 characters", () => {
    const tooLong = "a".repeat(129);
    const challenge = createHash("sha256")
      .update(tooLong)
      .digest("base64url");
    expect(verifyPkceChallenge(tooLong, challenge, "S256")).toBe(false);
  });

  it("rejects verifiers with disallowed characters", () => {
    // Spaces are not in the RFC 7636 unreserved charset.
    const badVerifier = "a a a a a a a a a a a a a a a a a a a a a a";
    expect(badVerifier.length).toBeGreaterThanOrEqual(43);
    const challenge = createHash("sha256")
      .update(badVerifier)
      .digest("base64url");
    expect(verifyPkceChallenge(badVerifier, challenge, "S256")).toBe(false);
  });

  it("rejects malformed inputs without throwing", () => {
    // @ts-expect-error — exercising runtime defenses against bad types.
    expect(verifyPkceChallenge(null, "challenge", "S256")).toBe(false);
    // @ts-expect-error — exercising runtime defenses against bad types.
    expect(verifyPkceChallenge("a".repeat(43), null, "S256")).toBe(false);
    // @ts-expect-error — exercising runtime defenses against bad types.
    expect(verifyPkceChallenge("a".repeat(43), "challenge", "bogus")).toBe(
      false,
    );
  });
});

describe("verifyPkceChallenge — plain (RFC 7636 §4.6, non-HAIP)", () => {
  it("accepts identical verifier+challenge", () => {
    const v = "a".repeat(43);
    expect(verifyPkceChallenge(v, v, "plain")).toBe(true);
  });

  it("rejects mismatched verifier+challenge", () => {
    const v = "a".repeat(43);
    const c = "b".repeat(43);
    expect(verifyPkceChallenge(v, c, "plain")).toBe(false);
  });
});

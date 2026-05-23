/**
 * `generateState` / `generateNonce` — 128-bit randomness conformance for
 * the OID4VP authorization request primitives (§5.3 + §11.2).
 *
 * What we pin:
 *   - `generateState` returns exactly 32 hex chars (16 bytes → 128 bits).
 *   - `generateNonce` returns a base64url-no-pad string that decodes to
 *     exactly 16 bytes (128 bits).
 *   - Each call returns a distinct value — the collision probability
 *     across 1 000 draws of a 128-bit value is < 2^-108, so a single
 *     collision in this test would be a defect, not flakiness.
 */

import { describe, it, expect } from "vitest";
import { generateNonce, generateState } from "../src/index.js";

describe("generateState — 128-bit hex", () => {
  it("returns a 32-char string", () => {
    const s = generateState();
    expect(typeof s).toBe("string");
    expect(s).toHaveLength(32);
  });

  it("uses only hex characters", () => {
    expect(generateState()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("produces distinct values across many calls (collision check)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1_000; i++) {
      seen.add(generateState());
    }
    expect(seen.size).toBe(1_000);
  });
});

describe("generateNonce — 128-bit base64url-no-pad", () => {
  it("returns a string with no base64 padding", () => {
    const n = generateNonce();
    expect(typeof n).toBe("string");
    expect(n).not.toContain("=");
  });

  it("uses only base64url characters", () => {
    expect(generateNonce()).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("decodes to exactly 16 bytes (128 bits)", () => {
    const n = generateNonce();
    const decoded = Buffer.from(n, "base64url");
    expect(decoded.byteLength).toBe(16);
  });

  it("renders as a 22-char string (16 bytes → ceil(16*8/6) chars, unpadded)", () => {
    // 16 bytes = 128 bits → 22 base64url chars (the last char only holds
    // 2 bits of payload). Unpadded length is deterministic.
    expect(generateNonce()).toHaveLength(22);
  });

  it("produces distinct values across many calls (collision check)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1_000; i++) {
      seen.add(generateNonce());
    }
    expect(seen.size).toBe(1_000);
  });
});

describe("state and nonce never collide with each other", () => {
  it("state-vs-nonce values are disjoint (different encoding, different draws)", () => {
    const states = new Set<string>();
    const nonces = new Set<string>();
    for (let i = 0; i < 100; i++) {
      states.add(generateState());
      nonces.add(generateNonce());
    }
    for (const s of states) expect(nonces.has(s)).toBe(false);
  });
});

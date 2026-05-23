/**
 * Code generators — authorization codes (RFC 6749 §4.1.2) and pre-
 * authorized codes (OID4VCI §4.1.1). Both are opaque, base64url, single-
 * use entropy strings; the bind state lives in the corresponding store.
 */

import { describe, it, expect } from "vitest";
import {
  AUTHORIZATION_CODE_BYTES,
  PRE_AUTHORIZED_CODE_BYTES,
  generateAuthorizationCode,
  generatePreAuthorizedCode,
} from "../src/index.js";

describe("generateAuthorizationCode", () => {
  it("emits a base64url string with the default entropy", () => {
    const c = generateAuthorizationCode();
    expect(typeof c).toBe("string");
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
    // base64url(32 bytes) = 43 chars.
    expect(c).toHaveLength(43);
    expect(AUTHORIZATION_CODE_BYTES).toBe(32);
  });

  it("yields fresh randomness on every call", () => {
    expect(generateAuthorizationCode()).not.toBe(generateAuthorizationCode());
  });

  it("honours a per-call byteLength", () => {
    const c = generateAuthorizationCode({ byteLength: 16 });
    // base64url(16 bytes) = 22 chars.
    expect(c).toHaveLength(22);
  });

  it("rejects byteLength below 16", () => {
    expect(() => generateAuthorizationCode({ byteLength: 8 })).toThrow();
  });

  it("rejects byteLength above 128", () => {
    expect(() => generateAuthorizationCode({ byteLength: 256 })).toThrow();
  });

  it("rejects non-integer byteLength", () => {
    expect(() => generateAuthorizationCode({ byteLength: 16.5 })).toThrow();
  });
});

describe("generatePreAuthorizedCode", () => {
  it("emits a base64url string with the default entropy", () => {
    const c = generatePreAuthorizedCode();
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(c).toHaveLength(43);
    expect(PRE_AUTHORIZED_CODE_BYTES).toBe(32);
  });

  it("yields fresh randomness on every call", () => {
    expect(generatePreAuthorizedCode()).not.toBe(generatePreAuthorizedCode());
  });

  it("emits distinct values from generateAuthorizationCode", () => {
    // Same entropy profile but two independent draws — vanishingly unlikely
    // to collide; we just check the calls don't interlock somehow.
    expect(generatePreAuthorizedCode()).not.toBe(generateAuthorizationCode());
  });
});

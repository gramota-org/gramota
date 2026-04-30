/**
 * Unit tests for the IETF Token Status List bit accessor + parser.
 *
 * Covers:
 *   - All 4 bit-widths (1, 2, 4, 8) with the documented LSB-first packing
 *   - Roundtrip: build → parse → getStatus matches what was set
 *   - Index out of range, invalid bits, missing claims, bad zlib, etc.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gateway/jose";
import {
  STATUS_INVALID,
  STATUS_SUSPENDED,
  STATUS_VALID,
  StatusListError,
  buildStatusListToken,
  getStatus,
  parseStatusListToken,
} from "../src/index.js";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

const ISSUER = "https://issuer.example.com";
const LIST_URL = "https://issuer.example.com/status/1";

describe("parseStatusListToken — happy path", () => {
  it("parses a freshly-built bits=1 list and roundtrips initial values", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 16,
      bits: 1,
      privateKey: priv,
      alg: "ES256",
      initial: { 0: 1, 5: 1, 15: 1 },
    });

    const list = parseStatusListToken(token);
    expect(list.bits).toBe(1);
    expect(list.length).toBe(16);
    expect(list.issuer).toBe(ISSUER);
    expect(list.subject).toBe(LIST_URL);

    // Asserted indices
    expect(getStatus(list, 0)).toBe(1);
    expect(getStatus(list, 5)).toBe(1);
    expect(getStatus(list, 15)).toBe(1);
    // Unset indices default to 0
    expect(getStatus(list, 1)).toBe(0);
    expect(getStatus(list, 14)).toBe(0);
  });

  it("preserves issuedAt/expiresAt/ttl when set on build", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: priv,
      alg: "ES256",
      issuedAt: 1700_000_000,
      expiresAt: 1800_000_000,
      ttl: 3600,
    });
    const list = parseStatusListToken(token);
    expect(list.issuedAt).toBe(1700_000_000);
    expect(list.expiresAt).toBe(1800_000_000);
    expect(list.ttl).toBe(3600);
  });
});

describe("getStatus — bit packing across all sizes (LSB-first per spec)", () => {
  it("bits=1: byte 0 = 0b1010_1100 → idx 0..7 = [0,0,1,1,0,1,0,1]", async () => {
    const { priv } = await makeKey();
    // Set a known bit pattern: idx 2,3,5,7 = 1
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      bits: 1,
      privateKey: priv,
      alg: "ES256",
      initial: { 2: 1, 3: 1, 5: 1, 7: 1 },
    });
    const list = parseStatusListToken(token);
    // LSB-first: byte should be 0b10101100 = 0xAC
    expect(list.bytes[0]).toBe(0xac);
    // Each individual index
    expect(getStatus(list, 0)).toBe(0);
    expect(getStatus(list, 1)).toBe(0);
    expect(getStatus(list, 2)).toBe(1);
    expect(getStatus(list, 3)).toBe(1);
    expect(getStatus(list, 4)).toBe(0);
    expect(getStatus(list, 5)).toBe(1);
    expect(getStatus(list, 6)).toBe(0);
    expect(getStatus(list, 7)).toBe(1);
  });

  it("bits=2: 4 statuses per byte; LSBs hold lowest indices", async () => {
    const { priv } = await makeKey();
    // idx 0=0, idx 1=1, idx 2=2, idx 3=3 → byte = 11_10_01_00 = 0xE4
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 4,
      bits: 2,
      privateKey: priv,
      alg: "ES256",
      initial: { 0: 0, 1: 1, 2: 2, 3: 3 },
    });
    const list = parseStatusListToken(token);
    expect(list.bytes[0]).toBe(0xe4);
    expect(getStatus(list, 0)).toBe(0);
    expect(getStatus(list, 1)).toBe(1);
    expect(getStatus(list, 2)).toBe(2);
    expect(getStatus(list, 3)).toBe(3);
  });

  it("bits=4: 2 statuses per byte; idx 0 in low nibble, idx 1 in high nibble", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 2,
      bits: 4,
      privateKey: priv,
      alg: "ES256",
      initial: { 0: 0xa, 1: 0xf },
    });
    const list = parseStatusListToken(token);
    expect(list.bytes[0]).toBe(0xfa); // high=1=0xF, low=0=0xA
    expect(getStatus(list, 0)).toBe(0xa);
    expect(getStatus(list, 1)).toBe(0xf);
  });

  it("bits=8: each byte holds exactly one status", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 4,
      bits: 8,
      privateKey: priv,
      alg: "ES256",
      initial: { 0: 0x42, 1: 0x00, 2: 0xff, 3: 0x77 },
    });
    const list = parseStatusListToken(token);
    expect(list.bytes[0]).toBe(0x42);
    expect(list.bytes[1]).toBe(0x00);
    expect(list.bytes[2]).toBe(0xff);
    expect(list.bytes[3]).toBe(0x77);
    expect(getStatus(list, 0)).toBe(0x42);
    expect(getStatus(list, 2)).toBe(0xff);
  });
});

describe("getStatus — boundary handling", () => {
  it("rejects negative indices", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: priv,
      alg: "ES256",
    });
    const list = parseStatusListToken(token);
    expect(() => getStatus(list, -1)).toThrowError(StatusListError);
  });

  it("rejects indices >= length", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: priv,
      alg: "ES256",
    });
    const list = parseStatusListToken(token);
    try {
      getStatus(list, 8);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe(
        "status_list.index_out_of_range",
      );
    }
  });

  it("rejects non-integer indices", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: priv,
      alg: "ES256",
    });
    const list = parseStatusListToken(token);
    expect(() => getStatus(list, 1.5)).toThrowError(StatusListError);
  });
});

describe("parseStatusListToken — input validation", () => {
  it("rejects non-string token", () => {
    // @ts-expect-error: testing runtime guard
    expect(() => parseStatusListToken(null)).toThrowError(StatusListError);
  });

  it("rejects token without 3 segments", () => {
    expect(() => parseStatusListToken("abc.def")).toThrowError(
      /3 segments/,
    );
  });

  it("rejects payload missing iss/sub/iat", () => {
    const header = Buffer.from('{"alg":"ES256"}', "utf-8").toString(
      "base64url",
    );
    const payload = Buffer.from(
      JSON.stringify({ status_list: { bits: 1, lst: "" } }),
      "utf-8",
    ).toString("base64url");
    const token = `${header}.${payload}.SIG`;
    try {
      parseStatusListToken(token);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe(
        "status_list.invalid_payload",
      );
    }
  });

  it("rejects unsupported bits values", () => {
    const header = Buffer.from('{"alg":"ES256"}', "utf-8").toString(
      "base64url",
    );
    const payload = Buffer.from(
      JSON.stringify({
        iss: "x",
        sub: "y",
        iat: 1,
        status_list: { bits: 3, lst: "a" },
      }),
      "utf-8",
    ).toString("base64url");
    const token = `${header}.${payload}.SIG`;
    try {
      parseStatusListToken(token);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe("status_list.invalid_bits");
    }
  });

  it("rejects garbage zlib data", () => {
    const header = Buffer.from('{"alg":"ES256"}', "utf-8").toString(
      "base64url",
    );
    // base64url("not zlib at all")
    const lst = Buffer.from("not zlib at all", "utf-8").toString(
      "base64url",
    );
    const payload = Buffer.from(
      JSON.stringify({
        iss: "x",
        sub: "y",
        iat: 1,
        status_list: { bits: 1, lst },
      }),
      "utf-8",
    ).toString("base64url");
    const token = `${header}.${payload}.SIG`;
    try {
      parseStatusListToken(token);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe(
        "status_list.invalid_compression",
      );
    }
  });
});

describe("status code constants", () => {
  it("match the IETF spec values", () => {
    expect(STATUS_VALID).toBe(0);
    expect(STATUS_INVALID).toBe(1);
    expect(STATUS_SUSPENDED).toBe(2);
  });
});

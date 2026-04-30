/**
 * Unit tests for x5c primitives.
 *
 * Test material is the real EU public-verifier JAR (cached in
 * tests/fixtures/eu-jar.txt) — a real ES256-signed JWS with an x5c chain
 * that goes leaf → "PID Issuer CA - UT 01". Cert validity window is
 * Feb 2024 → Feb 2026, so all chain-validation tests use a frozen `now`
 * inside that window.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  JoseVerificationError,
  extractPublicKeyFromX5c,
  parseX5cEntry,
  validateX5cChain,
  x5cToPem,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const jar = readFileSync(join(here, "fixtures", "eu-jar.txt"), "utf-8").trim();
const header = JSON.parse(
  Buffer.from(jar.split(".")[0]!, "base64url").toString("utf-8"),
) as { x5c?: string[] };
const x5c = header.x5c!;

// A "now" inside the cert validity window (cert valid 2024-02-26 → 2026-02-25).
const NOW_VALID = new Date("2025-06-01T00:00:00Z");
const NOW_EXPIRED = new Date("2099-01-01T00:00:00Z");

describe("x5cToPem", () => {
  it("wraps a single x5c entry in PEM headers with 64-char line widths", () => {
    const pem = x5cToPem(x5c[0]!);
    expect(pem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    expect(pem.includes("-----END CERTIFICATE-----")).toBe(true);
    // No body line should exceed 64 chars.
    const bodyLines = pem
      .split("\n")
      .filter((l) => !l.startsWith("---") && l.length > 0);
    for (const line of bodyLines) {
      expect(line.length).toBeLessThanOrEqual(64);
    }
  });

  it("rejects empty / non-string input", () => {
    expect(() => x5cToPem("")).toThrow(JoseVerificationError);
    // @ts-expect-error: testing runtime guard
    expect(() => x5cToPem(null)).toThrow(JoseVerificationError);
  });
});

describe("parseX5cEntry", () => {
  it("parses a real EU x5c entry into an X509Certificate", () => {
    const cert = parseX5cEntry(x5c[0]!);
    expect(cert.subject).toContain("EUDI Remote Verifier");
  });

  it("parses every cert in the EU chain", () => {
    for (const entry of x5c) {
      const cert = parseX5cEntry(entry);
      expect(typeof cert.subject).toBe("string");
      expect(cert.subject.length).toBeGreaterThan(0);
    }
  });

  it("rejects a malformed x5c entry", () => {
    try {
      parseX5cEntry("AAAA-not-a-cert");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(JoseVerificationError);
      expect((err as JoseVerificationError).code).toBe("jose.x5c_parse_failed");
    }
  });
});

describe("extractPublicKeyFromX5c", () => {
  it("extracts an EC P-256 JWK from the EU leaf cert", () => {
    const jwk = extractPublicKeyFromX5c(x5c);
    expect(jwk.kty).toBe("EC");
    expect(jwk["crv"]).toBe("P-256");
    expect(typeof jwk["x"]).toBe("string");
    expect(typeof jwk["y"]).toBe("string");
  });

  it("rejects empty x5c", () => {
    try {
      extractPublicKeyFromX5c([]);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe("jose.x5c_empty");
    }
  });

  it("rejects non-array x5c", () => {
    try {
      // @ts-expect-error: testing runtime guard
      extractPublicKeyFromX5c(undefined);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe("jose.x5c_missing");
    }
  });
});

describe("validateX5cChain", () => {
  // Pin the EU CA cert as a trust anchor — this is x5c[1] from the chain.
  // Outside CI we'd fetch this from a known location; for tests we inline it.
  const euCaPem = x5cToPem(x5c[1]!);

  it("validates the EU chain against x5c[1] as a trust anchor inside its validity window", () => {
    const result = validateX5cChain(x5c, {
      trustAnchors: [euCaPem],
      now: NOW_VALID,
    });
    expect(result.leaf.subject).toContain("EUDI Remote Verifier");
    expect(result.chain).toHaveLength(x5c.length);
    expect(result.anchor.fingerprint256).toBe(
      result.chain[result.chain.length - 1]!.fingerprint256,
    );
  });

  it("rejects when the leaf cert is past its validTo date", () => {
    try {
      validateX5cChain(x5c, {
        trustAnchors: [euCaPem],
        now: NOW_EXPIRED,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(JoseVerificationError);
      expect((err as JoseVerificationError).code).toBe(
        "jose.x5c_chain_invalid",
      );
      expect((err as JoseVerificationError).message).toMatch(/expired/);
    }
  });

  it("rejects when the chain doesn't lead to any trust anchor", () => {
    // Use the EU LEAF (not the CA) as the only "anchor" — chain won't reach it.
    const wrongAnchor = x5cToPem(x5c[0]!);
    try {
      validateX5cChain(x5c, {
        trustAnchors: [wrongAnchor],
        now: NOW_VALID,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe(
        "jose.x5c_no_trust_anchor",
      );
    }
  });

  it("rejects when trustAnchors is empty", () => {
    try {
      validateX5cChain(x5c, { trustAnchors: [], now: NOW_VALID });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe("jose.invalid_input");
    }
  });

  it("rejects when x5c is empty", () => {
    try {
      validateX5cChain([], { trustAnchors: [euCaPem], now: NOW_VALID });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe("jose.x5c_empty");
    }
  });
});

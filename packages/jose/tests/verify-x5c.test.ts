/**
 * Tests for verifyJwsWithX5c — the public API for verifying a JWS where the
 * key comes from the x5c JOSE header.
 *
 * Material: the real EU public-verifier JAR. This test proves our SDK can
 * cryptographically verify the signature on a real EU OID4VP authorization
 * request, which is exactly what an integrator would do in production.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  JoseVerificationError,
  verifyJwsWithX5c,
  x5cToPem,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const jar = readFileSync(join(here, "fixtures", "eu-jar.txt"), "utf-8").trim();

const header = JSON.parse(
  Buffer.from(jar.split(".")[0]!, "base64url").toString("utf-8"),
) as { alg?: string; typ?: string; x5c?: string[] };
const x5c = header.x5c!;

const NOW_VALID = new Date("2025-06-01T00:00:00Z");

describe("verifyJwsWithX5c — signature only (no chain validation)", () => {
  it("verifies the real EU JAR signature using x5c[0]", async () => {
    const result = await verifyJwsWithX5c(jar);

    expect(result.alg).toBe("ES256");
    expect(result.header["typ"]).toBe("oauth-authz-req+jwt");
    expect(result.payload["response_type"]).toBe("vp_token");
    expect(typeof result.payload["nonce"]).toBe("string");
    expect(result.chain).toBeUndefined();
  });

  it("rejects a JWS whose payload has been tampered", async () => {
    const segments = jar.split(".");
    const [headerB64, payloadB64, sig] = segments as [string, string, string];
    const tampered = `${headerB64}.${payloadB64.slice(0, -2)}AB.${sig}`;

    try {
      await verifyJwsWithX5c(tampered);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe(
        "jose.signature_invalid",
      );
    }
  });

  it("rejects a JWS whose signature has been tampered", async () => {
    const segments = jar.split(".");
    const [headerB64, payloadB64, sig] = segments as [string, string, string];
    const tampered = `${headerB64}.${payloadB64}.${sig.slice(0, -4)}AAAA`;

    try {
      await verifyJwsWithX5c(tampered);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe(
        "jose.signature_invalid",
      );
    }
  });

  it("rejects when the JOSE header has no x5c", async () => {
    // Build a header with only alg, no x5c.
    const noX5cHeader = Buffer.from(
      JSON.stringify({ alg: "ES256" }),
      "utf-8",
    ).toString("base64url");
    const fakeJws = `${noX5cHeader}.eyJ4Ijoiamlnc2F3In0.AAAA`;

    try {
      await verifyJwsWithX5c(fakeJws);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe("jose.x5c_missing");
    }
  });

  it("rejects when the algorithm is not in the allowlist", async () => {
    try {
      await verifyJwsWithX5c(jar, { algorithms: ["RS256"] });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe(
        "jose.alg_not_allowed",
      );
    }
  });
});

describe("verifyJwsWithX5c — with chain validation", () => {
  const euCaPem = x5cToPem(x5c[1]!);

  it("verifies signature AND validates chain against trusted anchor", async () => {
    const result = await verifyJwsWithX5c(jar, {
      trustAnchors: [euCaPem],
      now: NOW_VALID,
    });

    expect(result.payload["response_type"]).toBe("vp_token");
    expect(result.chain).toBeDefined();
    expect(result.chain?.leaf.subject).toContain("EUDI Remote Verifier");
    expect(result.chain?.anchor.fingerprint256).toBe(
      result.chain?.chain[result.chain.chain.length - 1]!.fingerprint256,
    );
  });

  it("rejects when chain validation succeeds but signature doesn't (wrong tampered body)", async () => {
    // Tamper the payload but keep cert chain intact.
    const segments = jar.split(".");
    const [headerB64, payloadB64, sig] = segments as [string, string, string];
    const tamperedPayload = payloadB64.slice(0, -4) + "ZZZZ";
    const tampered = `${headerB64}.${tamperedPayload}.${sig}`;

    try {
      await verifyJwsWithX5c(tampered, {
        trustAnchors: [euCaPem],
        now: NOW_VALID,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe(
        "jose.signature_invalid",
      );
    }
  });

  it("rejects when the chain doesn't lead to any provided trust anchor", async () => {
    // Provide a self-signed unrelated cert by re-using x5c[0] (the leaf) as the anchor.
    const unrelatedAnchor = x5cToPem(x5c[0]!);
    try {
      await verifyJwsWithX5c(jar, {
        trustAnchors: [unrelatedAnchor],
        now: NOW_VALID,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe(
        "jose.x5c_no_trust_anchor",
      );
    }
  });

  it("rejects when checked at a time outside the cert's validity window", async () => {
    try {
      await verifyJwsWithX5c(jar, {
        trustAnchors: [euCaPem],
        now: new Date("2099-01-01T00:00:00Z"),
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as JoseVerificationError).code).toBe(
        "jose.x5c_chain_invalid",
      );
      expect((err as JoseVerificationError).message).toMatch(/expired/);
    }
  });
});

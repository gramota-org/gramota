import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSdJwt } from "../src/parse.js";
import { verifyHashBinding } from "../src/verify-hash-binding.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "fixtures", "eu-sdjwt-kt");
const readFixture = (name: string): string =>
  readFileSync(join(fixturesDir, name), "utf-8").trim();

describe("verifyHashBinding", () => {
  describe("EU issuance token (all 4 disclosures present)", () => {
    const parsed = parseSdJwt(readFixture("exampleIssuanceSdJwt.txt"));
    const verified = verifyHashBinding(parsed);

    it("matches all 4 disclosures against the _sd digests", () => {
      expect(verified.matchedDisclosures).toHaveLength(4);
      expect(verified.unmatchedDisclosures).toHaveLength(0);
    });

    it("strips _sd and _sd_alg from the reconstructed claims", () => {
      expect(verified.claims).not.toHaveProperty("_sd_alg");
      const address = verified.claims["address"] as Record<string, unknown>;
      expect(address).not.toHaveProperty("_sd");
    });

    it("inserts the disclosed claims under address", () => {
      const address = verified.claims["address"] as Record<string, unknown>;
      expect(address).toEqual({
        street_address: "Schulstr. 12",
        locality: "Schulpforta",
        region: "Sachsen-Anhalt",
        country: "DE",
      });
    });

    it("preserves non-selectively-disclosed top-level claims", () => {
      expect(verified.claims["iss"]).toBe("https://example.com/issuer");
      expect(verified.claims["sub"]).toBe(
        "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      );
      expect(verified.claims["iat"]).toBe(1516239022);
      expect(verified.claims["exp"]).toBe(1735689661);
    });

    it("reports the hash algorithm used", () => {
      expect(verified.hashAlgorithm).toBe("sha-256");
    });
  });

  describe("EU presentation token (2 of 4 disclosures, others withheld)", () => {
    const parsed = parseSdJwt(readFixture("examplePresentationSdJwt.txt"));
    const verified = verifyHashBinding(parsed);

    it("matches only the disclosed claims", () => {
      expect(verified.matchedDisclosures).toHaveLength(2);
      expect(verified.unmatchedDisclosures).toHaveLength(0);
    });

    it("expands only the disclosed address fields, withholds the rest", () => {
      const address = verified.claims["address"] as Record<string, unknown>;
      expect(address).toEqual({
        locality: "Schulpforta",
        region: "Sachsen-Anhalt",
      });
      expect(address).not.toHaveProperty("street_address");
      expect(address).not.toHaveProperty("country");
    });
  });

  describe("security: rejects forged disclosures", () => {
    it("flags a disclosure whose digest is not in any _sd array as unmatched", () => {
      const issuance = readFixture("exampleIssuanceSdJwt.txt");
      const forgedDisclosure = Buffer.from(
        '["forgedSalt","admin","true"]',
        "utf-8",
      ).toString("base64url");
      const tampered = `${issuance}${forgedDisclosure}~`;

      const parsed = parseSdJwt(tampered);
      const verified = verifyHashBinding(parsed);

      expect(verified.unmatchedDisclosures).toHaveLength(1);
      expect(verified.unmatchedDisclosures[0]?.name).toBe("admin");
      expect(verified.claims).not.toHaveProperty("admin");
    });
  });

  describe("hash-algorithm handling", () => {
    it("defaults to sha-256 when _sd_alg is absent", () => {
      const tokenWithoutAlg = synthesizeSdJwt({
        sdAlg: undefined,
        hashAlg: "sha-256",
      });
      const verified = verifyHashBinding(parseSdJwt(tokenWithoutAlg));
      expect(verified.hashAlgorithm).toBe("sha-256");
      expect(verified.matchedDisclosures).toHaveLength(1);
    });

    it("rejects an unsupported _sd_alg", () => {
      const token = synthesizeSdJwt({
        sdAlg: "unicorn-512",
        hashAlg: "sha-256",
      });
      expect(() => verifyHashBinding(parseSdJwt(token))).toThrow(
        /unsupported.*alg/i,
      );
    });
  });
});

// --- helpers ----------------------------------------------------------------

function synthesizeSdJwt(opts: {
  sdAlg: string | undefined;
  hashAlg: "sha-256" | "sha-384" | "sha-512";
}): string {
  const b64u = (s: string): string =>
    Buffer.from(s, "utf-8").toString("base64url");

  const disclosure = b64u('["salt-1","color","blue"]');
  const digest = createHash(opts.hashAlg)
    .update(disclosure)
    .digest("base64url");

  const payloadObj: Record<string, unknown> = {
    iss: "https://example.com/issuer",
    iat: 1700000000,
    _sd: [digest],
  };
  if (opts.sdAlg !== undefined) {
    payloadObj["_sd_alg"] = opts.sdAlg;
  }

  const headerB64 = b64u('{"alg":"ES256"}');
  const payloadB64 = b64u(JSON.stringify(payloadObj));
  return `${headerB64}.${payloadB64}.SIG~${disclosure}~`;
}

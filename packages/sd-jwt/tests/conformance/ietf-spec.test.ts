// Conformance tests against the canonical IETF SD-JWT specification examples.
//
// Test vectors are extracted from
//   draft-ietf-oauth-selective-disclosure-jwt
// via the EU Commission's reference Kotlin implementation
// (refs/eudi-lib-jvm-sdjwt-kt/src/test/kotlin/.../SpecExamples.kt) using
// scripts/extract-spec-examples.mjs.
//
// The IETF examples exercise:
//   - Example 1 (all disclosed): full disclosure of all 8 object claims plus
//     2 array-element disclosures (nationalities).
//   - Example 1 (selective): same issuance with only 4 disclosures presented;
//     undisclosed claims and array elements must be silently withheld.
//   - Example 3 (complex): nested selective disclosure inside `verified_claims`,
//     including a nested SD object inside an array-element disclosure.
//
// Passing all three is the minimum bar for "we implement the spec correctly".

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSdJwt } from "../../src/parse.js";
import { verifyHashBinding } from "../../src/verify-hash-binding.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "..", "fixtures", "ietf-spec");
const readFixture = (name: string): string =>
  readFileSync(join(fixturesDir, `${name}.txt`), "utf-8").trim();

describe("IETF draft-ietf-oauth-selective-disclosure-jwt conformance", () => {
  describe("Example 1 — all 10 disclosures presented", () => {
    const parsed = parseSdJwt(readFixture("spec-example-1-all-disclosed"));
    const verified = verifyHashBinding(parsed);

    it("presents 10 disclosures (8 object claims + 2 array elements)", () => {
      expect(parsed.disclosures).toHaveLength(10);
      const objectDisclosures = parsed.disclosures.filter(
        (d) => d.name !== null,
      );
      const arrayDisclosures = parsed.disclosures.filter(
        (d) => d.name === null,
      );
      expect(objectDisclosures).toHaveLength(8);
      expect(arrayDisclosures).toHaveLength(2);
    });

    it("matches every disclosure (0 unmatched)", () => {
      expect(verified.matchedDisclosures).toHaveLength(10);
      expect(verified.unmatchedDisclosures).toHaveLength(0);
    });

    it("reconstructs all 8 object claims from the spec example", () => {
      expect(verified.claims["given_name"]).toBe("John");
      expect(verified.claims["family_name"]).toBe("Doe");
      expect(verified.claims["email"]).toBe("johndoe@example.com");
      expect(verified.claims["phone_number"]).toBe("+1-202-555-0101");
      expect(verified.claims["phone_number_verified"]).toBe(true);
      expect(verified.claims["birthdate"]).toBe("1940-01-01");
      expect(verified.claims["updated_at"]).toBe(1570000000);
      expect(verified.claims["address"]).toEqual({
        street_address: "123 Main St",
        locality: "Anytown",
        region: "Anystate",
        country: "US",
      });
    });

    it("expands array-element disclosures into the nationalities array", () => {
      expect(verified.claims["nationalities"]).toEqual(["US", "DE"]);
    });

    it("preserves the cnf (key binding) claim and other non-SD claims", () => {
      expect(verified.claims["iss"]).toBe("https://example.com/issuer");
      expect(verified.claims["iat"]).toBe(1683000000);
      expect(verified.claims["exp"]).toBe(1883000000);
      expect(verified.claims["sub"]).toBe("user_42");
      expect(verified.claims["cnf"]).toMatchObject({
        jwk: { kty: "EC", crv: "P-256" },
      });
    });

    it("strips _sd, _sd_alg, and array-element digest objects", () => {
      expect(verified.claims).not.toHaveProperty("_sd");
      expect(verified.claims).not.toHaveProperty("_sd_alg");
      const nats = verified.claims["nationalities"] as unknown[];
      for (const n of nats) {
        expect(typeof n).toBe("string");
      }
    });
  });

  describe("Example 1 — selective presentation (only given_name, family_name, address, US)", () => {
    const parsed = parseSdJwt(readFixture("spec-example-1-selective"));
    const verified = verifyHashBinding(parsed);

    it("presents 4 disclosures", () => {
      expect(parsed.disclosures).toHaveLength(4);
    });

    it("matches all 4 (0 unmatched — nothing forged)", () => {
      expect(verified.matchedDisclosures).toHaveLength(4);
      expect(verified.unmatchedDisclosures).toHaveLength(0);
    });

    it("reveals only the 3 disclosed object claims", () => {
      expect(verified.claims["given_name"]).toBe("John");
      expect(verified.claims["family_name"]).toBe("Doe");
      expect(verified.claims["address"]).toBeDefined();
    });

    it("withholds undisclosed claims (email, phone_number, birthdate, updated_at)", () => {
      expect(verified.claims).not.toHaveProperty("email");
      expect(verified.claims).not.toHaveProperty("phone_number");
      expect(verified.claims).not.toHaveProperty("phone_number_verified");
      expect(verified.claims).not.toHaveProperty("birthdate");
      expect(verified.claims).not.toHaveProperty("updated_at");
    });

    it("nationalities contains only the disclosed element (DE is withheld)", () => {
      expect(verified.claims["nationalities"]).toEqual(["US"]);
    });
  });

  describe("Example 3 — nested SD inside verified_claims", () => {
    const parsed = parseSdJwt(readFixture("spec-example-3-complex"));
    const verified = verifyHashBinding(parsed);

    it("parses without error", () => {
      expect(parsed.payload["verified_claims"]).toBeDefined();
    });

    it("matches every disclosure (0 unmatched)", () => {
      expect(verified.unmatchedDisclosures).toHaveLength(0);
    });

    it("expands the nested verification.time and verification.evidence", () => {
      const vc = verified.claims["verified_claims"] as Record<string, unknown>;
      const verification = vc["verification"] as Record<string, unknown>;
      expect(verification["trust_framework"]).toBe("de_aml");
      expect(verification["time"]).toBe("2012-04-23T18:25Z");
      expect(Array.isArray(verification["evidence"])).toBe(true);
    });

    it("expands the nested claims block (given_name, family_name, address)", () => {
      const vc = verified.claims["verified_claims"] as Record<string, unknown>;
      const claims = vc["claims"] as Record<string, unknown>;
      expect(claims["given_name"]).toBe("Max");
      expect(claims["family_name"]).toBe("Müller");
      expect(claims["address"]).toEqual({
        locality: "Maxstadt",
        postal_code: "12344",
        country: "DE",
        street_address: "Weidenstraße 22",
      });
    });

    it("strips every _sd and _sd_alg from the reconstructed tree", () => {
      const stringified = JSON.stringify(verified.claims);
      expect(stringified).not.toContain('"_sd"');
      expect(stringified).not.toContain('"_sd_alg"');
    });
  });
});

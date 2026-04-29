// Conformance tests against the EU Commission's reference SD-JWT-KT library.
// Fixtures copied from refs/eudi-lib-jvm-sdjwt-kt/src/test/resources/.
// Source: https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt
// License: Apache-2.0.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSdJwt } from "../../src/parse.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "..", "fixtures", "eu-sdjwt-kt");
const readFixture = (name: string): string =>
  readFileSync(join(fixturesDir, name), "utf-8").trim();

describe("EU eudi-lib-jvm-sdjwt-kt conformance", () => {
  describe("exampleIssuanceSdJwt.txt", () => {
    const token = readFixture("exampleIssuanceSdJwt.txt");
    const parsed = parseSdJwt(token);

    it("parses the JWT header (RS256, no typ)", () => {
      expect(parsed.header.alg).toBe("RS256");
      expect(parsed.header.typ).toBeUndefined();
    });

    it("parses the JWT payload with issuer and timestamps", () => {
      expect(parsed.payload.iss).toBe("https://example.com/issuer");
      expect(parsed.payload.iat).toBe(1516239022);
      expect(parsed.payload.exp).toBe(1735689661);
      expect(parsed.payload.sub).toBe("6c5c0a49-b589-431d-bae7-219122a9ec2c");
      expect(parsed.payload._sd_alg).toBe("sha-256");
    });

    it("preserves the nested _sd array under 'address'", () => {
      const address = parsed.payload["address"] as { _sd?: string[] };
      expect(address?._sd).toBeDefined();
      expect(address._sd).toHaveLength(4);
    });

    it("parses 4 selectively-disclosable address claims", () => {
      expect(parsed.disclosures).toHaveLength(4);

      const byName = Object.fromEntries(
        parsed.disclosures.map((d) => [d.name, d.value]),
      );
      expect(byName["street_address"]).toBe("Schulstr. 12");
      expect(byName["locality"]).toBe("Schulpforta");
      expect(byName["region"]).toBe("Sachsen-Anhalt");
      expect(byName["country"]).toBe("DE");
    });

    it("has no key-binding JWT (issuance form)", () => {
      expect(parsed.keyBindingJwt).toBeUndefined();
    });

    it("preserves the signed payload (header.payload) for signature verification", () => {
      const [headerB64, payloadB64] = token.split("~")[0]!.split(".") as [
        string,
        string,
        string,
      ];
      expect(parsed.signedPayload).toBe(`${headerB64}.${payloadB64}`);
    });
  });

  describe("examplePresentationSdJwt.txt", () => {
    const token = readFixture("examplePresentationSdJwt.txt");
    const parsed = parseSdJwt(token);

    it("preserves the same JWT as the issuance form", () => {
      const issuanceJwt = readFixture("exampleIssuanceSdJwt.txt").split("~")[0];
      const presentationJwt = token.split("~")[0];
      expect(presentationJwt).toBe(issuanceJwt);
    });

    it("contains only the 2 selectively-disclosed claims (locality + region)", () => {
      expect(parsed.disclosures).toHaveLength(2);
      const names = parsed.disclosures.map((d) => d.name).sort();
      expect(names).toEqual(["locality", "region"]);
    });

    it("has no key-binding JWT in this example", () => {
      expect(parsed.keyBindingJwt).toBeUndefined();
    });
  });
});

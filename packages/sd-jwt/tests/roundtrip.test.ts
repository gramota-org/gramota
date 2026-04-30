// Roundtrip tests: issue an SD-JWT with our encoder, then parse and verify it
// with our parser + hash-binding verifier. Proves the producer and consumer
// agree on every detail of the spec without needing an external service.

import { describe, it, expect } from "vitest";
import {
  issueSdJwt,
  stubSignature,
  deterministicSalts,
} from "../src/issue.js";
import { parseSdJwt } from "../src/parse.js";
import { verifyHashBinding } from "../src/verify-hash-binding.js";

const PAYLOAD = {
  iss: "https://issuer.example.com",
  iat: 1700000000,
  exp: 1800000000,
  sub: "user_42",
};

const SD_CLAIMS = {
  given_name: "John",
  family_name: "Doe",
  email: "johndoe@example.com",
  birthdate: "1940-01-01",
  address: {
    street_address: "123 Main St",
    locality: "Anytown",
    country: "US",
  },
};

describe("roundtrip: issue → parse → verifyHashBinding", () => {
  it("recovers all selectively-disclosable claims when all disclosures are presented", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: PAYLOAD,
      sdClaims: SD_CLAIMS,
      alg: "ES256",
      typ: "vc+sd-jwt",
      signer: stubSignature,
    });

    const parsed = parseSdJwt(token);
    const verified = verifyHashBinding(parsed);

    expect(parsed.header.alg).toBe("ES256");
    expect(parsed.header.typ).toBe("vc+sd-jwt");
    expect(disclosures).toHaveLength(Object.keys(SD_CLAIMS).length);

    expect(verified.matchedDisclosures).toHaveLength(disclosures.length);
    expect(verified.unmatchedDisclosures).toHaveLength(0);

    for (const [name, value] of Object.entries(SD_CLAIMS)) {
      expect(verified.claims[name]).toEqual(value);
    }
    for (const [name, value] of Object.entries(PAYLOAD)) {
      expect(verified.claims[name]).toEqual(value);
    }
    expect(verified.claims).not.toHaveProperty("_sd");
    expect(verified.claims).not.toHaveProperty("_sd_alg");
  });

  it("withholds undisclosed claims when only some disclosures are presented", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: PAYLOAD,
      sdClaims: SD_CLAIMS,
      alg: "ES256",
      signer: stubSignature,
    });

    // Simulate selective presentation: drop everything except given_name + address.
    const keep = new Set(["given_name", "address"]);
    const kept = disclosures.filter(
      (d) => d.name !== null && keep.has(d.name),
    );
    const [jwt] = token.split("~") as [string, ...string[]];
    const presentationToken = `${jwt}~${kept.map((d) => d.raw).join("~")}~`;

    const parsed = parseSdJwt(presentationToken);
    const verified = verifyHashBinding(parsed);

    expect(verified.matchedDisclosures).toHaveLength(2);
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.claims["given_name"]).toBe("John");
    expect(verified.claims["address"]).toEqual(SD_CLAIMS.address);

    expect(verified.claims).not.toHaveProperty("family_name");
    expect(verified.claims).not.toHaveProperty("email");
    expect(verified.claims).not.toHaveProperty("birthdate");
  });

  it("flags forged disclosures injected into a presentation", async () => {
    const { token } = await issueSdJwt({
      payload: PAYLOAD,
      sdClaims: SD_CLAIMS,
      alg: "ES256",
      signer: stubSignature,
    });

    // Forge a disclosure for a claim the issuer never signed.
    const forged = Buffer.from(
      '["forged-salt-1234567890","admin",true]',
      "utf-8",
    ).toString("base64url");
    const tampered = `${token}${forged}~`;

    const parsed = parseSdJwt(tampered);
    const verified = verifyHashBinding(parsed);

    expect(verified.unmatchedDisclosures).toHaveLength(1);
    expect(verified.unmatchedDisclosures[0]?.name).toBe("admin");
    expect(verified.claims).not.toHaveProperty("admin");
  });

  it("produces deterministic output with deterministic salts", async () => {
    const fixedSalts = [
      "salt-aaaaaaaaaaaaaaaa",
      "salt-bbbbbbbbbbbbbbbb",
      "salt-cccccccccccccccc",
    ];

    const issue = (): Promise<{ token: string }> =>
      issueSdJwt({
        payload: { iss: "https://issuer.example.com", iat: 1700000000 },
        sdClaims: { color: "blue", size: "large", weight: 42 },
        alg: "ES256",
        signer: () => "fixed-sig",
        saltGenerator: deterministicSalts(fixedSalts),
      });

    const a = await issue();
    const b = await issue();

    expect(a.token).toBe(b.token);
  });

  it("roundtrips correctly across all three SHA hash algorithms", async () => {
    for (const hashAlg of ["sha-256", "sha-384", "sha-512"] as const) {
      const { token, disclosures } = await issueSdJwt({
        payload: PAYLOAD,
        sdClaims: { color: "red" },
        alg: "ES256",
        signer: stubSignature,
        hashAlg,
      });

      const verified = verifyHashBinding(parseSdJwt(token));
      expect(verified.hashAlgorithm).toBe(hashAlg);
      expect(verified.matchedDisclosures).toHaveLength(1);
      expect(verified.unmatchedDisclosures).toHaveLength(0);
      expect(verified.claims["color"]).toBe("red");
      expect(disclosures[0]?.value).toBe("red");
    }
  });

  it("emits a token with no disclosures when no sdClaims are provided", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: PAYLOAD,
      alg: "ES256",
      signer: stubSignature,
    });

    expect(disclosures).toHaveLength(0);
    // The token must still end with `~` per spec.
    expect(token.endsWith("~")).toBe(true);
    expect(token.split("~")).toHaveLength(2); // [JWT, ""]

    const parsed = parseSdJwt(token);
    expect(parsed.disclosures).toHaveLength(0);
    expect(parsed.payload).not.toHaveProperty("_sd");
    expect(parsed.payload).not.toHaveProperty("_sd_alg");
  });

  it("rejects an empty signer return value", async () => {
    await expect(
      issueSdJwt({
        payload: PAYLOAD,
        alg: "ES256",
        signer: () => "",
      }),
    ).rejects.toThrow(/empty signature/);
  });

  it("rejects a missing alg", async () => {
    await expect(
      issueSdJwt({
        payload: PAYLOAD,
        // @ts-expect-error: testing runtime guard
        alg: "",
        signer: stubSignature,
      }),
    ).rejects.toThrow(/alg is required/);
  });
});

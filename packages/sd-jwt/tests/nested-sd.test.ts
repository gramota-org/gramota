// Nested object-property and array-element selective disclosure.
//
// Covers IETF SD-JWT §4.2.4 (nested SD in objects) and §4.2.5 (array-element
// SD). The encoder produces three kinds of disclosure:
//
//   1. Top-level object-property — `sdClaims: { name: value }`
//   2. Nested object-property   — `sd(value)` inside an object
//   3. Array-element             — `sd(value)` inside an array
//
// Each test issues an SD-JWT, parses it back, and confirms the disclosed
// claims reconstruct correctly via the verifier — i.e. the issuer side
// produces exactly what the existing verifier expects.

import { describe, it, expect } from "vitest";
import {
  deterministicSalts,
  issueSdJwt,
  sd,
  stubSignature,
} from "../src/issue.js";
import { parseSdJwt } from "../src/parse.js";
import { verifyHashBinding } from "../src/verify-hash-binding.js";

describe("nested SD: sd() inside an object property", () => {
  it("emits a nested _sd array on the parent object", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        address: {
          street_address: sd("Schulstr. 12"),
          locality: sd("Schulpforta"),
          country: "DE", // not SD — stays plain
        },
      },
      alg: "ES256",
      signer: stubSignature,
    });

    expect(disclosures).toHaveLength(2);

    const parsed = parseSdJwt(token);
    const address = parsed.payload["address"] as Record<string, unknown>;

    // Plain claim still present
    expect(address["country"]).toBe("DE");
    // SD claims removed from visible tree
    expect(address).not.toHaveProperty("street_address");
    expect(address).not.toHaveProperty("locality");
    // _sd array carries the digests
    expect(Array.isArray(address["_sd"])).toBe(true);
    expect((address["_sd"] as string[]).length).toBe(2);
    // Disclosures are object-property (arity 3): each has a name
    expect(disclosures.every((d) => d.name !== null)).toBe(true);
  });

  it("hash binding recovers the nested SD claims when all disclosures are presented", async () => {
    const { token } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        address: {
          street_address: sd("Schulstr. 12"),
          locality: sd("Schulpforta"),
          country: "DE",
        },
      },
      alg: "ES256",
      signer: stubSignature,
    });

    const verified = verifyHashBinding(parseSdJwt(token));
    expect(verified.unmatchedDisclosures).toHaveLength(0);

    const address = verified.claims["address"] as Record<string, unknown>;
    expect(address).toEqual({
      street_address: "Schulstr. 12",
      locality: "Schulpforta",
      country: "DE",
    });
  });

  it("withholds undisclosed nested claims when only some disclosures are presented", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        address: {
          street_address: sd("Schulstr. 12"),
          locality: sd("Schulpforta"),
          region: sd("Sachsen-Anhalt"),
          country: "DE",
        },
      },
      alg: "ES256",
      signer: stubSignature,
    });

    // Holder presents only the `locality` disclosure.
    const kept = disclosures.filter((d) => d.name === "locality");
    const [jwt] = token.split("~") as [string, ...string[]];
    const presentation = `${jwt}~${kept.map((d) => d.raw).join("~")}~`;

    const verified = verifyHashBinding(parseSdJwt(presentation));
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.matchedDisclosures).toHaveLength(1);

    const address = verified.claims["address"] as Record<string, unknown>;
    expect(address["locality"]).toBe("Schulpforta");
    expect(address["country"]).toBe("DE"); // plain — always visible
    expect(address).not.toHaveProperty("street_address");
    expect(address).not.toHaveProperty("region");
  });

  it("supports nested SD inside an sdClaims top-level entry", async () => {
    // The top-level entry produces an object-property disclosure whose
    // disclosed VALUE itself carries a nested `_sd` array — exactly the
    // shape IETF SD-JWT §4.2.4 calls out for hierarchical claim sets.
    const { token, disclosures } = await issueSdJwt({
      payload: { iss: "https://issuer.example.com" },
      sdClaims: {
        verified_claims: {
          trust_framework: "de_aml",
          time: sd("2012-04-23T18:25Z"),
          verification_process: sd("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7"),
        },
      },
      alg: "ES256",
      signer: stubSignature,
    });

    // 1 top-level disclosure for `verified_claims` plus 2 nested ones
    // (time, verification_process).
    expect(disclosures).toHaveLength(3);

    const verified = verifyHashBinding(parseSdJwt(token));
    const vc = verified.claims["verified_claims"] as Record<string, unknown>;
    expect(vc).toEqual({
      trust_framework: "de_aml",
      time: "2012-04-23T18:25Z",
      verification_process: "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
    });
  });
});

describe("array-element SD: sd() as an array entry", () => {
  it("emits arity-2 disclosures and {\"...\": digest} array slots", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        nationalities: [sd("DE"), sd("US"), "FR"],
      },
      alg: "ES256",
      signer: stubSignature,
    });

    expect(disclosures).toHaveLength(2);
    // Array-element disclosures have null name (arity 2).
    for (const d of disclosures) {
      if (d.value === "DE" || d.value === "US") {
        expect(d.name).toBeNull();
      }
    }

    const parsed = parseSdJwt(token);
    const nats = parsed.payload["nationalities"] as unknown[];
    expect(nats).toHaveLength(3);

    // Two SD slots are `{"...": digest}` objects; one plain string.
    const sdSlots = nats.filter(
      (n) =>
        typeof n === "object" &&
        n !== null &&
        "..." in (n as object),
    );
    const plainSlots = nats.filter((n) => typeof n === "string");
    expect(sdSlots).toHaveLength(2);
    expect(plainSlots).toEqual(["FR"]);
  });

  it("hash binding recovers array elements when all are disclosed", async () => {
    const { token } = await issueSdJwt({
      payload: {
        nationalities: [sd("DE"), sd("US"), "FR"],
      },
      alg: "ES256",
      signer: stubSignature,
    });

    const verified = verifyHashBinding(parseSdJwt(token));
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    // Order: DE (SD, disclosed), US (SD, disclosed), FR (plain). Plain
    // elements stay in their original slot; SD ones are placed where their
    // `{"...": digest}` object stood.
    expect(verified.claims["nationalities"]).toEqual(["DE", "US", "FR"]);
  });

  it("drops withheld array elements (selective presentation)", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: {
        nationalities: [sd("DE"), sd("US"), "FR"],
      },
      alg: "ES256",
      signer: stubSignature,
    });

    // Disclose only the DE element; the US slot must vanish from the verifier's
    // reconstructed array, the plain FR element stays.
    const kept = disclosures.filter((d) => d.value === "DE");
    const [jwt] = token.split("~") as [string, ...string[]];
    const presentation = `${jwt}~${kept.map((d) => d.raw).join("~")}~`;

    const verified = verifyHashBinding(parseSdJwt(presentation));
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.claims["nationalities"]).toEqual(["DE", "FR"]);
  });

  it("flags forged array-element disclosures as unmatched", async () => {
    const { token } = await issueSdJwt({
      payload: {
        nationalities: [sd("DE"), "FR"],
      },
      alg: "ES256",
      signer: stubSignature,
    });

    // Forge an arity-2 disclosure for a value the issuer never signed —
    // the verifier must see it as unmatched, not silently splice it in.
    const forged = Buffer.from(
      JSON.stringify(["forged-salt-1234567890", "CN"]),
      "utf-8",
    ).toString("base64url");
    const tampered = `${token}${forged}~`;

    const verified = verifyHashBinding(parseSdJwt(tampered));
    expect(verified.unmatchedDisclosures).toHaveLength(1);
    expect(verified.unmatchedDisclosures[0]?.value).toBe("CN");
    expect(verified.unmatchedDisclosures[0]?.name).toBeNull();
    // The reconstructed array does NOT contain "CN".
    expect(verified.claims["nationalities"]).toEqual(["DE", "FR"]);
  });
});

describe("nested SD: deep recursion through objects and arrays", () => {
  it("handles SD inside an SD-wrapped value (two levels deep)", async () => {
    const { token } = await issueSdJwt({
      payload: { iss: "https://issuer.example.com" },
      sdClaims: {
        // The whole `birth_info` object is itself SD; INSIDE it, two more
        // fields are also SD. The verifier expanding the outer disclosure
        // sees a nested `_sd` array and recurses to expand those too.
        birth_info: {
          country: sd("DE"),
          place: sd("Berlin"),
          year: 1990,
        },
      },
      alg: "ES256",
      signer: stubSignature,
    });

    const verified = verifyHashBinding(parseSdJwt(token));
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.claims["birth_info"]).toEqual({
      country: "DE",
      place: "Berlin",
      year: 1990,
    });
  });

  it("handles an SD-wrapped value inside an array element", async () => {
    // An array of address records — each entry is an SD object so the
    // holder can disclose individual addresses; inside, the fields are
    // also SD so the holder can disclose individual fields within the
    // chosen address.
    const { token } = await issueSdJwt({
      payload: {
        addresses: [
          sd({
            street_address: sd("Main St 1"),
            country: "DE",
          }),
          sd({
            street_address: sd("Second Ave 5"),
            country: "US",
          }),
        ],
      },
      alg: "ES256",
      signer: stubSignature,
    });

    const verified = verifyHashBinding(parseSdJwt(token));
    expect(verified.unmatchedDisclosures).toHaveLength(0);

    const addrs = verified.claims["addresses"] as unknown[];
    expect(addrs).toHaveLength(2);
    expect(addrs[0]).toEqual({ street_address: "Main St 1", country: "DE" });
    expect(addrs[1]).toEqual({ street_address: "Second Ave 5", country: "US" });
  });
});

describe("sd() marker: error cases and edge behavior", () => {
  it("rejects double-wrapped sd(sd(...)) markers", async () => {
    // Wrapping a value in sd() twice doesn't mean "extra disclosable" —
    // it's a usage bug. Throwing here surfaces the mistake at issue time
    // rather than producing a structurally-wrong disclosure that fails to
    // verify later (much harder to debug).
    await expect(
      issueSdJwt({
        payload: { a: sd(sd("nope")) },
        alg: "ES256",
        signer: stubSignature,
      }),
    ).rejects.toThrow(/sd\(\) marker can only appear/);
  });

  it("a symbol-keyed marker is opaque to JSON — payload is a plain object", async () => {
    // The sd() marker uses a non-enumerable symbol key. Object.entries
    // returns no entries for it, and JSON.stringify drops symbols, so the
    // marker is invisible at the wire level. A caller that accidentally
    // wraps the entire payload root produces an empty payload (no claims),
    // which is the same outcome as passing `payload: {}`. Documenting this
    // explicitly here so the behaviour is intentional, not surprising.
    const result = await issueSdJwt({
      // @ts-expect-error: testing runtime behaviour — root should be an
      // object, not an SD-wrapped value.
      payload: sd({ iss: "x" }),
      alg: "ES256",
      signer: stubSignature,
    });
    // No claims emitted; trailing-tilde token.
    expect(result.disclosures).toHaveLength(0);
    expect(result.token.endsWith("~")).toBe(true);
    expect(parseSdJwt(result.token).payload).toEqual({});
  });

  it("emits _sd_alg exactly when at least one disclosure is produced", async () => {
    // No SD anywhere → no _sd_alg.
    const plain = await issueSdJwt({
      payload: { iss: "x", a: 1 },
      alg: "ES256",
      signer: stubSignature,
    });
    expect(parseSdJwt(plain.token).payload["_sd_alg"]).toBeUndefined();

    // Nested SD only → _sd_alg present.
    const nested = await issueSdJwt({
      payload: { iss: "x", a: sd(1) },
      alg: "ES256",
      signer: stubSignature,
    });
    expect(parseSdJwt(nested.token).payload["_sd_alg"]).toBe("sha-256");

    // Top-level sdClaims only → _sd_alg present.
    const top = await issueSdJwt({
      payload: { iss: "x" },
      sdClaims: { a: 1 },
      alg: "ES256",
      signer: stubSignature,
    });
    expect(parseSdJwt(top.token).payload["_sd_alg"]).toBe("sha-256");
  });

  it("each disclosure (nested or top-level) gets a fresh salt", async () => {
    // Use deterministic salts so we can assert the encoder consumes one
    // per emitted disclosure — top-level entries plus every nested sd().
    const { disclosures } = await issueSdJwt({
      payload: {
        address: {
          street: sd("A"),
          city: sd("B"),
        },
      },
      sdClaims: { given_name: "Alice" },
      alg: "ES256",
      signer: stubSignature,
      saltGenerator: deterministicSalts(["s1", "s2", "s3"]),
    });

    expect(disclosures).toHaveLength(3);
    expect(new Set(disclosures.map((d) => d.salt))).toEqual(
      new Set(["s1", "s2", "s3"]),
    );
  });

  it("top-level sdClaims and nested sd() can coexist in the same call", async () => {
    const { token, disclosures } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        address: {
          street: sd("Main St"),
          country: "DE",
        },
        nationalities: [sd("DE"), "FR"],
      },
      sdClaims: {
        given_name: "Alice",
      },
      alg: "ES256",
      signer: stubSignature,
    });

    // 1 (given_name) + 1 (street) + 1 (DE nationality) = 3.
    expect(disclosures).toHaveLength(3);

    const verified = verifyHashBinding(parseSdJwt(token));
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.claims["given_name"]).toBe("Alice");
    expect(verified.claims["address"]).toEqual({
      street: "Main St",
      country: "DE",
    });
    expect(verified.claims["nationalities"]).toEqual(["DE", "FR"]);
  });
});

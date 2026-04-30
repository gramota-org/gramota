// Sign + verify roundtrip — proves our signJws and verifyJws are mutually
// consistent across all supported asymmetric algorithms.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import { signJws } from "../src/sign.js";
import { verifyJws } from "../src/verify.js";
import {
  JoseVerificationError,
  type JsonWebKey,
  type SupportedAlg,
} from "../src/types.js";

async function makeKeyPair(
  alg: SupportedAlg,
): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair(alg, {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

describe("signJws + verifyJws roundtrip", () => {
  const payload = {
    iss: "https://issuer.example.com",
    sub: "alice",
    iat: 1700000000,
  };

  it.each(["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"] as const)(
    "roundtrips %s",
    async (alg) => {
      const { pub, priv } = await makeKeyPair(alg);
      const jws = await signJws(payload, priv, { alg });
      const verified = await verifyJws(jws, pub);
      expect(verified.alg).toBe(alg);
      expect(verified.payload).toEqual(payload);
    },
  );

  it("sets typ in the header when provided", async () => {
    const { pub, priv } = await makeKeyPair("ES256");
    const jws = await signJws(payload, priv, { alg: "ES256", typ: "kb+jwt" });
    const verified = await verifyJws(jws, pub);
    expect(verified.header["typ"]).toBe("kb+jwt");
  });

  it("rejects alg=none at the type system + runtime", async () => {
    const { priv } = await makeKeyPair("ES256");
    await expect(
      signJws(payload, priv, {
        // @ts-expect-error: SupportedAlg never contains 'none'
        alg: "none",
      }),
    ).rejects.toBeInstanceOf(JoseVerificationError);
  });

  it("propagates jose's algorithm-mismatch error when alg doesn't match key", async () => {
    const { priv } = await makeKeyPair("ES256");
    await expect(
      signJws(payload, priv, { alg: "RS256" }),
    ).rejects.toBeInstanceOf(JoseVerificationError);
  });

  it("rejects a non-object payload", async () => {
    const { priv } = await makeKeyPair("ES256");
    await expect(
      // @ts-expect-error: testing runtime guard
      signJws("not an object", priv, { alg: "ES256" }),
    ).rejects.toBeInstanceOf(JoseVerificationError);
  });
});

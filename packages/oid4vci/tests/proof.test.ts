import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import { JwkSigner, verifyJws, type JsonWebKey, type Signer } from "@gramota/jose";
import { buildProofJwt } from "../src/index.js";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

describe("buildProofJwt — default JwkSigner", () => {
  it("produces a valid signed JWT verifiable with the embedded jwk", async () => {
    const { pub, priv } = await makeKey();
    const signer = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    const jwt = await buildProofJwt({
      audience: "https://issuer.example.com",
      signer,
      nonce: "c-nonce-1",
      iat: 1700000000,
    });

    // Verify the proof using the public key (which an issuer would do).
    const verified = await verifyJws(jwt, pub);
    expect(verified.alg).toBe("ES256");
    expect(verified.header["typ"]).toBe("openid4vci-proof+jwt");
    expect(verified.payload["aud"]).toBe("https://issuer.example.com");
    expect(verified.payload["iat"]).toBe(1700000000);
    expect(verified.payload["nonce"]).toBe("c-nonce-1");
  });

  it("embeds the holder's public JWK in the JOSE header (jwk parameter)", async () => {
    const { pub, priv } = await makeKey();
    const signer = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    const jwt = await buildProofJwt({
      audience: "https://issuer.example.com",
      signer,
      iat: 1700000000,
    });
    const headerB64 = jwt.split(".")[0]!;
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf-8"),
    ) as { jwk?: JsonWebKey };
    expect(header.jwk).toEqual(pub);
  });

  it("omits nonce when not supplied", async () => {
    const { pub, priv } = await makeKey();
    const signer = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    const jwt = await buildProofJwt({
      audience: "https://issuer.example.com",
      signer,
      iat: 1700000000,
    });
    const verified = await verifyJws(jwt, pub);
    expect(verified.payload["nonce"]).toBeUndefined();
  });

  it("includes iss when provided", async () => {
    const { pub, priv } = await makeKey();
    const signer = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    const jwt = await buildProofJwt({
      audience: "https://issuer.example.com",
      signer,
      iat: 1700000000,
      iss: "https://wallet.example.com",
    });
    const verified = await verifyJws(jwt, pub);
    expect(verified.payload["iss"]).toBe("https://wallet.example.com");
  });
});

describe("buildProofJwt — custom Signer (extensibility / HSM-style)", () => {
  it("accepts any Signer; the orchestrator never sees the private key", async () => {
    const { pub, priv } = await makeKey();
    let signCallCount = 0;

    // Stand-in for an HSM/WebAuthn signer: implements Signer without
    // exposing a private key on the instance. The actual signing here
    // delegates to a JwkSigner under the hood for test simplicity, but
    // the surface contract is identical to a real hardware-backed signer.
    class CapturingSigner implements Signer {
      readonly publicKey = pub;
      readonly alg = "ES256" as const;
      private readonly inner = new JwkSigner({
        publicKey: pub,
        privateKey: priv,
        alg: "ES256",
      });
      async sign(signedPayload: string): Promise<string> {
        signCallCount++;
        return await this.inner.sign(signedPayload);
      }
    }

    const jwt = await buildProofJwt({
      audience: "https://issuer.example.com",
      signer: new CapturingSigner(),
      iat: 1700000000,
    });

    expect(signCallCount).toBe(1);
    const verified = await verifyJws(jwt, pub);
    expect(verified.alg).toBe("ES256");
    expect(verified.payload["aud"]).toBe("https://issuer.example.com");
  });
});

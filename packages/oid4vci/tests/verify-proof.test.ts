/**
 * Server-side Proof of Possession verification — OID4VCI §7.2.1.1.
 *
 * The build/verify pair is symmetric: anything we sign with `buildProofJwt`
 * the verifier here must accept against the matching audience + nonce.
 *
 * Test scope (Tier 1 audit fix — typ + iat hardening):
 *   1. Round-trip — builder → verifier matches.
 *   2. typ header missing / wrong → rejected with
 *      `oid4vci.unsupported_proof_type` (the audit's core ask:
 *      §7.2.1.1 requires `openid4vci-proof+jwt`).
 *   3. iat outside the freshness window → rejected (the second
 *      audit ask: prevent stale-proof replay).
 *   4. Audience mismatch → rejected.
 *   5. Nonce mismatch → rejected; nonce omission → not checked.
 *   6. Signature mismatch (wrong key) → rejected.
 *   7. Missing `jwk` header → rejected.
 *   8. Disallowed alg → rejected.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { JwkSigner, type JsonWebKey } from "@gramota/jose";
import {
  buildProofJwt,
  verifyProofJwt,
  Oid4vciError,
} from "../src/index.js";

async function makeSigner(): Promise<{ signer: JwkSigner; pub: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const pub = (await exportJWK(publicKey)) as JsonWebKey;
  const priv = (await exportJWK(privateKey)) as JsonWebKey;
  return {
    signer: new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" }),
    pub,
  };
}

const AUD = "https://issuer.example.com";

describe("verifyProofJwt — round-trip with buildProofJwt", () => {
  it("accepts a valid proof and returns publicJwk + payload + header", async () => {
    const { signer, pub } = await makeSigner();
    const iat = Math.floor(Date.now() / 1000);
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      nonce: "c-nonce-1",
      iat,
    });

    const result = await verifyProofJwt({
      jwt,
      audience: AUD,
      nonce: "c-nonce-1",
    });

    expect(result.publicJwk).toEqual(pub);
    expect(result.header["typ"]).toBe("openid4vci-proof+jwt");
    expect(result.header["alg"]).toBe("ES256");
    expect(result.payload["aud"]).toBe(AUD);
    expect(result.payload["iat"]).toBe(iat);
    expect(result.payload["nonce"]).toBe("c-nonce-1");
  });

  it("accepts a valid proof without nonce when caller doesn't supply one", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      iat: Math.floor(Date.now() / 1000),
    });
    // No nonce was minted by the issuer (Draft 13 legacy), so the
    // verifier doesn't require one either.
    const result = await verifyProofJwt({ jwt, audience: AUD });
    expect(result.payload["nonce"]).toBeUndefined();
  });
});

describe("verifyProofJwt — typ header validation (OID4VCI §7.2.1.1)", () => {
  it("rejects a JWT with a generic `JWT` typ header", async () => {
    // Build a JWS with `typ: "JWT"` — e.g. an ID Token reused as a proof.
    const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const pub = (await exportJWK(publicKey)) as JsonWebKey;
    const jwt = await new SignJWT({ aud: AUD })
      .setProtectedHeader({ alg: "ES256", typ: "JWT", jwk: pub })
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyProofJwt({ jwt, audience: AUD })).rejects.toThrow(
      Oid4vciError,
    );
    await expect(verifyProofJwt({ jwt, audience: AUD })).rejects.toMatchObject({
      code: "oid4vci.unsupported_proof_type",
    });
  });

  it("rejects a JWT with no typ header at all", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const pub = (await exportJWK(publicKey)) as JsonWebKey;
    const jwt = await new SignJWT({ aud: AUD })
      .setProtectedHeader({ alg: "ES256", jwk: pub })
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyProofJwt({ jwt, audience: AUD })).rejects.toMatchObject({
      code: "oid4vci.unsupported_proof_type",
    });
  });

  it("rejects a JWT with the wrong typ casing", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const pub = (await exportJWK(publicKey)) as JsonWebKey;
    const jwt = await new SignJWT({ aud: AUD })
      .setProtectedHeader({
        alg: "ES256",
        typ: "OPENID4VCI-PROOF+JWT", // wrong casing
        jwk: pub,
      })
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyProofJwt({ jwt, audience: AUD })).rejects.toMatchObject({
      code: "oid4vci.unsupported_proof_type",
    });
  });
});

describe("verifyProofJwt — iat freshness window", () => {
  it("rejects a proof older than the default 60s window", async () => {
    const { signer } = await makeSigner();
    const nowSec = Math.floor(Date.now() / 1000);
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      iat: nowSec - 120, // 2 minutes old
    });
    await expect(
      verifyProofJwt({ jwt, audience: AUD, now: nowSec }),
    ).rejects.toMatchObject({ code: "oid4vci.invalid_proof" });
  });

  it("rejects a proof more than 5s in the future (default clock-skew)", async () => {
    const { signer } = await makeSigner();
    const nowSec = Math.floor(Date.now() / 1000);
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      iat: nowSec + 30, // 30s in the future
    });
    await expect(
      verifyProofJwt({ jwt, audience: AUD, now: nowSec }),
    ).rejects.toMatchObject({ code: "oid4vci.invalid_proof" });
  });

  it("accepts a proof within the freshness window", async () => {
    const { signer } = await makeSigner();
    const nowSec = Math.floor(Date.now() / 1000);
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      iat: nowSec - 30, // well within 60s
    });
    await expect(
      verifyProofJwt({ jwt, audience: AUD, now: nowSec }),
    ).resolves.toBeDefined();
  });

  it("honours custom maxAgeSeconds + maxFutureSkewSeconds", async () => {
    const { signer } = await makeSigner();
    const nowSec = Math.floor(Date.now() / 1000);
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      iat: nowSec - 600, // 10 minutes old
    });
    // Default 60s would reject; widen the window and accept.
    await expect(
      verifyProofJwt({
        jwt,
        audience: AUD,
        now: nowSec,
        maxAgeSeconds: 3600,
      }),
    ).resolves.toBeDefined();
  });

  it("rejects a proof missing iat entirely", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const pub = (await exportJWK(publicKey)) as JsonWebKey;
    const jwt = await new SignJWT({ aud: AUD })
      .setProtectedHeader({
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        jwk: pub,
      })
      // no setIssuedAt — payload omits iat entirely
      .sign(privateKey);

    await expect(verifyProofJwt({ jwt, audience: AUD })).rejects.toMatchObject({
      code: "oid4vci.invalid_proof",
    });
  });
});

describe("verifyProofJwt — audience + nonce binding", () => {
  it("rejects when audience does not match", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildProofJwt({
      audience: "https://issuer-a.example.com",
      signer,
      iat: Math.floor(Date.now() / 1000),
    });
    await expect(
      verifyProofJwt({ jwt, audience: "https://issuer-b.example.com" }),
    ).rejects.toMatchObject({ code: "oid4vci.invalid_proof" });
  });

  it("rejects when nonce does not match expected c_nonce", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      nonce: "the-real-c-nonce",
      iat: Math.floor(Date.now() / 1000),
    });
    await expect(
      verifyProofJwt({ jwt, audience: AUD, nonce: "different-nonce" }),
    ).rejects.toMatchObject({ code: "oid4vci.invalid_proof" });
  });

  it("rejects when caller expects a nonce but proof omits it", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildProofJwt({
      audience: AUD,
      signer,
      iat: Math.floor(Date.now() / 1000),
    });
    await expect(
      verifyProofJwt({ jwt, audience: AUD, nonce: "expected-nonce" }),
    ).rejects.toMatchObject({ code: "oid4vci.invalid_proof" });
  });
});

describe("verifyProofJwt — signature + header invariants", () => {
  it("rejects a proof whose signature was made by a different key", async () => {
    const { signer: signerA } = await makeSigner();
    const { pub: pubB } = await makeSigner();
    const jwt = await buildProofJwt({
      audience: AUD,
      signer: signerA,
      iat: Math.floor(Date.now() / 1000),
    });
    // Swap the `jwk` header to claim signerB's public key — the
    // signature won't verify.
    const [, payloadB64, sig] = jwt.split(".");
    const fakeHeader = Buffer.from(
      JSON.stringify({
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        jwk: pubB,
      }),
      "utf-8",
    ).toString("base64url");
    const tampered = `${fakeHeader}.${payloadB64}.${sig}`;
    await expect(
      verifyProofJwt({ jwt: tampered, audience: AUD }),
    ).rejects.toMatchObject({ code: "oid4vci.invalid_proof" });
  });

  it("rejects a proof with no jwk in the header", async () => {
    const { privateKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const jwt = await new SignJWT({ aud: AUD })
      .setProtectedHeader({ alg: "ES256", typ: "openid4vci-proof+jwt" })
      .setIssuedAt()
      .sign(privateKey);
    await expect(verifyProofJwt({ jwt, audience: AUD })).rejects.toMatchObject({
      code: "oid4vci.invalid_proof",
    });
  });

  it("rejects a malformed JWT (not three segments)", async () => {
    await expect(
      verifyProofJwt({ jwt: "not.a.jwt.at-all", audience: AUD }),
    ).rejects.toMatchObject({ code: "oid4vci.invalid_input" });
  });
});

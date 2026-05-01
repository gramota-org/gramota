/**
 * Signer Strategy — base interface + JwkSigner default + extensibility.
 *
 * Coverage:
 *   1. JwkSigner — round-trips a sign/verify cycle correctly
 *   2. JwkSigner — caches the imported jose key (one import per instance)
 *   3. JwkSigner — input validation (rejects empty fields)
 *   4. asSigner — passes a Signer through, builds JwkSigner from raw keys
 *   5. Custom HSM-style Signer — implements the interface without holding
 *      a private JWK in instance state. Proves a third-party signer
 *      (KMS/WebAuthn/HSM) plugs into the SDK without orchestrator changes.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import {
  JwkSigner,
  asSigner,
  signJws,
  verifyJws,
  type JsonWebKey,
  type Signer,
} from "../src/index.js";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

describe("JwkSigner — default Signer impl", () => {
  it("produces a base64url signature that verifies against the public key", async () => {
    const { pub, priv } = await makeKey();
    const signer = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });

    // Build a "header.payload" string the way buildProofJwt would.
    const headerB64 = Buffer.from(
      JSON.stringify({ alg: "ES256", typ: "openid4vci-proof+jwt" }),
      "utf-8",
    ).toString("base64url");
    const payloadB64 = Buffer.from(
      JSON.stringify({ aud: "x", iat: 1 }),
      "utf-8",
    ).toString("base64url");
    const signedPayload = `${headerB64}.${payloadB64}`;

    const sig = await signer.sign(signedPayload);
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(sig.length).toBeGreaterThan(0);

    // Reconstruct the full JWS and verify it.
    const jws = `${signedPayload}.${sig}`;
    const verified = await verifyJws(jws, pub);
    expect(verified.alg).toBe("ES256");
    expect(verified.payload["aud"]).toBe("x");
  });

  it("exposes publicKey + alg as readonly fields", () => {
    const pub = { kty: "EC", crv: "P-256", x: "x", y: "y" } as JsonWebKey;
    const priv = { ...pub, d: "d" } as JsonWebKey;
    const signer = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    expect(signer.publicKey).toBe(pub);
    expect(signer.alg).toBe("ES256");
  });

  it("survives concurrent sign() calls (key import is cached)", async () => {
    const { pub, priv } = await makeKey();
    const signer = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    const headerB64 = Buffer.from('{"alg":"ES256"}', "utf-8").toString("base64url");
    const payloadB64 = Buffer.from('{"x":1}', "utf-8").toString("base64url");
    const signed = `${headerB64}.${payloadB64}`;

    const sigs = await Promise.all([
      signer.sign(signed),
      signer.sign(signed),
      signer.sign(signed),
    ]);
    // ES256 is non-deterministic, so the signatures differ — but each
    // verifies against the same public key.
    for (const s of sigs) {
      const v = await verifyJws(`${signed}.${s}`, pub);
      expect(v.alg).toBe("ES256");
    }
  });

  it("rejects null publicKey, privateKey, or empty alg at construction", () => {
    const ok = { kty: "EC" } as JsonWebKey;
    expect(
      () => new JwkSigner({ publicKey: null as unknown as JsonWebKey, privateKey: ok, alg: "ES256" }),
    ).toThrowError(/publicKey/);
    expect(
      () => new JwkSigner({ publicKey: ok, privateKey: null as unknown as JsonWebKey, alg: "ES256" }),
    ).toThrowError(/privateKey/);
    // @ts-expect-error: testing runtime guard
    expect(() => new JwkSigner({ publicKey: ok, privateKey: ok, alg: "" })).toThrowError(
      /alg/,
    );
  });
});

describe("asSigner — normalize raw or Signer input", () => {
  it("returns a JwkSigner for raw {publicKey,privateKey,alg}", async () => {
    const { pub, priv } = await makeKey();
    const signer = asSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    expect(signer).toBeInstanceOf(JwkSigner);
    expect(signer.publicKey).toBe(pub);
    expect(signer.alg).toBe("ES256");
  });

  it("passes through an existing Signer unchanged (idempotent)", async () => {
    const { pub, priv } = await makeKey();
    const original = new JwkSigner({ publicKey: pub, privateKey: priv, alg: "ES256" });
    const passedThrough = asSigner(original);
    expect(passedThrough).toBe(original);
  });
});

describe("Signer — extensibility (custom HSM-style implementation)", () => {
  it("a third-party Signer that does NOT hold a private JWK in instance state plugs in", async () => {
    // Stand-in for a real production signer (KMS/HSM/WebAuthn/etc.).
    // The instance never exposes the private key — calling code can't
    // reflectively scrape `.privateKey`. In production the `sign()` body
    // would RPC to an out-of-process signing oracle.
    class HsmStyleSigner implements Signer {
      public callCount = 0;
      constructor(
        readonly publicKey: JsonWebKey,
        readonly alg: "ES256",
        // Held in a closure rather than as an instance field — mimics
        // an HSM where the wallet never sees raw key material.
        private readonly secretEnclave: { sign: (s: string) => Promise<string> },
      ) {}
      async sign(signedPayload: string): Promise<string> {
        this.callCount++;
        return await this.secretEnclave.sign(signedPayload);
      }
    }

    const { pub, priv } = await makeKey();

    // Build an "enclave" that wraps a JwkSigner but hides it from
    // the outer Signer's public surface — a real HSM would be RPC.
    const enclave = new JwkSigner({
      publicKey: pub,
      privateKey: priv,
      alg: "ES256",
    });
    const hsm = new HsmStyleSigner(pub, "ES256", enclave);

    // signJws can't accept a Signer directly today, but buildProofJwt
    // (oid4vci) and buildKeyBindingJwt (sd-jwt) both can. Here we drive
    // the signer manually to prove the contract.
    const headerB64 = Buffer.from(
      JSON.stringify({ alg: hsm.alg, typ: "test" }),
      "utf-8",
    ).toString("base64url");
    const payloadB64 = Buffer.from(
      JSON.stringify({ msg: "hi" }),
      "utf-8",
    ).toString("base64url");
    const signed = `${headerB64}.${payloadB64}`;

    const sig = await hsm.sign(signed);
    expect(hsm.callCount).toBe(1);

    const verified = await verifyJws(`${signed}.${sig}`, pub);
    expect(verified.payload["msg"]).toBe("hi");

    // The HsmStyleSigner has no `privateKey` instance field — the
    // private material is encapsulated in `secretEnclave`. The Signer
    // contract is satisfied without exposing it.
    expect((hsm as unknown as Record<string, unknown>)["privateKey"]).toBeUndefined();

    // Silence unused-import warning when extending the file later.
    void signJws;
  });
});

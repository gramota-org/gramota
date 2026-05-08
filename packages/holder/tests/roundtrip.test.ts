// The gold-standard E2E test: a real issuer issues, a real Holder receives,
// the Holder presents with selective disclosure, and a real Verifier
// verifies — all in process, no Docker, no phone, no HTTP.
//
// If this test passes, the entire SD-JWT-VC trust chain works end-to-end
// across our SDK.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK, importJWK, CompactSign } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { issueSdJwt } from "@gramota/sd-jwt";
import { Verifier } from "@gramota/verifier";
import { Holder } from "../src/holder.js";

const NOW = 1_700_000_050;
const IAT = 1_700_000_000;

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

async function makeIssuerSigner(privateKey: JsonWebKey) {
  const key = await importJWK(
    privateKey as Parameters<typeof importJWK>[0],
    "ES256",
  );
  return async (signedPayload: string): Promise<string> => {
    const [headerB64, payloadB64] = signedPayload.split(".") as [string, string];
    const sig = await new CompactSign(
      new TextEncoder().encode(
        Buffer.from(payloadB64, "base64url").toString("utf-8"),
      ),
    )
      .setProtectedHeader(
        JSON.parse(Buffer.from(headerB64, "base64url").toString("utf-8")),
      )
      .sign(key);
    return sig.split(".")[2]!;
  };
}

describe("Issuer → Holder → Verifier roundtrip", () => {
  it("verifies a presentation built from a real issued + held credential", async () => {
    const issuer = await makeKey();
    const holderKey = await makeKey();
    const signer = await makeIssuerSigner(issuer.priv);

    // ---- ISSUE ----
    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT,
        exp: IAT + 86400,
        cnf: { jwk: holderKey.pub },
      },
      sdClaims: {
        given_name: "Alice",
        family_name: "Smith",
        birthdate: "1985-06-15",
        age_over_18: true,
        nationality: "BG",
      },
      alg: "ES256",
      signer,
    });

    // ---- HOLD ----
    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });
    const stored = await holder.credentials.receive(issued, {
      trustedIssuers: [issuer.pub],
    });

    // ---- PRESENT (selective disclosure) ----
    const audience = "https://verifier.example.com";
    const nonce = "challenge-roundtrip-001";

    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name", "age_over_18"],
      audience,
      nonce,
      now: () => NOW - 5,
    });

    // ---- VERIFY ----
    const verifier = new Verifier({
      audience,
      issuerKey: issuer.pub,
    });
    const result = await verifier.presentations.verify(presentation, {
      nonce,
      now: () => NOW,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.claims).toEqual({
      given_name: "Alice",
      age_over_18: true,
    });
    expect(result.claims).not.toHaveProperty("family_name");
    expect(result.claims).not.toHaveProperty("birthdate");
    expect(result.claims).not.toHaveProperty("nationality");

    expect(result.metadata.issuer).toBe("https://issuer.example.com");
    expect(result.metadata.audience).toBe(audience);
    expect(result.metadata.holderKey).toEqual(holderKey.pub);

    expect(result.checks).toHaveLength(11);
    expect(result.checks.every((c) => c.passed)).toBe(true);
  });

  it("verifier detects when the holder presents to the wrong audience", async () => {
    const issuer = await makeKey();
    const holderKey = await makeKey();
    const signer = await makeIssuerSigner(issuer.priv);

    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT,
        cnf: { jwk: holderKey.pub },
      },
      sdClaims: { given_name: "Alice" },
      alg: "ES256",
      signer,
    });

    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });
    const stored = await holder.credentials.receive(issued, { trustedIssuers: [issuer.pub] });

    // Holder builds a presentation aimed at verifier A.
    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name"],
      audience: "https://verifier-a.example.com",
      nonce: "n-1",
      now: () => NOW - 5,
    });

    // Verifier B (different audience) tries to consume it. MUST reject.
    const verifierB = new Verifier({
      audience: "https://verifier-b.example.com",
      issuerKey: issuer.pub,
    });
    const result = await verifierB.presentations.verify(presentation, {
      nonce: "n-1",
      now: () => NOW,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.audience");
  });
});

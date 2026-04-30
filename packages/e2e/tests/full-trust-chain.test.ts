/**
 * Cross-package E2E: every package exercised in one realistic flow.
 *
 * Scenarios covered:
 *   1. Single-issuer happy path — full chain green.
 *   2. Multi-issuer: holder owns credentials from 2 distinct issuers.
 *   3. Issuer key rotation: old + new keys coexist, both verify cleanly.
 *   4. JwksUrlTrustResolver: verifier fetches keys at runtime.
 *   5. Cross-verifier replay rejection.
 *   6. Tampered presentations rejected by hash-binding / KB-JWT.
 *   7. Selective disclosure across multiple presentations from one credential.
 *
 * If this file is green, every package's public surface composes correctly.
 */

import { describe, it, expect } from "vitest";
import { issueSdJwt } from "@gateway/sd-jwt";
import {
  StaticTrustResolver,
  JwksUrlTrustResolver,
  type Fetcher,
} from "@gateway/trust";
import { Holder } from "@gateway/holder";
import { Verifier } from "@gateway/verifier";
import {
  newEs256KeyPair,
  makeIssuerSigner,
} from "../src/test-helpers.js";

const NOW_S = 1_700_000_050;
const IAT_S = 1_700_000_000;

describe("E2E scenario 1 — single-issuer happy path", () => {
  it("issues, holds, presents, verifies — every package, every check", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    // Issue with sd-jwt + jose
    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        exp: IAT_S + 86400,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: {
        given_name: "Alice",
        family_name: "Smith",
        birthdate: "1985-06-15",
        age_over_18: true,
      },
      alg: "ES256",
      signer: await makeIssuerSigner(issuer.privateJwk),
    });

    // Hold with @gateway/holder
    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.receive(issued, {
      trustedIssuers: [issuer.publicJwk],
    });

    // Present with selective disclosure
    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name", "age_over_18"],
      audience: "https://verifier.example.com",
      nonce: "scenario-1",
      now: () => NOW_S - 5,
    });

    // Verify with @gateway/verifier
    const verifier = new Verifier({
      audience: "https://verifier.example.com",
      issuerKey: issuer.publicJwk,
    });
    const result = await verifier.verify(presentation, {
      nonce: "scenario-1",
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.claims).toEqual({
      given_name: "Alice",
      age_over_18: true,
    });
    expect(result.metadata.issuer).toBe("https://issuer.example.com");
    expect(result.metadata.holderKey).toEqual(holderKey.publicJwk);
    expect(result.checks).toHaveLength(11);
    expect(result.checks.every((c) => c.passed)).toBe(true);
  });
});

describe("E2E scenario 2 — multi-issuer holder", () => {
  it("holder owns + presents credentials from two distinct issuers", async () => {
    const issuerA = await newEs256KeyPair();
    const issuerB = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    const sharedHolder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });

    // Receive from issuer A: identity credential
    const { token: idCred } = await issueSdJwt({
      payload: {
        iss: "https://gov.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "Bob", birthdate: "1990-01-01" },
      alg: "ES256",
      signer: await makeIssuerSigner(issuerA.privateJwk),
    });
    const idStored = await sharedHolder.receive(idCred, {
      trustedIssuers: [issuerA.publicJwk],
    });

    // Receive from issuer B: education credential
    const { token: eduCred } = await issueSdJwt({
      payload: {
        iss: "https://uni.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { degree: "MSc", university: "Sofia U" },
      alg: "ES256",
      signer: await makeIssuerSigner(issuerB.privateJwk),
    });
    const eduStored = await sharedHolder.receive(eduCred, {
      trustedIssuers: [issuerB.publicJwk],
    });

    // List + filter
    expect(await sharedHolder.list()).toHaveLength(2);
    const govOnly = await sharedHolder.list({ issuer: "https://gov.example.com" });
    expect(govOnly).toHaveLength(1);

    // Present each independently to a per-issuer verifier
    const verifierA = new Verifier({
      audience: "https://hr.example.com",
      issuerKey: issuerA.publicJwk,
    });
    const idPresentation = await sharedHolder.present({
      credentialId: idStored.id,
      disclose: ["given_name"],
      audience: "https://hr.example.com",
      nonce: "n-id",
      now: () => NOW_S - 5,
    });
    const idResult = await verifierA.verify(idPresentation, {
      nonce: "n-id",
      now: () => NOW_S,
    });
    expect(idResult.ok).toBe(true);
    if (!idResult.ok) return;
    expect(idResult.claims).toEqual({ given_name: "Bob" });

    const verifierB = new Verifier({
      audience: "https://hr.example.com",
      issuerKey: issuerB.publicJwk,
    });
    const eduPresentation = await sharedHolder.present({
      credentialId: eduStored.id,
      disclose: ["degree", "university"],
      audience: "https://hr.example.com",
      nonce: "n-edu",
      now: () => NOW_S - 5,
    });
    const eduResult = await verifierB.verify(eduPresentation, {
      nonce: "n-edu",
      now: () => NOW_S,
    });
    expect(eduResult.ok).toBe(true);
    if (!eduResult.ok) return;
    expect(eduResult.claims).toEqual({
      degree: "MSc",
      university: "Sofia U",
    });

    // The "wrong" verifier rejects credentials from the other issuer
    const wrongResult = await verifierA.verify(eduPresentation, {
      nonce: "n-edu",
      now: () => NOW_S,
    });
    expect(wrongResult.ok).toBe(false);
    if (wrongResult.ok) return;
    expect(wrongResult.failedCheck).toBe("issuer.signature");
  });
});

describe("E2E scenario 3 — issuer key rotation", () => {
  it("StaticTrustResolver with old + new keys verifies tokens signed by either", async () => {
    const oldKey = await newEs256KeyPair();
    const newKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    // Issue one token with the OLD key, one with the NEW key.
    const { token: tokenOld } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "Carol" },
      alg: "ES256",
      signer: await makeIssuerSigner(oldKey.privateJwk),
    });
    const { token: tokenNew } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "Carol" },
      alg: "ES256",
      signer: await makeIssuerSigner(newKey.privateJwk),
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const storedOld = await holder.receive(tokenOld, {
      trustedIssuers: [oldKey.publicJwk, newKey.publicJwk],
    });
    const storedNew = await holder.receive(tokenNew, {
      trustedIssuers: [oldKey.publicJwk, newKey.publicJwk],
    });

    // Verifier configured with BOTH keys via StaticTrustResolver — rotation
    // is transparent: the verifier simply tries each candidate.
    const verifier = new Verifier({
      audience: "https://v.example.com",
      trust: new StaticTrustResolver({
        "https://issuer.example.com": [oldKey.publicJwk, newKey.publicJwk],
      }),
    });

    const presOld = await holder.present({
      credentialId: storedOld.id,
      disclose: ["given_name"],
      audience: "https://v.example.com",
      nonce: "rot-1",
      now: () => NOW_S - 5,
    });
    const presNew = await holder.present({
      credentialId: storedNew.id,
      disclose: ["given_name"],
      audience: "https://v.example.com",
      nonce: "rot-2",
      now: () => NOW_S - 5,
    });

    const resOld = await verifier.verify(presOld, {
      nonce: "rot-1",
      now: () => NOW_S,
    });
    const resNew = await verifier.verify(presNew, {
      nonce: "rot-2",
      now: () => NOW_S,
    });

    expect(resOld.ok).toBe(true);
    expect(resNew.ok).toBe(true);
  });
});

describe("E2E scenario 4 — JwksUrlTrustResolver with mock HTTP", () => {
  it("verifier fetches issuer keys from a mocked JWKS URL", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    const issuerJwksUrl =
      "https://issuer.example.com/.well-known/jwks.json";

    let fetchCalls = 0;
    const fetcher: Fetcher = async (url) => {
      fetchCalls++;
      if (url !== issuerJwksUrl) {
        return { ok: false, status: 404, json: async () => ({}) };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ keys: [issuer.publicJwk] }),
      };
    };

    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "Diana" },
      alg: "ES256",
      signer: await makeIssuerSigner(issuer.privateJwk),
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.receive(issued, {
      trustedIssuers: [issuer.publicJwk],
    });

    const verifier = new Verifier({
      audience: "https://v.example.com",
      trust: new JwksUrlTrustResolver({ fetcher, cacheMs: 60_000 }),
    });

    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name"],
      audience: "https://v.example.com",
      nonce: "jwks-1",
      now: () => NOW_S - 5,
    });

    const result = await verifier.verify(presentation, {
      nonce: "jwks-1",
      now: () => NOW_S,
    });
    expect(result.ok).toBe(true);
    expect(fetchCalls).toBe(1);

    // Second verification — cache hit, no extra fetch.
    const pres2 = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name"],
      audience: "https://v.example.com",
      nonce: "jwks-2",
      now: () => NOW_S - 5,
    });
    const result2 = await verifier.verify(pres2, {
      nonce: "jwks-2",
      now: () => NOW_S,
    });
    expect(result2.ok).toBe(true);
    expect(fetchCalls).toBe(1);
  });
});

describe("E2E scenario 5 — cross-verifier replay rejection", () => {
  it("a presentation aimed at verifier A is rejected by verifier B", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "Eve" },
      alg: "ES256",
      signer: await makeIssuerSigner(issuer.privateJwk),
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.receive(issued, {
      trustedIssuers: [issuer.publicJwk],
    });

    // Holder builds presentation aimed at A.
    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name"],
      audience: "https://verifier-a.example.com",
      nonce: "n-1",
      now: () => NOW_S - 5,
    });

    // Verifier B (different audience) rejects.
    const verifierB = new Verifier({
      audience: "https://verifier-b.example.com",
      issuerKey: issuer.publicJwk,
    });
    const result = await verifierB.verify(presentation, {
      nonce: "n-1",
      now: () => NOW_S,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.audience");
  });
});

describe("E2E scenario 6 — tampered presentations are rejected", () => {
  it("injecting a forged disclosure post-presentation fails kb-jwt.transcript", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "Frank" },
      alg: "ES256",
      signer: await makeIssuerSigner(issuer.privateJwk),
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.receive(issued, {
      trustedIssuers: [issuer.publicJwk],
    });

    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name"],
      audience: "https://v.example.com",
      nonce: "tamper-1",
      now: () => NOW_S - 5,
    });

    // Inject a forged disclosure between the last legit one and the KB-JWT.
    const forged = Buffer.from(
      '["forged","admin",true]',
      "utf-8",
    ).toString("base64url");
    const lastTilde = presentation.lastIndexOf("~");
    const tampered =
      presentation.substring(0, lastTilde) +
      "~" +
      forged +
      "~" +
      presentation.substring(lastTilde + 1);

    const verifier = new Verifier({
      audience: "https://v.example.com",
      issuerKey: issuer.publicJwk,
    });
    const result = await verifier.verify(tampered, {
      nonce: "tamper-1",
      now: () => NOW_S,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect([
      "hash-binding.disclosures",
      "kb-jwt.transcript",
    ]).toContain(result.failedCheck);
  });
});

describe("E2E scenario 7 — multiple presentations from one credential", () => {
  it("the same credential can be presented N times with different selective subsets", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: {
        given_name: "Grace",
        family_name: "Hopper",
        birthdate: "1906-12-09",
        nationality: "US",
        title: "Rear Admiral",
      },
      alg: "ES256",
      signer: await makeIssuerSigner(issuer.privateJwk),
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.receive(issued, {
      trustedIssuers: [issuer.publicJwk],
    });

    const verifier = new Verifier({
      audience: "https://v.example.com",
      issuerKey: issuer.publicJwk,
    });

    const subsets: string[][] = [
      ["given_name"],
      ["given_name", "family_name"],
      ["birthdate"],
      ["nationality", "title"],
      [],
    ];

    let i = 0;
    for (const disclose of subsets) {
      const nonce = `multi-${i++}`;
      const pres = await holder.present({
        credentialId: stored.id,
        disclose,
        audience: "https://v.example.com",
        nonce,
        now: () => NOW_S - 5,
      });
      const result = await verifier.verify(pres, {
        nonce,
        now: () => NOW_S,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) continue;
      expect(Object.keys(result.claims).sort()).toEqual([...disclose].sort());
    }
  });
});

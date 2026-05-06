// Tests for the `require` predicate option on VerifyOptions.
//
// Coverage:
//   - true → result.ok stays true; require.predicate appended to checks.
//   - false → result.ok = false; failedCheck = "require.predicate".
//   - { passed: false, reason } → failure with custom reason.
//   - Predicate sees the same `claims` + `metadata` shape as the success result.
//   - Async predicate is awaited.
//   - Predicate that throws propagates the throw (NOT silently treated as failure).
//   - Predicate runs AFTER crypto checks; signature failures short-circuit before it.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { buildKeyBindingJwt, issueSdJwt } from "@gramota/sd-jwt";
import { Verifier } from "../src/index.js";

const AUDIENCE = "https://my-bank.example.com";
const NONCE = "nonce-abc-123";
const NOW_S = 1_750_000_050;
const ISSUED_AT_S = 1_750_000_000;
const fixedNow = (): number => NOW_S;

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

/** Build a real, signed presentation for tests. */
async function makePresentation(
  subject: Record<string, unknown>,
): Promise<{ token: string; issuerPub: JsonWebKey }> {
  const issuer = await makeKey();
  const holder = await makeKey();
  const { CompactSign, importJWK } = await import("jose");

  const issuerSigner = async (signedPayload: string): Promise<string> => {
    const key = await importJWK(
      issuer.priv as Parameters<typeof importJWK>[0],
      "ES256",
    );
    const [headerB64, payloadB64] = signedPayload.split(".") as [string, string];
    const headerJson = Buffer.from(headerB64, "base64url").toString("utf-8");
    const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");
    const sig = await new CompactSign(
      new TextEncoder().encode(payloadJson),
    )
      .setProtectedHeader(JSON.parse(headerJson))
      .sign(key);
    return sig.split(".")[2]!;
  };

  const { token: issuance } = await issueSdJwt({
    payload: {
      iss: "https://issuer.test",
      iat: ISSUED_AT_S,
      vct: "urn:eudi:pid:1",
      cnf: { jwk: holder.pub },
    },
    sdClaims: subject,
    alg: "ES256",
    typ: "vc+sd-jwt",
    signer: issuerSigner,
    hashAlg: "sha-256",
  });

  const kbJwt = await buildKeyBindingJwt(issuance, {
    aud: AUDIENCE,
    nonce: NONCE,
    iat: ISSUED_AT_S,
    alg: "ES256",
    privateKey: holder.priv,
  });

  return { token: `${issuance}${kbJwt}`, issuerPub: issuer.pub };
}

describe("VerifyOptions.require — application predicate", () => {
  it("predicate returning true keeps ok=true and appends require.predicate to checks", async () => {
    const { token, issuerPub } = await makePresentation({
      age_over_18: true,
      nationality: "BG",
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    const r = await verifier.verify(token, {
      nonce: NONCE,
      now: fixedNow,
      require: ({ claims }) => claims["age_over_18"] === true,
    });

    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const last = r.checks[r.checks.length - 1];
    expect(last?.name).toBe("require.predicate");
    expect(last?.passed).toBe(true);
  });

  it("predicate returning false fails with failedCheck=require.predicate", async () => {
    const { token, issuerPub } = await makePresentation({
      age_over_18: false,
      nationality: "BG",
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    const r = await verifier.verify(token, {
      nonce: NONCE,
      now: fixedNow,
      require: ({ claims }) => claims["age_over_18"] === true,
    });

    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.failedCheck).toBe("require.predicate");
    expect(r.reason).toMatch(/require predicate returned false/);
  });

  it("predicate returning { passed: false, reason } supplies a custom reason", async () => {
    const { token, issuerPub } = await makePresentation({
      nationality: "US",
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    const r = await verifier.verify(token, {
      nonce: NONCE,
      now: fixedNow,
      require: ({ claims }) =>
        claims["nationality"] === "BG"
          ? true
          : { passed: false, reason: `nationality is ${claims["nationality"]}, need BG` },
    });

    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.failedCheck).toBe("require.predicate");
    expect(r.reason).toBe("nationality is US, need BG");
  });

  it("predicate sees the same claims + metadata shape as the success result", async () => {
    const { token, issuerPub } = await makePresentation({
      given_name: "Greta",
      age_over_18: true,
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    let seenClaims: unknown;
    let seenMetadata: unknown;
    const r = await verifier.verify(token, {
      nonce: NONCE,
      now: fixedNow,
      require: ({ claims, metadata }) => {
        seenClaims = claims;
        seenMetadata = metadata;
        return true;
      },
    });

    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(seenClaims).toEqual(r.claims);
    expect(seenMetadata).toEqual(r.metadata);
    expect((seenClaims as Record<string, unknown>)["given_name"]).toBe("Greta");
    expect((seenMetadata as Record<string, unknown>)["audience"]).toBe(AUDIENCE);
  });

  it("async predicate is awaited", async () => {
    const { token, issuerPub } = await makePresentation({
      age_over_18: true,
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    let asyncDone = false;
    const r = await verifier.verify(token, {
      nonce: NONCE,
      now: fixedNow,
      require: async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        asyncDone = true;
        return true;
      },
    });
    expect(asyncDone).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("predicate that throws propagates the throw (no silent failure)", async () => {
    const { token, issuerPub } = await makePresentation({
      age_over_18: true,
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    await expect(
      verifier.verify(token, {
        nonce: NONCE,
        now: fixedNow,
        require: () => {
          throw new Error("predicate explosion");
        },
      }),
    ).rejects.toThrow(/predicate explosion/);
  });

  it("predicate is NOT called when crypto checks fail (saves wasted work)", async () => {
    const { token, issuerPub } = await makePresentation({
      age_over_18: true,
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    let predicateCalled = false;
    const r = await verifier.verify(token, {
      nonce: "wrong-nonce",
      now: fixedNow,
      require: () => {
        predicateCalled = true;
        return true;
      },
    });

    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.failedCheck).toBe("kb-jwt.nonce");
    expect(predicateCalled).toBe(false);
  });

  it("composes — two business rules ANDed in a single predicate", async () => {
    const { token, issuerPub } = await makePresentation({
      age_over_18: true,
      nationality: "BG",
    });
    const verifier = new Verifier({ audience: AUDIENCE, issuerKey: issuerPub });

    const EU = new Set(["BG", "FR", "DE"]);
    const r = await verifier.verify(token, {
      nonce: NONCE,
      now: fixedNow,
      require: ({ claims }) =>
        claims["age_over_18"] === true &&
        EU.has(claims["nationality"] as string),
    });

    expect(r.ok).toBe(true);
  });
});

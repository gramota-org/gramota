// Holder unit tests + spec-driven failure modes for receive() and present().

import { describe, it, expect, beforeEach } from "vitest";
import { generateKeyPair, exportJWK, importJWK, CompactSign } from "jose";
import type { JsonWebKey } from "@gateway/jose";
import { issueSdJwt } from "@gateway/sd-jwt";
import { Holder, HolderError } from "../src/holder.js";

interface Setup {
  issuerPub: JsonWebKey;
  issuerPriv: JsonWebKey;
  holderPub: JsonWebKey;
  holderPriv: JsonWebKey;
  issuanceToken: string;
}

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

async function realIssuerSigner(privateKey: JsonWebKey) {
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

async function setup(opts?: { boundTo?: JsonWebKey }): Promise<Setup> {
  const issuer = await makeKey();
  const holder = await makeKey();
  const signer = await realIssuerSigner(issuer.priv);

  const { token } = await issueSdJwt({
    payload: {
      iss: "https://issuer.example.com",
      iat: 1700000000,
      cnf: { jwk: opts?.boundTo ?? holder.pub },
    },
    sdClaims: {
      given_name: "John",
      family_name: "Doe",
      birthdate: "1980-01-01",
    },
    alg: "ES256",
    signer,
  });

  return {
    issuerPub: issuer.pub,
    issuerPriv: issuer.priv,
    holderPub: holder.pub,
    holderPriv: holder.priv,
    issuanceToken: token,
  };
}

describe("Holder construction", () => {
  it("requires privateKey", () => {
    expect(
      // @ts-expect-error: missing required field
      () => new Holder({ publicKey: {}, alg: "ES256" }),
    ).toThrow(/privateKey/);
  });

  it("requires publicKey", () => {
    expect(
      // @ts-expect-error: missing required field
      () => new Holder({ privateKey: {}, alg: "ES256" }),
    ).toThrow(/publicKey/);
  });

  it("requires alg", () => {
    expect(
      // @ts-expect-error: missing required field
      () => new Holder({ privateKey: {}, publicKey: {} }),
    ).toThrow(/alg/);
  });

  it("uses InMemoryCredentialStore by default", async () => {
    const { pub, priv } = await makeKey();
    const holder = new Holder({
      privateKey: priv,
      publicKey: pub,
      alg: "ES256",
    });
    expect(await holder.credentials.list()).toEqual([]);
  });
});

describe("Holder.receive — IETF SD-JWT §5.1 holder verification", () => {
  let s: Setup;
  let holder: Holder;

  beforeEach(async () => {
    s = await setup();
    holder = new Holder({
      privateKey: s.holderPriv,
      publicKey: s.holderPub,
      alg: "ES256",
    });
  });

  it("accepts a credential signed by a trusted issuer and bound to this holder", async () => {
    const stored = await holder.credentials.receive(s.issuanceToken, {
      trustedIssuers: [s.issuerPub],
    });

    expect(stored.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(stored.issuer).toBe("https://issuer.example.com");
    expect(stored.token).toBe(s.issuanceToken);
    expect(stored.parsed.disclosures).toHaveLength(3);
  });

  it("persists the credential — list() returns it after receive()", async () => {
    const stored = await holder.credentials.receive(s.issuanceToken, {
      trustedIssuers: [s.issuerPub],
    });
    const all = await holder.credentials.list();
    expect(all).toHaveLength(1);
    expect(all[0]?.id).toBe(stored.id);
  });

  it("rejects when issuer signature does not verify against any trusted key", async () => {
    const { pub: wrong } = await makeKey();
    await expect(
      holder.credentials.receive(s.issuanceToken, { trustedIssuers: [wrong] }),
    ).rejects.toThrow(/issuer signature/);
  });

  it("rejects when no trusted issuers provided", async () => {
    await expect(
      holder.credentials.receive(s.issuanceToken, { trustedIssuers: [] }),
    ).rejects.toThrow(/trustedIssuer/);
  });

  it("rejects credentials bound to a DIFFERENT holder's cnf", async () => {
    const otherHolder = await makeKey();
    const sCrossBound = await setup({ boundTo: otherHolder.pub });

    await expect(
      holder.credentials.receive(sCrossBound.issuanceToken, {
        trustedIssuers: [sCrossBound.issuerPub],
      }),
    ).rejects.toThrow(/cnf\.jwk does not match/);
  });

  it("rejects credentials with no cnf claim", async () => {
    const issuer = await makeKey();
    const signer = await realIssuerSigner(issuer.priv);
    const { token } = await issueSdJwt({
      payload: { iss: "https://issuer.example.com", iat: 1700000000 },
      sdClaims: { given_name: "John" },
      alg: "ES256",
      signer,
    });

    await expect(
      holder.credentials.receive(token, { trustedIssuers: [issuer.pub] }),
    ).rejects.toThrow(/cnf/);
  });

  it("rejects malformed tokens", async () => {
    await expect(
      holder.credentials.receive("not-a-token", { trustedIssuers: [s.issuerPub] }),
    ).rejects.toThrow(/malformed/);
  });
});

describe("Holder.present — IETF SD-JWT §5.2 + §4.3 presentation building", () => {
  let s: Setup;
  let holder: Holder;
  let storedId: string;

  beforeEach(async () => {
    s = await setup();
    holder = new Holder({
      privateKey: s.holderPriv,
      publicKey: s.holderPub,
      alg: "ES256",
    });
    const stored = await holder.credentials.receive(s.issuanceToken, {
      trustedIssuers: [s.issuerPub],
    });
    storedId = stored.id;
  });

  it("builds a presentation with only the requested disclosures", async () => {
    const presentation = await holder.present({
      credentialId: storedId,
      disclose: ["given_name"],
      audience: "https://verifier.example.com",
      nonce: "challenge-1",
    });

    // Token shape: <jwt>~<d>~<kb-jwt>
    const segments = presentation.split("~");
    expect(segments.length).toBeGreaterThanOrEqual(3);

    // Last segment is the KB-JWT (contains dots), middle segment(s) are disclosures.
    const kbJwt = segments[segments.length - 1]!;
    expect(kbJwt.split(".").length).toBe(3);
  });

  it("excludes non-selected disclosures from the presentation", async () => {
    const stored = await holder.credentials.get(storedId);
    const presentation = await holder.present({
      credentialId: storedId,
      disclose: ["given_name"],
      audience: "https://verifier.example.com",
      nonce: "challenge-1",
    });

    // family_name's raw disclosure should NOT appear in the presentation.
    const familyDisclosure = stored!.parsed.disclosures.find(
      (d) => d.name === "family_name",
    )!;
    expect(presentation.includes(familyDisclosure.raw)).toBe(false);

    // given_name's raw disclosure SHOULD appear.
    const givenDisclosure = stored!.parsed.disclosures.find(
      (d) => d.name === "given_name",
    )!;
    expect(presentation.includes(givenDisclosure.raw)).toBe(true);
  });

  it("supports disclosing zero claims (proof of possession only)", async () => {
    const presentation = await holder.present({
      credentialId: storedId,
      disclose: [],
      audience: "https://verifier.example.com",
      nonce: "challenge-1",
    });

    // Shape: <jwt>~<kb-jwt>
    expect(presentation.split("~").length).toBe(2);
  });

  it("rejects when the credential id is not found", async () => {
    await expect(
      holder.present({
        credentialId: "does-not-exist",
        disclose: [],
        audience: "https://verifier.example.com",
        nonce: "n",
      }),
    ).rejects.toThrow(/not found/);
  });

  it("rejects when a requested disclosure is not selectively disclosable", async () => {
    await expect(
      holder.present({
        credentialId: storedId,
        disclose: ["nonexistent_claim"],
        audience: "https://verifier.example.com",
        nonce: "n",
      }),
    ).rejects.toThrow(/not available/);
  });

  it("rejects empty audience", async () => {
    await expect(
      holder.present({
        credentialId: storedId,
        disclose: [],
        audience: "",
        nonce: "n",
      }),
    ).rejects.toThrow(/audience/);
  });

  it("rejects empty nonce", async () => {
    await expect(
      holder.present({
        credentialId: storedId,
        disclose: [],
        audience: "https://verifier.example.com",
        nonce: "",
      }),
    ).rejects.toThrow(/nonce/);
  });
});

describe("Holder — multi-credential management", () => {
  it("stores and queries multiple credentials independently", async () => {
    const s1 = await setup();
    const holder = new Holder({
      privateKey: s1.holderPriv,
      publicKey: s1.holderPub,
      alg: "ES256",
    });

    // Issue a second credential to the same holder.
    const issuer2 = await makeKey();
    const signer2 = await realIssuerSigner(issuer2.priv);
    const { token: token2 } = await issueSdJwt({
      payload: {
        iss: "https://second-issuer.example.com",
        iat: 1700000000,
        cnf: { jwk: s1.holderPub },
      },
      sdClaims: { age_over_18: true },
      alg: "ES256",
      signer: signer2,
    });

    await holder.credentials.receive(s1.issuanceToken, { trustedIssuers: [s1.issuerPub] });
    await holder.credentials.receive(token2, { trustedIssuers: [issuer2.pub] });

    const all = await holder.credentials.list();
    expect(all).toHaveLength(2);

    const fromFirst = await holder.credentials.list({
      issuer: "https://issuer.example.com",
    });
    expect(fromFirst).toHaveLength(1);

    const withAge = await holder.credentials.list({ withClaim: "age_over_18" });
    expect(withAge).toHaveLength(1);
    expect(withAge[0]?.issuer).toBe("https://second-issuer.example.com");
  });

  it("remove() drops a credential", async () => {
    const s = await setup();
    const holder = new Holder({
      privateKey: s.holderPriv,
      publicKey: s.holderPub,
      alg: "ES256",
    });
    const stored = await holder.credentials.receive(s.issuanceToken, {
      trustedIssuers: [s.issuerPub],
    });

    expect(await holder.credentials.remove(stored.id)).toBe(true);
    expect(await holder.credentials.list()).toEqual([]);
  });
});

// Quiet "unused export" warning for HolderError in this file
void HolderError;

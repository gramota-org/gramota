// Issuer.issueBatch — OID4VCI Draft 14/15 batch issuance.
//
// One issuance call → N credentials, one per holder-key entry. The EU wallet
// asks for `numberOfCredentials = 10` so that each presentation can use a
// fresh credential (one-time-use, unlinkable). Each credential in the batch
// is bound to a *different* holder key (per-credential `cnf.jwk`); the
// claims, vct, and expiry are shared.
//
// Why a separate method instead of a polymorphic `issue()`:
//   - cleaner types (no holderKey | holderKeys union),
//   - matches the protocol shape (Draft 15 has a dedicated batch flow),
//   - lets us add per-credential overrides (status, credentialId) without
//     making the single-issue type signature wider.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { parseSdJwt } from "@gramota/sd-jwt";
import { Issuer, IssuerError } from "../src/index.js";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

async function makeIssuer(): Promise<Issuer> {
  const { pub, priv } = await makeKey();
  return new Issuer({
    privateKey: priv,
    publicKey: pub,
    alg: "ES256",
    issuerId: "https://issuer.example.com",
  });
}

describe("Issuer.issueBatch — happy path", () => {
  it("issues N credentials, one per holder-key entry", async () => {
    const issuer = await makeIssuer();
    const [h1, h2, h3] = await Promise.all([makeKey(), makeKey(), makeKey()]);

    const results = await issuer.issueBatch({
      subject: { given_name: "Alice", birthdate: "1985-06-15" },
      selectivelyDisclosable: ["given_name", "birthdate"],
      vct: "https://credentials.example.com/identity_v1",
      credentials: [
        { holderKey: h1.pub },
        { holderKey: h2.pub },
        { holderKey: h3.pub },
      ],
    });

    expect(results).toHaveLength(3);

    // Each credential binds to its respective holder key.
    expect(parseSdJwt(results[0]!.token).payload["cnf"]).toEqual({
      jwk: h1.pub,
    });
    expect(parseSdJwt(results[1]!.token).payload["cnf"]).toEqual({
      jwk: h2.pub,
    });
    expect(parseSdJwt(results[2]!.token).payload["cnf"]).toEqual({
      jwk: h3.pub,
    });
  });

  it("each credential has a distinct credentialId (unlinkable per-credential identifier)", async () => {
    const issuer = await makeIssuer();
    const [h1, h2, h3] = await Promise.all([makeKey(), makeKey(), makeKey()]);

    const results = await issuer.issueBatch({
      subject: { x: 1 },
      vct: "https://credentials.example.com/x",
      credentials: [
        { holderKey: h1.pub },
        { holderKey: h2.pub },
        { holderKey: h3.pub },
      ],
    });

    const ids = results.map((r) => r.credentialId);
    expect(new Set(ids).size).toBe(3); // all distinct
  });

  it("each credential has distinct SD salts (unlinkable disclosures)", async () => {
    const issuer = await makeIssuer();
    const [h1, h2] = await Promise.all([makeKey(), makeKey()]);

    const results = await issuer.issueBatch({
      subject: { given_name: "Carol" },
      selectivelyDisclosable: ["given_name"],
      vct: "https://credentials.example.com/x",
      credentials: [{ holderKey: h1.pub }, { holderKey: h2.pub }],
    });

    // Salts are randomly generated per call → two credentials over the same
    // claim must serialize differently.
    expect(results[0]!.disclosures[0]!.salt).not.toBe(
      results[1]!.disclosures[0]!.salt,
    );
    expect(results[0]!.token).not.toBe(results[1]!.token);
  });

  it("per-credential credentialId override is respected", async () => {
    const issuer = await makeIssuer();
    const [h1, h2] = await Promise.all([makeKey(), makeKey()]);

    const results = await issuer.issueBatch({
      subject: { x: 1 },
      vct: "https://credentials.example.com/x",
      credentials: [
        { holderKey: h1.pub, credentialId: "batch-1" },
        { holderKey: h2.pub, credentialId: "batch-2" },
      ],
    });

    expect(results[0]!.credentialId).toBe("batch-1");
    expect(results[1]!.credentialId).toBe("batch-2");
  });

  it("per-credential status passes through (each gets its own status-list index)", async () => {
    const issuer = await makeIssuer();
    const [h1, h2] = await Promise.all([makeKey(), makeKey()]);

    const status1 = {
      status_list: { idx: 100, uri: "https://issuer.example.com/status/1" },
    };
    const status2 = {
      status_list: { idx: 101, uri: "https://issuer.example.com/status/1" },
    };

    const results = await issuer.issueBatch({
      subject: { x: 1 },
      vct: "https://credentials.example.com/x",
      credentials: [
        { holderKey: h1.pub, status: status1 },
        { holderKey: h2.pub, status: status2 },
      ],
    });

    expect(parseSdJwt(results[0]!.token).payload["status"]).toEqual(status1);
    expect(parseSdJwt(results[1]!.token).payload["status"]).toEqual(status2);
  });

  it("shared expiresIn applies to every credential in the batch", async () => {
    const issuer = await makeIssuer();
    const [h1, h2] = await Promise.all([makeKey(), makeKey()]);

    const results = await issuer.issueBatch({
      subject: { x: 1 },
      vct: "https://credentials.example.com/x",
      issuedAt: 1_700_000_000,
      expiresIn: 86_400,
      credentials: [{ holderKey: h1.pub }, { holderKey: h2.pub }],
    });

    expect(results[0]!.expiresAt).toBe(1_700_086_400);
    expect(results[1]!.expiresAt).toBe(1_700_086_400);
  });
});

describe("Issuer.credentials.issueBatch — Stripe-shaped namespacing", () => {
  it("issuer.credentials.issueBatch resolves to the same impl as issuer.issueBatch", async () => {
    const issuer = await makeIssuer();
    const [h1, h2] = await Promise.all([makeKey(), makeKey()]);

    const a = await issuer.credentials.issueBatch({
      subject: { x: 1 },
      vct: "https://credentials.example.com/x",
      credentials: [{ holderKey: h1.pub }, { holderKey: h2.pub }],
    });

    expect(a).toHaveLength(2);
    expect(parseSdJwt(a[0]!.token).payload["cnf"]).toEqual({ jwk: h1.pub });
    expect(parseSdJwt(a[1]!.token).payload["cnf"]).toEqual({ jwk: h2.pub });
  });
});

describe("Issuer.issueBatch — validation failures", () => {
  it("rejects empty credentials array", async () => {
    const issuer = await makeIssuer();
    await expect(
      issuer.issueBatch({
        subject: { x: 1 },
        vct: "https://credentials.example.com/x",
        credentials: [],
      }),
    ).rejects.toThrow(/credentials.*non-empty/i);
  });

  it("propagates validation errors from individual entries (e.g. missing holderKey)", async () => {
    const issuer = await makeIssuer();
    const { pub } = await makeKey();
    await expect(
      issuer.issueBatch({
        subject: { x: 1 },
        vct: "https://credentials.example.com/x",
        credentials: [
          { holderKey: pub },
          // @ts-expect-error: testing runtime guard
          { holderKey: null },
        ],
      }),
    ).rejects.toBeInstanceOf(IssuerError);
  });

  it("rejects shared selectivelyDisclosable claim missing from subject (validated once)", async () => {
    const issuer = await makeIssuer();
    const [h1, h2] = await Promise.all([makeKey(), makeKey()]);
    await expect(
      issuer.issueBatch({
        subject: { given_name: "X" },
        selectivelyDisclosable: ["given_name", "missing_claim"],
        vct: "https://credentials.example.com/x",
        credentials: [{ holderKey: h1.pub }, { holderKey: h2.pub }],
      }),
    ).rejects.toThrow(/missing_claim/);
  });
});

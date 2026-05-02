// Issuer unit tests — construction validation + issuance correctness.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { parseSdJwt, verifyHashBinding } from "@gramota/sd-jwt";
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

describe("Issuer construction", () => {
  it("requires privateKey", async () => {
    const { pub } = await makeKey();
    expect(
      () =>
        // @ts-expect-error: missing required field
        new Issuer({
          publicKey: pub,
          alg: "ES256",
          issuerId: "https://issuer.example.com",
        }),
    ).toThrow(/privateKey/);
  });

  it("requires publicKey", async () => {
    const { priv } = await makeKey();
    expect(
      () =>
        // @ts-expect-error: missing required field
        new Issuer({
          privateKey: priv,
          alg: "ES256",
          issuerId: "https://issuer.example.com",
        }),
    ).toThrow(/publicKey/);
  });

  it("requires alg", async () => {
    const { pub, priv } = await makeKey();
    expect(
      () =>
        // @ts-expect-error: missing required field
        new Issuer({
          privateKey: priv,
          publicKey: pub,
          issuerId: "https://issuer.example.com",
        }),
    ).toThrow(/alg/);
  });

  it("requires issuerId", async () => {
    const { pub, priv } = await makeKey();
    expect(
      () =>
        // @ts-expect-error: missing required field
        new Issuer({ privateKey: priv, publicKey: pub, alg: "ES256" }),
    ).toThrow(/issuerId/);
  });
});

describe("Issuer.issue — happy path", () => {
  async function makeIssuer(): Promise<{
    issuer: Issuer;
    pub: JsonWebKey;
    priv: JsonWebKey;
  }> {
    const { pub, priv } = await makeKey();
    return {
      issuer: new Issuer({
        privateKey: priv,
        publicKey: pub,
        alg: "ES256",
        issuerId: "https://issuer.example.com",
      }),
      pub,
      priv,
    };
  }

  it("issues a credential bound to the holder's cnf", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: { given_name: "Alice", birthdate: "1985-06-15" },
      selectivelyDisclosable: ["given_name", "birthdate"],
      holderKey: holder.pub,
      vct: "https://credentials.example.com/identity_v1",
    });

    expect(result.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~/);
    expect(result.credentialId).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.disclosures).toHaveLength(2);

    const parsed = parseSdJwt(result.token);
    expect(parsed.payload["iss"]).toBe("https://issuer.example.com");
    expect(parsed.payload["vct"]).toBe(
      "https://credentials.example.com/identity_v1",
    );
    expect(parsed.payload["cnf"]).toEqual({ jwk: holder.pub });
    expect(parsed.header.typ).toBe("vc+sd-jwt");
    expect(parsed.header.alg).toBe("ES256");
  });

  it("makes only the named claims selectively disclosable", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: {
        given_name: "Bob",
        family_name: "Public",
        nationality: "BG",
        always_visible: "yes",
      },
      selectivelyDisclosable: ["given_name", "nationality"],
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
    });

    const parsed = parseSdJwt(result.token);

    // Disclosed claims (SD): given_name, nationality
    const discloseNames = parsed.disclosures
      .map((d) => d.name)
      .filter((n): n is string => n !== null)
      .sort();
    expect(discloseNames).toEqual(["given_name", "nationality"]);

    // Direct claims (not SD): family_name, always_visible — visible in payload
    expect(parsed.payload["family_name"]).toBe("Public");
    expect(parsed.payload["always_visible"]).toBe("yes");
    // SD ones are NOT directly in the payload
    expect(parsed.payload["given_name"]).toBeUndefined();
    expect(parsed.payload["nationality"]).toBeUndefined();
  });

  it("hash binding verifies for the freshly-issued token", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: { age_over_18: true, given_name: "Carol" },
      selectivelyDisclosable: ["age_over_18", "given_name"],
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
    });

    const parsed = parseSdJwt(result.token);
    const verified = verifyHashBinding(parsed);

    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.matchedDisclosures).toHaveLength(2);
    expect(verified.claims["given_name"]).toBe("Carol");
    expect(verified.claims["age_over_18"]).toBe(true);
  });

  it("expiresIn computes exp = iat + seconds", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: { x: 1 },
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
      issuedAt: 1_700_000_000,
      expiresIn: 86_400,
    });

    expect(result.expiresAt).toBe(1_700_086_400);
    const parsed = parseSdJwt(result.token);
    expect(parsed.payload["exp"]).toBe(1_700_086_400);
    expect(parsed.payload["iat"]).toBe(1_700_000_000);
  });

  it("expiresAt sets exp directly", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: { x: 1 },
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
      issuedAt: 1_700_000_000,
      expiresAt: 2_000_000_000,
    });

    expect(result.expiresAt).toBe(2_000_000_000);
  });

  it("notBefore sets nbf claim", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: { x: 1 },
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
      issuedAt: 1_700_000_000,
      notBefore: 1_700_001_000,
    });

    const parsed = parseSdJwt(result.token);
    expect(parsed.payload["nbf"]).toBe(1_700_001_000);
  });

  it("status passes through unchanged", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const status = {
      status_list: { idx: 42, uri: "https://issuer.example.com/status/1" },
    };
    const result = await issuer.issue({
      subject: { x: 1 },
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
      status,
    });

    const parsed = parseSdJwt(result.token);
    expect(parsed.payload["status"]).toEqual(status);
  });

  it("custom credentialId overrides the random UUID", async () => {
    const { issuer } = await makeIssuer();
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: { x: 1 },
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
      credentialId: "my-tracking-id-123",
    });

    expect(result.credentialId).toBe("my-tracking-id-123");
  });

  it("kid header is set when configured on Issuer", async () => {
    const { pub, priv } = await makeKey();
    const issuer = new Issuer({
      privateKey: priv,
      publicKey: pub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
      kid: "issuer-key-2026",
    });
    const holder = await makeKey();

    const result = await issuer.issue({
      subject: { x: 1 },
      holderKey: holder.pub,
      vct: "https://credentials.example.com/x",
    });

    const parsed = parseSdJwt(result.token);
    expect(parsed.header["kid"]).toBe("issuer-key-2026");
  });
});

describe("Issuer.issue — validation failures", () => {
  async function makeIssuer(): Promise<Issuer> {
    const { pub, priv } = await makeKey();
    return new Issuer({
      privateKey: priv,
      publicKey: pub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
  }

  it("rejects missing vct", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      // @ts-expect-error: missing required field
      issuer.issue({
        subject: { x: 1 },
        holderKey: holder.pub,
      }),
    ).rejects.toThrow(/vct/);
  });

  it("rejects empty vct string", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      issuer.issue({
        subject: { x: 1 },
        holderKey: holder.pub,
        vct: "",
      }),
    ).rejects.toThrow(/vct/);
  });

  it("rejects missing holderKey", async () => {
    const issuer = await makeIssuer();
    await expect(
      // @ts-expect-error: missing required field
      issuer.issue({
        subject: { x: 1 },
        vct: "https://credentials.example.com/x",
      }),
    ).rejects.toThrow(/holderKey/);
  });

  it("rejects selectively-disclosable claims missing from subject", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      issuer.issue({
        subject: { given_name: "X" },
        selectivelyDisclosable: ["given_name", "missing_claim"],
        holderKey: holder.pub,
        vct: "https://credentials.example.com/x",
      }),
    ).rejects.toThrow(/missing_claim/);
  });

  it("rejects subject containing reserved JWT claims", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      issuer.issue({
        subject: { iss: "https://x.com", given_name: "X" },
        holderKey: holder.pub,
        vct: "https://credentials.example.com/x",
      }),
    ).rejects.toThrow(/reserved.*iss/);
  });

  it("rejects expiresIn AND expiresAt together", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      issuer.issue({
        subject: { x: 1 },
        holderKey: holder.pub,
        vct: "https://credentials.example.com/x",
        expiresIn: 60,
        expiresAt: 2_000_000_000,
      }),
    ).rejects.toThrow(/mutually exclusive/);
  });

  it("rejects expiresIn <= 0", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      issuer.issue({
        subject: { x: 1 },
        holderKey: holder.pub,
        vct: "https://credentials.example.com/x",
        expiresIn: 0,
      }),
    ).rejects.toThrow(/expiresIn/);
  });

  it("rejects expiresAt <= issuedAt", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      issuer.issue({
        subject: { x: 1 },
        holderKey: holder.pub,
        vct: "https://credentials.example.com/x",
        issuedAt: 1_700_000_000,
        expiresAt: 1_700_000_000, // equal, not greater
      }),
    ).rejects.toThrow(/expiresAt/);
  });

  it("rejects non-object subject", async () => {
    const issuer = await makeIssuer();
    const holder = await makeKey();
    await expect(
      issuer.issue({
        // @ts-expect-error: testing runtime guard
        subject: "not an object",
        holderKey: holder.pub,
        vct: "https://credentials.example.com/x",
      }),
    ).rejects.toBeInstanceOf(IssuerError);
  });
});

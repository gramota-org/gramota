// Public API contract tests. The Verifier API surface is what every customer
// will touch — these tests are the contract. If a test fails, it's an API
// regression that affects every caller.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import type { JsonWebKey } from "@gateway/jose";
import {
  buildKeyBindingJwt,
  computeSdHash,
  issueSdJwt,
  type HashAlg,
} from "@gateway/sd-jwt";
import { Verifier, verify, inspect, VerificationError } from "../src/index.js";

const AUDIENCE = "https://my-bank.example.com";
const NONCE = "nonce-abcdefg-1234567890";
const NOW_S = 1_700_000_050;
const ISSUED_AT_S = 1_700_000_000;

interface TestSetup {
  issuerPub: JsonWebKey;
  issuerPriv: JsonWebKey;
  holderPub: JsonWebKey;
  holderPriv: JsonWebKey;
  presentationToken: string;
}

async function makeKey(
  alg: "ES256" | "RS256" = "ES256",
): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair(alg, {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

async function setup(opts?: {
  hashAlg?: HashAlg;
  audience?: string;
  nonce?: string;
  iat?: number;
  signKbWith?: JsonWebKey;
  signIssuerWith?: JsonWebKey;
  givenName?: string;
  familyName?: string;
  birthdate?: string;
}): Promise<TestSetup> {
  const issuer = await makeKey("ES256");
  const holder = await makeKey("ES256");

  const issuerSigner = async (signedPayload: string): Promise<string> => {
    const { importJWK, CompactSign } = await import("jose");
    const key = await importJWK(
      (opts?.signIssuerWith ??
        issuer.priv) as Parameters<typeof importJWK>[0],
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
      iss: "https://issuer.example.com",
      iat: ISSUED_AT_S,
      exp: ISSUED_AT_S + 86400,
      cnf: { jwk: holder.pub },
    },
    sdClaims: {
      given_name: opts?.givenName ?? "John",
      family_name: opts?.familyName ?? "Doe",
      birthdate: opts?.birthdate ?? "1980-01-01",
    },
    alg: "ES256",
    signer: issuerSigner,
    ...(opts?.hashAlg ? { hashAlg: opts.hashAlg } : {}),
  });

  const kbJwt = await buildKeyBindingJwt(issuance, {
    aud: opts?.audience ?? AUDIENCE,
    nonce: opts?.nonce ?? NONCE,
    iat: opts?.iat ?? NOW_S - 5,
    alg: "ES256",
    privateKey: opts?.signKbWith ?? holder.priv,
    ...(opts?.hashAlg ? { hashAlg: opts.hashAlg } : {}),
  });

  return {
    issuerPub: issuer.pub,
    issuerPriv: issuer.priv,
    holderPub: holder.pub,
    holderPriv: holder.priv,
    presentationToken: `${issuance}${kbJwt}`,
  };
}

const baseOpts = (): { nonce: string; now: () => number } => ({
  nonce: NONCE,
  now: () => NOW_S,
});

// ===========================================================================
// API: happy path + ergonomics
// ===========================================================================

describe("Verifier — happy path", () => {
  it("verifies an end-to-end presentation and returns claims + metadata", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, baseOpts());

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.claims).toEqual({
      given_name: "John",
      family_name: "Doe",
      birthdate: "1980-01-01",
    });
    expect(result.metadata.issuer).toBe("https://issuer.example.com");
    expect(result.metadata.audience).toBe(AUDIENCE);
    expect(result.metadata.issuedAt).toBe(ISSUED_AT_S);
    expect(result.metadata.expiresAt).toBe(ISSUED_AT_S + 86400);
    expect(result.metadata.holderKey).toEqual(s.holderPub);
  });

  it("strips iss/iat/exp/cnf/_sd/_sd_alg from claims", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, baseOpts());
    if (!result.ok) throw new Error("expected ok");

    expect(result.claims).not.toHaveProperty("iss");
    expect(result.claims).not.toHaveProperty("iat");
    expect(result.claims).not.toHaveProperty("exp");
    expect(result.claims).not.toHaveProperty("cnf");
    expect(result.claims).not.toHaveProperty("_sd");
    expect(result.claims).not.toHaveProperty("_sd_alg");
  });

  it("records every check as passed in result.checks", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, baseOpts());
    if (!result.ok) throw new Error("expected ok");

    const expected = [
      "structure.parse",
      "trust.resolution",
      "issuer.signature",
      "hash-binding.disclosures",
      "kb-jwt.present",
      "kb-jwt.cnf-binding",
      "kb-jwt.signature",
      "kb-jwt.audience",
      "kb-jwt.nonce",
      "kb-jwt.time",
      "kb-jwt.transcript",
    ];
    expect(result.checks.map((c) => c.name)).toEqual(expected);
    expect(result.checks.every((c) => c.passed)).toBe(true);
  });

  it("supports type narrowing via generic on verify<T>()", async () => {
    interface MyClaims {
      given_name: string;
      family_name: string;
      birthdate: string;
    }
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify<MyClaims>(s.presentationToken, baseOpts());
    if (!result.ok) throw new Error("expected ok");

    // Type-level — won't compile if narrowing is broken.
    const name: string = result.claims.given_name;
    expect(name).toBe("John");
  });

  it("works as a standalone verify() function (no class)", async () => {
    const s = await setup();
    const result = await verify(s.presentationToken, {
      audience: AUDIENCE,
      issuerKey: s.issuerPub,
      nonce: NONCE,
      now: () => NOW_S,
    });
    expect(result.ok).toBe(true);
  });
});

// ===========================================================================
// API: result.unwrap() ergonomics
// ===========================================================================

describe("VerifyResult.unwrap()", () => {
  it("returns claims on success", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const claims = (await v.verify(s.presentationToken, baseOpts())).unwrap();
    expect(claims["given_name"]).toBe("John");
  });

  it("throws VerificationError on failure", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, {
      ...baseOpts(),
      nonce: "wrong-nonce",
    });
    expect(() => result.unwrap()).toThrow(VerificationError);
  });

  it("VerificationError carries the failure result for logging", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, {
      ...baseOpts(),
      nonce: "wrong-nonce",
    });
    try {
      result.unwrap();
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerificationError);
      const ve = err as VerificationError;
      expect(ve.result.ok).toBe(false);
      expect(ve.result.failedCheck).toBe("kb-jwt.nonce");
    }
  });
});

// ===========================================================================
// API: failures map to specific check names
// ===========================================================================

describe("Verifier — failure classification", () => {
  it("structure.parse — malformed token", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify("not.a.valid.token", baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("structure.parse");
  });

  it("issuer.signature — wrong issuer key supplied", async () => {
    const s = await setup();
    const wrong = await makeKey("ES256");
    const v = new Verifier({ audience: AUDIENCE, issuerKey: wrong.pub });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("issuer.signature");
  });

  it("hash-binding.disclosures — forged disclosure injected", async () => {
    const s = await setup();
    const forged = Buffer.from(
      '["forged-salt","admin",true]',
      "utf-8",
    ).toString("base64url");
    const lastTilde = s.presentationToken.lastIndexOf("~");
    const tampered = `${s.presentationToken.substring(
      0,
      lastTilde,
    )}~${forged}~${s.presentationToken.substring(lastTilde + 1)}`;

    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(tampered, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // The forged disclosure either fails hash-binding (if injected before kb-jwt
    // signing) or fails kb-jwt.transcript (if injected after).
    expect([
      "hash-binding.disclosures",
      "kb-jwt.transcript",
    ]).toContain(result.failedCheck);
  });

  it("kb-jwt.present — token without KB-JWT", async () => {
    const issuer = await makeKey("ES256");
    const holder = await makeKey("ES256");
    const issuerSigner = async (signedPayload: string): Promise<string> => {
      const { importJWK, CompactSign } = await import("jose");
      const key = await importJWK(
        issuer.priv as Parameters<typeof importJWK>[0],
        "ES256",
      );
      const [headerB64, payloadB64] = signedPayload.split(".") as [
        string,
        string,
      ];
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
    const { token: issuanceOnly } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: ISSUED_AT_S,
        cnf: { jwk: holder.pub },
      },
      sdClaims: { given_name: "John" },
      alg: "ES256",
      signer: issuerSigner,
    });

    const v = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
    });
    const result = await v.verify(issuanceOnly, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.present");
  });

  it("kb-jwt.signature — KB-JWT signed with wrong key", async () => {
    const evil = await makeKey("ES256");
    const s = await setup({ signKbWith: evil.priv });

    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.signature");
  });

  it("kb-jwt.audience — verifier mismatch", async () => {
    const s = await setup({ audience: "https://other-verifier.example.com" });
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.audience");
  });

  it("kb-jwt.nonce — challenge mismatch", async () => {
    const s = await setup();
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, {
      ...baseOpts(),
      nonce: "different-nonce",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.nonce");
  });

  it("kb-jwt.time — KB-JWT too old", async () => {
    const s = await setup({ iat: NOW_S - 3600 });
    const v = new Verifier({ audience: AUDIENCE, issuerKey: s.issuerPub });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.time");
  });
});

// ===========================================================================
// API: configuration
// ===========================================================================

describe("Verifier — configuration", () => {
  it("rejects construction without audience", () => {
    expect(
      // @ts-expect-error: missing required field
      () => new Verifier({ issuerKey: { kty: "EC" } }),
    ).toThrow(/audience/);
  });

  it("rejects construction with neither issuerKey nor trust", () => {
    expect(
      () => new Verifier({ audience: AUDIENCE }),
    ).toThrow(/issuerKey.*trust/);
  });

  it("rejects construction with both issuerKey AND trust", async () => {
    const s = await setup();
    const { StaticTrustResolver } = await import("@gateway/trust");
    expect(
      () =>
        new Verifier({
          audience: AUDIENCE,
          issuerKey: s.issuerPub,
          trust: new StaticTrustResolver([s.issuerPub]),
        }),
    ).toThrow(/exactly one/);
  });

  it("accepts a TrustResolver via the trust option", async () => {
    const s = await setup();
    const { StaticTrustResolver } = await import("@gateway/trust");
    const v = new Verifier({
      audience: AUDIENCE,
      trust: new StaticTrustResolver([s.issuerPub]),
    });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(true);
  });

  it("trust.resolution failure is a distinct check name", async () => {
    const s = await setup();
    const { StaticTrustResolver } = await import("@gateway/trust");
    // Configured per-issuer for a different iss → resolution will fail.
    const v = new Verifier({
      audience: AUDIENCE,
      trust: new StaticTrustResolver({
        "https://other-issuer.example.com": [s.issuerPub],
      }),
    });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("trust.resolution");
  });

  it("respects custom algorithms allowlist", async () => {
    const s = await setup();
    // ES256 token, but only RS256 allowed → both issuer.signature and
    // kb-jwt.signature will fail. The first to fail is issuer.signature.
    const v = new Verifier({
      audience: AUDIENCE,
      issuerKey: s.issuerPub,
      algorithms: ["RS256"],
    });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("issuer.signature");
  });

  it("respects custom maxKbJwtAgeSeconds", async () => {
    // Default maxAge=60. Setup uses iat=NOW-5 which passes default.
    // With maxAge=2, iat=NOW-5 fails.
    const s = await setup({ iat: NOW_S - 5 });
    const v = new Verifier({
      audience: AUDIENCE,
      issuerKey: s.issuerPub,
      maxKbJwtAgeSeconds: 2,
    });
    const result = await v.verify(s.presentationToken, baseOpts());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("kb-jwt.time");
  });
});

// ===========================================================================
// inspect() — debug parser, no verification
// ===========================================================================

describe("inspect()", () => {
  it("returns parsed structure for valid tokens without verifying", async () => {
    const s = await setup();
    const inspected = inspect(s.presentationToken);
    expect(inspected.header.alg).toBe("ES256");
    expect(inspected.disclosures.length).toBe(3);
    expect(inspected.keyBindingJwt).toBeDefined();
  });

  it("does NOT verify — accepts a token with a wrong KB-JWT signature", async () => {
    const evil = await makeKey("ES256");
    const s = await setup({ signKbWith: evil.priv });
    // inspect returns structure even though the KB-JWT signature is invalid.
    const inspected = inspect(s.presentationToken);
    expect(inspected.keyBindingJwt).toBeDefined();
  });
});

// ===========================================================================
// Sanity: silence unused imports
// ===========================================================================

void SignJWT;
void computeSdHash;

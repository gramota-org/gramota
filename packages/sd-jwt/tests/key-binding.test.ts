// Mission-critical: KB-JWT verification tests covering every rule in
// IETF draft-ietf-oauth-selective-disclosure-jwt §4.3, every failure mode,
// and the security properties (replay protection, transcript binding).
//
// If any of these tests fails or is removed, the SD-JWT-VC security model
// is broken. Treat this file as the contract.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import type { JsonWebKey, SupportedAlg } from "@gramota/jose";
import { issueSdJwt, stubSignature } from "../src/issue.js";
import { parseSdJwt } from "../src/parse.js";
import {
  buildKeyBindingJwt,
  verifyKeyBinding,
} from "../src/key-binding.js";
import { computeSdHash } from "../src/sd-hash.js";
import { SdJwtError, type ParsedSdJwt } from "../src/types.js";

const AUD = "https://verifier.example.com";
const NONCE = "n-0S6_WzA2Mj-rand-12345";

interface Scenario {
  holderPub: JsonWebKey;
  holderPriv: JsonWebKey;
  presentation: string;
  parsed: ParsedSdJwt;
}

async function makeKeyPair(
  alg: SupportedAlg = "ES256",
): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair(alg, {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

/** Build a complete signed presentation: SD-JWT with cnf binding, and a valid
 * KB-JWT signed by the holder, ready to verify. */
async function buildScenario(opts?: {
  holderPub?: JsonWebKey;
  holderPriv?: JsonWebKey;
  iat?: number;
  hashAlg?: "sha-256" | "sha-384" | "sha-512";
  alg?: SupportedAlg;
  signKbWith?: JsonWebKey;
  aud?: string;
  nonce?: string;
}): Promise<Scenario> {
  const { pub, priv } =
    opts?.holderPub && opts?.holderPriv
      ? { pub: opts.holderPub, priv: opts.holderPriv }
      : await makeKeyPair("ES256");

  const { token: issuanceToken } = await issueSdJwt({
    payload: {
      iss: "https://issuer.example.com",
      iat: 1700000000,
      cnf: { jwk: pub },
    },
    sdClaims: { given_name: "John", family_name: "Doe" },
    alg: "ES256",
    signer: stubSignature,
    ...(opts?.hashAlg ? { hashAlg: opts.hashAlg } : {}),
  });

  // The issuance form already ends with `~`. That's our presentationPrefix.
  const presentationPrefix = issuanceToken;

  const kbJwt = await buildKeyBindingJwt(presentationPrefix, {
    aud: opts?.aud ?? AUD,
    nonce: opts?.nonce ?? NONCE,
    alg: opts?.alg ?? "ES256",
    privateKey: opts?.signKbWith ?? priv,
    ...(opts?.iat !== undefined ? { iat: opts.iat } : {}),
    ...(opts?.hashAlg ? { hashAlg: opts.hashAlg } : {}),
  });

  const presentation = `${presentationPrefix}${kbJwt}`;
  return {
    holderPub: pub,
    holderPriv: priv,
    presentation,
    parsed: parseSdJwt(presentation),
  };
}

const NOW = 1700000050; // 50s after iat=1700000000
const baseRequirements = (): {
  expectedAudience: string;
  expectedNonce: string;
  now: () => number;
} => ({
  expectedAudience: AUD,
  expectedNonce: NONCE,
  now: () => NOW,
});

// ===========================================================================
// Happy path
// ===========================================================================

describe("KB-JWT — happy path", () => {
  it("verifies a valid KB-JWT with all rules satisfied", async () => {
    const s = await buildScenario({ iat: NOW - 5 });
    const verified = await verifyKeyBinding(s.parsed, baseRequirements());

    expect(verified.header.typ).toBe("kb+jwt");
    expect(verified.header.alg).toBe("ES256");
    expect(verified.payload.aud).toBe(AUD);
    expect(verified.payload.nonce).toBe(NONCE);
    expect(verified.payload.sd_hash).toBe(
      computeSdHash(s.parsed.presentationPrefix),
    );
    expect(verified.holderKey).toEqual(s.holderPub);
  });

  it("computeSdHash produces deterministic output for known input", () => {
    // Canonical: empty presentation prefix would never be valid, so we use
    // a synthetic but stable input.
    const input = "abc.def.ghi~WyJzYWx0IiwibiIsInYiXQ~";
    const hash = computeSdHash(input);
    // Independently verified with:
    //   printf '%s' '<input>' | openssl dgst -sha256 -binary \
    //     | base64 | tr '+/' '-_' | tr -d '='
    expect(hash).toBe("tulCAkx71JPAa7NisNqDEzXnSZmhYPlNR4bexR_OGQg");
  });
});

// ===========================================================================
// Rule 1 — typ MUST be kb+jwt
// ===========================================================================

describe("KB-JWT rule 1 — typ MUST be 'kb+jwt'", () => {
  async function buildWithTyp(
    typ: string | undefined,
  ): Promise<ParsedSdJwt> {
    const { pub, priv } = await makeKeyPair("ES256");
    const { token: prefix } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: 1700000000,
        cnf: { jwk: pub },
      },
      sdClaims: { given_name: "John" },
      alg: "ES256",
      signer: stubSignature,
    });

    const sdHash = computeSdHash(prefix);
    const importedKey = await (
      await import("jose")
    ).importJWK(priv as Parameters<typeof import("jose").importJWK>[0], "ES256");
    const builder = new SignJWT({
      iat: NOW - 5,
      aud: AUD,
      nonce: NONCE,
      sd_hash: sdHash,
    });
    const header: { alg: "ES256"; typ?: string } = { alg: "ES256" };
    if (typ !== undefined) header.typ = typ;
    const kbJwt = await builder.setProtectedHeader(header).sign(importedKey);

    return parseSdJwt(`${prefix}${kbJwt}`);
  }

  it("rejects typ=vc+sd-jwt", async () => {
    const parsed = await buildWithTyp("vc+sd-jwt");
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/typ/);
  });

  it("rejects typ=JWT", async () => {
    const parsed = await buildWithTyp("JWT");
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/typ/);
  });

  it("rejects missing typ", async () => {
    const parsed = await buildWithTyp(undefined);
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/typ/);
  });
});

// ===========================================================================
// Rule 2 — signing key MUST be cnf.jwk in the parent SD-JWT
// ===========================================================================

describe("KB-JWT rule 2 — signing key MUST be cnf.jwk", () => {
  it("rejects when KB-JWT is signed by a key NOT in cnf", async () => {
    const holderA = await makeKeyPair("ES256");
    const holderB = await makeKeyPair("ES256");

    // Bind cnf=holderA, but sign KB-JWT with holderB's private.
    const s = await buildScenario({
      holderPub: holderA.pub,
      holderPriv: holderA.priv,
      signKbWith: holderB.priv,
      iat: NOW - 5,
    });

    await expect(
      verifyKeyBinding(s.parsed, baseRequirements()),
    ).rejects.toBeInstanceOf(SdJwtError);
  });

  it("rejects when parent SD-JWT has no cnf claim", async () => {
    const { priv } = await makeKeyPair("ES256");
    const { token: prefix } = await issueSdJwt({
      payload: { iss: "https://issuer.example.com", iat: 1700000000 },
      sdClaims: { given_name: "John" },
      alg: "ES256",
      signer: stubSignature,
    });
    const kbJwt = await buildKeyBindingJwt(prefix, {
      aud: AUD,
      nonce: NONCE,
      alg: "ES256",
      privateKey: priv,
      iat: NOW - 5,
    });
    const parsed = parseSdJwt(`${prefix}${kbJwt}`);

    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/cnf/);
  });

  it("rejects when cnf.jwk is missing (cnf present but no jwk)", async () => {
    const { priv } = await makeKeyPair("ES256");
    const { token: prefix } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: 1700000000,
        cnf: { kid: "some-kid" }, // no jwk
      },
      sdClaims: { given_name: "John" },
      alg: "ES256",
      signer: stubSignature,
    });
    const kbJwt = await buildKeyBindingJwt(prefix, {
      aud: AUD,
      nonce: NONCE,
      alg: "ES256",
      privateKey: priv,
      iat: NOW - 5,
    });
    const parsed = parseSdJwt(`${prefix}${kbJwt}`);

    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/cnf\.jwk/);
  });
});

// ===========================================================================
// Rule 3 — alg constraints
// ===========================================================================

describe("KB-JWT rule 3 — alg constraints", () => {
  it("rejects when alg not in allowlist", async () => {
    const s = await buildScenario({ iat: NOW - 5 });
    await expect(
      verifyKeyBinding(s.parsed, {
        ...baseRequirements(),
        algorithms: ["RS256"],
      }),
    ).rejects.toBeInstanceOf(SdJwtError);
  });

  it("accepts when alg explicitly allowed", async () => {
    const s = await buildScenario({ iat: NOW - 5 });
    const verified = await verifyKeyBinding(s.parsed, {
      ...baseRequirements(),
      algorithms: ["ES256"],
    });
    expect(verified.header.alg).toBe("ES256");
  });
});

// ===========================================================================
// Rule 4 — sd_hash transcript binding
// ===========================================================================

describe("KB-JWT rule 4 — sd_hash transcript binding", () => {
  it("computes sd_hash over <issuer-jws>~<d1>~...~<dN>~ exactly", async () => {
    const s = await buildScenario({ iat: NOW - 5 });
    const verified = await verifyKeyBinding(s.parsed, baseRequirements());
    // Recompute manually to be sure.
    expect(verified.payload.sd_hash).toBe(
      computeSdHash(s.parsed.presentationPrefix),
    );
  });

  it("rejects when a disclosure is added after KB-JWT signing", async () => {
    // Build a presentation, then try to inject an extra disclosure between
    // the SD-JWT and the KB-JWT — the KB-JWT's sd_hash will no longer match.
    const s = await buildScenario({ iat: NOW - 5 });
    const forged = Buffer.from(
      '["forged-salt","admin",true]',
      "utf-8",
    ).toString("base64url");

    // Splice forged disclosure before the KB-JWT.
    const lastTilde = s.presentation.lastIndexOf("~");
    const before = s.presentation.substring(0, lastTilde);
    const kb = s.presentation.substring(lastTilde + 1);
    const tampered = `${before}~${forged}~${kb}`;
    const tamperedParsed = parseSdJwt(tampered);

    await expect(
      verifyKeyBinding(tamperedParsed, baseRequirements()),
    ).rejects.toThrow(/sd_hash/);
  });

  it("rejects when a disclosure is removed without rebuilding KB-JWT", async () => {
    const s = await buildScenario({ iat: NOW - 5 });
    // Remove the first disclosure from the presentation.
    const parts = s.presentation.split("~");
    parts.splice(1, 1); // drop d1
    const tampered = parts.join("~");
    const tamperedParsed = parseSdJwt(tampered);

    await expect(
      verifyKeyBinding(tamperedParsed, baseRequirements()),
    ).rejects.toThrow(/sd_hash/);
  });

  it("rejects when disclosures are reordered", async () => {
    const s = await buildScenario({ iat: NOW - 5 });
    const parts = s.presentation.split("~");
    // parts: [jwt, d1, d2, kb] — swap d1 and d2.
    [parts[1], parts[2]] = [parts[2]!, parts[1]!];
    const tampered = parts.join("~");
    const tamperedParsed = parseSdJwt(tampered);

    await expect(
      verifyKeyBinding(tamperedParsed, baseRequirements()),
    ).rejects.toThrow(/sd_hash/);
  });
});

// ===========================================================================
// Rule 5 — required payload claims
// ===========================================================================

describe("KB-JWT rule 5 — required claims", () => {
  async function buildWithoutClaim(
    omit: "iat" | "aud" | "nonce" | "sd_hash",
  ): Promise<ParsedSdJwt> {
    const { pub, priv } = await makeKeyPair("ES256");
    const { token: prefix } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: 1700000000,
        cnf: { jwk: pub },
      },
      sdClaims: { given_name: "John" },
      alg: "ES256",
      signer: stubSignature,
    });

    const fullPayload: Record<string, unknown> = {
      iat: NOW - 5,
      aud: AUD,
      nonce: NONCE,
      sd_hash: computeSdHash(prefix),
    };
    delete fullPayload[omit];

    const importedKey = await (
      await import("jose")
    ).importJWK(priv as Parameters<typeof import("jose").importJWK>[0], "ES256");
    const kbJwt = await new SignJWT(fullPayload)
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .sign(importedKey);

    return parseSdJwt(`${prefix}${kbJwt}`);
  }

  it("rejects missing iat", async () => {
    const parsed = await buildWithoutClaim("iat");
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/iat/);
  });

  it("rejects missing aud", async () => {
    const parsed = await buildWithoutClaim("aud");
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/aud/);
  });

  it("rejects missing nonce", async () => {
    const parsed = await buildWithoutClaim("nonce");
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/nonce/);
  });

  it("rejects missing sd_hash", async () => {
    const parsed = await buildWithoutClaim("sd_hash");
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/sd_hash/);
  });
});

// ===========================================================================
// Rule 6/7 — replay protection (aud + nonce)
// ===========================================================================

describe("KB-JWT rule 6/7 — replay protection", () => {
  it("rejects when aud doesn't match expected verifier", async () => {
    const s = await buildScenario({ iat: NOW - 5, aud: "https://other-verifier.com" });
    await expect(
      verifyKeyBinding(s.parsed, baseRequirements()),
    ).rejects.toThrow(/aud/);
  });

  it("rejects when nonce doesn't match challenge", async () => {
    const s = await buildScenario({ iat: NOW - 5, nonce: "different-nonce" });
    await expect(
      verifyKeyBinding(s.parsed, baseRequirements()),
    ).rejects.toThrow(/nonce/);
  });
});

// ===========================================================================
// Rule 8 — time validation (iat tolerance)
// ===========================================================================

describe("KB-JWT rule 8 — iat time validation", () => {
  it("rejects iat too far in the future (clock skew)", async () => {
    const s = await buildScenario({ iat: NOW + 120 }); // 120s ahead, exceeds 30s skew
    await expect(
      verifyKeyBinding(s.parsed, baseRequirements()),
    ).rejects.toThrow(/future/);
  });

  it("rejects iat too old (replay window)", async () => {
    const s = await buildScenario({ iat: NOW - 3600 }); // 1h old, exceeds 60s maxAge
    await expect(
      verifyKeyBinding(s.parsed, baseRequirements()),
    ).rejects.toThrow(/old/);
  });

  it("accepts iat within tolerance window", async () => {
    const s = await buildScenario({ iat: NOW - 30 });
    const verified = await verifyKeyBinding(s.parsed, baseRequirements());
    expect(verified.payload.iat).toBe(NOW - 30);
  });
});

// ===========================================================================
// Rule 9 — KB-JWT presence
// ===========================================================================

describe("KB-JWT presence", () => {
  it("rejects when KB-JWT is absent (issuance form)", async () => {
    const { pub } = await makeKeyPair("ES256");
    const { token: issuanceOnly } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: 1700000000,
        cnf: { jwk: pub },
      },
      sdClaims: { given_name: "John" },
      alg: "ES256",
      signer: stubSignature,
    });
    const parsed = parseSdJwt(issuanceOnly);
    await expect(
      verifyKeyBinding(parsed, baseRequirements()),
    ).rejects.toThrow(/required but absent/);
  });
});

// ===========================================================================
// Builder validation
// ===========================================================================

describe("buildKeyBindingJwt input validation", () => {
  it("rejects an empty presentationPrefix", async () => {
    const { priv } = await makeKeyPair("ES256");
    await expect(
      buildKeyBindingJwt("", {
        aud: AUD,
        nonce: NONCE,
        alg: "ES256",
        privateKey: priv,
      }),
    ).rejects.toThrow(/non-empty/);
  });

  it("rejects a presentationPrefix not ending with '~'", async () => {
    const { priv } = await makeKeyPair("ES256");
    await expect(
      buildKeyBindingJwt("a.b.c", {
        aud: AUD,
        nonce: NONCE,
        alg: "ES256",
        privateKey: priv,
      }),
    ).rejects.toThrow(/end with '~'/);
  });
});

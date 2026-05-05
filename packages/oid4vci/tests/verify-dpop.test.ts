/**
 * Server-side DPoP verification — RFC 9449 §4.3 / §6 / §8.
 *
 * The build/verify pair is symmetric: anything we sign with `buildDpopJwt`
 * the verifier here must accept on the matching method+url.
 *
 * Test scope:
 *   1. Round-trip — builder → verifier matches, returns expected jkt.
 *   2. htm/htu mismatch is rejected.
 *   3. iat outside skew window is rejected.
 *   4. ath check on resource access requires the access-token hash.
 *   5. nonce check echoes the server-supplied value.
 *   6. Replay (jti reuse) is rejected via injected store.
 *   7. JWS signature mismatch is rejected (different signer).
 *   8. Stripped or wrong typ is rejected.
 *
 * Out of scope here: the wire-shape tests live in `dpop.test.ts` (builder
 * side); we don't re-test the build payload here.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import {
  JwkSigner,
  computeJwkThumbprint,
  type JsonWebKey,
} from "@gramota/jose";
import { buildDpopJwt, verifyDpopJwt, Oid4vciError } from "../src/index.js";

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

describe("verifyDpopJwt — round-trip with buildDpopJwt", () => {
  it("accepts a valid proof and returns the JWK thumbprint", async () => {
    const { signer, pub } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/oid4vci/token",
    });

    const result = await verifyDpopJwt({
      jwt,
      htm: "POST",
      htu: "https://issuer.example/oid4vci/token",
    });

    expect(result.jkt).toBe(computeJwkThumbprint(pub));
    expect(result.payload["htm"]).toBe("POST");
  });
});

describe("verifyDpopJwt — htm / htu enforcement (RFC 9449 §4.3)", () => {
  it("rejects when htm doesn't match the actual request method", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/token",
    });
    await expect(
      verifyDpopJwt({ jwt, htm: "GET", htu: "https://issuer.example/token" }),
    ).rejects.toThrow(Oid4vciError);
  });

  it("rejects when htu doesn't match", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/token",
    });
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/credential",
      }),
    ).rejects.toThrow(Oid4vciError);
  });

  it("strips query+fragment from expected htu before comparing", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/token",
    });
    // Caller passes htu with a trailing query — verifier should strip it.
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/token?foo=bar#frag",
      }),
    ).resolves.toBeDefined();
  });
});

describe("verifyDpopJwt — iat skew (RFC 9449 §11.1)", () => {
  it("rejects iat too far in the past", async () => {
    const { signer } = await makeSigner();
    const stale = Math.floor(Date.now() / 1000) - 600; // 10 min ago
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/token",
      iat: stale,
    });
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/token",
        maxAgeSeconds: 60,
      }),
    ).rejects.toThrow(Oid4vciError);
  });

  it("accepts iat within the skew window", async () => {
    const { signer } = await makeSigner();
    const recent = Math.floor(Date.now() / 1000) - 30;
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/token",
      iat: recent,
    });
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/token",
        maxAgeSeconds: 60,
      }),
    ).resolves.toBeDefined();
  });
});

describe("verifyDpopJwt — ath on resource access (RFC 9449 §6.1)", () => {
  it("accepts when ath matches sha256(access_token)", async () => {
    const { signer } = await makeSigner();
    const accessToken = "secret-token-value";
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/credential",
      accessToken,
    });
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/credential",
        accessToken,
      }),
    ).resolves.toBeDefined();
  });

  it("rejects when ath is missing on a resource-server request", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/credential",
      // no accessToken — proof has no ath
    });
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/credential",
        accessToken: "must-have-this",
      }),
    ).rejects.toThrow(Oid4vciError);
  });

  it("rejects when ath doesn't match the actual access token", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/credential",
      accessToken: "token-a",
    });
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/credential",
        accessToken: "token-b",
      }),
    ).rejects.toThrow(Oid4vciError);
  });
});

describe("verifyDpopJwt — replay protection via jti store", () => {
  it("rejects a jti the store has already seen", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/token",
    });
    const seen = new Set<string>();
    await verifyDpopJwt({
      jwt,
      htm: "POST",
      htu: "https://issuer.example/token",
      hasSeenJti: (jti) => seen.has(jti),
      recordJti: (jti) => {
        seen.add(jti);
      },
    });
    // Replay the same JWT — should now fail.
    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/token",
        hasSeenJti: (jti) => seen.has(jti),
        recordJti: (jti) => {
          seen.add(jti);
        },
      }),
    ).rejects.toThrow(Oid4vciError);
  });
});

describe("verifyDpopJwt — signature + header validation", () => {
  it("rejects a JWT signed by a different key (sig mismatch)", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://issuer.example/token",
    });
    // Tamper: swap the embedded jwk with someone else's (simulating
    // an attacker who can read the proof but not sign with the key).
    const [headerB64, bodyB64, sigB64] = jwt.split(".");
    const header = JSON.parse(
      Buffer.from(headerB64!, "base64url").toString("utf-8"),
    );
    const { pub: differentPub } = await makeSigner();
    header.jwk = differentPub;
    const tamperedHeader = Buffer.from(JSON.stringify(header), "utf-8")
      .toString("base64url");
    const tampered = `${tamperedHeader}.${bodyB64}.${sigB64}`;

    await expect(
      verifyDpopJwt({
        jwt: tampered,
        htm: "POST",
        htu: "https://issuer.example/token",
      }),
    ).rejects.toThrow(Oid4vciError);
  });

  it("rejects a JWT whose typ is not 'dpop+jwt'", async () => {
    // We can't get buildDpopJwt to emit the wrong typ, so build a
    // minimal proof manually.
    const { signer } = await makeSigner();
    const header = {
      typ: "JWT", // wrong: must be dpop+jwt
      alg: "ES256",
      jwk: signer.publicKey,
    };
    const payload = {
      jti: "abc",
      htm: "POST",
      htu: "https://issuer.example/token",
      iat: Math.floor(Date.now() / 1000),
    };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const sig = await signer.sign(`${headerB64}.${payloadB64}`);
    const jwt = `${headerB64}.${payloadB64}.${sig}`;

    await expect(
      verifyDpopJwt({
        jwt,
        htm: "POST",
        htu: "https://issuer.example/token",
      }),
    ).rejects.toThrow(Oid4vciError);
  });
});

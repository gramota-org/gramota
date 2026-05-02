/**
 * DPoP — RFC 9449 conformance.
 *
 * Wire format per RFC 9449 §4.2:
 *
 *   header  { typ: "dpop+jwt", alg: <jws alg>, jwk: <pubkey> }
 *   payload { jti, htm, htu, iat, ath?, nonce? }
 *   sig
 *
 * Test coverage:
 *   1. Header has typ=dpop+jwt + alg + jwk (public-only)
 *   2. Payload has jti (unique per call), htm, htu, iat
 *   3. ath is sha256(access_token) base64url-encoded (RFC 9449 §6.1)
 *   4. nonce is included when supplied (RFC 9449 §8)
 *   5. htu strips fragment + query per spec
 *   6. Signature verifies against the embedded jwk
 *   7. Two calls produce different jti (replay-protection)
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";
import {
  JwkSigner,
  verifyJws,
  type JsonWebKey,
} from "@gateway/jose";
import { buildDpopJwt, computeAccessTokenHash } from "../src/index.js";

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

describe("buildDpopJwt — header per RFC 9449 §4.2", () => {
  it("sets typ=dpop+jwt, alg from signer, jwk to signer's public key", async () => {
    const { signer, pub } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://as.example.com/token",
    });
    const headerB64 = jwt.split(".")[0]!;
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    expect(header["typ"]).toBe("dpop+jwt");
    expect(header["alg"]).toBe("ES256");
    expect(header["jwk"]).toEqual(pub);
  });

  it("never includes the private key in the embedded jwk", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://as.example.com/token",
    });
    const header = JSON.parse(
      Buffer.from(jwt.split(".")[0]!, "base64url").toString("utf-8"),
    ) as { jwk?: Record<string, unknown> };
    expect(header.jwk?.["d"]).toBeUndefined();
  });
});

describe("buildDpopJwt — payload per RFC 9449 §4.2", () => {
  it("sets htm + htu + iat + jti", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://as.example.com/token",
      iat: 1700000000,
    });
    const payloadB64 = jwt.split(".")[1]!;
    const p = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    expect(p["htm"]).toBe("POST");
    expect(p["htu"]).toBe("https://as.example.com/token");
    expect(p["iat"]).toBe(1700000000);
    expect(typeof p["jti"]).toBe("string");
    expect((p["jti"] as string).length).toBeGreaterThanOrEqual(16);
  });

  it("yields a fresh jti per call (replay protection)", async () => {
    const { signer } = await makeSigner();
    const a = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://x.example.com/token",
    });
    const b = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://x.example.com/token",
    });
    const jtiA = (
      JSON.parse(
        Buffer.from(a.split(".")[1]!, "base64url").toString("utf-8"),
      ) as Record<string, unknown>
    )["jti"];
    const jtiB = (
      JSON.parse(
        Buffer.from(b.split(".")[1]!, "base64url").toString("utf-8"),
      ) as Record<string, unknown>
    )["jti"];
    expect(jtiA).not.toBe(jtiB);
  });

  it("strips fragment from htu (RFC 9449 §4.2)", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://as.example.com/token#fragment",
    });
    const p = JSON.parse(
      Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    expect(p["htu"]).toBe("https://as.example.com/token");
  });

  it("strips query from htu (RFC 9449 §4.2 — htu is the URI without query/fragment)", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://as.example.com/token?foo=bar&baz=qux",
    });
    const p = JSON.parse(
      Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    expect(p["htu"]).toBe("https://as.example.com/token");
  });
});

describe("buildDpopJwt — ath (access token hash) per RFC 9449 §6.1", () => {
  it("sets ath = base64url(sha256(access_token)) when accessToken is supplied", async () => {
    const { signer } = await makeSigner();
    const accessToken = "ya29.access-token-example";
    const expectedAth = createHash("sha256")
      .update(accessToken)
      .digest("base64url");
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://rs.example.com/credential",
      accessToken,
    });
    const p = JSON.parse(
      Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    expect(p["ath"]).toBe(expectedAth);
  });

  it("omits ath when no accessToken is supplied (token-endpoint use)", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://as.example.com/token",
    });
    const p = JSON.parse(
      Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    expect(p["ath"]).toBeUndefined();
  });
});

describe("buildDpopJwt — server-supplied nonce (RFC 9449 §8)", () => {
  it("includes nonce when supplied", async () => {
    const { signer } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://as.example.com/token",
      nonce: "server-nonce-42",
    });
    const p = JSON.parse(
      Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    expect(p["nonce"]).toBe("server-nonce-42");
  });
});

describe("buildDpopJwt — signature verifies against embedded jwk", () => {
  it("issuer can verify the JWS using the jwk in the header (sender key binding)", async () => {
    const { signer, pub } = await makeSigner();
    const jwt = await buildDpopJwt({
      signer,
      htm: "POST",
      htu: "https://rs.example.com/credential",
      accessToken: "x",
    });
    const verified = await verifyJws(jwt, pub);
    expect(verified.alg).toBe("ES256");
    expect(verified.header["typ"]).toBe("dpop+jwt");
  });
});

describe("computeAccessTokenHash — RFC 9449 §6.1 standalone helper", () => {
  it("matches an independent SHA-256 + base64url computation", () => {
    const token = "test-token-12345";
    const expected = createHash("sha256").update(token).digest("base64url");
    expect(computeAccessTokenHash(token)).toBe(expected);
  });

  it("rejects empty input", () => {
    expect(() => computeAccessTokenHash("")).toThrowError(/non-empty/);
  });
});

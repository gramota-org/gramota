/**
 * `direct_post.jwt` (JWE-encrypted Authorization Response) — OID4VP
 * §8.3.1, HAIP §5.1.
 *
 * Round-trip + invariants we pin:
 *   1. Generate key → encrypt response → decrypt → equals input.
 *   2. The cleartext payload is a JSON object — never URL-encoded.
 *   3. Header allowlist defaults to ECDH-ES / A256GCM (HAIP baseline).
 *   4. Foreign keys can't decrypt (signature/tag fails).
 *   5. Wrong alg / wrong enc are rejected with stable error codes
 *      BEFORE crypto runs.
 *   6. Tampered ciphertext fails authentication.
 *   7. Both PEX (string vp_token + presentation_submission) and DCQL
 *      (object vp_token, no submission) shapes round-trip.
 */

import { describe, it, expect } from "vitest";
import { CompactEncrypt } from "jose";
import {
  DEFAULT_RESPONSE_JWE_ALG,
  DEFAULT_RESPONSE_JWE_ENC,
  Oid4vpError,
  decryptAuthorizationResponse,
  encryptAuthorizationResponse,
  generateResponseEncryptionKey,
  type AuthorizationResponse,
} from "../src/index.js";

describe("generateResponseEncryptionKey — default ECDH-ES P-256", () => {
  it("returns a public + private JWK pair annotated with use=enc + alg", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    expect(publicJwk.kty).toBe("EC");
    expect(publicJwk.crv).toBe("P-256");
    expect(publicJwk.use).toBe("enc");
    expect(publicJwk.alg).toBe(DEFAULT_RESPONSE_JWE_ALG);
    expect(publicJwk.d).toBeUndefined();
    expect(privateJwk.kty).toBe("EC");
    expect(typeof privateJwk.d).toBe("string");
    expect(privateJwk.use).toBe("enc");
    expect(privateJwk.alg).toBe(DEFAULT_RESPONSE_JWE_ALG);
    expect(privateJwk.x).toBe(publicJwk.x);
    expect(privateJwk.y).toBe(publicJwk.y);
  });

  it("applies a caller-supplied kid to both halves of the keypair", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey({
      kid: "verifier-enc-key-1",
    });
    expect(publicJwk.kid).toBe("verifier-enc-key-1");
    expect(privateJwk.kid).toBe("verifier-enc-key-1");
  });
});

describe("encrypt/decrypt round-trip — DCQL response shape", () => {
  it("decrypted response equals the input (DCQL vp_token object form)", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = {
      vp_token: {
        pid: "eyJ...sd-jwt-vc...AAAA~salt-x~",
      },
      state: "verifier-state-abc",
    };

    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: publicJwk,
    });
    // JWE compact serialisation has 5 dot-separated segments.
    expect(jwe.split(".")).toHaveLength(5);

    const result = await decryptAuthorizationResponse({
      jwe,
      privateKey: privateJwk,
    });
    expect(result.response).toEqual(response);
    expect(result.header["alg"]).toBe(DEFAULT_RESPONSE_JWE_ALG);
    expect(result.header["enc"]).toBe(DEFAULT_RESPONSE_JWE_ENC);
  });

  it("DCQL responses don't need presentation_submission", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = {
      vp_token: { pid: "presentation-string" },
    };
    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: publicJwk,
    });
    const result = await decryptAuthorizationResponse({
      jwe,
      privateKey: privateJwk,
    });
    expect(result.response.presentation_submission).toBeUndefined();
    expect(result.response.vp_token).toEqual({ pid: "presentation-string" });
  });
});

describe("encrypt/decrypt round-trip — PEX response shape", () => {
  it("string vp_token + presentation_submission survive the round-trip", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = {
      vp_token: "single-credential-string",
      presentation_submission: {
        id: "submission-1",
        definition_id: "pid-request",
        descriptor_map: [
          {
            id: "pid",
            format: "vc+sd-jwt",
            path: "$",
          },
        ],
      },
      state: "s",
    };
    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: publicJwk,
    });
    const result = await decryptAuthorizationResponse({
      jwe,
      privateKey: privateJwk,
    });
    expect(result.response).toEqual(response);
  });

  it("string-array vp_token survives the round-trip", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = {
      vp_token: ["cred-1", "cred-2"],
      presentation_submission: { id: "x", definition_id: "y", descriptor_map: [] },
    };
    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: publicJwk,
    });
    const result = await decryptAuthorizationResponse({
      jwe,
      privateKey: privateJwk,
    });
    expect(result.response.vp_token).toEqual(["cred-1", "cred-2"]);
  });
});

describe("decryptAuthorizationResponse — security invariants", () => {
  it("fails to decrypt when the private key is a different one", async () => {
    const { publicJwk: verifierPub } = await generateResponseEncryptionKey();
    const { privateJwk: foreignPriv } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = { vp_token: { pid: "x" } };
    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: verifierPub,
    });
    await expect(
      decryptAuthorizationResponse({ jwe, privateKey: foreignPriv }),
    ).rejects.toMatchObject({ code: "oid4vp.response_encryption_failed" });
  });

  it("rejects a JWE alg that's not in the allowlist", async () => {
    // Encrypt with ECDH-ES (default), then ask to decrypt with an alg
    // allowlist that excludes ECDH-ES.
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = { vp_token: { pid: "x" } };
    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: publicJwk,
    });
    await expect(
      decryptAuthorizationResponse({
        jwe,
        privateKey: privateJwk,
        alg: ["RSA-OAEP-256"],
      }),
    ).rejects.toMatchObject({ code: "oid4vp.response_encryption_failed" });
  });

  it("rejects a JWE enc that's not in the allowlist", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = { vp_token: { pid: "x" } };
    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: publicJwk,
    });
    await expect(
      decryptAuthorizationResponse({
        jwe,
        privateKey: privateJwk,
        enc: ["A128GCM"],
      }),
    ).rejects.toMatchObject({ code: "oid4vp.response_encryption_failed" });
  });

  it("rejects a malformed JWE (wrong number of segments)", async () => {
    const { privateJwk } = await generateResponseEncryptionKey();
    await expect(
      decryptAuthorizationResponse({
        jwe: "not.a.valid.jwe",
        privateKey: privateJwk,
      }),
    ).rejects.toMatchObject({ code: "oid4vp.malformed_body" });
  });

  it("rejects a JWE with tampered ciphertext (AEAD tag mismatch)", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const response: AuthorizationResponse = { vp_token: { pid: "x" } };
    const jwe = await encryptAuthorizationResponse({
      response,
      encryptionKey: publicJwk,
    });
    // Flip one byte inside the ciphertext segment.
    const segs = jwe.split(".");
    const ciphertext = Buffer.from(segs[3]!, "base64url");
    ciphertext[0] = ciphertext[0]! ^ 0x01;
    segs[3] = ciphertext.toString("base64url");
    const tampered = segs.join(".");
    await expect(
      decryptAuthorizationResponse({ jwe: tampered, privateKey: privateJwk }),
    ).rejects.toMatchObject({ code: "oid4vp.response_encryption_failed" });
  });

  it("rejects when cleartext isn't a JSON object", async () => {
    // Build a JWE whose cleartext is `42` — JSON, but not an object.
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const importJWK = (await import("jose")).importJWK;
    const pubKey = await importJWK(publicJwk as Parameters<typeof importJWK>[0], "ECDH-ES");
    const cleartext = new TextEncoder().encode("42");
    const jwe = await new CompactEncrypt(cleartext)
      .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
      .encrypt(pubKey);
    await expect(
      decryptAuthorizationResponse({ jwe, privateKey: privateJwk }),
    ).rejects.toMatchObject({ code: "oid4vp.invalid_json" });
  });

  it("rejects when vp_token is missing from cleartext", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const importJWK = (await import("jose")).importJWK;
    const pubKey = await importJWK(publicJwk as Parameters<typeof importJWK>[0], "ECDH-ES");
    const cleartext = new TextEncoder().encode(JSON.stringify({ state: "x" }));
    const jwe = await new CompactEncrypt(cleartext)
      .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
      .encrypt(pubKey);
    await expect(
      decryptAuthorizationResponse({ jwe, privateKey: privateJwk }),
    ).rejects.toMatchObject({ code: "oid4vp.required_field_missing" });
  });

  it("rejects a PEX response (string vp_token) without presentation_submission", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey();
    const importJWK = (await import("jose")).importJWK;
    const pubKey = await importJWK(publicJwk as Parameters<typeof importJWK>[0], "ECDH-ES");
    const cleartext = new TextEncoder().encode(
      JSON.stringify({ vp_token: "single-cred-string" }),
    );
    const jwe = await new CompactEncrypt(cleartext)
      .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM" })
      .encrypt(pubKey);
    await expect(
      decryptAuthorizationResponse({ jwe, privateKey: privateJwk }),
    ).rejects.toMatchObject({ code: "oid4vp.required_field_missing" });
  });
});

describe("encrypt — input validation", () => {
  it("rejects when encryptionKey is missing", async () => {
    await expect(
      encryptAuthorizationResponse({
        response: { vp_token: { pid: "x" } },
        encryptionKey: null as unknown as never,
      }),
    ).rejects.toBeInstanceOf(Oid4vpError);
  });

  it("honours caller-supplied alg + enc overrides on the header", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey({
      alg: "ECDH-ES",
    });
    const jwe = await encryptAuthorizationResponse({
      response: { vp_token: { pid: "x" } },
      encryptionKey: publicJwk,
      alg: "ECDH-ES",
      enc: "A128GCM",
    });
    const result = await decryptAuthorizationResponse({
      jwe,
      privateKey: privateJwk,
      enc: ["A128GCM"],
    });
    expect(result.header["enc"]).toBe("A128GCM");
  });

  it("emits a JWE with the encryption JWK's kid in the header when set", async () => {
    const { publicJwk, privateJwk } = await generateResponseEncryptionKey({
      kid: "k-1",
    });
    const jwe = await encryptAuthorizationResponse({
      response: { vp_token: { pid: "x" } },
      encryptionKey: publicJwk,
    });
    const headerB64 = jwe.split(".")[0]!;
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf-8"),
    ) as { kid?: string };
    expect(header.kid).toBe("k-1");
    // Round-trip still works.
    await expect(
      decryptAuthorizationResponse({ jwe, privateKey: privateJwk }),
    ).resolves.toBeDefined();
  });
});

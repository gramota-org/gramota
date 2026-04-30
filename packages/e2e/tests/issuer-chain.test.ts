/**
 * Full chain with the new Issuer class:
 *
 *   Issuer.issue → Holder.credentials.receive → Holder.respond
 *      → Verifier.response
 *
 * Every package's class API is exercised. If green, customers can write
 * a full deployment using only the four classes (Issuer, Holder, Verifier
 * + the standalone OID4VP/PE/Trust types as they need them).
 */

import { describe, it, expect } from "vitest";
import { Issuer } from "@gateway/issuer";
import { Holder } from "@gateway/holder";
import { Verifier } from "@gateway/verifier";
import { newEs256KeyPair } from "../src/test-helpers.js";

const NOW_S = 1_700_000_050;
const IAT_S = 1_700_000_000;

describe("Issuer → Holder → Verifier — class APIs only", () => {
  it("issues, holds, presents via OID4VP, verifies — full chain green", async () => {
    const issuerKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    // ---- ISSUER ----
    const issuer = new Issuer({
      privateKey: issuerKey.privateJwk,
      publicKey: issuerKey.publicJwk,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });

    const { token, credentialId } = await issuer.issue({
      subject: {
        given_name: "Hannah",
        family_name: "Issued",
        birthdate: "1990-07-15",
        nationality: "BG",
      },
      selectivelyDisclosable: [
        "given_name",
        "family_name",
        "birthdate",
        "nationality",
      ],
      holderKey: holderKey.publicJwk,
      vct: "https://credentials.example.com/identity_v1",
      issuedAt: IAT_S,
      expiresIn: 86_400,
    });

    expect(token).toContain("~");
    expect(credentialId).toMatch(/^[0-9a-f-]{36}$/);

    // ---- HOLDER ----
    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.credentials.receive(token, {
      trustedIssuers: [issuerKey.publicJwk],
    });
    expect(stored.issuer).toBe("https://issuer.example.com");

    // ---- VERIFIER ----
    const audience = "https://my-bank.example.com";
    const verifier = new Verifier({
      audience,
      issuerKey: issuerKey.publicJwk,
    });

    const created = verifier.request({
      baseUrl: "openid4vp://authorize",
      nonce: "issuer-chain-nonce",
      state: "issuer-chain-state",
      responseUri: `${audience}/oid4vp/cb`,
      presentationDefinition: {
        id: "pd-issuer-chain",
        input_descriptors: [
          {
            id: "id",
            format: { "vc+sd-jwt": { alg: ["ES256"] } },
            constraints: {
              limit_disclosure: "required",
              fields: [
                { path: ["$.given_name"] },
                { path: ["$.birthdate"] },
              ],
            },
          },
        ],
      },
    });

    const respond = await holder.respond(created.url, {
      now: () => NOW_S - 5,
    });

    const result = await verifier.response(respond.body, {
      expectedNonce: "issuer-chain-nonce",
      expectedState: "issuer-chain-state",
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.claims).toEqual({
      given_name: "Hannah",
      birthdate: "1990-07-15",
    });
    expect(result.metadata.issuer).toBe("https://issuer.example.com");
    expect(result.metadata.holderKey).toEqual(holderKey.publicJwk);
    expect(result.checks).toHaveLength(11);
    expect(result.checks.every((c) => c.passed)).toBe(true);
  });

  it("vct flows through to the credential and is visible in the parsed payload", async () => {
    const issuerKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const issuer = new Issuer({
      privateKey: issuerKey.privateJwk,
      publicKey: issuerKey.publicJwk,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });

    const { token } = await issuer.issue({
      subject: { x: 1 },
      holderKey: holderKey.publicJwk,
      vct: "https://credentials.example.com/eu_pid_v1",
    });

    expect(token).toContain("~");
    // vct is non-SD so it appears directly in the JWT payload — decode the
    // payload bytes to confirm.
    const payloadB64 = token.split("~")[0]!.split(".")[1]!;
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf-8"),
    );
    expect(payload.vct).toBe("https://credentials.example.com/eu_pid_v1");
  });
});

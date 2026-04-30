/**
 * E2E using ONLY the class-based public API — no standalone OID4VP /
 * presentation-exchange functions in this file. This is the API manifesto
 * shape: every customer touches `Verifier.method(...)` and `Holder.method(...)`,
 * the lower-level functions are an escape hatch.
 *
 * If a customer can write end-to-end OID4VP using only the class API, we've
 * delivered on the "Stripe-grade DX" promise.
 */

import { describe, it, expect } from "vitest";
import { issueSdJwt } from "@gateway/sd-jwt";
import { Holder } from "@gateway/holder";
import { Verifier } from "@gateway/verifier";
import { newEs256KeyPair, makeIssuerSigner } from "../src/test-helpers.js";

const NOW_S = 1_700_000_050;
const IAT_S = 1_700_000_000;

describe("Class-based API — full OID4VP flow without standalone functions", () => {
  it("verifier.request → holder.respond → verifier.response", async () => {
    // ---- Setup ----
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const signer = await makeIssuerSigner(issuer.privateJwk);

    const { token } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: {
        given_name: "Joana",
        family_name: "Tester",
        birthdate: "1990-07-15",
        nationality: "BG",
      },
      alg: "ES256",
      signer,
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    await holder.credentials.receive(token, { trustedIssuers: [issuer.publicJwk] });

    // ---- VERIFIER builds the request URL via class method ----
    const audience = "https://my-bank.example.com";
    const verifier = new Verifier({
      audience,
      issuerKey: issuer.publicJwk,
    });

    const created = verifier.request({
      baseUrl: "openid4vp://authorize",
      nonce: "class-api-nonce",
      state: "class-api-state",
      responseUri: `${audience}/oid4vp/cb`,
      presentationDefinition: {
        id: "pd-class-1",
        input_descriptors: [
          {
            id: "id-card",
            format: { "vc+sd-jwt": { alg: ["ES256"] } },
            constraints: {
              limit_disclosure: "required",
              fields: [
                { path: ["$.given_name"], filter: { type: "string" } },
                { path: ["$.birthdate"], filter: { type: "string" } },
              ],
            },
          },
        ],
      },
    });

    expect(created.url).toMatch(/^openid4vp:/);
    expect(created.nonce).toBe("class-api-nonce");
    expect(created.state).toBe("class-api-state");
    expect(created.request.client_id).toBe(audience);
    expect(created.request.response_mode).toBe("direct_post");

    // ---- HOLDER processes URL → produces response body via class method ----
    const respond = await holder.respond(created.url, {
      now: () => NOW_S - 5,
    });

    expect([...respond.disclosed].sort()).toEqual(["birthdate", "given_name"]);
    expect(respond.body).toContain("vp_token=");
    expect(respond.body).toContain("presentation_submission=");
    expect(respond.body).toContain("state=class-api-state");

    // ---- VERIFIER verifies the response via class method ----
    const result = await verifier.response(respond.body, {
      expectedNonce: "class-api-nonce",
      expectedState: "class-api-state",
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.claims).toEqual({
      given_name: "Joana",
      birthdate: "1990-07-15",
    });
    expect(result.metadata.holderKey).toEqual(holderKey.publicJwk);
    expect(result.checks).toHaveLength(11);
  });

  it("verifyPresentationResponse fails fast on state mismatch", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const signer = await makeIssuerSigner(issuer.privateJwk);
    const { token } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "X" },
      alg: "ES256",
      signer,
    });
    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    await holder.credentials.receive(token, { trustedIssuers: [issuer.publicJwk] });

    const verifier = new Verifier({
      audience: "https://v.example.com",
      issuerKey: issuer.publicJwk,
    });
    const created = verifier.request({
      baseUrl: "openid4vp://",
      nonce: "n",
      state: "expected-state",
      responseUri: "https://v.example.com/cb",
      presentationDefinition: {
        id: "pd-x",
        input_descriptors: [
          {
            id: "x",
            constraints: { fields: [{ path: ["$.given_name"] }] },
          },
        ],
      },
    });

    const respond = await holder.respond(created.url, {
      now: () => NOW_S - 5,
    });

    const result = await verifier.response(respond.body, {
      expectedNonce: "n",
      expectedState: "WRONG-STATE",
      now: () => NOW_S,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failedCheck).toBe("structure.parse");
    expect(result.reason).toMatch(/state mismatch/);
  });

  it("respondTo throws when no credential satisfies the presentation_definition", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const signer = await makeIssuerSigner(issuer.privateJwk);
    const { token } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "X" },
      alg: "ES256",
      signer,
    });
    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    await holder.credentials.receive(token, { trustedIssuers: [issuer.publicJwk] });

    const verifier = new Verifier({
      audience: "https://v.example.com",
      issuerKey: issuer.publicJwk,
    });
    const created = verifier.request({
      baseUrl: "openid4vp://",
      nonce: "n",
      responseUri: "https://v.example.com/cb",
      presentationDefinition: {
        id: "pd-impossible",
        input_descriptors: [
          {
            id: "passport",
            constraints: { fields: [{ path: ["$.passport_number"] }] },
          },
        ],
      },
    });

    await expect(holder.respond(created.url)).rejects.toThrow(
      /unmatched descriptors/,
    );
  });
});

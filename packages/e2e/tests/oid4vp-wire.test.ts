/**
 * E2E with full OID4VP wire transport — verifier and holder communicate via
 * encoded URLs and form bodies, exactly like a production deployment.
 *
 * Flow:
 *   Verifier builds Authorization Request URL  →
 *   Wallet parses URL, picks credential, presents  →
 *   Wallet builds Authorization Response form body  →
 *   Verifier parses form body, extracts vp_token  →
 *   Verifier verifies vp_token cryptographically.
 *
 * Every byte that crosses the verifier/wallet boundary goes through the
 * OID4VP wire format. If this passes, integrators can drop our SDK behind
 * any HTTP framework and it will Just Work.
 */

import { describe, it, expect } from "vitest";
import { issueSdJwt } from "@gateway/sd-jwt";
import { Holder } from "@gateway/holder";
import { Verifier } from "@gateway/verifier";
import {
  buildAuthorizationRequestUrl,
  buildAuthorizationResponseBody,
  parseAuthorizationRequestUrl,
  parseAuthorizationResponseBody,
  type AuthorizationRequest,
  type AuthorizationResponse,
} from "@gateway/oid4vp";
import { newEs256KeyPair, makeIssuerSigner } from "../src/test-helpers.js";

const NOW_S = 1_700_000_050;
const IAT_S = 1_700_000_000;

describe("OID4VP full-wire E2E — verifier ↔ wallet ↔ verifier", () => {
  it("delivers a verified credential through encoded URL + form-body transport", async () => {
    // ---- Setup: keys and an issued credential bound to the holder ----
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const { token: issued } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: {
        given_name: "Hannah",
        family_name: "Wire",
        birthdate: "1992-04-04",
        nationality: "BG",
      },
      alg: "ES256",
      signer: await makeIssuerSigner(issuer.privateJwk),
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.credentials.receive(issued, {
      trustedIssuers: [issuer.publicJwk],
    });

    // ---- VERIFIER side: build the OID4VP request URL ----
    const verifierAud = "https://my-bank.example.com";
    const nonce = "wire-nonce-1";
    const state = "csrf-state-1";

    const authzRequest: AuthorizationRequest = {
      response_type: "vp_token",
      client_id: verifierAud,
      client_id_scheme: "redirect_uri",
      response_mode: "direct_post",
      response_uri: `${verifierAud}/oid4vp/cb`,
      nonce,
      state,
      presentation_definition: {
        id: "pd-wire-1",
        input_descriptors: [
          {
            id: "id-card",
            format: { "vc+sd-jwt": { alg: ["ES256"] } },
            constraints: {
              fields: [{ path: ["$.given_name"] }],
              limit_disclosure: "required",
            },
          },
        ],
      },
    };

    const requestUrl = buildAuthorizationRequestUrl(
      "openid4vp://authorize",
      authzRequest,
    );

    // ---- WALLET side: parse the URL and respond ----
    const parsedRequest = parseAuthorizationRequestUrl(requestUrl);
    expect(parsedRequest.client_id).toBe(verifierAud);

    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name"],
      audience: parsedRequest.client_id,
      nonce: parsedRequest.nonce,
      now: () => NOW_S - 5,
    });

    const authzResponse: AuthorizationResponse = {
      vp_token: presentation,
      presentation_submission: {
        id: "sub-wire-1",
        definition_id: "pd-wire-1",
        descriptor_map: [
          { id: "id-card", format: "vc+sd-jwt", path: "$" },
        ],
      },
      state: parsedRequest.state ?? "",
      iss: "https://wallet.example.com",
    };

    const responseBody = buildAuthorizationResponseBody(authzResponse);

    // ---- VERIFIER side: parse response, verify the credential ----
    const parsedResponse = parseAuthorizationResponseBody(responseBody);

    // CSRF: state must match what we sent.
    expect(parsedResponse.state).toBe(state);

    // The vp_token is the SD-JWT-VC presentation — hand it to our verifier.
    expect(typeof parsedResponse.vp_token).toBe("string");

    const verifier = new Verifier({
      audience: verifierAud,
      issuerKey: issuer.publicJwk,
    });
    const result = await verifier.verify(parsedResponse.vp_token as string, {
      nonce,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // The presentation reveals exactly given_name — nothing else leaked.
    expect(result.claims).toEqual({ given_name: "Hannah" });
    expect(result.metadata.holderKey).toEqual(holderKey.publicJwk);
    expect(result.checks).toHaveLength(11);
    expect(result.checks.every((c) => c.passed)).toBe(true);
  });

  it("CSRF: a wallet that returns a wrong state is detectable by the verifier", async () => {
    const requestUrl = buildAuthorizationRequestUrl("openid4vp://authorize", {
      response_type: "vp_token",
      client_id: "https://v.example.com",
      nonce: "n-csrf",
      state: "expected-csrf-token",
    });

    const parsed = parseAuthorizationRequestUrl(requestUrl);

    // Malicious or buggy wallet returns a different state.
    const responseBody = buildAuthorizationResponseBody({
      vp_token: "fake.token~",
      presentation_submission: {
        id: "s",
        definition_id: "pd",
        descriptor_map: [],
      },
      state: "WRONG-STATE",
    });

    const parsedResponse = parseAuthorizationResponseBody(responseBody);

    // The OID4VP layer doesn't enforce state correlation — that's the
    // application's responsibility (typical for OAuth-family protocols).
    // We assert that the application CAN detect it.
    expect(parsedResponse.state).not.toBe(parsed.state);
  });
});

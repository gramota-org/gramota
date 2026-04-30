/**
 * Full E2E with DIF Presentation Exchange driving the holder's selection.
 *
 * Verifier publishes a presentation_definition; holder mechanically picks
 * the right credential and the minimum disclosures; submission is built;
 * verifier verifies. No human in the loop on the holder side beyond
 * "consent to release these claims".
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
} from "@gateway/oid4vp";
import {
  buildPresentationSubmission,
  selectForDefinition,
  type PresentationDefinition,
} from "@gateway/presentation-exchange";
import { newEs256KeyPair, makeIssuerSigner } from "../src/test-helpers.js";

const NOW_S = 1_700_000_050;
const IAT_S = 1_700_000_000;

describe("E2E with Presentation Exchange — verifier-driven disclosure selection", () => {
  it("verifier→PD→holder selects→presents→verifier verifies", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const signer = await makeIssuerSigner(issuer.privateJwk);

    // Holder has 2 credentials: an ID and a degree.
    const { token: idCred } = await issueSdJwt({
      payload: {
        iss: "https://gov.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: {
        given_name: "Ivan",
        family_name: "Petrov",
        birthdate: "1985-03-12",
        nationality: "BG",
      },
      alg: "ES256",
      signer,
    });
    const { token: eduCred } = await issueSdJwt({
      payload: {
        iss: "https://uni.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { degree: "MSc Computer Science", university: "Sofia U" },
      alg: "ES256",
      signer,
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const idStored = await holder.receive(idCred, {
      trustedIssuers: [issuer.publicJwk],
    });
    await holder.receive(eduCred, {
      trustedIssuers: [issuer.publicJwk],
    });

    // Verifier defines: "I want given_name + birthdate, vc+sd-jwt format,
    // selective disclosure mandatory".
    const presentationDefinition: PresentationDefinition = {
      id: "pd-id-only",
      name: "Identity verification",
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
    };

    const audience = "https://my-bank.example.com";
    const nonce = "pd-nonce-1";

    const authzRequest: AuthorizationRequest = {
      response_type: "vp_token",
      client_id: audience,
      client_id_scheme: "redirect_uri",
      response_mode: "direct_post",
      response_uri: `${audience}/oid4vp/cb`,
      nonce,
      state: "csrf-pd",
      presentation_definition: presentationDefinition as unknown as Readonly<
        Record<string, unknown>
      >,
    };
    const requestUrl = buildAuthorizationRequestUrl(
      "openid4vp://authorize",
      authzRequest,
    );

    // ---- HOLDER: parse, select, present ----
    const parsedRequest = parseAuthorizationRequestUrl(requestUrl);
    const incomingPd = parsedRequest.presentation_definition as
      | PresentationDefinition
      | undefined;
    expect(incomingPd).toBeDefined();
    if (incomingPd === undefined) return;

    const credentials = await holder.list();
    const selection = selectForDefinition({
      definition: incomingPd,
      credentials,
    });
    expect(selection.fullySatisfied).toBe(true);
    expect(selection.matches).toHaveLength(1);
    expect(selection.matches[0]?.credential.id).toBe(idStored.id);
    expect([...(selection.matches[0]?.disclose ?? [])].sort()).toEqual([
      "birthdate",
      "given_name",
    ]);

    // Build the presentation per the selection.
    const match = selection.matches[0]!;
    const presentation = await holder.present({
      credentialId: match.credential.id,
      disclose: match.disclose,
      audience: parsedRequest.client_id,
      nonce: parsedRequest.nonce,
      now: () => NOW_S - 5,
    });

    const submission = buildPresentationSubmission(incomingPd, selection);

    const responseBody = buildAuthorizationResponseBody({
      vp_token: presentation,
      presentation_submission: submission as unknown as Readonly<
        Record<string, unknown>
      >,
      state: parsedRequest.state ?? "",
    });

    // ---- VERIFIER: parse, verify ----
    const parsedResponse = parseAuthorizationResponseBody(responseBody);
    expect(parsedResponse.state).toBe("csrf-pd");

    const submissionParsed =
      parsedResponse.presentation_submission as unknown as {
        definition_id: string;
        descriptor_map: { id: string; format: string; path: string }[];
      };
    expect(submissionParsed.definition_id).toBe("pd-id-only");
    expect(submissionParsed.descriptor_map[0]?.path).toBe("$");

    const verifier = new Verifier({
      audience,
      issuerKey: issuer.publicJwk,
    });
    const result = await verifier.verify(parsedResponse.vp_token as string, {
      nonce,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // Reveals exactly what the PD asked for, nothing else.
    expect(result.claims).toEqual({
      given_name: "Ivan",
      birthdate: "1985-03-12",
    });
    expect(result.claims).not.toHaveProperty("family_name");
    expect(result.claims).not.toHaveProperty("nationality");
  });

  it("flags an unsatisfiable PD without leaking which credentials exist", async () => {
    const issuer = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const signer = await makeIssuerSigner(issuer.privateJwk);

    const { token } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: IAT_S,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { given_name: "Maria" },
      alg: "ES256",
      signer,
    });
    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    await holder.receive(token, { trustedIssuers: [issuer.publicJwk] });

    const definition: PresentationDefinition = {
      id: "pd-impossible",
      input_descriptors: [
        {
          id: "passport",
          constraints: {
            fields: [{ path: ["$.passport_number"] }],
          },
        },
      ],
    };
    const sel = selectForDefinition({
      definition,
      credentials: await holder.list(),
    });
    expect(sel.fullySatisfied).toBe(false);
    expect(sel.unmatched).toHaveLength(1);
    expect(sel.unmatched[0]?.descriptor.id).toBe("passport");
  });
});

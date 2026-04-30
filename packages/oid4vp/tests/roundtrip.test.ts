// OID4VP wire-format roundtrip — verifier crafts a request, parses a
// wallet-formatted response, hands the vp_token to our existing verifier.

import { describe, it, expect } from "vitest";
import {
  buildAuthorizationRequestUrl,
  parseAuthorizationRequestUrl,
  buildAuthorizationResponseBody,
  parseAuthorizationResponseBody,
  type AuthorizationRequest,
  type AuthorizationResponse,
} from "../src/index.js";

describe("OID4VP wire-format roundtrip — verifier ↔ wallet", () => {
  it("verifier→wallet→verifier preserves all fields with no loss", () => {
    // Verifier builds the request URL and shares it with the wallet (QR /
    // deep link / etc).
    const request: AuthorizationRequest = {
      response_type: "vp_token",
      client_id: "https://my-bank.example.com",
      client_id_scheme: "redirect_uri",
      response_mode: "direct_post",
      response_uri: "https://my-bank.example.com/oid4vp/cb",
      nonce: "n-roundtrip-1",
      state: "session-42",
      presentation_definition: {
        id: "pd-1",
        input_descriptors: [
          {
            id: "id-card",
            format: { "vc+sd-jwt": { alg: ["ES256", "ES384"] } },
            constraints: {
              fields: [{ path: ["$.given_name", "$.birthdate"] }],
              limit_disclosure: "required",
            },
          },
        ],
      },
    };

    const requestUrl = buildAuthorizationRequestUrl(
      "openid4vp://authorize",
      request,
    );

    // Wallet parses the request.
    const parsedRequest = parseAuthorizationRequestUrl(requestUrl);
    expect(parsedRequest).toEqual(request);

    // Wallet builds a response (vp_token comes from Holder.present).
    const response: AuthorizationResponse = {
      vp_token: "fake.issuer.jws~disclosure1~kbjwt.h.p.s",
      presentation_submission: {
        id: "sub-1",
        definition_id: "pd-1",
        descriptor_map: [
          { id: "id-card", format: "vc+sd-jwt", path: "$" },
        ],
      },
      state: parsedRequest.state ?? "",
      iss: "https://wallet.example.com",
    };

    const responseBody = buildAuthorizationResponseBody(response);

    // Verifier parses the response from the form-encoded body.
    const parsedResponse = parseAuthorizationResponseBody(responseBody);

    expect(parsedResponse).toEqual(response);
    expect(parsedResponse.state).toBe(parsedRequest.state);
  });

  it("parsed response.state is bound to the original request — anti-CSRF", () => {
    const request: AuthorizationRequest = {
      response_type: "vp_token",
      client_id: "https://v.example.com",
      nonce: "n-csrf",
      state: "csrf-token-abc",
    };
    const requestUrl = buildAuthorizationRequestUrl(
      "openid4vp://",
      request,
    );
    const parsedRequest = parseAuthorizationRequestUrl(requestUrl);

    // A correct wallet echoes state unchanged.
    const responseBody = buildAuthorizationResponseBody({
      vp_token: "fake-vp",
      presentation_submission: {
        id: "s",
        definition_id: "pd",
        descriptor_map: [],
      },
      state: parsedRequest.state ?? "",
    });

    const parsedResponse = parseAuthorizationResponseBody(responseBody);
    expect(parsedResponse.state).toBe(request.state);
  });
});

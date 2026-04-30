// OID4VP §6 — Authorization Response wire-format tests.

import { describe, it, expect } from "vitest";
import {
  buildAuthorizationResponseBody,
  parseAuthorizationResponseBody,
  parseAuthorizationResponseFromParams,
  Oid4vpError,
  type AuthorizationResponse,
} from "../src/index.js";

const submission = {
  id: "sub-1",
  definition_id: "pd-1",
  descriptor_map: [
    { id: "id-card", format: "vc+sd-jwt", path: "$" },
  ],
};

describe("buildAuthorizationResponseBody", () => {
  it("encodes a single-vp-token response as form data", () => {
    const body = buildAuthorizationResponseBody({
      vp_token: "header.payload.sig~d1~kbjwt",
      presentation_submission: submission,
      state: "abc-123",
    });

    const params = new URLSearchParams(body);
    expect(params.get("vp_token")).toBe("header.payload.sig~d1~kbjwt");
    expect(JSON.parse(params.get("presentation_submission")!)).toEqual(
      submission,
    );
    expect(params.get("state")).toBe("abc-123");
  });

  it("encodes multiple vp_tokens as a JSON array string", () => {
    const body = buildAuthorizationResponseBody({
      vp_token: ["tok1~", "tok2~"],
      presentation_submission: submission,
    });
    const params = new URLSearchParams(body);
    expect(JSON.parse(params.get("vp_token")!)).toEqual(["tok1~", "tok2~"]);
  });

  it("rejects building a response missing vp_token", () => {
    expect(() =>
      buildAuthorizationResponseBody({
        // @ts-expect-error: deliberately missing required field
        presentation_submission: submission,
      }),
    ).toThrow(Oid4vpError);
  });

  it("rejects building a response missing presentation_submission", () => {
    expect(() =>
      buildAuthorizationResponseBody({
        // @ts-expect-error: deliberately missing required field
        vp_token: "x",
      }),
    ).toThrow(Oid4vpError);
  });

  it("rejects vp_token that isn't a string or string[]", () => {
    expect(() =>
      buildAuthorizationResponseBody({
        // @ts-expect-error: deliberately wrong type
        vp_token: 42,
        presentation_submission: submission,
      }),
    ).toThrow(/string/);
  });
});

describe("parseAuthorizationResponseBody", () => {
  it("round-trips a single-vp-token response", () => {
    const original: AuthorizationResponse = {
      vp_token: "h.p.s~d~kb",
      presentation_submission: submission,
      state: "abc",
      iss: "https://wallet.example.com",
    };
    const body = buildAuthorizationResponseBody(original);
    expect(parseAuthorizationResponseBody(body)).toEqual(original);
  });

  it("round-trips a multi-vp-token response", () => {
    const original: AuthorizationResponse = {
      vp_token: ["tok1~", "tok2~"],
      presentation_submission: submission,
    };
    const body = buildAuthorizationResponseBody(original);
    expect(parseAuthorizationResponseBody(body)).toEqual(original);
  });

  it("rejects body missing vp_token", () => {
    expect(() =>
      parseAuthorizationResponseBody(
        "presentation_submission=" + encodeURIComponent(JSON.stringify(submission)),
      ),
    ).toThrow(/vp_token/);
  });

  it("rejects body missing presentation_submission", () => {
    expect(() =>
      parseAuthorizationResponseBody("vp_token=h.p.s~"),
    ).toThrow(/presentation_submission/);
  });

  it("rejects when presentation_submission is not valid JSON", () => {
    expect(() =>
      parseAuthorizationResponseBody(
        "vp_token=h.p.s~&presentation_submission=NOT_JSON",
      ),
    ).toThrow(/not valid JSON/);
  });

  it("rejects when presentation_submission is not a JSON object", () => {
    expect(() =>
      parseAuthorizationResponseBody(
        `vp_token=h.p.s~&presentation_submission=${encodeURIComponent(
          JSON.stringify("not an object"),
        )}`,
      ),
    ).toThrow(/JSON object/);
  });
});

describe("parseAuthorizationResponseFromParams", () => {
  it("accepts a plain object (framework body parsers)", () => {
    const result = parseAuthorizationResponseFromParams({
      vp_token: "tok~",
      presentation_submission: JSON.stringify(submission),
      state: "x",
    });
    expect(result.vp_token).toBe("tok~");
    expect(result.state).toBe("x");
  });

  it("accepts URLSearchParams", () => {
    const p = new URLSearchParams();
    p.set("vp_token", "tok~");
    p.set("presentation_submission", JSON.stringify(submission));
    const result = parseAuthorizationResponseFromParams(p);
    expect(result.vp_token).toBe("tok~");
  });
});

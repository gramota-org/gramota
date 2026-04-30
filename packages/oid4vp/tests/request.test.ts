// OID4VP §5 — Authorization Request wire-format tests.

import { describe, it, expect } from "vitest";
import {
  buildAuthorizationRequestUrl,
  parseAuthorizationRequestUrl,
  parseAuthorizationRequestSearchParams,
  Oid4vpError,
  type AuthorizationRequest,
} from "../src/index.js";

const minimal: AuthorizationRequest = {
  response_type: "vp_token",
  client_id: "https://verifier.example.com",
  nonce: "n-12345",
};

const haipShaped: AuthorizationRequest = {
  response_type: "vp_token",
  client_id: "verifier.example.com",
  client_id_scheme: "x509_san_dns",
  response_mode: "direct_post",
  response_uri: "https://verifier.example.com/oid4vp/callback",
  nonce: "n-67890",
  state: "opaque-state-abc",
  presentation_definition: {
    id: "pd-1",
    input_descriptors: [
      {
        id: "id-card",
        constraints: {
          fields: [{ path: ["$.given_name"] }],
        },
      },
    ],
  },
};

describe("buildAuthorizationRequestUrl", () => {
  it("encodes a minimal request as URL params", () => {
    const url = buildAuthorizationRequestUrl(
      "openid4vp://authorize",
      minimal,
    );
    expect(url).toContain("response_type=vp_token");
    expect(url).toContain("client_id=https%3A%2F%2Fverifier.example.com");
    expect(url).toContain("nonce=n-12345");
  });

  it("JSON-encodes presentation_definition into the URL", () => {
    const url = buildAuthorizationRequestUrl(
      "openid4vp://authorize",
      haipShaped,
    );
    const parsedUrl = new URL(url);
    const pd = parsedUrl.searchParams.get("presentation_definition")!;
    const decoded = JSON.parse(pd);
    expect(decoded.id).toBe("pd-1");
  });

  it("works with HTTP base URLs (web flows) and custom schemes (mobile flows)", () => {
    const httpUrl = buildAuthorizationRequestUrl(
      "https://wallet.example.com/authorize",
      minimal,
    );
    const customUrl = buildAuthorizationRequestUrl("openid4vp://", minimal);
    expect(httpUrl).toMatch(/^https:/);
    expect(customUrl).toMatch(/^openid4vp:/);
  });

  it("rejects building a request missing response_type", () => {
    expect(() =>
      // @ts-expect-error: deliberately missing required field
      buildAuthorizationRequestUrl("openid4vp://", {
        client_id: "x",
        nonce: "y",
      }),
    ).toThrow(Oid4vpError);
  });

  it("rejects response_type other than vp_token", () => {
    expect(() =>
      buildAuthorizationRequestUrl("openid4vp://", {
        ...minimal,
        // @ts-expect-error: deliberately wrong literal
        response_type: "code",
      }),
    ).toThrow(/vp_token/);
  });

  it("rejects when both presentation_definition and _uri are present", () => {
    expect(() =>
      buildAuthorizationRequestUrl("openid4vp://", {
        ...minimal,
        presentation_definition: { id: "x", input_descriptors: [] },
        presentation_definition_uri: "https://x.com/pd",
      }),
    ).toThrow(/mutually exclusive/);
  });

  it("rejects response_mode=direct_post without response_uri", () => {
    expect(() =>
      buildAuthorizationRequestUrl("openid4vp://", {
        ...minimal,
        response_mode: "direct_post",
      }),
    ).toThrow(/response_uri/);
  });
});

describe("parseAuthorizationRequestUrl", () => {
  it("round-trips a minimal request", () => {
    const url = buildAuthorizationRequestUrl("openid4vp://", minimal);
    const parsed = parseAuthorizationRequestUrl(url);
    expect(parsed).toEqual(minimal);
  });

  it("round-trips a HAIP-shaped request with presentation_definition", () => {
    const url = buildAuthorizationRequestUrl("openid4vp://", haipShaped);
    const parsed = parseAuthorizationRequestUrl(url);
    expect(parsed).toEqual(haipShaped);
  });

  it("rejects URLs missing required fields", () => {
    expect(() =>
      parseAuthorizationRequestUrl(
        "openid4vp://authorize?response_type=vp_token&client_id=x",
      ),
    ).toThrow(/nonce/);
  });

  it("rejects URLs that aren't URLs", () => {
    expect(() => parseAuthorizationRequestUrl("not a url")).toThrow(
      /not a valid URL/,
    );
  });

  it("rejects malformed presentation_definition JSON", () => {
    expect(() =>
      parseAuthorizationRequestUrl(
        "openid4vp://authorize?response_type=vp_token&client_id=x&nonce=y&presentation_definition=NOT_JSON",
      ),
    ).toThrow(/invalid JSON/);
  });
});

describe("parseAuthorizationRequestSearchParams", () => {
  it("accepts a URLSearchParams instance directly", () => {
    const url = buildAuthorizationRequestUrl("openid4vp://", minimal);
    const params = new URL(url).searchParams;
    expect(parseAuthorizationRequestSearchParams(params)).toEqual(minimal);
  });

  it("accepts a plain object (e.g. Express's req.query)", () => {
    const obj: Record<string, string> = {
      response_type: "vp_token",
      client_id: "x",
      nonce: "y",
    };
    expect(parseAuthorizationRequestSearchParams(obj)).toEqual({
      response_type: "vp_token",
      client_id: "x",
      nonce: "y",
    });
  });
});

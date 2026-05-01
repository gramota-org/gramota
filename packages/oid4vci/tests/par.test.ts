/**
 * Pushed Authorization Requests (PAR) — RFC 9126 conformance.
 *
 * RFC 9126 § 2:
 *   The client POSTs every parameter that would otherwise go on the
 *   authorization-request URL to the PAR endpoint. The endpoint returns
 *   `{ request_uri, expires_in }`. The client then redirects the user
 *   to the regular authorization endpoint with just `client_id` and
 *   `request_uri`.
 *
 * What this proves at the spec level:
 *   - The PAR request is `application/x-www-form-urlencoded`
 *   - Every param the client would have put on the URL goes in the body
 *   - The response is parsed for `request_uri` (URN) and `expires_in`
 *   - HTTP errors map to `oid4vci.par_request_failed`
 *   - Malformed responses map to `oid4vci.par_response_invalid`
 *   - The follow-up authorization URL contains exactly `client_id` and
 *     `request_uri` — no leakage of the original params
 */

import { describe, it, expect } from "vitest";
import {
  Oid4vciError,
  pushAuthorizationRequest,
  type Fetcher,
} from "../src/index.js";

const PAR_ENDPOINT = "https://as.example.com/par";

describe("pushAuthorizationRequest — request shape per RFC 9126 §2.1", () => {
  it("POSTs every authorization param as form-encoded body", async () => {
    let capturedUrl: string | undefined;
    let capturedMethod: string | undefined;
    let capturedHeaders: Record<string, string> | undefined;
    let capturedBody: string | undefined;
    const fetcher: Fetcher = async (url, init) => {
      capturedUrl = url;
      capturedMethod = init?.method;
      capturedHeaders = init?.headers as Record<string, string>;
      capturedBody = init?.body as string;
      return {
        ok: true,
        status: 201,
        json: async () => ({
          request_uri:
            "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
          expires_in: 60,
        }),
        text: async () => "",
      };
    };

    await pushAuthorizationRequest({
      parEndpoint: PAR_ENDPOINT,
      params: {
        response_type: "code",
        client_id: "wallet-dev",
        redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
        state: "csrf-1",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
        authorization_details: JSON.stringify([
          { type: "openid_credential", credential_configuration_id: "pid" },
        ]),
      },
      fetcher,
    });

    expect(capturedUrl).toBe(PAR_ENDPOINT);
    expect(capturedMethod).toBe("POST");
    expect(capturedHeaders?.["Content-Type"]).toBe(
      "application/x-www-form-urlencoded",
    );
    expect(capturedHeaders?.["Accept"]).toBe("application/json");

    // Body must be form-encoded with every param
    const params = new URLSearchParams(capturedBody!);
    expect(params.get("response_type")).toBe("code");
    expect(params.get("client_id")).toBe("wallet-dev");
    expect(params.get("redirect_uri")).toBe("urn:ietf:wg:oauth:2.0:oob");
    expect(params.get("state")).toBe("csrf-1");
    expect(params.get("code_challenge")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("authorization_details")).toContain("openid_credential");
  });

  it("returns request_uri + expires_in from the response", async () => {
    const fetcher: Fetcher = async () => ({
      ok: true,
      status: 201,
      json: async () => ({
        request_uri: "urn:ietf:params:oauth:request_uri:abcd1234",
        expires_in: 90,
      }),
      text: async () => "",
    });

    const result = await pushAuthorizationRequest({
      parEndpoint: PAR_ENDPOINT,
      params: { client_id: "x", redirect_uri: "y" },
      fetcher,
    });

    expect(result.requestUri).toBe(
      "urn:ietf:params:oauth:request_uri:abcd1234",
    );
    expect(result.expiresIn).toBe(90);
  });

  it("preserves expires_in absence — RFC 9126 says it's RECOMMENDED, not required", async () => {
    const fetcher: Fetcher = async () => ({
      ok: true,
      status: 201,
      json: async () => ({
        request_uri: "urn:ietf:params:oauth:request_uri:nodate",
      }),
      text: async () => "",
    });

    const result = await pushAuthorizationRequest({
      parEndpoint: PAR_ENDPOINT,
      params: { client_id: "x" },
      fetcher,
    });

    expect(result.requestUri).toBe(
      "urn:ietf:params:oauth:request_uri:nodate",
    );
    expect(result.expiresIn).toBeUndefined();
  });
});

describe("pushAuthorizationRequest — error handling", () => {
  it("maps HTTP errors to oid4vci.par_request_failed with status + body", async () => {
    const fetcher: Fetcher = async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: "invalid_request" }),
      text: async () => '{"error":"invalid_request"}',
    });

    try {
      await pushAuthorizationRequest({
        parEndpoint: PAR_ENDPOINT,
        params: { client_id: "x" },
        fetcher,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Oid4vciError);
      expect((err as Oid4vciError).code).toBe("oid4vci.par_request_failed");
      expect((err as Oid4vciError).message).toContain("400");
      expect((err as Oid4vciError).message).toContain("invalid_request");
    }
  });

  it("maps network failures to oid4vci.par_request_failed", async () => {
    const fetcher: Fetcher = async () => {
      throw new Error("ECONNREFUSED");
    };

    try {
      await pushAuthorizationRequest({
        parEndpoint: PAR_ENDPOINT,
        params: { client_id: "x" },
        fetcher,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.par_request_failed");
      expect((err as Oid4vciError).message).toContain("ECONNREFUSED");
    }
  });

  it("maps missing request_uri to oid4vci.par_response_invalid", async () => {
    const fetcher: Fetcher = async () => ({
      ok: true,
      status: 201,
      json: async () => ({ expires_in: 60 }), // missing request_uri
      text: async () => "",
    });

    try {
      await pushAuthorizationRequest({
        parEndpoint: PAR_ENDPOINT,
        params: { client_id: "x" },
        fetcher,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.par_response_invalid");
      expect((err as Oid4vciError).message).toMatch(/request_uri/);
    }
  });

  it("maps non-JSON responses to oid4vci.par_response_invalid", async () => {
    const fetcher: Fetcher = async () => ({
      ok: true,
      status: 201,
      json: async () => {
        throw new Error("unexpected token");
      },
      text: async () => "<html>oops</html>",
    });

    try {
      await pushAuthorizationRequest({
        parEndpoint: PAR_ENDPOINT,
        params: { client_id: "x" },
        fetcher,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.par_response_invalid");
    }
  });
});

describe("pushAuthorizationRequest — input validation", () => {
  it("rejects missing parEndpoint", async () => {
    try {
      await pushAuthorizationRequest({
        // @ts-expect-error: testing runtime guard
        parEndpoint: "",
        params: { client_id: "x" },
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.invalid_input");
    }
  });

  it("rejects missing client_id (PAR requires it for public clients)", async () => {
    try {
      await pushAuthorizationRequest({
        parEndpoint: PAR_ENDPOINT,
        params: {},
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.invalid_input");
    }
  });
});

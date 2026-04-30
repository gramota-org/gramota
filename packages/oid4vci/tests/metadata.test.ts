import { describe, it, expect } from "vitest";
import {
  Oid4vciError,
  fetchIssuerMetadata,
  resolveTokenEndpoint,
  validateMetadata,
  type Fetcher,
  type IssuerMetadata,
} from "../src/index.js";

const validMetadata: IssuerMetadata = {
  credential_issuer: "https://issuer.example.com",
  credential_endpoint: "https://issuer.example.com/credential",
  token_endpoint: "https://issuer.example.com/token",
  credential_configurations_supported: {
    pid: {
      format: "vc+sd-jwt",
      vct: "https://credentials.example.com/pid",
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: ["ES256"],
    },
  },
};

function jsonFetcher(map: Record<string, unknown | number>): Fetcher {
  return async (url) => {
    const v = map[url];
    if (typeof v === "number") {
      return {
        ok: false,
        status: v,
        json: async () => ({}),
        text: async () => "",
      };
    }
    if (v === undefined) {
      return {
        ok: false,
        status: 404,
        json: async () => ({}),
        text: async () => "not found",
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => v,
      text: async () => JSON.stringify(v),
    };
  };
}

describe("fetchIssuerMetadata", () => {
  it("fetches from /.well-known/openid-credential-issuer", async () => {
    const fetcher = jsonFetcher({
      "https://issuer.example.com/.well-known/openid-credential-issuer":
        validMetadata,
    });
    const m = await fetchIssuerMetadata("https://issuer.example.com", { fetcher });
    expect(m.credential_issuer).toBe("https://issuer.example.com");
    expect(m.credential_endpoint).toBe("https://issuer.example.com/credential");
  });

  it("strips trailing slash from credential_issuer before appending well-known", async () => {
    const fetcher = jsonFetcher({
      "https://issuer.example.com/.well-known/openid-credential-issuer":
        validMetadata,
    });
    const m = await fetchIssuerMetadata("https://issuer.example.com/", {
      fetcher,
    });
    expect(m.credential_issuer).toBe("https://issuer.example.com");
  });

  it("rejects non-2xx HTTP responses", async () => {
    const fetcher = jsonFetcher({
      "https://issuer.example.com/.well-known/openid-credential-issuer": 500,
    });
    try {
      await fetchIssuerMetadata("https://issuer.example.com", { fetcher });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.metadata_fetch_failed");
    }
  });
});

describe("validateMetadata", () => {
  it("rejects metadata missing credential_issuer", () => {
    try {
      validateMetadata({
        credential_endpoint: "https://x.com/credential",
        credential_configurations_supported: {},
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).message).toMatch(/credential_issuer/);
    }
  });

  it("rejects metadata missing credential_endpoint", () => {
    try {
      validateMetadata({
        credential_issuer: "https://x.com",
        credential_configurations_supported: {},
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).message).toMatch(/credential_endpoint/);
    }
  });

  it("rejects metadata missing credential_configurations_supported", () => {
    try {
      validateMetadata({
        credential_issuer: "https://x.com",
        credential_endpoint: "https://x.com/credential",
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).message).toMatch(
        /credential_configurations_supported/,
      );
    }
  });
});

describe("resolveTokenEndpoint", () => {
  it("returns the explicit token_endpoint when present", () => {
    expect(resolveTokenEndpoint(validMetadata)).toBe(
      "https://issuer.example.com/token",
    );
  });

  it("falls back to <issuer>/token when no token_endpoint", () => {
    const m = { ...validMetadata };
    delete m.token_endpoint;
    expect(resolveTokenEndpoint(m)).toBe("https://issuer.example.com/token");
  });
});

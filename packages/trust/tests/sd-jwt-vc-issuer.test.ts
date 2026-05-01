/**
 * SdJwtVcIssuerTrustResolver — IETF SD-JWT-VC issuer-discovery resolver.
 *
 * Spec: draft-ietf-oauth-sd-jwt-vc, well-known endpoint
 *   <iss>/.well-known/jwt-vc-issuer
 *
 * Coverage:
 *   1. Embedded JWKS happy path
 *   2. Indirection (jwks_uri) happy path
 *   3. issuer-field mismatch is rejected (security check)
 *   4. kid filtering picks the matching key
 *   5. Per-issuer caching (cacheMs)
 *   6. HTTP errors / malformed responses surface as TrustResolutionError
 */

import { describe, it, expect } from "vitest";
import {
  SdJwtVcIssuerTrustResolver,
  TrustResolutionError,
  type Fetcher,
} from "../src/index.js";

const ISSUER = "https://issuer.example.com";
const METADATA_URL = `${ISSUER}/.well-known/jwt-vc-issuer`;

interface MockResponses {
  metadata?: unknown;
  jwks?: unknown;
  /** Override metadata HTTP status (default: 200). */
  metadataStatus?: number;
  /** Override metadata response.ok flag (default: true). */
  metadataOk?: boolean;
  /** Override jwks HTTP status (default: 200). */
  jwksStatus?: number;
}

function mockServer(map: Record<string, MockResponses>): Fetcher {
  return async (url) => {
    const entry = map[url];
    if (entry === undefined) {
      return { ok: false, status: 404, json: async () => ({ error: "not found" }) };
    }
    if (url.includes(".well-known/jwt-vc-issuer")) {
      return {
        ok: entry.metadataOk ?? (entry.metadataStatus === undefined),
        status: entry.metadataStatus ?? 200,
        json: async () => entry.metadata,
      };
    }
    return {
      ok: entry.jwksStatus === undefined,
      status: entry.jwksStatus ?? 200,
      json: async () => entry.jwks,
    };
  };
}

describe("SdJwtVcIssuerTrustResolver — embedded JWKS form", () => {
  it("fetches and returns the embedded keys array", async () => {
    const k1 = { kty: "EC", crv: "P-256", x: "X1", y: "Y1", kid: "kid-1" };
    const k2 = { kty: "EC", crv: "P-256", x: "X2", y: "Y2", kid: "kid-2" };
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({
        [METADATA_URL]: {
          metadata: { issuer: ISSUER, jwks: { keys: [k1, k2] } },
        },
      }),
    });

    const keys = await resolver.resolveIssuerKeys({
      iss: ISSUER,
      kid: undefined,
      header: {},
    });
    expect(keys).toHaveLength(2);
    expect((keys[0] as Record<string, unknown>)["kid"]).toBe("kid-1");
  });

  it("filters by kid when the JWS header carries one", async () => {
    const k1 = { kty: "EC", kid: "rotation-1" };
    const k2 = { kty: "EC", kid: "rotation-2" };
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({
        [METADATA_URL]: {
          metadata: { issuer: ISSUER, jwks: { keys: [k1, k2] } },
        },
      }),
    });
    const keys = await resolver.resolveIssuerKeys({
      iss: ISSUER,
      kid: "rotation-2",
      header: {},
    });
    expect(keys).toHaveLength(1);
    expect((keys[0] as Record<string, unknown>)["kid"]).toBe("rotation-2");
  });

  it("falls back to all keys when kid doesn't match any", async () => {
    const k1 = { kty: "EC", kid: "rotation-1" };
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({
        [METADATA_URL]: {
          metadata: { issuer: ISSUER, jwks: { keys: [k1] } },
        },
      }),
    });
    const keys = await resolver.resolveIssuerKeys({
      iss: ISSUER,
      kid: "no-such-kid",
      header: {},
    });
    expect(keys).toHaveLength(1); // fallback: full set
  });
});

describe("SdJwtVcIssuerTrustResolver — indirection (jwks_uri)", () => {
  it("follows jwks_uri to the second-level JWKS", async () => {
    const k = { kty: "EC", kid: "behind-uri" };
    const JWKS_URI = "https://issuer.example.com/keys.json";
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({
        [METADATA_URL]: { metadata: { issuer: ISSUER, jwks_uri: JWKS_URI } },
        [JWKS_URI]: { jwks: { keys: [k] } },
      }),
    });
    const keys = await resolver.resolveIssuerKeys({
      iss: ISSUER,
      kid: undefined,
      header: {},
    });
    expect(keys).toHaveLength(1);
    expect((keys[0] as Record<string, unknown>)["kid"]).toBe("behind-uri");
  });
});

describe("SdJwtVcIssuerTrustResolver — security guards", () => {
  it("rejects metadata whose issuer field doesn't match the resolved iss", async () => {
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({
        [METADATA_URL]: {
          metadata: {
            issuer: "https://attacker.example.com",
            jwks: { keys: [{ kty: "EC" }] },
          },
        },
      }),
    });
    try {
      await resolver.resolveIssuerKeys({
        iss: ISSUER,
        kid: undefined,
        header: {},
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(TrustResolutionError);
      expect((err as TrustResolutionError).code).toBe("trust.malformed_jwks");
      expect((err as TrustResolutionError).message).toMatch(/issuer/);
    }
  });

  it("rejects metadata missing both jwks and jwks_uri", async () => {
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({
        [METADATA_URL]: { metadata: { issuer: ISSUER } },
      }),
    });
    try {
      await resolver.resolveIssuerKeys({
        iss: ISSUER,
        kid: undefined,
        header: {},
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as TrustResolutionError).code).toBe("trust.malformed_jwks");
    }
  });

  it("rejects when iss is missing from the JWS context", async () => {
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({}),
    });
    try {
      await resolver.resolveIssuerKeys({
        iss: undefined,
        kid: undefined,
        header: {},
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as TrustResolutionError).code).toBe("trust.iss_required");
    }
  });

  it("surfaces HTTP errors from the metadata fetch", async () => {
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher: mockServer({
        [METADATA_URL]: { metadataOk: false, metadataStatus: 500 },
      }),
    });
    try {
      await resolver.resolveIssuerKeys({
        iss: ISSUER,
        kid: undefined,
        header: {},
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as TrustResolutionError).code).toBe("trust.http_error");
      expect((err as TrustResolutionError).message).toContain("500");
    }
  });
});

describe("SdJwtVcIssuerTrustResolver — caching", () => {
  it("serves repeat lookups for the same iss from cache (one fetch only)", async () => {
    let fetches = 0;
    const fetcher: Fetcher = async (url) => {
      fetches++;
      if (url === METADATA_URL) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            issuer: ISSUER,
            jwks: { keys: [{ kty: "EC", kid: "k" }] },
          }),
        };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    };
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher,
      cacheMs: 60_000,
    });

    await resolver.resolveIssuerKeys({ iss: ISSUER, kid: undefined, header: {} });
    await resolver.resolveIssuerKeys({ iss: ISSUER, kid: undefined, header: {} });
    await resolver.resolveIssuerKeys({ iss: ISSUER, kid: undefined, header: {} });

    expect(fetches).toBe(1);
  });

  it("re-fetches after cache expiry", async () => {
    let fetches = 0;
    let now = 0;
    const fetcher: Fetcher = async () => {
      fetches++;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          issuer: ISSUER,
          jwks: { keys: [{ kty: "EC" }] },
        }),
      };
    };
    const resolver = new SdJwtVcIssuerTrustResolver({
      fetcher,
      cacheMs: 1000,
      now: () => now,
    });

    await resolver.resolveIssuerKeys({ iss: ISSUER, kid: undefined, header: {} });
    expect(fetches).toBe(1);

    now = 2000; // past expiry
    await resolver.resolveIssuerKeys({ iss: ISSUER, kid: undefined, header: {} });
    expect(fetches).toBe(2);
  });

  it("invalidate(iss) forces a re-fetch", async () => {
    let fetches = 0;
    const fetcher: Fetcher = async () => {
      fetches++;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          issuer: ISSUER,
          jwks: { keys: [{ kty: "EC" }] },
        }),
      };
    };
    const resolver = new SdJwtVcIssuerTrustResolver({ fetcher });

    await resolver.resolveIssuerKeys({ iss: ISSUER, kid: undefined, header: {} });
    expect(fetches).toBe(1);

    resolver.invalidate(ISSUER);
    await resolver.resolveIssuerKeys({ iss: ISSUER, kid: undefined, header: {} });
    expect(fetches).toBe(2);
  });
});

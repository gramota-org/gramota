// JwksUrlTrustResolver — strategy that fetches RFC 7517 JWK Sets.

import { describe, it, expect, vi } from "vitest";
import {
  JwksUrlTrustResolver,
  TrustResolutionError,
  type Fetcher,
} from "../src/index.js";

const k = (kid: string, n = "rsa-modulus"): Record<string, unknown> => ({
  kty: "RSA",
  alg: "RS256",
  kid,
  n,
  e: "AQAB",
});

function mockFetcher(map: Record<string, unknown | "error" | number>): {
  fetcher: Fetcher;
  calls: string[];
} {
  const calls: string[] = [];
  const fetcher: Fetcher = async (url) => {
    calls.push(url);
    const body = map[url];
    if (body === "error") throw new Error("network error");
    if (typeof body === "number") {
      return { ok: false, status: body, json: async () => ({}) };
    }
    if (body === undefined) {
      return { ok: false, status: 404, json: async () => ({}) };
    }
    return { ok: true, status: 200, json: async () => body, text: async () => "" };
  };
  return { fetcher, calls };
}

describe("JwksUrlTrustResolver", () => {
  it("fetches JWKS from {iss}/.well-known/jwks.json by default", async () => {
    const { fetcher, calls } = mockFetcher({
      "https://issuer.example.com/.well-known/jwks.json": {
        keys: [k("a")],
      },
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    const keys = await r.resolveIssuerKeys({
      iss: "https://issuer.example.com",
      kid: undefined,
      header: {},
    });
    expect(keys).toHaveLength(1);
    expect(calls).toEqual([
      "https://issuer.example.com/.well-known/jwks.json",
    ]);
  });

  it("strips a trailing slash from iss before appending the well-known path", async () => {
    const { fetcher, calls } = mockFetcher({
      "https://issuer.example.com/.well-known/jwks.json": {
        keys: [k("a")],
      },
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    await r.resolveIssuerKeys({
      iss: "https://issuer.example.com/",
      kid: undefined,
      header: {},
    });
    expect(calls).toEqual([
      "https://issuer.example.com/.well-known/jwks.json",
    ]);
  });

  it("supports a custom URL builder (e.g. SD-JWT-VC §5.1 jwt-issuer)", async () => {
    const { fetcher, calls } = mockFetcher({
      "https://issuer.example.com/.well-known/jwt-issuer": {
        keys: [k("a")],
      },
    });
    const r = new JwksUrlTrustResolver({
      fetcher,
      jwksUrl: (iss) => `${iss.replace(/\/$/, "")}/.well-known/jwt-issuer`,
    });
    await r.resolveIssuerKeys({
      iss: "https://issuer.example.com",
      kid: undefined,
      header: {},
    });
    expect(calls[0]).toBe(
      "https://issuer.example.com/.well-known/jwt-issuer",
    );
  });

  it("filters by kid when set", async () => {
    const { fetcher } = mockFetcher({
      "https://x.com/.well-known/jwks.json": {
        keys: [k("a"), k("b"), k("c")],
      },
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    const keys = await r.resolveIssuerKeys({
      iss: "https://x.com",
      kid: "b",
      header: { kid: "b" },
    });
    expect(keys).toHaveLength(1);
    expect((keys[0] as Record<string, unknown>)["kid"]).toBe("b");
  });

  it("falls back to all keys when no kid match", async () => {
    const { fetcher } = mockFetcher({
      "https://x.com/.well-known/jwks.json": { keys: [k("a")] },
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    const keys = await r.resolveIssuerKeys({
      iss: "https://x.com",
      kid: "nonexistent",
      header: { kid: "nonexistent" },
    });
    expect(keys).toHaveLength(1);
  });

  it("caches results within the TTL", async () => {
    const { fetcher, calls } = mockFetcher({
      "https://x.com/.well-known/jwks.json": { keys: [k("a")] },
    });
    let now = 0;
    const r = new JwksUrlTrustResolver({
      fetcher,
      cacheMs: 60_000,
      now: () => now,
    });
    await r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} });
    now = 30_000; // within TTL
    await r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} });

    expect(calls).toHaveLength(1);
  });

  it("re-fetches after TTL expires", async () => {
    const { fetcher, calls } = mockFetcher({
      "https://x.com/.well-known/jwks.json": { keys: [k("a")] },
    });
    let now = 0;
    const r = new JwksUrlTrustResolver({
      fetcher,
      cacheMs: 60_000,
      now: () => now,
    });
    await r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} });
    now = 60_001; // past TTL
    await r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} });

    expect(calls).toHaveLength(2);
  });

  it("invalidate() forces a re-fetch", async () => {
    const { fetcher, calls } = mockFetcher({
      "https://x.com/.well-known/jwks.json": { keys: [k("a")] },
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    await r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} });
    r.invalidate("https://x.com");
    await r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} });
    expect(calls).toHaveLength(2);
  });

  it("throws TrustResolutionError when iss is missing", async () => {
    const r = new JwksUrlTrustResolver();
    await expect(
      r.resolveIssuerKeys({ iss: undefined, kid: undefined, header: {} }),
    ).rejects.toBeInstanceOf(TrustResolutionError);
  });

  it("throws TrustResolutionError on network failure", async () => {
    const { fetcher } = mockFetcher({
      "https://x.com/.well-known/jwks.json": "error",
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    await expect(
      r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} }),
    ).rejects.toBeInstanceOf(TrustResolutionError);
  });

  it("throws TrustResolutionError on non-2xx HTTP response", async () => {
    const { fetcher } = mockFetcher({
      "https://x.com/.well-known/jwks.json": 500,
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    await expect(
      r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} }),
    ).rejects.toThrow(/HTTP 500/);
  });

  it("throws when JWKS body is malformed (missing 'keys' array)", async () => {
    const { fetcher } = mockFetcher({
      "https://x.com/.well-known/jwks.json": { foo: "bar" },
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    await expect(
      r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} }),
    ).rejects.toThrow(/keys.*array/);
  });

  it("throws when a JWKS entry is not a JSON object", async () => {
    const { fetcher } = mockFetcher({
      "https://x.com/.well-known/jwks.json": { keys: ["not an object"] },
    });
    const r = new JwksUrlTrustResolver({ fetcher });
    await expect(
      r.resolveIssuerKeys({ iss: "https://x.com", kid: undefined, header: {} }),
    ).rejects.toThrow(/non-object/);
  });

  // Silence unused mock import warnings in some tooling.
  void vi;
});

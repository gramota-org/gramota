// StaticTrustResolver — strategy contract for in-memory trust lists.

import { describe, it, expect } from "vitest";
import {
  StaticTrustResolver,
  TrustResolutionError,
} from "../src/index.js";
import type { JsonWebKey } from "@gateway/jose";

const k = (kid: string, n = "rsa-modulus"): JsonWebKey => ({
  kty: "RSA",
  alg: "RS256",
  kid,
  n,
  e: "AQAB",
});

const ctx = (
  iss: string | undefined,
  kid?: string,
): {
  iss: string | undefined;
  kid: string | undefined;
  header: Record<string, unknown>;
} => ({
  iss,
  kid,
  header: kid !== undefined ? { kid } : {},
});

describe("StaticTrustResolver — flat list mode", () => {
  it("returns all configured keys when no kid hint is present", async () => {
    const r = new StaticTrustResolver([k("a"), k("b", "different-modulus")]);
    const keys = await r.resolveIssuerKeys(ctx("https://x.com"));
    expect(keys).toHaveLength(2);
  });

  it("filters by kid when both sides have one and at least one matches", async () => {
    const r = new StaticTrustResolver([k("a"), k("b", "different")]);
    const keys = await r.resolveIssuerKeys(ctx("https://x.com", "b"));
    expect(keys).toHaveLength(1);
    expect((keys[0] as Record<string, unknown>)["kid"]).toBe("b");
  });

  it("falls back to all keys when kid does not match any", async () => {
    const r = new StaticTrustResolver([k("a"), k("b", "different")]);
    const keys = await r.resolveIssuerKeys(ctx("https://x.com", "no-such-kid"));
    expect(keys).toHaveLength(2);
  });

  it("rejects construction with empty list", () => {
    expect(() => new StaticTrustResolver([])).toThrow();
  });

  it("rejects construction with non-array, non-object input", () => {
    // @ts-expect-error: testing runtime guard
    expect(() => new StaticTrustResolver("not valid")).toThrow();
  });
});

describe("StaticTrustResolver — per-issuer map mode", () => {
  it("returns the keys for the matching issuer", async () => {
    const r = new StaticTrustResolver({
      "https://issuer-a.com": [k("a")],
      "https://issuer-b.com": [k("b", "rsa-b-1"), k("b2", "rsa-b-2")],
    });
    const a = await r.resolveIssuerKeys(ctx("https://issuer-a.com"));
    expect(a).toHaveLength(1);

    const b = await r.resolveIssuerKeys(ctx("https://issuer-b.com"));
    expect(b).toHaveLength(2);
  });

  it("throws when iss is missing from the JWT", async () => {
    const r = new StaticTrustResolver({ "https://x.com": [k("a")] });
    await expect(r.resolveIssuerKeys(ctx(undefined))).rejects.toBeInstanceOf(
      TrustResolutionError,
    );
  });

  it("throws when iss is not configured (issuer isolation)", async () => {
    const r = new StaticTrustResolver({ "https://x.com": [k("a")] });
    await expect(
      r.resolveIssuerKeys(ctx("https://untrusted.com")),
    ).rejects.toThrow(/not in the static trust list/);
  });

  it("supports key rotation via multiple keys per issuer", async () => {
    const r = new StaticTrustResolver({
      "https://x.com": [k("old", "old-modulus"), k("new", "new-modulus")],
    });
    const keys = await r.resolveIssuerKeys(ctx("https://x.com"));
    expect(keys).toHaveLength(2);
  });

  it("rejects an empty issuer map", () => {
    expect(() => new StaticTrustResolver({})).toThrow();
  });
});

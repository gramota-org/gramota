/**
 * LoTeTrustResolver — relying-party allow-list pinning per ARF §6.6.5.
 *
 * What we pin:
 *   1. Issuer URLs not on the allow-list → hard reject with
 *      `trust.issuer_not_configured`.
 *   2. Missing iss in context → `trust.iss_required`.
 *   3. notBefore / notAfter — staged / expired entries → reject.
 *   4. kid filtering — when both sides have kid, prefer matches; fall
 *      back to all when no match.
 *   5. Inner resolver intersection — when configured, the inner
 *      resolver's keys are intersected with the LoTE-pinned set; an
 *      inner failure (e.g. network unreachable) falls through to
 *      LoTE pinning (the LoTE is the source of truth).
 *   6. listIssuers / lookup are diagnostic surfaces for upstream
 *      logging.
 */

import { describe, it, expect } from "vitest";
import {
  LoTeTrustResolver,
  TrustResolutionError,
  type LoTeEntry,
  type TrustResolver,
} from "../src/index.js";
import type { JsonWebKey } from "@gramota/jose";

// Construct a minimal EC P-256 JWK; the LoTE only compares by
// kty + crv + x + y for thumbprint-style intersection so the
// numbers don't have to be valid points for these tests.
const ec = (kid: string, x = "x-base", y = "y-base"): JsonWebKey => ({
  kty: "EC",
  crv: "P-256",
  alg: "ES256",
  kid,
  x,
  y,
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

describe("LoTeTrustResolver — constructor validation", () => {
  it("requires a non-empty entries array", () => {
    expect(() => new LoTeTrustResolver({ entries: [] })).toThrow(
      TrustResolutionError,
    );
    expect(() =>
      new LoTeTrustResolver({ entries: null as unknown as LoTeEntry[] }),
    ).toThrow(TrustResolutionError);
  });

  it("rejects entries with no iss / empty iss", () => {
    expect(
      () =>
        new LoTeTrustResolver({
          entries: [{ iss: "", keys: [ec("a")] }],
        }),
    ).toThrow(TrustResolutionError);
  });

  it("rejects entries with no keys", () => {
    expect(
      () =>
        new LoTeTrustResolver({
          entries: [{ iss: "https://issuer", keys: [] }],
        }),
    ).toThrow(TrustResolutionError);
  });

  it("rejects duplicate iss entries", () => {
    expect(
      () =>
        new LoTeTrustResolver({
          entries: [
            { iss: "https://issuer", keys: [ec("a")] },
            { iss: "https://issuer", keys: [ec("b")] },
          ],
        }),
    ).toThrow(TrustResolutionError);
  });
});

describe("LoTeTrustResolver — allow-list gating", () => {
  const trusted = new LoTeTrustResolver({
    entries: [
      {
        iss: "https://issuer-bg.gramota.eu",
        keys: [ec("bg-2025")],
        country: "bg",
      },
      {
        iss: "https://issuer-de.example",
        keys: [ec("de-2025-1"), ec("de-2025-2")],
        country: "de",
      },
    ],
  });

  it("returns the pinned keys for a trusted iss", async () => {
    const keys = await trusted.resolveIssuerKeys(
      ctx("https://issuer-bg.gramota.eu"),
    );
    expect(keys).toHaveLength(1);
    expect(keys[0]!.kid).toBe("bg-2025");
  });

  it("rejects an iss that's not on the LoTE", async () => {
    await expect(
      trusted.resolveIssuerKeys(ctx("https://attacker.example")),
    ).rejects.toMatchObject({ code: "trust.issuer_not_configured" });
  });

  it("rejects a context with no iss", async () => {
    await expect(
      trusted.resolveIssuerKeys(ctx(undefined)),
    ).rejects.toMatchObject({ code: "trust.iss_required" });
  });

  it("returns all configured keys when multiple are pinned", async () => {
    const keys = await trusted.resolveIssuerKeys(
      ctx("https://issuer-de.example"),
    );
    expect(keys).toHaveLength(2);
  });
});

describe("LoTeTrustResolver — kid filtering", () => {
  const trusted = new LoTeTrustResolver({
    entries: [
      {
        iss: "https://issuer.example",
        keys: [ec("k1", "x1", "y1"), ec("k2", "x2", "y2")],
      },
    ],
  });

  it("prefers keys whose kid matches the header kid", async () => {
    const keys = await trusted.resolveIssuerKeys(
      ctx("https://issuer.example", "k2"),
    );
    expect(keys).toHaveLength(1);
    expect(keys[0]!.kid).toBe("k2");
  });

  it("falls back to all keys when no kid matches", async () => {
    const keys = await trusted.resolveIssuerKeys(
      ctx("https://issuer.example", "unknown-kid"),
    );
    expect(keys).toHaveLength(2);
  });
});

describe("LoTeTrustResolver — notBefore / notAfter window", () => {
  // Pretend "now" is 1700000000 (2023-11-14).
  const FIXED_NOW = 1700000000;
  const resolver = new LoTeTrustResolver({
    entries: [
      {
        iss: "https://staged.example",
        keys: [ec("staged")],
        notBefore: FIXED_NOW + 1000,
      },
      {
        iss: "https://expired.example",
        keys: [ec("expired")],
        notAfter: FIXED_NOW - 1000,
      },
      {
        iss: "https://active.example",
        keys: [ec("active")],
        notBefore: FIXED_NOW - 1000,
        notAfter: FIXED_NOW + 1000,
      },
    ],
    now: () => FIXED_NOW,
  });

  it("rejects an iss whose entry is staged (notBefore > now)", async () => {
    await expect(
      resolver.resolveIssuerKeys(ctx("https://staged.example")),
    ).rejects.toMatchObject({ code: "trust.issuer_not_configured" });
  });

  it("rejects an iss whose entry has expired (notAfter <= now)", async () => {
    await expect(
      resolver.resolveIssuerKeys(ctx("https://expired.example")),
    ).rejects.toMatchObject({ code: "trust.issuer_not_configured" });
  });

  it("accepts an iss within its activation window", async () => {
    const keys = await resolver.resolveIssuerKeys(
      ctx("https://active.example"),
    );
    expect(keys).toHaveLength(1);
    expect(keys[0]!.kid).toBe("active");
  });
});

describe("LoTeTrustResolver — inner resolver composition", () => {
  // Build two keys; the inner resolver returns both, the LoTE pins
  // only one — intersection should keep only the pinned one.
  const pinned = ec("rotated-2025", "X-NEW", "Y-NEW");
  const dropped = ec("legacy-2024", "X-OLD", "Y-OLD");

  const innerOk: TrustResolver = {
    async resolveIssuerKeys() {
      return [pinned, dropped];
    },
  };

  it("intersects inner resolver keys with the LoTE-pinned set", async () => {
    const lote = new LoTeTrustResolver({
      entries: [{ iss: "https://issuer.example", keys: [pinned] }],
      inner: innerOk,
    });
    const keys = await lote.resolveIssuerKeys(ctx("https://issuer.example"));
    // Inner returned 2 keys; LoTE pinned 1 of them; intersection = 1.
    expect(keys).toHaveLength(1);
    expect(keys[0]!.kid).toBe("rotated-2025");
  });

  it("returns the LoTE pinned set if the inner resolver fails", async () => {
    const innerFails: TrustResolver = {
      async resolveIssuerKeys(): Promise<never> {
        throw new TrustResolutionError(
          "trust.fetch_failed",
          "well-known fetch failed",
        );
      },
    };
    const lote = new LoTeTrustResolver({
      entries: [{ iss: "https://issuer.example", keys: [pinned] }],
      inner: innerFails,
    });
    const keys = await lote.resolveIssuerKeys(ctx("https://issuer.example"));
    expect(keys).toHaveLength(1);
    expect(keys[0]!.kid).toBe("rotated-2025");
  });

  it("returns the LoTE pinned set if inner keys don't intersect", async () => {
    // Inner returns ONLY the dropped key — the pinned key is not in
    // its response. Intersection is empty; fall back to LoTE pinned.
    const innerDrift: TrustResolver = {
      async resolveIssuerKeys() {
        return [dropped];
      },
    };
    const lote = new LoTeTrustResolver({
      entries: [{ iss: "https://issuer.example", keys: [pinned] }],
      inner: innerDrift,
    });
    const keys = await lote.resolveIssuerKeys(ctx("https://issuer.example"));
    expect(keys).toHaveLength(1);
    expect(keys[0]!.kid).toBe("rotated-2025");
  });

  it("rejects untrusted iss even when inner resolver would return keys", async () => {
    const lote = new LoTeTrustResolver({
      entries: [{ iss: "https://allowed.example", keys: [pinned] }],
      inner: innerOk, // would happily return keys for any iss
    });
    await expect(
      lote.resolveIssuerKeys(ctx("https://untrusted.example")),
    ).rejects.toMatchObject({ code: "trust.issuer_not_configured" });
  });
});

describe("LoTeTrustResolver — diagnostic surfaces", () => {
  const lote = new LoTeTrustResolver({
    entries: [
      {
        iss: "https://issuer-a.example",
        keys: [ec("a")],
        name: "Issuer A",
        country: "fr",
      },
      { iss: "https://issuer-b.example", keys: [ec("b")] },
    ],
  });

  it("listIssuers returns all trusted iss URLs", () => {
    expect([...lote.listIssuers()].sort()).toEqual([
      "https://issuer-a.example",
      "https://issuer-b.example",
    ]);
  });

  it("lookup returns the full entry for a trusted iss", () => {
    const entry = lote.lookup("https://issuer-a.example");
    expect(entry).toBeDefined();
    expect(entry?.name).toBe("Issuer A");
    expect(entry?.country).toBe("fr");
  });

  it("lookup returns undefined for an untrusted iss", () => {
    expect(lote.lookup("https://attacker.example")).toBeUndefined();
  });
});

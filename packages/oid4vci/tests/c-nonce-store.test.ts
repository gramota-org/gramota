/**
 * c_nonce store — OID4VCI Final §7 nonce-endpoint pool.
 *
 * Verifies the lifecycle every wallet flow depends on:
 *   - mint() returns a base64url string + the declared TTL
 *   - consume() returns true exactly once per minted value
 *   - expired entries no longer consume
 *   - prune() drops expired entries without touching live ones
 *   - size cap trims oldest 10% under runaway minting
 */

import { describe, it, expect } from "vitest";
import {
  CNonceStore,
  C_NONCE_TTL_SECONDS,
} from "../src/index.js";

describe("CNonceStore — mint", () => {
  it("returns a base64url string with the default TTL", async () => {
    const store = new CNonceStore();
    const { nonce, expiresInSeconds } = await store.mint();
    expect(typeof nonce).toBe("string");
    expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(expiresInSeconds).toBe(C_NONCE_TTL_SECONDS);
  });

  it("honours a per-call ttlSeconds override", async () => {
    const store = new CNonceStore();
    const { expiresInSeconds } = await store.mint({ ttlSeconds: 30 });
    expect(expiresInSeconds).toBe(30);
  });

  it("honours a store-level default ttl override", async () => {
    const store = new CNonceStore({ ttlSeconds: 90 });
    const { expiresInSeconds } = await store.mint();
    expect(expiresInSeconds).toBe(90);
  });

  it("yields fresh randomness on every call", async () => {
    const store = new CNonceStore();
    const a = await store.mint();
    const b = await store.mint();
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe("CNonceStore — consume", () => {
  it("consumes a freshly-minted nonce once", async () => {
    const store = new CNonceStore();
    const { nonce } = await store.mint();
    expect(await store.consume(nonce)).toBe(true);
  });

  it("rejects a double-consume (single-use replay protection)", async () => {
    const store = new CNonceStore();
    const { nonce } = await store.mint();
    expect(await store.consume(nonce)).toBe(true);
    expect(await store.consume(nonce)).toBe(false);
  });

  it("rejects an unknown nonce", async () => {
    const store = new CNonceStore();
    expect(await store.consume("never-minted")).toBe(false);
  });

  it("rejects an expired nonce", async () => {
    // 1-second TTL, then sleep past it.
    const store = new CNonceStore();
    const { nonce } = await store.mint({ ttlSeconds: 0 });
    // wait long enough that Date.now() definitely passed the expiry mark.
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(await store.consume(nonce)).toBe(false);
  });

  it("does not consume similar but distinct nonce strings", async () => {
    const store = new CNonceStore();
    const { nonce } = await store.mint();
    expect(await store.consume(nonce + "x")).toBe(false);
    // Original still consumable.
    expect(await store.consume(nonce)).toBe(true);
  });
});

describe("CNonceStore — prune", () => {
  it("removes expired entries without touching live ones", async () => {
    const store = new CNonceStore();
    const fresh = await store.mint({ ttlSeconds: 60 });
    const stale = await store.mint({ ttlSeconds: 0 });
    // Let the stale one expire.
    await new Promise((resolve) => setTimeout(resolve, 10));
    store.prune();
    // The stale one is gone — consume returns false.
    expect(await store.consume(stale.nonce)).toBe(false);
    // The fresh one survives.
    expect(await store.consume(fresh.nonce)).toBe(true);
  });

  it("is idempotent (no entries → no errors)", () => {
    const store = new CNonceStore();
    expect(() => store.prune()).not.toThrow();
    expect(() => store.prune()).not.toThrow();
  });
});

describe("CNonceStore — overflow defense", () => {
  it("trims the oldest 10% when the soft cap is exceeded", async () => {
    const store = new CNonceStore({ maxEntries: 10 });
    const minted: string[] = [];
    for (let i = 0; i < 10; i++) {
      const { nonce } = await store.mint();
      minted.push(nonce);
    }
    // Cap reached — the next mint triggers a trim of the first 10% (=1).
    await store.mint();
    // The very first nonce should have been evicted by the trim.
    expect(await store.consume(minted[0]!)).toBe(false);
    // A later one survives.
    expect(await store.consume(minted[9]!)).toBe(true);
  });
});

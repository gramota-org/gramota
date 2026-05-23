/**
 * In-memory DpopJtiStore — the SDK default implementation of the host
 * interface verifyDpopJwt uses for RFC 9449 §11.1 replay protection.
 */

import { describe, it, expect } from "vitest";
import { InMemoryDpopJtiStore } from "../src/index.js";

describe("InMemoryDpopJtiStore — checkAndRecord", () => {
  it("returns false on first sight (new jti)", async () => {
    const store = new InMemoryDpopJtiStore({ pruneIntervalMs: 0 });
    const seen = await store.checkAndRecord(
      "jti-1",
      new Date(Date.now() + 60_000),
    );
    expect(seen).toBe(false);
    store.stop();
  });

  it("returns true on a replay (same jti within window)", async () => {
    const store = new InMemoryDpopJtiStore({ pruneIntervalMs: 0 });
    const expiry = new Date(Date.now() + 60_000);
    await store.checkAndRecord("jti-1", expiry);
    const second = await store.checkAndRecord("jti-1", expiry);
    expect(second).toBe(true);
    store.stop();
  });

  it("treats distinct jtis independently", async () => {
    const store = new InMemoryDpopJtiStore({ pruneIntervalMs: 0 });
    const expiry = new Date(Date.now() + 60_000);
    expect(await store.checkAndRecord("jti-a", expiry)).toBe(false);
    expect(await store.checkAndRecord("jti-b", expiry)).toBe(false);
    expect(await store.checkAndRecord("jti-a", expiry)).toBe(true);
    store.stop();
  });

  it("re-accepts a jti after its expiry passes", async () => {
    const store = new InMemoryDpopJtiStore({ pruneIntervalMs: 0 });
    const pastExpiry = new Date(Date.now() - 1000);
    await store.checkAndRecord("jti-expired", pastExpiry);
    // The original entry was inserted with an already-passed expiry, so
    // the "previously seen" guard considers it forgotten.
    const second = await store.checkAndRecord(
      "jti-expired",
      new Date(Date.now() + 60_000),
    );
    expect(second).toBe(false);
    store.stop();
  });
});

describe("InMemoryDpopJtiStore — prune", () => {
  it("removes expired entries", async () => {
    const store = new InMemoryDpopJtiStore({ pruneIntervalMs: 0 });
    await store.checkAndRecord("alive", new Date(Date.now() + 60_000));
    await store.checkAndRecord("dead", new Date(Date.now() - 1000));
    store.prune();
    // 'alive' still flagged as seen; 'dead' was pruned.
    expect(await store.checkAndRecord("alive", new Date(Date.now() + 60_000))).toBe(true);
    expect(await store.checkAndRecord("dead", new Date(Date.now() + 60_000))).toBe(false);
    store.stop();
  });

  it("stop() is idempotent", () => {
    const store = new InMemoryDpopJtiStore({ pruneIntervalMs: 0 });
    expect(() => store.stop()).not.toThrow();
    expect(() => store.stop()).not.toThrow();
  });
});

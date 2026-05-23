/**
 * PAR (Pushed Authorization Request) store — RFC 9126.
 *
 * The wallet pushes its auth parameters to /par; the store returns a
 * one-shot request_uri the wallet uses on the redirect. Single-use,
 * TTL-bounded.
 */

import { describe, it, expect } from "vitest";
import {
  ParStore,
  PAR_DEFAULT_TTL_SECONDS,
  type ParRequestPayload,
} from "../src/index.js";

const samplePayload: ParRequestPayload = {
  clientId: "wallet-dev",
  responseType: "code",
  redirectUri: "https://wallet.example.com/cb",
  codeChallenge: "ZGVtby1jaGFsbGVuZ2U",
  codeChallengeMethod: "S256",
  state: "abc",
};

describe("ParStore — put", () => {
  it("returns a request_uri prefixed with the RFC 9126 URN", async () => {
    const store = new ParStore();
    const { requestUri, expiresInSeconds } = await store.put(samplePayload);
    expect(requestUri.startsWith("urn:ietf:params:oauth:request_uri:")).toBe(true);
    expect(expiresInSeconds).toBe(PAR_DEFAULT_TTL_SECONDS);
  });

  it("honours a per-call ttlSeconds override", async () => {
    const store = new ParStore();
    const { expiresInSeconds } = await store.put(samplePayload, {
      ttlSeconds: 30,
    });
    expect(expiresInSeconds).toBe(30);
  });

  it("honours a store-level default ttl override", async () => {
    const store = new ParStore({ ttlSeconds: 45 });
    const { expiresInSeconds } = await store.put(samplePayload);
    expect(expiresInSeconds).toBe(45);
  });

  it("mints a distinct request_uri on every call", async () => {
    const store = new ParStore();
    const a = await store.put(samplePayload);
    const b = await store.put(samplePayload);
    expect(a.requestUri).not.toBe(b.requestUri);
  });
});

describe("ParStore — consume", () => {
  it("returns the exact payload that was put", async () => {
    const store = new ParStore();
    const { requestUri } = await store.put(samplePayload);
    const got = await store.consume(requestUri);
    expect(got).toEqual(samplePayload);
  });

  it("rejects a double-consume", async () => {
    const store = new ParStore();
    const { requestUri } = await store.put(samplePayload);
    await store.consume(requestUri);
    expect(await store.consume(requestUri)).toBeUndefined();
  });

  it("rejects an unknown request_uri", async () => {
    const store = new ParStore();
    expect(
      await store.consume("urn:ietf:params:oauth:request_uri:nope"),
    ).toBeUndefined();
  });

  it("rejects an expired request_uri", async () => {
    const store = new ParStore();
    const { requestUri } = await store.put(samplePayload, { ttlSeconds: 0 });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(await store.consume(requestUri)).toBeUndefined();
  });
});

describe("ParStore — prune", () => {
  it("clears expired entries without touching live ones", async () => {
    const store = new ParStore();
    const fresh = await store.put(samplePayload, { ttlSeconds: 60 });
    const stale = await store.put(samplePayload, { ttlSeconds: 0 });
    await new Promise((resolve) => setTimeout(resolve, 10));
    store.prune();
    expect(await store.consume(stale.requestUri)).toBeUndefined();
    expect(await store.consume(fresh.requestUri)).toEqual(samplePayload);
  });
});

describe("ParStore — attestation passthrough", () => {
  it("round-trips the HAIP §6.3 attestation headers", async () => {
    const store = new ParStore();
    const payload: ParRequestPayload = {
      ...samplePayload,
      attestation: {
        header: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ3YWxsZXQifQ.sig",
        pop: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ3YWxsZXQifQ.sig",
      },
    };
    const { requestUri } = await store.put(payload);
    const got = await store.consume(requestUri);
    expect(got?.attestation?.header).toBe(payload.attestation!.header);
    expect(got?.attestation?.pop).toBe(payload.attestation!.pop);
  });
});

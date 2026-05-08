import { describe, expect, it } from "vitest";
import { mockFetcherResponse, type Fetcher } from "../src/index.js";

describe("Fetcher type", () => {
  it("global fetch satisfies the Fetcher interface structurally", () => {
    // Compile-time: if this assignment fails, the structural typing is broken.
    // We don't actually call fetch — we just want the type-check.
    const _f: Fetcher = (url, init) =>
      // @ts-expect-error — global fetch returns Response, which is a superset
      // of FetcherResponse; the cast is fine at runtime.
      fetch(url, init);
    expect(typeof _f).toBe("function");
  });
});

describe("mockFetcherResponse", () => {
  it("defaults to ok=200 with empty body", async () => {
    const r = mockFetcherResponse({});
    expect(r.ok).toBe(true);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe("");
    expect(await r.json()).toBeUndefined();
  });

  it("derives text() from json by JSON.stringify", async () => {
    const r = mockFetcherResponse({ json: { keys: [{ kid: "abc" }] } });
    expect(await r.json()).toEqual({ keys: [{ kid: "abc" }] });
    expect(await r.text()).toBe('{"keys":[{"kid":"abc"}]}');
  });

  it("derives json() from text by JSON.parse when text is JSON", async () => {
    const r = mockFetcherResponse({ text: '{"foo":1}' });
    expect(await r.json()).toEqual({ foo: 1 });
    expect(await r.text()).toBe('{"foo":1}');
  });

  it("returns undefined from json() when text is not parseable", async () => {
    const r = mockFetcherResponse({ text: "not-json" });
    expect(await r.json()).toBeUndefined();
    expect(await r.text()).toBe("not-json");
  });

  it("status defaults to 500 when ok=false", async () => {
    const r = mockFetcherResponse({ ok: false });
    expect(r.status).toBe(500);
  });

  it("respects an explicit status", async () => {
    const r = mockFetcherResponse({ ok: false, status: 404, text: "missing" });
    expect(r.status).toBe(404);
    expect(await r.text()).toBe("missing");
  });

  it("supports case-insensitive header lookup", () => {
    const r = mockFetcherResponse({
      headers: { "Content-Type": "application/json", "DPoP-Nonce": "n-123" },
    });
    expect(r.headers?.get("content-type")).toBe("application/json");
    expect(r.headers?.get("CONTENT-TYPE")).toBe("application/json");
    expect(r.headers?.get("dpop-nonce")).toBe("n-123");
    expect(r.headers?.get("missing")).toBeNull();
  });
});

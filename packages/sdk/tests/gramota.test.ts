import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import {
  Gramota,
  GramotaError,
  isGramotaError,
  mockFetcherResponse,
} from "../src/index.js";

async function makeIssuerKey(): Promise<JsonWebKey> {
  const kp = await generateKeyPair("ES256", { extractable: true });
  return (await exportJWK(kp.publicKey)) as JsonWebKey;
}

describe("Gramota — facade construction", () => {
  it("constructs without options for QR-only use", () => {
    const g = new Gramota();
    expect(g.qr).toBeDefined();
    // qr methods exist
    expect(typeof g.qr.fromUrl).toBe("function");
  });

  it("re-exports GramotaError + isGramotaError + mockFetcherResponse from core", () => {
    expect(GramotaError).toBeDefined();
    expect(isGramotaError(new GramotaError("x", "code"))).toBe(true);
    const r = mockFetcherResponse({ json: { ok: 1 } });
    expect(r.ok).toBe(true);
  });
});

describe("Gramota — lazy property access", () => {
  it("verifier throws a friendly TypeError when accessed without config", () => {
    const g = new Gramota();
    expect(() => g.verifier).toThrow(/pass `verifier` config/);
  });

  it("issuer throws a friendly TypeError when accessed without config", () => {
    const g = new Gramota();
    expect(() => g.issuer).toThrow(/pass `issuer` config/);
  });

  it("holder throws a friendly TypeError when accessed without config", () => {
    const g = new Gramota();
    expect(() => g.holder).toThrow(/pass `holder` config/);
  });
});

describe("Gramota — verifier facade", () => {
  it("returns a configured Verifier with namespace properties", async () => {
    const issuerKey = await makeIssuerKey();
    const g = new Gramota({
      verifier: { audience: "https://example.com", issuerKey },
    });

    expect(typeof g.verifier.presentations.verify).toBe("function");
    expect(typeof g.verifier.responses.verify).toBe("function");
    expect(typeof g.verifier.requests.create).toBe("function");
  });

  it("memoises the Verifier instance across accesses", async () => {
    const issuerKey = await makeIssuerKey();
    const g = new Gramota({
      verifier: { audience: "https://example.com", issuerKey },
    });

    expect(g.verifier).toBe(g.verifier);
  });
});

describe("Gramota — qr facade", () => {
  it("renders a real QR data URL through the default renderer", async () => {
    const g = new Gramota();
    const code = g.qr.fromUrl("https://example.com");
    const dataUrl = await code.toDataUrl();
    expect(dataUrl.startsWith("data:image/png;base64,")).toBe(true);
  });

  it("respects QrClient options passed via the facade", async () => {
    const g = new Gramota({ qr: { width: 256, errorCorrection: "H" } });
    const code = g.qr.fromUrl("https://example.com");
    expect(code).toBeDefined();
  });
});

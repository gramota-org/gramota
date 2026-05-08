/**
 * Unit tests for `@gramota/qr`.
 *
 * Coverage focuses on the pattern surface:
 *   - Strategy substitutability — `MockRenderer` plugs in cleanly.
 *   - Factory Method correctness — every `qr.from*` builds the right URL.
 *   - Lazy + memoised result class — renderer invoked at most once
 *     per format per QrCode.
 *   - Error codes — invalid input surfaces stable QrError codes.
 *
 * The default renderer's actual qrcode-npm output isn't unit-tested
 * here (it's well-covered by `qrcode`'s own suite); we run one smoke
 * test to confirm the Adapter wiring works end-to-end.
 */
import { describe, it, expect } from "vitest";
import {
  qr,
  QrClient,
  QrCode,
  QrError,
  type QrFormat,
  type QrOptions,
  type QrRenderer,
  DefaultQrRenderer,
} from "../src/index.js";

/** Test-only renderer that records every call without invoking
 * `qrcode`. Used to verify the orchestrator's contract. */
class MockRenderer implements QrRenderer {
  calls: { url: string; format: QrFormat; options: QrOptions }[] = [];
  async render(
    url: string,
    format: QrFormat,
    options: QrOptions,
  ): Promise<string | Uint8Array> {
    this.calls.push({ url, format, options });
    if (format === "png") return new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
    return `<mock-${format}>${url}</mock-${format}>`;
  }
}

describe("qr.fromUrl — factory + input validation", () => {
  it("rejects empty input with qr.invalid_url", () => {
    expect(() => qr.fromUrl("")).toThrow(QrError);
    try {
      qr.fromUrl("");
    } catch (e) {
      expect((e as QrError).code).toBe("qr.invalid_url");
    }
  });

  it("rejects non-URI input", () => {
    try {
      qr.fromUrl("not a url");
    } catch (e) {
      expect((e as QrError).code).toBe("qr.invalid_url");
    }
  });

  it("accepts custom URI schemes (deep links)", () => {
    const client = new QrClient({ renderer: new MockRenderer() });
    const code = client.fromUrl("openid4vp://?client_id=abc");
    expect(code.url).toBe("openid4vp://?client_id=abc");
  });

  it("accepts https URLs", () => {
    const client = new QrClient({ renderer: new MockRenderer() });
    const code = client.fromUrl("https://example.com/verify/abc");
    expect(code).toBeInstanceOf(QrCode);
  });
});

describe("Strategy: custom QrRenderer plugs in", () => {
  it("the orchestrator never touches `qrcode` when a custom renderer is supplied", async () => {
    const mock = new MockRenderer();
    const client = new QrClient({ renderer: mock });
    const code = client.fromUrl("https://example.com");
    const dataUrl = await code.toDataUrl();
    const svg = await code.toSvg();
    expect(dataUrl).toBe("<mock-dataUrl>https://example.com</mock-dataUrl>");
    expect(svg).toBe("<mock-svg>https://example.com</mock-svg>");
    expect(mock.calls.map((c) => c.format)).toEqual(["dataUrl", "svg"]);
  });

  it("forwards QrOptions to the renderer (without leaking the renderer ref)", async () => {
    const mock = new MockRenderer();
    const client = new QrClient({
      renderer: mock,
      width: 500,
      margin: 4,
      colors: { dark: "#0b1220", light: "#f1f5f9" },
      errorCorrection: "Q",
    });
    const code = client.fromUrl("https://example.com");
    await code.toDataUrl();
    expect(mock.calls[0]!.options).toEqual({
      width: 500,
      margin: 4,
      colors: { dark: "#0b1220", light: "#f1f5f9" },
      errorCorrection: "Q",
    });
    // The renderer key MUST NOT appear in the options the renderer sees.
    expect(mock.calls[0]!.options).not.toHaveProperty("renderer");
  });

  it("per-call options layer over the constructor defaults", async () => {
    const mock = new MockRenderer();
    const client = new QrClient({ renderer: mock, width: 200, margin: 4 });
    const code = client.fromUrl("https://example.com", { width: 800 });
    await code.toDataUrl();
    expect(mock.calls[0]!.options).toEqual({ width: 800, margin: 4 });
  });
});

describe("Lazy + memoisation", () => {
  it("renders each format on first call only — subsequent calls hit the cache", async () => {
    const mock = new MockRenderer();
    const client = new QrClient({ renderer: mock });
    const code = client.fromUrl("https://example.com");

    // Two awaits of the same format → still one render.
    const a = await code.toDataUrl();
    const b = await code.toDataUrl();
    expect(a).toBe(b);
    expect(mock.calls.filter((c) => c.format === "dataUrl")).toHaveLength(1);

    // Different format → another render.
    await code.toSvg();
    expect(mock.calls.filter((c) => c.format === "svg")).toHaveLength(1);
  });

  it("concurrent first-callers share the same in-flight render", async () => {
    const mock = new MockRenderer();
    const client = new QrClient({ renderer: mock });
    const code = client.fromUrl("https://example.com");

    // Fire three concurrent toDataUrl() before any has resolved.
    const [a, b, c] = await Promise.all([
      code.toDataUrl(),
      code.toDataUrl(),
      code.toDataUrl(),
    ]);
    expect(a).toBe(b);
    expect(b).toBe(c);
    // The renderer ran exactly once, not three times.
    expect(mock.calls).toHaveLength(1);
  });
});

describe("qr.fromAuthorizationRequest — composes with @gramota/oid4vp", () => {
  it("builds the openid4vp:// deep link before rendering", async () => {
    const client = new QrClient({ renderer: new MockRenderer() });
    const code = client.fromAuthorizationRequest({
      response_type: "vp_token",
      client_id: "x509_san_dns:my-bank.com",
      nonce: "n-12345",
      state: "s-12345",
    });
    expect(code.url).toMatch(/^openid4vp:\/\//);
    expect(code.url).toContain("client_id=x509_san_dns");
    expect(code.url).toContain("nonce=n-12345");
  });

  it("honours a custom scheme (HAIP / vendor schemes)", () => {
    const client = new QrClient({ renderer: new MockRenderer() });
    const code = client.fromAuthorizationRequest(
      {
        response_type: "vp_token",
        client_id: "https://my-bank.com",
        nonce: "n",
      },
      { scheme: "haip://" },
    );
    expect(code.url).toMatch(/^haip:\/\//);
  });
});

describe("qr.fromCredentialOffer — composes with @gramota/oid4vci", () => {
  it("builds the openid-credential-offer:// deep link", () => {
    const client = new QrClient({ renderer: new MockRenderer() });
    const code = client.fromCredentialOffer({
      credential_issuer: "https://acme.gramota.dev",
      credential_configuration_ids: ["urn:eudi:pid:1_sd_jwt_vc"],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": "abc123",
        },
      },
    });
    expect(code.url).toMatch(/^openid-credential-offer:\/\//);
    expect(code.url).toContain("credential_offer=");
    expect(decodeURIComponent(code.url.split("credential_offer=")[1]!)).toContain(
      "acme.gramota.dev",
    );
  });
});

describe("DefaultQrRenderer — Adapter smoke test (real qrcode lib)", () => {
  it("renders a real PNG data URL through the qrcode npm package", async () => {
    const code = qr.fromUrl("https://example.com");
    const dataUrl = await code.toDataUrl();
    expect(dataUrl.startsWith("data:image/png;base64,")).toBe(true);
    expect(dataUrl.length).toBeGreaterThan(100);
  });

  it("renders an SVG string through the qrcode npm package", async () => {
    const code = qr.fromUrl("https://example.com");
    const svg = await code.toSvg();
    expect(svg).toMatch(/^<\?xml|^<svg/);
    expect(svg).toContain("</svg>");
  });

  it("renders raw PNG bytes (Uint8Array) through the qrcode npm package", async () => {
    const code = qr.fromUrl("https://example.com");
    const png = await code.toPng();
    expect(png).toBeInstanceOf(Uint8Array);
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    expect(png[0]).toBe(0x89);
    expect(png[1]).toBe(0x50);
    expect(png[2]).toBe(0x4e);
    expect(png[3]).toBe(0x47);
  });

  it("DefaultQrRenderer is constructible standalone (for DI)", () => {
    const renderer = new DefaultQrRenderer();
    expect(renderer).toBeDefined();
    // Substitutable for the QrRenderer interface.
    const _: QrRenderer = renderer;
    expect(_.render).toBeTypeOf("function");
  });
});

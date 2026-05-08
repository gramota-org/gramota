/**
 * Surface tests for the Stripe-shaped resource namespaces:
 *
 *   verifier.presentations.verify(token, opts)
 *   verifier.responses.verify(rawBody, opts)
 *   verifier.requests.create(opts)
 *
 * The verification correctness is exercised in `verify.test.ts`. These
 * tests just lock in the public shape and confirm the namespace
 * properties don't lose `this`.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Verifier } from "../src/index.js";

async function makeIssuerKey(): Promise<JsonWebKey> {
  const kp = await generateKeyPair("ES256", { extractable: true });
  return (await exportJWK(kp.publicKey)) as JsonWebKey;
}

describe("verifier.* — Stripe-shaped namespaces", () => {
  it("exposes presentations / responses / requests as instance properties", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });

    expect(typeof v.presentations.verify).toBe("function");
    expect(typeof v.responses.verify).toBe("function");
    expect(typeof v.requests.create).toBe("function");
  });

  it("requests.create returns a signed authorization request URL", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });
    const out = v.requests.create({
      baseUrl: "openid4vp://",
      clientId: "x509_san_dns:example.com",
      nonce: "namespace-test-nonce",
    });

    expect(out.url).toMatch(/^openid4vp:\/\//);
    expect(out.request.client_id).toBe("x509_san_dns:example.com");
    expect(out.request.nonce).toBe("namespace-test-nonce");
  });

  it("presentations.verify rejects without a nonce", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });
    await expect(
      v.presentations.verify("not-even-a-token", {} as never),
    ).rejects.toThrow(/nonce is required/);
  });

  it("responses.verify rejects without expectedNonce", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });
    await expect(
      v.responses.verify("vp_token=garbage", {} as never),
    ).rejects.toThrow(/expectedNonce is required/);
  });
});

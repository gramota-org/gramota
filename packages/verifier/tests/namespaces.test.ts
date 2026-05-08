/**
 * Sanity coverage for the Stripe-shaped namespace surface introduced
 * in 0.3.0:
 *
 *   verifier.presentations.verify(token, opts)
 *   verifier.responses.verify(rawBody, opts)
 *   verifier.requests.create(opts)
 *
 * These are thin wrappers that delegate to the (now @deprecated) flat
 * methods. The point of the tests is to lock in the public shape and
 * confirm the wrappers don't lose the `this` context.
 *
 * The verification correctness is exercised in `verify.test.ts` against
 * the flat `verify()` method — the namespace is a pure delegation, so
 * doubling that coverage isn't worth the fixture cost.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Verifier } from "../src/index.js";

async function makeIssuerKey(): Promise<JsonWebKey> {
  const kp = await generateKeyPair("ES256", { extractable: true });
  return (await exportJWK(kp.publicKey)) as JsonWebKey;
}

describe("verifier.* — Stripe-shaped namespaces are present and bound", () => {
  it("exposes presentations / responses / requests as instance properties", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });

    expect(typeof v.presentations.verify).toBe("function");
    expect(typeof v.responses.verify).toBe("function");
    expect(typeof v.requests.create).toBe("function");
  });

  it("requests.create returns the same shape as the deprecated request()", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });
    const opts = {
      baseUrl: "openid4vp://",
      clientId: "x509_san_dns:example.com",
      nonce: "namespace-test-nonce",
    } as const;

    const fromNamespace = v.requests.create(opts);
    const fromFlat = v.request(opts);

    expect(fromNamespace.url).toBe(fromFlat.url);
    expect(fromNamespace.request.client_id).toBe(fromFlat.request.client_id);
    expect(fromNamespace.request.nonce).toBe(fromFlat.request.nonce);
  });

  it("presentations.verify rejects without a nonce just like verify()", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });

    // Both shapes share the same options validation path.
    await expect(
      v.presentations.verify("not-even-a-token", {} as never),
    ).rejects.toThrow(/nonce is required/);
    await expect(
      v.verify("not-even-a-token", {} as never),
    ).rejects.toThrow(/nonce is required/);
  });

  it("responses.verify rejects without expectedNonce just like response()", async () => {
    const issuerKey = await makeIssuerKey();
    const v = new Verifier({ audience: "https://example.com", issuerKey });

    await expect(
      v.responses.verify("vp_token=garbage", {} as never),
    ).rejects.toThrow(/expectedNonce is required/);
    await expect(
      v.response("vp_token=garbage", {} as never),
    ).rejects.toThrow(/expectedNonce is required/);
  });
});

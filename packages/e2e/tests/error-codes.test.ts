/**
 * Error-code contract tests. Every package's error class has a `code: string`
 * field with a stable, typed value. These codes are the public API for log
 * filters, alerting, dashboards, and i18n — they must not silently change.
 *
 * If a code is renamed without consumer-facing notice, this file fails.
 */

import { describe, it, expect } from "vitest";
import { Issuer, IssuerError } from "@gramota/issuer";
import { Holder, HolderError } from "@gramota/holder";
import { Verifier, VerifierError } from "@gramota/verifier";
import { JoseError } from "@gramota/jose";
import {
  SdJwtError,
  parseSdJwt,
} from "@gramota/sd-jwt";
import { Oid4vpError, parseAuthorizationRequestUrl } from "@gramota/oid4vp";
import {
  PresentationExchangeError,
  parseJsonPath,
} from "@gramota/presentation-exchange";
import {
  StaticTrustResolver,
  TrustResolutionError,
} from "@gramota/trust";
import { newEs256KeyPair, makeIssuerSigner } from "../src/test-helpers.js";

describe("Error codes — present, typed, switchable", () => {
  it("SdJwtError carries 'sd_jwt.parse.*' codes", () => {
    try {
      parseSdJwt("");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(SdJwtError);
      const e = err as SdJwtError;
      expect(e.code).toMatch(/^sd_jwt\.parse\./);
    }
  });

  it("Oid4vpError carries 'oid4vp.*' codes", () => {
    try {
      parseAuthorizationRequestUrl("not a url");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Oid4vpError);
      expect((err as Oid4vpError).code).toBe("oid4vp.invalid_url");
    }
  });

  it("PresentationExchangeError carries 'pe.*' codes", () => {
    try {
      parseJsonPath("foo.bar");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PresentationExchangeError);
      expect((err as PresentationExchangeError).code).toBe("pe.jsonpath_invalid");
    }
  });

  it("TrustResolutionError carries 'trust.*' codes", async () => {
    const r = new StaticTrustResolver({
      "https://x.com": [{ kty: "EC", crv: "P-256", x: "x", y: "y" }],
    });
    try {
      await r.resolveIssuerKeys({ iss: undefined, kid: undefined, header: {} });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(TrustResolutionError);
      expect((err as TrustResolutionError).code).toBe("trust.iss_required");
    }
  });

  it("IssuerError carries 'issuer.*' codes", async () => {
    const issuerKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const issuer = new Issuer({
      privateKey: issuerKey.privateJwk,
      publicKey: issuerKey.publicJwk,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    try {
      // @ts-expect-error: vct intentionally omitted to trigger the runtime guard
      await issuer.issue({
        subject: { x: 1 },
        holderKey: holderKey.publicJwk,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(IssuerError);
      expect((err as IssuerError).code).toBe("issuer.vct_required");
    }
  });

  it("HolderError carries 'holder.*' codes", async () => {
    const issuerKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    try {
      await holder.credentials.receive("not-a-token", {
        trustedIssuers: [issuerKey.publicJwk],
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(HolderError);
      expect((err as HolderError).code).toBe("holder.malformed_token");
    }
  });

  it("SdJwtError carries 'sd_jwt.kb.*' codes", async () => {
    const issuerKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();

    // Issue a credential with proper cnf binding.
    const { issueSdJwt, buildKeyBindingJwt } = await import("@gramota/sd-jwt");
    const signer = await makeIssuerSigner(issuerKey.privateJwk);
    const { token } = await issueSdJwt({
      payload: {
        iss: "https://issuer.example.com",
        iat: 1700000000,
        cnf: { jwk: holderKey.publicJwk },
      },
      sdClaims: { x: 1 },
      alg: "ES256",
      signer,
    });

    // Build a KB-JWT for *this* token.
    const kb = await buildKeyBindingJwt(token, {
      aud: "expected-aud",
      nonce: "n-1",
      alg: "ES256",
      privateKey: holderKey.privateJwk,
      iat: 1_700_000_500,
    });

    const presentation = `${token}${kb}`;
    const parsed = parseSdJwt(presentation);

    const { verifyKeyBinding } = await import("@gramota/sd-jwt");
    try {
      await verifyKeyBinding(parsed, {
        expectedAudience: "WRONG-AUDIENCE",
        expectedNonce: "n-1",
        now: () => 1_700_000_500,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(SdJwtError);
      expect((err as SdJwtError).code).toBe(
        "sd_jwt.kb.audience_mismatch",
      );
    }
  });

  it("VerifierError exposes a `code` property equal to result.failedCheck", async () => {
    const issuerKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const issuer = new Issuer({
      privateKey: issuerKey.privateJwk,
      publicKey: issuerKey.publicJwk,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    const { token } = await issuer.issue({
      subject: { given_name: "X" },
      selectivelyDisclosable: ["given_name"],
      holderKey: holderKey.publicJwk,
      vct: "https://credentials.example.com/x",
    });

    const holder = new Holder({
      privateKey: holderKey.privateJwk,
      publicKey: holderKey.publicJwk,
      alg: "ES256",
    });
    const stored = await holder.credentials.receive(token, {
      trustedIssuers: [issuerKey.publicJwk],
    });
    const presentation = await holder.present({
      credentialId: stored.id,
      disclose: ["given_name"],
      audience: "https://verifier.example.com",
      nonce: "n-vc",
    });

    const verifier = new Verifier({
      audience: "https://OTHER-VERIFIER.example.com",
      issuerKey: issuerKey.publicJwk,
    });
    const result = await verifier.verify(presentation, { nonce: "n-vc" });

    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(result.failedCheck).toBe("kb-jwt.audience");

    try {
      result.unwrap();
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifierError);
      const ve = err as VerifierError;
      expect(ve.code).toBe("kb-jwt.audience");
      expect(ve.code).toBe(ve.result.failedCheck);
    }
  });

  it("JoseError carries 'jose.*' codes", async () => {
    const { verifyJws } = await import("@gramota/jose");
    try {
      await verifyJws("not-a-jws", { kty: "EC", crv: "P-256", x: "x", y: "y" });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(JoseError);
      expect((err as JoseError).code).toMatch(/^jose\./);
    }
  });

  it("customers can switch on err.code with TypeScript narrowing", async () => {
    const issuerKey = await newEs256KeyPair();
    const holderKey = await newEs256KeyPair();
    const issuer = new Issuer({
      privateKey: issuerKey.privateJwk,
      publicKey: issuerKey.publicJwk,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    try {
      await issuer.issue({
        subject: { x: 1 },
        holderKey: holderKey.publicJwk,
        vct: "https://credentials.example.com/x",
        expiresIn: 60,
        expiresAt: 2_000_000_000,
      });
      throw new Error("should have thrown");
    } catch (err) {
      if (err instanceof IssuerError) {
        // Type system: err.code is "issuer.vct_required" | "issuer.expiry_conflict" | ...
        switch (err.code) {
          case "issuer.expiry_conflict":
            // exhaustive narrowing works
            expect(err.message).toContain("mutually exclusive");
            return;
          case "issuer.vct_required":
          case "issuer.holder_key_required":
          case "issuer.subject_invalid":
          case "issuer.expiry_invalid":
          case "issuer.disclosable_missing":
          case "issuer.reserved_claim_in_subject":
            throw new Error("unexpected code: " + err.code);
        }
      }
      throw err;
    }
  });
});

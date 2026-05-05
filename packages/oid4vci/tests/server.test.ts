/**
 * Server-side credential-request parsing — OID4VCI Draft 13/14/15
 * normalisation.
 *
 * The wire shape changed across drafts. This test pins down what the
 * normaliser accepts:
 *
 *   - Draft 13: `{ format, vct, proof }`
 *   - Draft 14/15: `{ credential_configuration_id, proofs: { jwt: [...] } }`
 *
 * Wallets in the wild straddle drafts (the EU reference wallet
 * eudi-lib-jvm-openid4vci-kt 0.9.x sends Draft 14/15, our own
 * synthetic-holder sends Draft 13). Issuers using this normaliser
 * speak both without code-fork.
 */

import { describe, it, expect } from "vitest";
import {
  Oid4vciError,
  buildSubdomainIssuerUrl,
  parseCredentialRequest,
  type IssuerMetadata,
} from "../src/index.js";

const DUMMY_PROOF_JWT = "header.body.sig"; // structure-only — we don't verify here

const PID_METADATA: IssuerMetadata = {
  credential_issuer: "https://issuer.example",
  credential_endpoint: "https://issuer.example/oid4vci/credential",
  credential_configurations_supported: {
    "urn:eudi:pid:1_sd_jwt_vc": {
      format: "dc+sd-jwt",
      vct: "urn:eudi:pid:1",
      cryptographic_binding_methods_supported: ["jwk"],
    },
  },
};

describe("parseCredentialRequest — Draft 13 (legacy format+vct)", () => {
  it("normalises a complete Draft 13 body", () => {
    const out = parseCredentialRequest({
      body: {
        format: "dc+sd-jwt",
        vct: "urn:eudi:pid:1",
        proof: { proof_type: "jwt", jwt: DUMMY_PROOF_JWT },
      },
    });
    expect(out.format).toBe("dc+sd-jwt");
    expect(out.vct).toBe("urn:eudi:pid:1");
    expect(out.proofJwt).toBe(DUMMY_PROOF_JWT);
    expect(out.proofJwts).toEqual([DUMMY_PROOF_JWT]);
  });

  it("rejects Draft 13 missing format", () => {
    expect(() =>
      parseCredentialRequest({
        body: {
          vct: "urn:eudi:pid:1",
          proof: { proof_type: "jwt", jwt: DUMMY_PROOF_JWT },
        },
      }),
    ).toThrow(Oid4vciError);
  });
});

describe("parseCredentialRequest — Draft 14/15 (credential_configuration_id + proofs.jwt[])", () => {
  it("normalises a body using credential_configuration_id + metadata lookup", () => {
    const out = parseCredentialRequest({
      body: {
        credential_configuration_id: "urn:eudi:pid:1_sd_jwt_vc",
        proofs: { jwt: [DUMMY_PROOF_JWT] },
      },
      issuerMetadata: PID_METADATA,
    });
    expect(out.credentialConfigurationId).toBe("urn:eudi:pid:1_sd_jwt_vc");
    expect(out.format).toBe("dc+sd-jwt"); // pulled from metadata
    expect(out.vct).toBe("urn:eudi:pid:1"); // pulled from metadata
    expect(out.proofJwt).toBe(DUMMY_PROOF_JWT);
  });

  it("returns all proofs when batch issuance is requested", () => {
    const out = parseCredentialRequest({
      body: {
        credential_configuration_id: "urn:eudi:pid:1_sd_jwt_vc",
        proofs: { jwt: ["a.b.c", "d.e.f", "g.h.i"] },
      },
      issuerMetadata: PID_METADATA,
    });
    expect(out.proofJwts).toEqual(["a.b.c", "d.e.f", "g.h.i"]);
    expect(out.proofJwt).toBe("a.b.c");
  });

  it("rejects an unknown credential_configuration_id when metadata is provided", () => {
    expect(() =>
      parseCredentialRequest({
        body: {
          credential_configuration_id: "unknown",
          proofs: { jwt: [DUMMY_PROOF_JWT] },
        },
        issuerMetadata: PID_METADATA,
      }),
    ).toThrow(Oid4vciError);
  });

  it("accepts unknown credential_configuration_id when metadata is omitted (lazy mode)", () => {
    const out = parseCredentialRequest({
      body: {
        credential_configuration_id: "anything-goes",
        proofs: { jwt: [DUMMY_PROOF_JWT] },
      },
    });
    expect(out.credentialConfigurationId).toBe("anything-goes");
  });
});

describe("parseCredentialRequest — input guards", () => {
  it("rejects non-object body", () => {
    expect(() => parseCredentialRequest({ body: "not an object" })).toThrow(
      Oid4vciError,
    );
    expect(() => parseCredentialRequest({ body: null })).toThrow(Oid4vciError);
    expect(() => parseCredentialRequest({ body: [] })).toThrow(Oid4vciError);
  });

  it("rejects body with no proof at all", () => {
    expect(() =>
      parseCredentialRequest({
        body: { credential_configuration_id: "urn:eudi:pid:1_sd_jwt_vc" },
        issuerMetadata: PID_METADATA,
      }),
    ).toThrow(Oid4vciError);
  });

  it("ignores proofs.jwt entries that aren't strings", () => {
    expect(() =>
      parseCredentialRequest({
        body: {
          credential_configuration_id: "urn:eudi:pid:1_sd_jwt_vc",
          proofs: { jwt: [42, null, ""] as unknown as string[] },
        },
        issuerMetadata: PID_METADATA,
      }),
    ).toThrow(Oid4vciError);
  });
});

describe("buildSubdomainIssuerUrl — multi-tenant URL builder", () => {
  it("injects the subdomain as the leftmost DNS label", () => {
    expect(buildSubdomainIssuerUrl("https://gramota.dev", "acme")).toBe(
      "https://acme.gramota.dev",
    );
  });

  it("preserves explicit ports and removes the trailing slash", () => {
    expect(
      buildSubdomainIssuerUrl("https://localtest.me:4444", "demo"),
    ).toBe("https://demo.localtest.me:4444");
  });

  it("preserves nested subdomains in the base", () => {
    expect(
      buildSubdomainIssuerUrl("https://api.staging.gramota.dev", "acme"),
    ).toBe("https://acme.api.staging.gramota.dev");
  });

  it("rejects an empty subdomain", () => {
    expect(() => buildSubdomainIssuerUrl("https://x.example", "")).toThrow(
      Oid4vciError,
    );
  });

  it("rejects subdomains that aren't valid DNS labels", () => {
    // underscores (the original bug that pushed us to slugs in the first place)
    expect(() =>
      buildSubdomainIssuerUrl("https://x.example", "with_underscore"),
    ).toThrow(Oid4vciError);
    // leading hyphen
    expect(() => buildSubdomainIssuerUrl("https://x.example", "-bad")).toThrow(
      Oid4vciError,
    );
    // uppercase (DNS labels are lowercase by convention; we enforce it
    // because the wallet/server may compare case-sensitively)
    expect(() => buildSubdomainIssuerUrl("https://x.example", "ACME")).toThrow(
      Oid4vciError,
    );
    // too long (>63 chars)
    expect(() =>
      buildSubdomainIssuerUrl("https://x.example", "a".repeat(64)),
    ).toThrow(Oid4vciError);
  });

  it("rejects an invalid base URL", () => {
    expect(() => buildSubdomainIssuerUrl("not a url", "acme")).toThrow(
      Oid4vciError,
    );
  });
});

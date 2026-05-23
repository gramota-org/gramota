/**
 * Spec-shaped well-known metadata builders.
 *
 * The output JSON shape is mandated by OID4VCI §11.2 + RFC 8414. Tests
 * pin the field names, defaults, and conditional fields so wallet interop
 * doesn't drift across refactors.
 */

import { describe, it, expect } from "vitest";
import {
  buildAuthorizationServerMetadata,
  buildIssuerMetadata,
} from "../src/index.js";

const ISSUER = "https://acme.gramota.dev";

describe("buildIssuerMetadata", () => {
  it("emits the minimum spec-required shape", () => {
    const md = buildIssuerMetadata({
      credentialIssuer: ISSUER,
      credentialEndpoint: `${ISSUER}/oid4vci/credential`,
      nonceEndpoint: `${ISSUER}/oid4vci/nonce`,
      credentialConfigurationsSupported: {
        "urn:eudi:pid:1_sd_jwt_vc": { format: "dc+sd-jwt" },
      },
    });

    expect(md["credential_issuer"]).toBe(ISSUER);
    expect(md["credential_endpoint"]).toBe(`${ISSUER}/oid4vci/credential`);
    expect(md["nonce_endpoint"]).toBe(`${ISSUER}/oid4vci/nonce`);
    expect(md["credential_configurations_supported"]).toEqual({
      "urn:eudi:pid:1_sd_jwt_vc": { format: "dc+sd-jwt" },
    });
    // Defaults to issuer-as-AS.
    expect(md["authorization_servers"]).toEqual([ISSUER]);
  });

  it("honours authorizationServers when delegated", () => {
    const md = buildIssuerMetadata({
      credentialIssuer: ISSUER,
      credentialEndpoint: `${ISSUER}/c`,
      nonceEndpoint: `${ISSUER}/n`,
      credentialConfigurationsSupported: { x: { format: "dc+sd-jwt" } },
      authorizationServers: ["https://as.example.com"],
    });
    expect(md["authorization_servers"]).toEqual(["https://as.example.com"]);
  });

  it("includes batch_credential_issuance when set", () => {
    const md = buildIssuerMetadata({
      credentialIssuer: ISSUER,
      credentialEndpoint: `${ISSUER}/c`,
      nonceEndpoint: `${ISSUER}/n`,
      credentialConfigurationsSupported: { x: { format: "dc+sd-jwt" } },
      batchCredentialIssuance: { batchSize: 50 },
    });
    expect(md["batch_credential_issuance"]).toEqual({ batch_size: 50 });
  });

  it("omits batch_credential_issuance when not set", () => {
    const md = buildIssuerMetadata({
      credentialIssuer: ISSUER,
      credentialEndpoint: `${ISSUER}/c`,
      nonceEndpoint: `${ISSUER}/n`,
      credentialConfigurationsSupported: { x: { format: "dc+sd-jwt" } },
    });
    expect("batch_credential_issuance" in md).toBe(false);
  });

  it("merges `extra` fields verbatim", () => {
    const md = buildIssuerMetadata({
      credentialIssuer: ISSUER,
      credentialEndpoint: `${ISSUER}/c`,
      nonceEndpoint: `${ISSUER}/n`,
      credentialConfigurationsSupported: { x: { format: "dc+sd-jwt" } },
      extra: { signed_metadata: "abc", vendor_field: 1 },
    });
    expect(md["signed_metadata"]).toBe("abc");
    expect(md["vendor_field"]).toBe(1);
  });

  it("throws on missing required fields", () => {
    expect(() =>
      buildIssuerMetadata({
        // @ts-expect-error — missing credentialIssuer to exercise the guard.
        credentialIssuer: "",
        credentialEndpoint: "x",
        nonceEndpoint: "y",
        credentialConfigurationsSupported: {},
      }),
    ).toThrow();
  });
});

describe("buildAuthorizationServerMetadata", () => {
  it("emits the pre-auth-only shape (no auth-code endpoints)", () => {
    const md = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      tokenEndpoint: `${ISSUER}/oid4vci/token`,
      grantTypesSupported: [
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      ],
    });

    expect(md["issuer"]).toBe(ISSUER);
    expect(md["token_endpoint"]).toBe(`${ISSUER}/oid4vci/token`);
    expect(md["grant_types_supported"]).toEqual([
      "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ]);
    expect(md["token_endpoint_auth_methods_supported"]).toEqual(["none"]);
    expect(md["dpop_signing_alg_values_supported"]).toEqual(["ES256"]);
    expect(md["response_types_supported"]).toEqual([]);
    // No auth-code grant → no authorize/par/pkce advertisement.
    expect("authorization_endpoint" in md).toBe(false);
    expect("pushed_authorization_request_endpoint" in md).toBe(false);
    expect("code_challenge_methods_supported" in md).toBe(false);
  });

  it("emits the HAIP auth-code shape (PAR-required, PKCE S256)", () => {
    const md = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      tokenEndpoint: `${ISSUER}/oid4vci/token`,
      authorizationEndpoint: `${ISSUER}/oid4vci/authorize`,
      pushedAuthorizationRequestEndpoint: `${ISSUER}/oid4vci/par`,
      requirePushedAuthorizationRequests: true,
      grantTypesSupported: [
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "authorization_code",
      ],
    });

    expect(md["authorization_endpoint"]).toBe(`${ISSUER}/oid4vci/authorize`);
    expect(md["pushed_authorization_request_endpoint"]).toBe(
      `${ISSUER}/oid4vci/par`,
    );
    expect(md["require_pushed_authorization_requests"]).toBe(true);
    // Defaults applied when caller doesn't override.
    expect(md["response_types_supported"]).toEqual(["code"]);
    expect(md["code_challenge_methods_supported"]).toEqual(["S256"]);
  });

  it("respects caller-supplied response_types + code_challenge_methods", () => {
    const md = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      tokenEndpoint: `${ISSUER}/t`,
      authorizationEndpoint: `${ISSUER}/a`,
      grantTypesSupported: ["authorization_code"],
      responseTypesSupported: ["code", "code id_token"],
      codeChallengeMethodsSupported: ["S256"],
    });
    expect(md["response_types_supported"]).toEqual(["code", "code id_token"]);
    expect(md["code_challenge_methods_supported"]).toEqual(["S256"]);
  });

  it("respects caller-supplied token_endpoint_auth_methods", () => {
    const md = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      tokenEndpoint: `${ISSUER}/t`,
      grantTypesSupported: ["authorization_code"],
      tokenEndpointAuthMethodsSupported: ["attest_jwt_client_auth"],
    });
    expect(md["token_endpoint_auth_methods_supported"]).toEqual([
      "attest_jwt_client_auth",
    ]);
  });

  it("merges `extra` fields verbatim", () => {
    const md = buildAuthorizationServerMetadata({
      issuer: ISSUER,
      tokenEndpoint: `${ISSUER}/t`,
      grantTypesSupported: ["authorization_code"],
      extra: { vendor_capabilities: ["x", "y"] },
    });
    expect(md["vendor_capabilities"]).toEqual(["x", "y"]);
  });

  it("throws on missing required fields", () => {
    expect(() =>
      buildAuthorizationServerMetadata({
        issuer: "",
        tokenEndpoint: "x",
        grantTypesSupported: ["authorization_code"],
      }),
    ).toThrow();
    expect(() =>
      buildAuthorizationServerMetadata({
        issuer: ISSUER,
        tokenEndpoint: "x",
        grantTypesSupported: [],
      }),
    ).toThrow();
  });
});

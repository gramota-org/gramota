/**
 * RFC 9101 JAR signing conformance for OID4VP authorization requests.
 *
 * What we pin (per RFC 9101 §10 + OID4VP §5.10):
 *   - Compact-serialised JWS, three segments separated by `.`
 *   - Header `alg=ES256`, `typ=oauth-authz-req+jwt`
 *   - Header `x5c` is an array carrying the signing cert
 *   - Payload IS the AuthorizationRequest object (not wrapped)
 *   - Signature verifies against the public key inside x5c[0]
 *   - Defensive guards: malformed/missing key, missing x5c
 */

import { describe, it, expect } from "vitest";
import { importX509, jwtVerify } from "jose";
import {
  Oid4vpError,
  generateSigningCert,
  signAuthorizationRequest,
  type AuthorizationRequest,
  type SigningCert,
} from "../src/index.js";

async function makeCertAndRequest(): Promise<{
  cert: SigningCert;
  request: AuthorizationRequest;
}> {
  const cert = await generateSigningCert({ sanDns: "verifier.example" });
  const request: AuthorizationRequest = {
    response_type: "vp_token",
    client_id: "x509_san_dns:verifier.example",
    response_mode: "direct_post",
    response_uri: "https://verifier.example/v1/verifications/abc/response",
    nonce: "nonce-123",
    state: "state-456",
    dcql_query: {
      credentials: [
        {
          id: "pid",
          format: "dc+sd-jwt",
          meta: { vct_values: ["urn:eudi:pid:1"] },
          claims: [{ path: ["given_name"] }],
        },
      ],
    },
  };
  return { cert, request };
}

function decodeHeader(jwt: string): Record<string, unknown> {
  const headerB64 = jwt.split(".")[0]!;
  return JSON.parse(Buffer.from(headerB64, "base64url").toString("utf-8"));
}

function decodePayload(jwt: string): Record<string, unknown> {
  const bodyB64 = jwt.split(".")[1]!;
  return JSON.parse(Buffer.from(bodyB64, "base64url").toString("utf-8"));
}

describe("signAuthorizationRequest — wire shape", () => {
  it("produces a compact-serialised JWS (3 dot-separated segments)", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    expect(jwt.split(".")).toHaveLength(3);
  });

  it("sets header alg=ES256 and typ=oauth-authz-req+jwt", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    const header = decodeHeader(jwt);
    expect(header["alg"]).toBe("ES256");
    expect(header["typ"]).toBe("oauth-authz-req+jwt");
  });

  it("includes the cert chain in the x5c header", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    const header = decodeHeader(jwt);
    expect(Array.isArray(header["x5c"])).toBe(true);
    expect((header["x5c"] as string[])[0]).toBe(cert.x5c[0]);
  });

  it("encodes the AuthorizationRequest as the JWS payload (no envelope)", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    const payload = decodePayload(jwt);
    expect(payload["client_id"]).toBe(request.client_id);
    expect(payload["nonce"]).toBe(request.nonce);
    expect(payload["state"]).toBe(request.state);
    expect(payload["response_type"]).toBe("vp_token");
  });
});

describe("signAuthorizationRequest — signature verifies via x5c", () => {
  it("the JWS signature verifies against the cert's public key", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    const pub = await importX509(cert.certificatePem, "ES256");
    const { payload, protectedHeader } = await jwtVerify(jwt, pub, {
      typ: "oauth-authz-req+jwt",
    });
    expect(protectedHeader.alg).toBe("ES256");
    expect((payload as Record<string, unknown>)["client_id"]).toBe(
      request.client_id,
    );
  });
});

describe("signAuthorizationRequest — defensive guards", () => {
  it("rejects when privateKeyPem is missing from the cert", async () => {
    const { request } = await makeCertAndRequest();
    await expect(
      signAuthorizationRequest({
        request,
        cert: {
          privateKeyPem: undefined as unknown as string,
          certificatePem: "",
          x5c: ["abc"],
          sanDns: "x",
        },
      }),
    ).rejects.toBeInstanceOf(Oid4vpError);
  });

  it("rejects when x5c is empty", async () => {
    const { cert, request } = await makeCertAndRequest();
    await expect(
      signAuthorizationRequest({
        request,
        cert: { ...cert, x5c: [] },
      }),
    ).rejects.toBeInstanceOf(Oid4vpError);
  });

  it("rejects malformed PKCS#8 with a stable error code", async () => {
    const { cert, request } = await makeCertAndRequest();
    try {
      await signAuthorizationRequest({
        request,
        cert: { ...cert, privateKeyPem: "not a real pem" },
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Oid4vpError);
      expect((err as Oid4vpError).code).toBe("oid4vp.jar_signing_failed");
    }
  });
});

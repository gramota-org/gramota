/**
 * RFC 9101 JAR signing conformance for OID4VP authorization requests.
 *
 * What we pin (per RFC 9101 §10 + OID4VP §5.8 + §5.10):
 *   - Compact-serialised JWS, three segments separated by `.`
 *   - Header `alg=ES256`, `typ=oauth-authz-req+jwt`
 *   - Header `x5c` is an array carrying the signing cert
 *   - Payload IS the AuthorizationRequest object (not wrapped)
 *   - Payload always carries `aud`, `iat`, `exp` (audit gap closed
 *     2026-05; previously the wrapper in apps/api set these). Defaults:
 *     `aud = https://self-issued.me/v2`, lifetime 300 s.
 *   - Signature verifies against the public key inside x5c[0]
 *   - Defensive guards: malformed/missing key, missing x5c
 */

import { describe, it, expect } from "vitest";
import { importX509, jwtVerify } from "jose";
import {
  DEFAULT_JAR_AUDIENCE,
  DEFAULT_JAR_LIFETIME_SECONDS,
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

describe("signAuthorizationRequest — JWT timing claims (RFC 9101 §4 / OID4VP §5.8)", () => {
  it("always emits aud, iat, exp on the JAR payload", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    const payload = decodePayload(jwt);
    expect(typeof payload["aud"]).toBe("string");
    expect(typeof payload["iat"]).toBe("number");
    expect(typeof payload["exp"]).toBe("number");
  });

  it("defaults aud to https://self-issued.me/v2 (HAIP static discovery)", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    expect(decodePayload(jwt)["aud"]).toBe("https://self-issued.me/v2");
    // Also pin the exported constant — downstream consumers rely on it.
    expect(DEFAULT_JAR_AUDIENCE).toBe("https://self-issued.me/v2");
  });

  it("honours a caller-supplied aud override", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({
      request,
      cert,
      aud: "https://wallet.example.com/oid4vp",
    });
    expect(decodePayload(jwt)["aud"]).toBe(
      "https://wallet.example.com/oid4vp",
    );
  });

  it("falls back to the default when aud is explicitly undefined", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({
      request,
      cert,
      aud: undefined,
    });
    expect(decodePayload(jwt)["aud"]).toBe(DEFAULT_JAR_AUDIENCE);
  });

  it("defaults jarLifetimeSeconds to 300 (exp - iat == 300)", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({ request, cert });
    const payload = decodePayload(jwt);
    const iat = payload["iat"] as number;
    const exp = payload["exp"] as number;
    expect(exp - iat).toBe(DEFAULT_JAR_LIFETIME_SECONDS);
    expect(DEFAULT_JAR_LIFETIME_SECONDS).toBe(300);
  });

  it("honours a caller-supplied jarLifetimeSeconds override", async () => {
    const { cert, request } = await makeCertAndRequest();
    const jwt = await signAuthorizationRequest({
      request,
      cert,
      jarLifetimeSeconds: 60,
    });
    const payload = decodePayload(jwt);
    expect((payload["exp"] as number) - (payload["iat"] as number)).toBe(60);
  });

  it("accepts an injectable now() for deterministic testing", async () => {
    const { cert, request } = await makeCertAndRequest();
    const fixed = 1_700_000_000;
    const jwt = await signAuthorizationRequest({
      request,
      cert,
      now: () => fixed,
      jarLifetimeSeconds: 120,
    });
    const payload = decodePayload(jwt);
    expect(payload["iat"]).toBe(fixed);
    expect(payload["exp"]).toBe(fixed + 120);
  });

  it("never overrides a payload-level aud/iat/exp the caller pre-set on the request", async () => {
    const { cert, request } = await makeCertAndRequest();
    // Cast: AuthorizationRequest doesn't declare aud/iat/exp, but the
    // spread-and-merge contract must still respect any extra fields the
    // caller hands in (forward-compat for future spec extensions).
    const augmented = {
      ...request,
      aud: "https://wallet-preset.example/x",
      iat: 42,
      exp: 84,
    } as unknown as AuthorizationRequest;
    const jwt = await signAuthorizationRequest({
      request: augmented,
      cert,
    });
    const payload = decodePayload(jwt);
    expect(payload["aud"]).toBe("https://wallet-preset.example/x");
    expect(payload["iat"]).toBe(42);
    expect(payload["exp"]).toBe(84);
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

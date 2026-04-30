/**
 * Offline replay against captured/extracted real EU public-verifier output.
 *
 * Always runs in CI — no network needed. The fixture
 * `init-transaction.example.json` was extracted from the EU verifier's own
 * published OpenAPI spec (`refs/.../openapi.json`), so the bytes here are the
 * EU's authoritative example of what their dev verifier returns.
 *
 * If a real capture is performed (capture-eudiw-public.mjs), the output
 * lands beside this file as `init-transaction.json` and a parallel test
 * could be added.
 *
 * Purpose: prove our SDK can correctly parse what the EU verifier emits,
 * specifically the inner JAR (JWT-Secured Authorization Request) which
 * carries the OID4VP authorization request as a signed JWT.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(
  here,
  "..",
  "fixtures",
  "captured",
  "eudiw-public",
  "init-transaction.example.json",
);

interface InitTxnFixture {
  transaction_id: string;
  client_id: string;
  request: string; // JWT-Secured Authorization Request (signed JWT)
}

const fixture = JSON.parse(
  readFileSync(fixturePath, "utf-8"),
) as InitTxnFixture;

describe("EUDIW public verifier — offline fixture replay", () => {
  it("the init-transaction response carries an x509_san_dns client_id", () => {
    expect(fixture.client_id).toMatch(/^x509_san_dns:/);
    expect(fixture.client_id).toContain("verifier-backend.eudiw.dev");
  });

  it("the JAR (request JWT) is a 3-segment compact JWS", () => {
    const segments = fixture.request.split(".");
    expect(segments).toHaveLength(3);
    for (const s of segments) {
      expect(s.length).toBeGreaterThan(0);
    }
  });

  it("the JAR header advertises x5c chain + ES256 + oauth-authz-req+jwt typ", () => {
    const headerB64 = fixture.request.split(".")[0]!;
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf-8"),
    ) as { alg?: string; typ?: string; x5c?: string[] };
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("oauth-authz-req+jwt");
    expect(Array.isArray(header.x5c)).toBe(true);
    expect((header.x5c ?? []).length).toBeGreaterThanOrEqual(1);
  });

  it("the JAR payload is an OID4VP authorization request with required fields", () => {
    const payloadB64 = fixture.request.split(".")[1]!;
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;

    // OID4VP §5 required fields:
    expect(payload["response_type"]).toBe("vp_token");
    expect(typeof payload["client_id"]).toBe("string");
    expect(typeof payload["nonce"]).toBe("string");

    // EUDI HAIP profile-specific:
    expect(payload["response_mode"]).toBe("direct_post.jwt");
    expect(payload["client_id_scheme"]).toBe("x509_san_dns");
    expect(typeof payload["response_uri"]).toBe("string");
    expect(payload["response_uri"]).toContain("verifier-backend.eudiw.dev");
    expect(payload["aud"]).toBe("https://self-issued.me/v2");

    // The presentation_definition that drives the wallet's selection.
    const pd = payload["presentation_definition"] as
      | { id: string; input_descriptors: unknown[] }
      | undefined;
    expect(pd).toBeDefined();
    if (pd === undefined) return;
    expect(typeof pd.id).toBe("string");
    expect(Array.isArray(pd.input_descriptors)).toBe(true);
    expect(pd.input_descriptors.length).toBeGreaterThan(0);
  });

  it("the input_descriptor matches EUDI PID schema (eu.europa.ec.eudi.pid.1)", () => {
    const payloadB64 = fixture.request.split(".")[1]!;
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf-8"),
    ) as {
      presentation_definition: {
        input_descriptors: Array<{
          id: string;
          format: Record<string, { alg?: string[] }>;
          constraints: { fields: Array<{ path: string[] }> };
        }>;
      };
    };
    const desc = payload.presentation_definition.input_descriptors[0]!;
    expect(desc.id).toBe("eu.europa.ec.eudi.pid.1");
    expect(desc.format["mso_mdoc"]).toBeDefined();
    expect(desc.format["mso_mdoc"]?.alg).toContain("ES256");
    expect(desc.constraints.fields[0]?.path[0]).toContain("family_name");
  });

  it("client_metadata advertises EUDI's response-encryption requirements", () => {
    const payloadB64 = fixture.request.split(".")[1]!;
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf-8"),
    ) as {
      client_metadata: {
        authorization_encrypted_response_alg: string;
        authorization_encrypted_response_enc: string;
        jwks_uri: string;
      };
    };
    expect(payload.client_metadata.authorization_encrypted_response_alg).toBe(
      "ECDH-ES",
    );
    expect(payload.client_metadata.authorization_encrypted_response_enc).toBe(
      "A128CBC-HS256",
    );
    expect(payload.client_metadata.jwks_uri).toContain(
      "verifier-backend.eudiw.dev",
    );
  });
});

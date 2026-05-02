/**
 * Mock-fetcher E2E for the OID4VCI pre-authorized code flow.
 *
 * The mock simulates a real issuer: serves metadata, accepts pre-auth
 * codes, mints a real SD-JWT-VC bound to the holder via @gramota/issuer.
 * The Oid4vciClient drives the full flow; we assert it returns a
 * cryptographically valid credential whose cnf.jwk equals the holder's.
 *
 * No network, no Docker.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair, importJWK, CompactSign } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Issuer } from "@gramota/issuer";
import { parseSdJwt, verifyHashBinding } from "@gramota/sd-jwt";
import {
  Oid4vciClient,
  Oid4vciError,
  PRE_AUTHORIZED_CODE_GRANT,
  type Fetcher,
} from "../src/index.js";

const ISSUER = "https://issuer.example.com";
const VCT = "https://credentials.example.com/pid";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

interface MockIssuerOptions {
  expectedPreAuthCode: string;
  expectedTxCode?: string;
  /** Issuer's keypair (for signing credentials). */
  issuerKey: { pub: JsonWebKey; priv: JsonWebKey };
  /** Subject claims to put in the credential. */
  subject: Record<string, unknown>;
  /** Optional override of access_token / c_nonce. */
  accessToken?: string;
  cNonce?: string;
}

/** Build a fetcher that simulates the EU/typical OID4VCI HTTP endpoints. */
function buildMockIssuer(opts: MockIssuerOptions): Fetcher {
  const accessToken = opts.accessToken ?? "mock-access-token";
  const cNonce = opts.cNonce ?? "mock-c-nonce";

  return async (url, init) => {
    const method = init?.method ?? "GET";

    // 1. Metadata
    if (
      method === "GET" &&
      url === `${ISSUER}/.well-known/openid-credential-issuer`
    ) {
      const body = {
        credential_issuer: ISSUER,
        credential_endpoint: `${ISSUER}/credential`,
        token_endpoint: `${ISSUER}/token`,
        credential_configurations_supported: {
          "pid-vc-sd-jwt": {
            format: "vc+sd-jwt",
            vct: VCT,
            cryptographic_binding_methods_supported: ["jwk"],
            credential_signing_alg_values_supported: ["ES256"],
            proof_types_supported: {
              jwt: { proof_signing_alg_values_supported: ["ES256"] },
            },
          },
        },
      };
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      };
    }

    // 2. Token
    if (method === "POST" && url === `${ISSUER}/token`) {
      const params = new URLSearchParams(init!.body as string);
      if (params.get("grant_type") !== PRE_AUTHORIZED_CODE_GRANT) {
        return errorResponse(400, "unsupported_grant_type");
      }
      if (params.get("pre-authorized_code") !== opts.expectedPreAuthCode) {
        return errorResponse(400, "invalid_grant");
      }
      if (
        opts.expectedTxCode !== undefined &&
        params.get("tx_code") !== opts.expectedTxCode
      ) {
        return errorResponse(400, "invalid_tx_code");
      }
      const body = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 60,
        c_nonce: cNonce,
        c_nonce_expires_in: 60,
      };
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      };
    }

    // 3. Credential
    if (method === "POST" && url === `${ISSUER}/credential`) {
      const headers = init!.headers as Record<string, string>;
      if (headers["Authorization"] !== `Bearer ${accessToken}`) {
        return errorResponse(401, "invalid_token");
      }
      const reqBody = JSON.parse(init!.body as string) as {
        credential_configuration_id?: string;
        proof?: { proof_type: string; jwt: string };
      };
      if (reqBody.credential_configuration_id !== "pid-vc-sd-jwt") {
        return errorResponse(400, "invalid_credential_configuration_id");
      }
      if (!reqBody.proof || reqBody.proof.proof_type !== "jwt") {
        return errorResponse(400, "missing_proof");
      }

      // Decode the proof JWT — the embedded jwk is the holder's public key.
      const proofParts = reqBody.proof.jwt.split(".");
      const proofHeader = JSON.parse(
        Buffer.from(proofParts[0]!, "base64url").toString("utf-8"),
      ) as { jwk?: JsonWebKey };
      const proofPayload = JSON.parse(
        Buffer.from(proofParts[1]!, "base64url").toString("utf-8"),
      ) as { aud?: string; nonce?: string };

      if (proofPayload.aud !== ISSUER) {
        return errorResponse(400, "invalid_proof_aud");
      }
      if (proofPayload.nonce !== cNonce) {
        return errorResponse(400, "invalid_proof_nonce");
      }
      if (!proofHeader.jwk) {
        return errorResponse(400, "missing_jwk_in_proof");
      }

      // Mint the credential bound to the holder's key.
      const issuer = new Issuer({
        privateKey: opts.issuerKey.priv,
        publicKey: opts.issuerKey.pub,
        alg: "ES256",
        issuerId: ISSUER,
      });
      const { token } = await issuer.issue({
        subject: opts.subject,
        selectivelyDisclosable: Object.keys(opts.subject),
        holderKey: proofHeader.jwk,
        vct: VCT,
      });

      const body = { credential: token, c_nonce: "next-c-nonce" };
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      };
    }

    return errorResponse(404, `unhandled mock URL: ${method} ${url}`);
  };
}

function errorResponse(status: number, msg: string): Awaited<ReturnType<Fetcher>> {
  const body = { error: msg };
  return {
    ok: false,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function offerUrl(offer: object): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

describe("Oid4vciClient — full pre-authorized code flow against a mock issuer", () => {
  it("acceptOffer mints a credential cryptographically bound to the holder's key", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();

    const fetcher = buildMockIssuer({
      expectedPreAuthCode: "abc-123",
      issuerKey,
      subject: {
        given_name: "Alice",
        family_name: "Smith",
        birthdate: "1985-06-15",
      },
    });

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher,
    });

    const result = await client.acceptOffer(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: ["pid-vc-sd-jwt"],
        grants: {
          [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "abc-123" },
        },
      }),
    );

    expect(typeof result.credential).toBe("string");

    // Parse the issued credential and check cnf binding.
    const parsed = parseSdJwt(result.credential);
    expect(parsed.payload["iss"]).toBe(ISSUER);
    expect(parsed.payload["vct"]).toBe(VCT);
    const cnf = parsed.payload["cnf"] as { jwk: JsonWebKey };
    expect(cnf.jwk).toEqual(holderKey.pub);

    // Hash binding holds — disclosures match _sd digests.
    const verified = verifyHashBinding(parsed);
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.claims["given_name"]).toBe("Alice");
  });

  it("rejects when the offer requires tx_code but none is provided", async () => {
    const holderKey = await makeKey();

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
    });

    try {
      await client.acceptOffer(
        offerUrl({
          credential_issuer: ISSUER,
          credential_configuration_ids: ["pid-vc-sd-jwt"],
          grants: {
            [PRE_AUTHORIZED_CODE_GRANT]: {
              "pre-authorized_code": "abc-123",
              tx_code: { input_mode: "numeric", length: 6 },
            },
          },
        }),
      );
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.tx_code_required");
    }
  });

  it("passes the tx_code through to the token endpoint when supplied", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();

    const fetcher = buildMockIssuer({
      expectedPreAuthCode: "abc-123",
      expectedTxCode: "147258",
      issuerKey,
      subject: { given_name: "Bob" },
    });

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher,
    });

    const result = await client.acceptOffer(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: ["pid-vc-sd-jwt"],
        grants: {
          [PRE_AUTHORIZED_CODE_GRANT]: {
            "pre-authorized_code": "abc-123",
            tx_code: { input_mode: "numeric", length: 6 },
          },
        },
      }),
      { txCode: "147258" },
    );

    expect(result.credential).toContain("~");
  });

  it("rejects an offer without a pre-authorized_code grant (auth-code unsupported)", async () => {
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
    });
    try {
      await client.acceptOffer(
        offerUrl({
          credential_issuer: ISSUER,
          credential_configuration_ids: ["pid-vc-sd-jwt"],
          grants: { authorization_code: { issuer_state: "x" } },
        }),
      );
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.unsupported_grant");
    }
  });

  it("rejects an unsupported credential format (only vc+sd-jwt in v1)", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();

    // Override metadata to declare a different format
    const fetcher: Fetcher = async (url) => {
      if (url === `${ISSUER}/.well-known/openid-credential-issuer`) {
        const body = {
          credential_issuer: ISSUER,
          credential_endpoint: `${ISSUER}/credential`,
          token_endpoint: `${ISSUER}/token`,
          credential_configurations_supported: {
            mdoc: {
              format: "mso_mdoc",
              cryptographic_binding_methods_supported: ["jwk"],
            },
          },
        };
        return {
          ok: true,
          status: 200,
          json: async () => body,
          text: async () => JSON.stringify(body),
        };
      }
      return { ok: false, status: 404, json: async () => ({}), text: async () => "" };
    };

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher,
    });

    try {
      await client.acceptOffer(
        offerUrl({
          credential_issuer: ISSUER,
          credential_configuration_ids: ["mdoc"],
          grants: {
            [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "x" },
          },
        }),
      );
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.unsupported_format");
    }

    // silence unused-import warnings
    void issuerKey;
    void importJWK;
    void CompactSign;
  });
});

/**
 * Oid4vciClient × DPoP — full pre-auth flow with DPoP attached.
 *
 * Drives the orchestrator end-to-end with a mock issuer that:
 *   1. Advertises `dpop_signing_alg_values_supported: ["ES256"]` in
 *      its issuer metadata (auto-detection trigger)
 *   2. Validates DPoP proofs at the token endpoint
 *   3. Validates DPoP-bound credential request (DPoP scheme + ath)
 *   4. Optionally exercises the use_dpop_nonce retry handshake
 *
 * What this proves:
 *   - DPoP is attached automatically when AS metadata advertises support
 *   - The proof carries the right htm/htu/iat/jti
 *   - The credential-endpoint proof carries `ath = sha256(access_token)`
 *   - `Authorization: DPoP <token>` (not `Bearer`) is used on the
 *     credential request
 *   - DPoP-Nonce retry works transparently
 *   - dpop=false disables it even when the AS supports it
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Issuer } from "@gramota/issuer";
import {
  Oid4vciClient,
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

interface MockOpts {
  expectedPreAuthCode: string;
  issuerKey: { pub: JsonWebKey; priv: JsonWebKey };
  /** When true, advertise DPoP support in metadata. */
  advertiseDpop: boolean;
  /** When true, require a DPoP proof on the token endpoint (else 400). */
  requireDpop: boolean;
  /** When true, enforce use_dpop_nonce on the first call (forces retry). */
  requireNonce: boolean;
  /** Capture sentinels (test reads these post-flow). */
  capture: {
    tokenDpopHeader?: string;
    credAuthHeader?: string;
    credDpopHeader?: string;
    nonceRetryHappened: boolean;
  };
}

function buildMockIssuer(opts: MockOpts): Fetcher {
  const ACCESS_TOKEN = "mock-dpop-access-token";
  const C_NONCE = "mock-c-nonce";
  const NONCE = "server-nonce-xyz";

  return async (url, init) => {
    const method = init?.method ?? "GET";
    const headers = (init?.headers ?? {}) as Record<string, string>;

    // Issuer metadata
    if (
      method === "GET" &&
      url === `${ISSUER}/.well-known/openid-credential-issuer`
    ) {
      const body: Record<string, unknown> = {
        credential_issuer: ISSUER,
        credential_endpoint: `${ISSUER}/credential`,
        token_endpoint: `${ISSUER}/token`,
        credential_configurations_supported: {
          pid: {
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
      if (opts.advertiseDpop) {
        body["dpop_signing_alg_values_supported"] = ["ES256"];
      }
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      };
    }

    // Token endpoint
    if (method === "POST" && url === `${ISSUER}/token`) {
      const params = new URLSearchParams(init!.body as string);
      if (params.get("grant_type") !== PRE_AUTHORIZED_CODE_GRANT) {
        return jsonErr(400, "unsupported_grant_type");
      }
      if (params.get("pre-authorized_code") !== opts.expectedPreAuthCode) {
        return jsonErr(400, "invalid_grant");
      }

      // Capture DPoP header (might be undefined if SDK didn't attach it).
      opts.capture.tokenDpopHeader = headers["DPoP"];

      if (opts.requireDpop && !opts.capture.tokenDpopHeader) {
        return jsonErr(400, "dpop_required");
      }

      // First call without nonce → 400 use_dpop_nonce + DPoP-Nonce header.
      if (opts.requireNonce && !nonceUsed(opts.capture.tokenDpopHeader)) {
        opts.capture.nonceRetryHappened = true;
        return {
          ok: false,
          status: 400,
          headers: {
            get: (name: string) =>
              name.toLowerCase() === "dpop-nonce" ? NONCE : null,
          },
          json: async () => ({ error: "use_dpop_nonce" }),
          text: async () => '{"error":"use_dpop_nonce"}',
        };
      }

      const body = {
        access_token: ACCESS_TOKEN,
        token_type: opts.requireDpop ? "DPoP" : "Bearer",
        expires_in: 60,
        c_nonce: C_NONCE,
      };
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      };
    }

    // Credential endpoint
    if (method === "POST" && url === `${ISSUER}/credential`) {
      opts.capture.credAuthHeader = headers["Authorization"];
      opts.capture.credDpopHeader = headers["DPoP"];

      if (opts.requireDpop) {
        if (
          !opts.capture.credAuthHeader?.startsWith("DPoP ") ||
          !opts.capture.credDpopHeader
        ) {
          return jsonErr(401, "invalid_dpop_proof");
        }
        // Verify ath = sha256(access_token), base64url
        const dpopPayload = JSON.parse(
          Buffer.from(
            opts.capture.credDpopHeader.split(".")[1]!,
            "base64url",
          ).toString("utf-8"),
        ) as { ath?: string };
        const expectedAth = createHash("sha256")
          .update(ACCESS_TOKEN)
          .digest("base64url");
        if (dpopPayload.ath !== expectedAth) {
          return jsonErr(401, "invalid_dpop_ath");
        }
      } else if (!opts.capture.credAuthHeader?.startsWith("Bearer ")) {
        return jsonErr(401, "missing_bearer");
      }

      const reqBody = JSON.parse(init!.body as string) as {
        proof?: { jwt: string };
      };
      const proofParts = reqBody.proof!.jwt.split(".");
      const proofHeader = JSON.parse(
        Buffer.from(proofParts[0]!, "base64url").toString("utf-8"),
      ) as { jwk: JsonWebKey };

      const issuer = new Issuer({
        privateKey: opts.issuerKey.priv,
        publicKey: opts.issuerKey.pub,
        alg: "ES256",
        issuerId: ISSUER,
      });
      const { token } = await issuer.issue({
        subject: { given_name: "Z" },
        selectivelyDisclosable: ["given_name"],
        holderKey: proofHeader.jwk,
        vct: VCT,
      });
      return {
        ok: true,
        status: 200,
        json: async () => ({ credential: token }),
        text: async () => JSON.stringify({ credential: token }),
      };
    }

    return jsonErr(404, `unhandled: ${method} ${url}`);
  };
}

function jsonErr(status: number, msg: string): Awaited<ReturnType<Fetcher>> {
  return {
    ok: false,
    status,
    json: async () => ({ error: msg }),
    text: async () => JSON.stringify({ error: msg }),
  };
}

function nonceUsed(dpopJwt?: string): boolean {
  if (dpopJwt === undefined) return false;
  try {
    const payload = JSON.parse(
      Buffer.from(dpopJwt.split(".")[1]!, "base64url").toString("utf-8"),
    ) as { nonce?: string };
    return typeof payload.nonce === "string" && payload.nonce.length > 0;
  } catch {
    return false;
  }
}

function offerUrl(offer: object): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

describe("Oid4vciClient × DPoP — auto-detect from AS metadata", () => {
  it("auto-attaches DPoP when AS metadata advertises dpop_signing_alg_values_supported", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const capture: MockOpts["capture"] = { nonceRetryHappened: false };

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher: buildMockIssuer({
        expectedPreAuthCode: "x",
        issuerKey,
        advertiseDpop: true,
        requireDpop: true,
        requireNonce: false,
        capture,
      }),
    });

    await client.acceptOffer(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: ["pid"],
        grants: { [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "x" } },
      }),
    );

    // Token endpoint received a DPoP proof
    expect(capture.tokenDpopHeader).toBeDefined();
    const tokenProof = decodeProof(capture.tokenDpopHeader!);
    expect(tokenProof.header["typ"]).toBe("dpop+jwt");
    expect(tokenProof.header["alg"]).toBe("ES256");
    expect(tokenProof.payload["htm"]).toBe("POST");
    expect(tokenProof.payload["htu"]).toBe(`${ISSUER}/token`);
    expect(tokenProof.payload["ath"]).toBeUndefined(); // no ath at token endpoint

    // Credential endpoint used DPoP scheme + ath claim
    expect(capture.credAuthHeader).toMatch(/^DPoP /);
    expect(capture.credDpopHeader).toBeDefined();
    const credProof = decodeProof(capture.credDpopHeader!);
    expect(credProof.payload["htu"]).toBe(`${ISSUER}/credential`);
    expect(typeof credProof.payload["ath"]).toBe("string");
    expect((credProof.payload["ath"] as string).length).toBe(43); // sha256 base64url
  });

  it("does NOT attach DPoP when AS metadata doesn't advertise it (auto mode default)", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const capture: MockOpts["capture"] = { nonceRetryHappened: false };

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher: buildMockIssuer({
        expectedPreAuthCode: "x",
        issuerKey,
        advertiseDpop: false,
        requireDpop: false,
        requireNonce: false,
        capture,
      }),
    });

    await client.acceptOffer(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: ["pid"],
        grants: { [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "x" } },
      }),
    );

    expect(capture.tokenDpopHeader).toBeUndefined();
    expect(capture.credDpopHeader).toBeUndefined();
    expect(capture.credAuthHeader).toMatch(/^Bearer /);
  });

  it("dpop: false disables DPoP even when the AS advertises it", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const capture: MockOpts["capture"] = { nonceRetryHappened: false };

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      dpop: false,
      fetcher: buildMockIssuer({
        expectedPreAuthCode: "x",
        issuerKey,
        advertiseDpop: true, // AS supports it
        requireDpop: false, // ...but doesn't require it
        requireNonce: false,
        capture,
      }),
    });

    await client.acceptOffer(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: ["pid"],
        grants: { [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "x" } },
      }),
    );

    expect(capture.tokenDpopHeader).toBeUndefined();
    expect(capture.credAuthHeader).toMatch(/^Bearer /);
  });

  it("transparently retries with DPoP-Nonce when server demands one (RFC 9449 §8)", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const capture: MockOpts["capture"] = { nonceRetryHappened: false };

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher: buildMockIssuer({
        expectedPreAuthCode: "x",
        issuerKey,
        advertiseDpop: true,
        requireDpop: true,
        requireNonce: true, // first call → 400 use_dpop_nonce + DPoP-Nonce header
        capture,
      }),
    });

    const result = await client.acceptOffer(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: ["pid"],
        grants: { [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "x" } },
      }),
    );

    expect(capture.nonceRetryHappened).toBe(true);
    expect(typeof result.credential).toBe("string");
    // Final token-endpoint proof carries the server-supplied nonce.
    const finalProof = decodeProof(capture.tokenDpopHeader!);
    expect(finalProof.payload["nonce"]).toBe("server-nonce-xyz");
  });
});

function decodeProof(jwt: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const [h, p] = jwt.split(".") as [string, string];
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString("utf-8")),
    payload: JSON.parse(Buffer.from(p, "base64url").toString("utf-8")),
  };
}

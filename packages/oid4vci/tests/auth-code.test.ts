/**
 * Mock-fetcher E2E for the OID4VCI auth-code flow + PKCE (RFC 7636).
 *
 * The auth-code flow is interactive — the user authenticates at the
 * issuer's authorization endpoint and the issuer redirects back with a
 * `?code=&state=`. We can't simulate the browser leg, but we can drive
 * the URL-building, CSRF state, PKCE verifier exchange, and credential
 * mint deterministically through a mock fetcher.
 *
 * Two phases:
 *   1. authorize() builds the authorization URL + returns secrets.
 *   2. claim() exchanges the code for a token and mints a credential.
 *
 * The mock issuer here:
 *   - validates the PKCE challenge against the verifier (S256)
 *   - validates the redirect_uri / client_id match
 *   - mints a real SD-JWT-VC bound to the holder's key
 *
 * No network, no Docker.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gateway/jose";
import { Issuer } from "@gateway/issuer";
import { parseSdJwt, verifyHashBinding } from "@gateway/sd-jwt";
import {
  AUTHORIZATION_CODE_GRANT,
  Oid4vciClient,
  Oid4vciError,
  parseAuthCallback,
  type Fetcher,
} from "../src/index.js";

const ISSUER = "https://issuer.example.com";
const VCT = "https://credentials.example.com/pid";
const AUTHZ_ENDPOINT = `${ISSUER}/authorize`;
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const CRED_ENDPOINT = `${ISSUER}/credential`;

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
  expectedClientId: string;
  expectedRedirectUri: string;
  expectedCredentialConfigurationId: string;
  /** The S256 challenge the issuer expects (= base64url(sha256(verifier))). */
  expectedCodeChallenge: string;
  /** The auth code the issuer will mint and accept. */
  authCode: string;
  /** Issuer's keypair for credential signing. */
  issuerKey: { pub: JsonWebKey; priv: JsonWebKey };
  /** Subject claims to bake into the credential. */
  subject: Record<string, unknown>;
  /** Optional access_token / c_nonce overrides. */
  accessToken?: string;
  cNonce?: string;
}

function buildMockIssuer(opts: MockIssuerOptions): Fetcher {
  const accessToken = opts.accessToken ?? "mock-access-token";
  const cNonce = opts.cNonce ?? "mock-c-nonce";

  return async (url, init) => {
    const method = init?.method ?? "GET";

    // 1. Issuer metadata
    if (
      method === "GET" &&
      url === `${ISSUER}/.well-known/openid-credential-issuer`
    ) {
      const body = {
        credential_issuer: ISSUER,
        credential_endpoint: CRED_ENDPOINT,
        token_endpoint: TOKEN_ENDPOINT,
        authorization_endpoint: AUTHZ_ENDPOINT,
        credential_configurations_supported: {
          [opts.expectedCredentialConfigurationId]: {
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

    // 2. Token (auth-code grant — verifier check happens here)
    if (method === "POST" && url === TOKEN_ENDPOINT) {
      const params = new URLSearchParams(init!.body as string);
      if (params.get("grant_type") !== AUTHORIZATION_CODE_GRANT) {
        return errorResponse(400, "unsupported_grant_type");
      }
      if (params.get("code") !== opts.authCode) {
        return errorResponse(400, "invalid_grant");
      }
      if (params.get("redirect_uri") !== opts.expectedRedirectUri) {
        return errorResponse(400, "redirect_uri_mismatch");
      }
      if (params.get("client_id") !== opts.expectedClientId) {
        return errorResponse(400, "client_id_mismatch");
      }
      const verifier = params.get("code_verifier");
      if (verifier === null) {
        return errorResponse(400, "missing_code_verifier");
      }
      // RFC 7636 §4.6: derive challenge from verifier and compare.
      const derivedChallenge = createHash("sha256")
        .update(verifier)
        .digest("base64url");
      if (derivedChallenge !== opts.expectedCodeChallenge) {
        return errorResponse(400, "pkce_verifier_mismatch");
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

    // 3. Credential (same shape as the pre-auth flow)
    if (method === "POST" && url === CRED_ENDPOINT) {
      const headers = init!.headers as Record<string, string>;
      if (headers["Authorization"] !== `Bearer ${accessToken}`) {
        return errorResponse(401, "invalid_token");
      }
      const reqBody = JSON.parse(init!.body as string) as {
        credential_configuration_id?: string;
        proof?: { proof_type: string; jwt: string };
      };
      if (
        reqBody.credential_configuration_id !==
        opts.expectedCredentialConfigurationId
      ) {
        return errorResponse(400, "invalid_credential_configuration_id");
      }
      if (!reqBody.proof || reqBody.proof.proof_type !== "jwt") {
        return errorResponse(400, "missing_proof");
      }

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

const REDIRECT_URI = "https://wallet.example.com/cb";
const CLIENT_ID = "wallet-public-client";
const CONFIG_ID = "pid-vc-sd-jwt";

describe("Oid4vciClient — auth-code flow", () => {
  it("authorize → user consent → claim mints a credential bound to the holder", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();

    // Pre-pick the verifier so the mock can compute the expected challenge.
    const codeVerifier = "verifier-" + "x".repeat(40); // 49 chars > 43
    const expectedChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    const state = "csrf-state-abc";
    const authCode = "auth-code-xyz";

    const fetcher = buildMockIssuer({
      expectedClientId: CLIENT_ID,
      expectedRedirectUri: REDIRECT_URI,
      expectedCredentialConfigurationId: CONFIG_ID,
      expectedCodeChallenge: expectedChallenge,
      authCode,
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

    // Step 1: authorize
    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: { issuer_state: "iss-st-1" } },
      }),
      {
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        codeVerifier,
        state,
      },
    );

    // The URL must point at the issuer's authorization endpoint with the
    // expected query parameters (PKCE challenge, state, authorization_details).
    const u = new URL(start.authorizationUrl);
    expect(`${u.origin}${u.pathname}`).toBe(AUTHZ_ENDPOINT);
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(u.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(u.searchParams.get("state")).toBe(state);
    expect(u.searchParams.get("code_challenge")).toBe(expectedChallenge);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    const ad = JSON.parse(u.searchParams.get("authorization_details")!);
    expect(ad).toEqual([
      { type: "openid_credential", credential_configuration_id: CONFIG_ID },
    ]);
    expect(u.searchParams.get("issuer_state")).toBe("iss-st-1");

    expect(start.codeVerifier).toBe(codeVerifier);
    expect(start.state).toBe(state);

    // --- simulate the user consenting at the issuer; issuer redirects back ---
    const callbackUrl = `${REDIRECT_URI}?code=${authCode}&state=${state}`;

    // Step 2: claim
    const claimed = await client.claim({
      callbackUrl,
      codeVerifier,
      state,
      metadata: start.metadata,
      authorizationServerMetadata: start.authorizationServerMetadata,
      offer: start.offer,
      credentialConfigurationId: start.credentialConfigurationId,
      redirectUri: REDIRECT_URI,
      clientId: CLIENT_ID,
    });

    // The issuer minted a real SD-JWT-VC bound to the holder.
    expect(typeof claimed.credential).toBe("string");
    const parsed = parseSdJwt(claimed.credential);
    expect(parsed.payload["iss"]).toBe(ISSUER);
    expect(parsed.payload["vct"]).toBe(VCT);
    expect((parsed.payload["cnf"] as { jwk: JsonWebKey }).jwk).toEqual(
      holderKey.pub,
    );
    const verified = verifyHashBinding(parsed);
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.claims["given_name"]).toBe("Alice");
  });

  it("rejects the callback when state doesn't match (CSRF)", async () => {
    const holderKey = await makeKey();
    const issuerKey = await makeKey();
    const codeVerifier = "v".repeat(50);
    const expectedChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

    const fetcher = buildMockIssuer({
      expectedClientId: CLIENT_ID,
      expectedRedirectUri: REDIRECT_URI,
      expectedCredentialConfigurationId: CONFIG_ID,
      expectedCodeChallenge: expectedChallenge,
      authCode: "code-1",
      issuerKey,
      subject: { given_name: "Eve" },
    });

    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher,
    });

    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      {
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        codeVerifier,
        state: "honest-state",
      },
    );

    // Attacker-controlled callback with a different state.
    const tamperedCallback = `${REDIRECT_URI}?code=code-1&state=evil-state`;

    try {
      await client.claim({
        callbackUrl: tamperedCallback,
        codeVerifier,
        state: "honest-state",
        metadata: start.metadata,
        authorizationServerMetadata: start.authorizationServerMetadata,
        offer: start.offer,
        credentialConfigurationId: start.credentialConfigurationId,
        redirectUri: REDIRECT_URI,
        clientId: CLIENT_ID,
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Oid4vciError);
      expect((err as Oid4vciError).code).toBe("oid4vci.invalid_input");
      expect((err as Oid4vciError).message).toMatch(/state/);
    }
  });

  it("propagates issuer auth errors via parseAuthCallback (e.g. user denies consent)", () => {
    expect(() =>
      parseAuthCallback(
        `${REDIRECT_URI}?error=access_denied&error_description=user%20denied`,
      ),
    ).toThrowError(/access_denied/);
  });

  it("rejects a callback URL missing `code`", () => {
    expect(() => parseAuthCallback(`${REDIRECT_URI}?state=abc`)).toThrowError(
      /code/,
    );
  });

  it("rejects a callback URL missing `state`", () => {
    expect(() => parseAuthCallback(`${REDIRECT_URI}?code=abc`)).toThrowError(
      /state/,
    );
  });

  it("authorize requires a clientId", async () => {
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
    });

    try {
      await client.authorize(
        offerUrl({
          credential_issuer: ISSUER,
          credential_configuration_ids: [CONFIG_ID],
          grants: { [AUTHORIZATION_CODE_GRANT]: {} },
        }),
        // @ts-expect-error: intentionally missing clientId
        { redirectUri: REDIRECT_URI },
      );
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.invalid_input");
    }
  });
});

/**
 * Tests for holder.offers.{authorize, claim} — Stripe-style auth-code flow.
 *
 * The mock issuer:
 *   1. Serves OID4VCI metadata (incl. authorization_endpoint).
 *   2. Validates the PKCE verifier against the challenge on token exchange.
 *   3. Mints a real SD-JWT-VC bound to the holder via @gramota/issuer.
 *
 * This exercises the holder's pending-flow cache (state → context),
 * trusted-issuer validation, and the storage round-trip — same as the
 * pre-auth happy path, except via the interactive authorize/claim pair.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Issuer } from "@gramota/issuer";
import {
  AUTHORIZATION_CODE_GRANT,
  type Fetcher,
} from "@gramota/oid4vci";
import { Holder, HolderError } from "../src/index.js";

const ISSUER_URL = "https://issuer.example.com";
const VCT = "https://credentials.example.com/pid";
const AUTHZ_ENDPOINT = `${ISSUER_URL}/authorize`;
const TOKEN_ENDPOINT = `${ISSUER_URL}/token`;
const CRED_ENDPOINT = `${ISSUER_URL}/credential`;
const PAR_ENDPOINT = `${ISSUER_URL}/par`;
const REDIRECT_URI = "https://wallet.example.com/cb";
const CONFIG_ID = "pid";

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
  issuerKey: { pub: JsonWebKey; priv: JsonWebKey };
  subject: Record<string, unknown>;
  selectivelyDisclosable: readonly string[];
  expectedCodeChallenge: string;
  expectedClientId: string;
  expectedRedirectUri: string;
  authCode: string;
}

function mockIssuerFetcher(opts: MockOpts): Fetcher {
  return async (url, init) => {
    const method = init?.method ?? "GET";

    if (
      method === "GET" &&
      url === `${ISSUER_URL}/.well-known/openid-credential-issuer`
    ) {
      return jsonOk({
        credential_issuer: ISSUER_URL,
        credential_endpoint: CRED_ENDPOINT,
        token_endpoint: TOKEN_ENDPOINT,
        authorization_endpoint: AUTHZ_ENDPOINT,
        // RFC 9126 PAR is mandatory in the SDK.
        pushed_authorization_request_endpoint: PAR_ENDPOINT,
        credential_configurations_supported: {
          [CONFIG_ID]: {
            format: "vc+sd-jwt",
            vct: VCT,
            cryptographic_binding_methods_supported: ["jwk"],
            credential_signing_alg_values_supported: ["ES256"],
            proof_types_supported: {
              jwt: { proof_signing_alg_values_supported: ["ES256"] },
            },
          },
        },
      });
    }

    // PAR endpoint — RFC 9126
    if (method === "POST" && url === PAR_ENDPOINT) {
      const params = new URLSearchParams(init!.body as string);
      if (params.get("client_id") !== opts.expectedClientId) {
        return jsonErr(400, "client_id_mismatch");
      }
      if (params.get("redirect_uri") !== opts.expectedRedirectUri) {
        return jsonErr(400, "redirect_uri_mismatch");
      }
      if (params.get("code_challenge") !== opts.expectedCodeChallenge) {
        return jsonErr(400, "code_challenge_mismatch");
      }
      return jsonOk({
        request_uri: `urn:ietf:params:oauth:request_uri:test-${Math.random()
          .toString(36)
          .slice(2, 10)}`,
        expires_in: 60,
      });
    }

    if (method === "POST" && url === TOKEN_ENDPOINT) {
      const params = new URLSearchParams(init!.body as string);
      if (params.get("grant_type") !== AUTHORIZATION_CODE_GRANT) {
        return jsonErr(400, "unsupported_grant_type");
      }
      if (params.get("code") !== opts.authCode) {
        return jsonErr(400, "invalid_grant");
      }
      if (params.get("redirect_uri") !== opts.expectedRedirectUri) {
        return jsonErr(400, "redirect_uri_mismatch");
      }
      if (params.get("client_id") !== opts.expectedClientId) {
        return jsonErr(400, "client_id_mismatch");
      }
      const verifier = params.get("code_verifier");
      if (verifier === null) return jsonErr(400, "missing_verifier");
      const derived = createHash("sha256").update(verifier).digest("base64url");
      if (derived !== opts.expectedCodeChallenge) {
        return jsonErr(400, "pkce_mismatch");
      }
      return jsonOk({
        access_token: "mock-token",
        token_type: "Bearer",
        c_nonce: "mock-nonce",
        c_nonce_expires_in: 60,
      });
    }

    if (method === "POST" && url === CRED_ENDPOINT) {
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
        issuerId: ISSUER_URL,
      });
      const { token } = await issuer.issue({
        subject: opts.subject,
        selectivelyDisclosable: opts.selectivelyDisclosable,
        holderKey: proofHeader.jwk,
        vct: VCT,
      });
      return jsonOk({ credential: token });
    }

    return jsonErr(404, `unhandled: ${method} ${url}`);
  };
}

function jsonOk(body: object): Awaited<ReturnType<Fetcher>> {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
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

function offerUrl(offer: object): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

describe("holder.offers.authorize — step 1 (build URL, return secrets)", () => {
  it("returns a redirect URL whose params encode PKCE + state + authorization_details", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();

    const codeVerifier = "v" + "x".repeat(50);
    const expectedChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

    const fetcher = mockIssuerFetcher({
      issuerKey,
      subject: { given_name: "Alice" },
      selectivelyDisclosable: ["given_name"],
      expectedCodeChallenge: expectedChallenge,
      expectedClientId: REDIRECT_URI, // default = redirectUri
      expectedRedirectUri: REDIRECT_URI,
      authCode: "code-1",
    });

    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    const start = await holder.offers.authorize(
      offerUrl({
        credential_issuer: ISSUER_URL,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      {
        redirectUri: REDIRECT_URI,
        codeVerifier,
        state: "csrf-1",
        fetcher,
      },
    );

    expect(start.codeVerifier).toBe(codeVerifier);
    expect(start.state).toBe("csrf-1");

    // Post-PAR URL: only client_id + request_uri. All other params went
    // to the PAR endpoint (which validates them) and got bound to the URN.
    const u = new URL(start.authorizationUrl);
    expect(`${u.origin}${u.pathname}`).toBe(AUTHZ_ENDPOINT);
    expect(u.searchParams.get("request_uri")).toMatch(
      /^urn:ietf:params:oauth:request_uri:/,
    );
    // public client default: client_id == redirect_uri
    expect(u.searchParams.get("client_id")).toBe(REDIRECT_URI);
    // Sensitive params must NOT appear on the URL (PAR's whole point).
    expect(u.searchParams.get("code_challenge")).toBeNull();
    expect(u.searchParams.get("redirect_uri")).toBeNull();
    expect(u.searchParams.get("state")).toBeNull();
  });
});

describe("holder.offers.claim — step 2 (full auth-code → store roundtrip)", () => {
  it("authorize → claim mints, validates and stores a credential", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();

    const codeVerifier = "v" + "x".repeat(50);
    const expectedChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

    const fetcher = mockIssuerFetcher({
      issuerKey,
      subject: {
        given_name: "Greta",
        family_name: "Authorizer",
        birthdate: "1990-01-01",
      },
      selectivelyDisclosable: ["given_name", "family_name", "birthdate"],
      expectedCodeChallenge: expectedChallenge,
      expectedClientId: REDIRECT_URI,
      expectedRedirectUri: REDIRECT_URI,
      authCode: "code-1",
    });

    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    const start = await holder.offers.authorize(
      offerUrl({
        credential_issuer: ISSUER_URL,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      {
        redirectUri: REDIRECT_URI,
        codeVerifier,
        state: "csrf-1",
        fetcher,
      },
    );

    // simulate the user consent + redirect back to the wallet
    const callbackUrl = `${REDIRECT_URI}?code=code-1&state=${start.state}`;

    const stored = await holder.offers.claim({
      callbackUrl,
      codeVerifier: start.codeVerifier,
      state: start.state,
      trustedIssuers: [issuerKey.pub],
      fetcher,
    });

    expect(stored.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(stored.issuer).toBe(ISSUER_URL);
    expect(stored.parsed.disclosures).toHaveLength(3);

    const all = await holder.credentials.list();
    expect(all).toHaveLength(1);
    expect(all[0]?.id).toBe(stored.id);
  });

  it("rejects a credential signed by an UN-trusted issuer (same guard as accept)", async () => {
    const goodIssuerKey = await makeKey();
    const evilIssuerKey = await makeKey();
    const holderKey = await makeKey();

    const codeVerifier = "v" + "x".repeat(50);
    const expectedChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

    const fetcher = mockIssuerFetcher({
      issuerKey: evilIssuerKey, // mock will mint with evil key
      subject: { given_name: "Mallory" },
      selectivelyDisclosable: ["given_name"],
      expectedCodeChallenge: expectedChallenge,
      expectedClientId: REDIRECT_URI,
      expectedRedirectUri: REDIRECT_URI,
      authCode: "code-1",
    });

    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    const start = await holder.offers.authorize(
      offerUrl({
        credential_issuer: ISSUER_URL,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      {
        redirectUri: REDIRECT_URI,
        codeVerifier,
        state: "csrf-evil",
        fetcher,
      },
    );

    await expect(
      holder.offers.claim({
        callbackUrl: `${REDIRECT_URI}?code=code-1&state=${start.state}`,
        codeVerifier: start.codeVerifier,
        state: start.state,
        trustedIssuers: [goodIssuerKey.pub], // not the evil one
        fetcher,
      }),
    ).rejects.toThrow(/issuer signature/);
  });

  it("claim() throws holder.unknown_flow when state is unknown (no prior authorize)", async () => {
    const holderKey = await makeKey();
    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    try {
      await holder.offers.claim({
        callbackUrl: `${REDIRECT_URI}?code=x&state=never-issued`,
        codeVerifier: "v".repeat(50),
        state: "never-issued",
        trustedIssuers: [],
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(HolderError);
      expect((err as HolderError).code).toBe("holder.unknown_flow");
    }
  });

  it("claim() drops the pending flow on success — second call with same state fails", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const codeVerifier = "v" + "x".repeat(50);
    const expectedChallenge = createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

    const fetcher = mockIssuerFetcher({
      issuerKey,
      subject: { given_name: "First" },
      selectivelyDisclosable: ["given_name"],
      expectedCodeChallenge: expectedChallenge,
      expectedClientId: REDIRECT_URI,
      expectedRedirectUri: REDIRECT_URI,
      authCode: "code-1",
    });

    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    const start = await holder.offers.authorize(
      offerUrl({
        credential_issuer: ISSUER_URL,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      {
        redirectUri: REDIRECT_URI,
        codeVerifier,
        state: "one-shot",
        fetcher,
      },
    );

    const callbackUrl = `${REDIRECT_URI}?code=code-1&state=${start.state}`;
    await holder.offers.claim({
      callbackUrl,
      codeVerifier: start.codeVerifier,
      state: start.state,
      trustedIssuers: [issuerKey.pub],
      fetcher,
    });

    // Replay attempt — should be rejected (no pending flow).
    await expect(
      holder.offers.claim({
        callbackUrl,
        codeVerifier: start.codeVerifier,
        state: start.state,
        trustedIssuers: [issuerKey.pub],
        fetcher,
      }),
    ).rejects.toThrow(/no pending auth-code flow/);
  });
});

/**
 * GoF Strategy pattern: `AuthorizationTransport` + concrete strategies.
 *
 * These tests prove three things:
 *
 *   1. ParAuthorizationTransport (default) — pushes params to the AS and
 *      builds the post-PAR redirect URL with only `client_id + request_uri`.
 *
 *   2. DirectAuthorizationTransport — encodes every param on the URL,
 *      bypassing PAR. Useful for non-PAR ASes; opt-in via Oid4vciClientConfig.
 *
 *   3. Custom transports plug in via Dependency Inversion — Oid4vciClient
 *      depends on the AuthorizationTransport abstraction, not on PAR
 *      specifically. A user-defined CapturingTransport here proves that.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gateway/jose";
import {
  AUTHORIZATION_CODE_GRANT,
  DirectAuthorizationTransport,
  Oid4vciClient,
  Oid4vciError,
  ParAuthorizationTransport,
  type AuthorizationTransport,
  type DeliverInput,
  type Fetcher,
} from "../src/index.js";

const ISSUER = "https://issuer.example.com";
const VCT = "https://credentials.example.com/pid";
const AUTHZ_ENDPOINT = `${ISSUER}/authorize`;
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const CRED_ENDPOINT = `${ISSUER}/credential`;
const PAR_ENDPOINT = `${ISSUER}/par`;
const REDIRECT_URI = "https://wallet.example.com/cb";
const CLIENT_ID = "wallet-public-client";
const CONFIG_ID = "pid-vc-sd-jwt";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

function offerUrl(offer: object): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

/** Mock issuer that exposes BOTH a PAR endpoint and a directly-reachable
 * authorization endpoint, so the same fixture can drive both strategies. */
function dualModeFetcher(opts: { withParEndpoint: boolean }): Fetcher {
  return async (url, init) => {
    const method = init?.method ?? "GET";
    if (
      method === "GET" &&
      url === `${ISSUER}/.well-known/openid-credential-issuer`
    ) {
      const body: Record<string, unknown> = {
        credential_issuer: ISSUER,
        credential_endpoint: CRED_ENDPOINT,
        token_endpoint: TOKEN_ENDPOINT,
        authorization_endpoint: AUTHZ_ENDPOINT,
        credential_configurations_supported: {
          [CONFIG_ID]: {
            format: "vc+sd-jwt",
            vct: VCT,
            cryptographic_binding_methods_supported: ["jwk"],
          },
        },
      };
      if (opts.withParEndpoint) {
        body["pushed_authorization_request_endpoint"] = PAR_ENDPOINT;
      }
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      };
    }
    if (method === "POST" && url === PAR_ENDPOINT) {
      return {
        ok: true,
        status: 201,
        json: async () => ({
          request_uri: "urn:ietf:params:oauth:request_uri:test-strat",
          expires_in: 60,
        }),
        text: async () => "",
      };
    }
    return { ok: false, status: 404, json: async () => ({}), text: async () => "" };
  };
}

describe("AuthorizationTransport — ParAuthorizationTransport (default)", () => {
  it("is the default transport when no custom one is configured", async () => {
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher: dualModeFetcher({ withParEndpoint: true }),
    });

    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      { clientId: CLIENT_ID, redirectUri: REDIRECT_URI },
    );

    // PAR roundtrip happened — URL has request_uri, not raw params.
    const u = new URL(start.authorizationUrl);
    expect(u.searchParams.get("request_uri")).toMatch(
      /^urn:ietf:params:oauth:request_uri:/,
    );
    expect(u.searchParams.get("code_challenge")).toBeNull();
  });

  it("throws par_endpoint_missing when the AS doesn't advertise a PAR endpoint", async () => {
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher: dualModeFetcher({ withParEndpoint: false }),
      authorizationTransport: new ParAuthorizationTransport(),
    });

    try {
      await client.authorize(
        offerUrl({
          credential_issuer: ISSUER,
          credential_configuration_ids: [CONFIG_ID],
          grants: { [AUTHORIZATION_CODE_GRANT]: {} },
        }),
        { clientId: CLIENT_ID, redirectUri: REDIRECT_URI },
      );
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.par_endpoint_missing");
    }
  });
});

describe("AuthorizationTransport — DirectAuthorizationTransport (opt-in)", () => {
  it("encodes every param on the authorization-endpoint URL", async () => {
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      // Issuer that doesn't expose PAR — would throw with the default
      // transport, but Direct works against any AS.
      fetcher: dualModeFetcher({ withParEndpoint: false }),
      authorizationTransport: new DirectAuthorizationTransport(),
    });

    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      { clientId: CLIENT_ID, redirectUri: REDIRECT_URI },
    );

    const u = new URL(start.authorizationUrl);
    expect(`${u.origin}${u.pathname}`).toBe(AUTHZ_ENDPOINT);
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(u.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")?.length).toBe(43);
    // No request_uri — that's PAR-specific.
    expect(u.searchParams.get("request_uri")).toBeNull();
  });

  it("works even when the AS happens to also expose PAR (Direct ignores it)", async () => {
    // Proves Direct doesn't accidentally fall back to PAR when offered.
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher: dualModeFetcher({ withParEndpoint: true }),
      authorizationTransport: new DirectAuthorizationTransport(),
    });

    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      { clientId: CLIENT_ID, redirectUri: REDIRECT_URI },
    );

    const u = new URL(start.authorizationUrl);
    expect(u.searchParams.get("code_challenge")).not.toBeNull();
    expect(u.searchParams.get("request_uri")).toBeNull();
  });
});

describe("AuthorizationTransport — extensibility (custom strategies)", () => {
  it("Oid4vciClient depends on the abstraction — a user-defined transport plugs in", async () => {
    // A strategy that records what it received and returns a marker URL.
    // Could equally be a real JAR (RFC 9101) implementation, an mTLS
    // transport, an offline-QR encoder, etc.
    let captured: DeliverInput | undefined;
    class CapturingTransport implements AuthorizationTransport {
      async deliver(input: DeliverInput): Promise<string> {
        captured = input;
        return `https://wallet.example.com/marker?seen=${
          Object.keys(input.params).length
        }`;
      }
    }

    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
      fetcher: dualModeFetcher({ withParEndpoint: true }),
      authorizationTransport: new CapturingTransport(),
    });

    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIG_ID],
        grants: { [AUTHORIZATION_CODE_GRANT]: { issuer_state: "iss-state" } },
      }),
      {
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        scope: "openid",
      },
    );

    // The custom transport saw the canonical params.
    expect(captured).toBeDefined();
    expect(captured!.clientId).toBe(CLIENT_ID);
    expect(captured!.params["response_type"]).toBe("code");
    expect(captured!.params["client_id"]).toBe(CLIENT_ID);
    expect(captured!.params["redirect_uri"]).toBe(REDIRECT_URI);
    expect(captured!.params["code_challenge_method"]).toBe("S256");
    expect(captured!.params["scope"]).toBe("openid");
    expect(captured!.params["issuer_state"]).toBe("iss-state");
    expect(captured!.params["authorization_details"]).toContain(
      "openid_credential",
    );

    // The orchestrator returned exactly what the transport produced.
    // 9 params: response_type, client_id, redirect_uri, state,
    // code_challenge, code_challenge_method, authorization_details,
    // scope, issuer_state.
    expect(start.authorizationUrl).toBe(
      "https://wallet.example.com/marker?seen=9",
    );

    // PKCE+state were still generated by the orchestrator and returned
    // to the caller — independent of which transport was picked.
    expect(start.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(start.state.length).toBeGreaterThan(0);
  });

  it("ParAuthorizationTransport.deliver() is callable directly without Oid4vciClient", async () => {
    // The strategies are first-class — power users compose them with
    // their own pipelines (e.g. server-side flows, browser extensions).
    const transport = new ParAuthorizationTransport();
    let postedTo: string | undefined;
    let postedBody: string | undefined;
    const fetcher: Fetcher = async (url, init) => {
      postedTo = url;
      postedBody = init?.body as string;
      return {
        ok: true,
        status: 201,
        json: async () => ({
          request_uri: "urn:ietf:params:oauth:request_uri:standalone",
          expires_in: 30,
        }),
        text: async () => "",
      };
    };

    const url = await transport.deliver({
      authorizationServerMetadata: {
        issuer: ISSUER,
        authorization_endpoint: AUTHZ_ENDPOINT,
        token_endpoint: TOKEN_ENDPOINT,
        pushed_authorization_request_endpoint: PAR_ENDPOINT,
      },
      params: {
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_challenge: "X".repeat(43),
        code_challenge_method: "S256",
      },
      clientId: CLIENT_ID,
      fetcher,
    });

    expect(postedTo).toBe(PAR_ENDPOINT);
    expect(postedBody).toContain("client_id=" + CLIENT_ID);
    const u = new URL(url);
    expect(u.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(u.searchParams.get("request_uri")).toBe(
      "urn:ietf:params:oauth:request_uri:standalone",
    );
  });
});

/**
 * Tests for holder.offers.{parse, accept} — the Stripe-style namespace
 * that ties OID4VCI to the holder's credential store.
 *
 * Uses a mock issuer (powered by @gramota/issuer) so the full flow runs
 * without network: parse → metadata → token → proof JWT → credential
 * request → validate → store.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Issuer } from "@gramota/issuer";
import { PRE_AUTHORIZED_CODE_GRANT, type Fetcher } from "@gramota/oid4vci";
import { Holder } from "../src/index.js";

const ISSUER_URL = "https://issuer.example.com";
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

function mockIssuerFetcher(opts: {
  expectedPreAuthCode: string;
  issuerKey: { pub: JsonWebKey; priv: JsonWebKey };
  subject: Record<string, unknown>;
  selectivelyDisclosable: readonly string[];
}): Fetcher {
  return async (url, init) => {
    const method = init?.method ?? "GET";

    if (
      method === "GET" &&
      url === `${ISSUER_URL}/.well-known/openid-credential-issuer`
    ) {
      const body = {
        credential_issuer: ISSUER_URL,
        credential_endpoint: `${ISSUER_URL}/credential`,
        token_endpoint: `${ISSUER_URL}/token`,
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
      return jsonOk(body);
    }

    if (method === "POST" && url === `${ISSUER_URL}/token`) {
      const params = new URLSearchParams(init!.body as string);
      if (params.get("pre-authorized_code") !== opts.expectedPreAuthCode) {
        return jsonErr(400, "invalid_grant");
      }
      return jsonOk({
        access_token: "mock-token",
        token_type: "Bearer",
        c_nonce: "mock-nonce",
        c_nonce_expires_in: 60,
      });
    }

    if (method === "POST" && url === `${ISSUER_URL}/credential`) {
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

describe("holder.offers.parse — pure offer URL parsing", () => {
  it("parses a valid offer URL without any network access", async () => {
    const { pub, priv } = await makeKey();
    const holder = new Holder({
      privateKey: priv,
      publicKey: pub,
      alg: "ES256",
    });

    const url = offerUrl({
      credential_issuer: ISSUER_URL,
      credential_configuration_ids: ["pid"],
      grants: {
        [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "x" },
      },
    });

    const offer = holder.offers.parse(url);
    expect(offer.credential_issuer).toBe(ISSUER_URL);
    expect(offer.credential_configuration_ids).toEqual(["pid"]);
  });
});

describe("holder.offers.accept — full OID4VCI → store roundtrip", () => {
  it("accepts an offer, validates the credential, stores it in the holder", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();

    const fetcher = mockIssuerFetcher({
      expectedPreAuthCode: "pre-auth-1",
      issuerKey,
      subject: {
        given_name: "Greta",
        family_name: "Acceptor",
        birthdate: "1992-03-15",
      },
      selectivelyDisclosable: ["given_name", "family_name", "birthdate"],
    });

    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    const url = offerUrl({
      credential_issuer: ISSUER_URL,
      credential_configuration_ids: ["pid"],
      grants: {
        [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "pre-auth-1" },
      },
    });

    const stored = await holder.offers.accept(url, {
      trustedIssuers: [issuerKey.pub],
      fetcher,
    });

    expect(stored.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(stored.issuer).toBe(ISSUER_URL);
    expect(stored.parsed.disclosures).toHaveLength(3);

    // Stored credential is queryable via the credentials namespace.
    const all = await holder.credentials.list();
    expect(all).toHaveLength(1);
    expect(all[0]?.id).toBe(stored.id);
  });

  it("rejects an issued credential signed by an UN-TRUSTED issuer", async () => {
    const goodIssuerKey = await makeKey();
    const evilIssuerKey = await makeKey(); // signs the credential
    const holderKey = await makeKey();

    const fetcher = mockIssuerFetcher({
      expectedPreAuthCode: "x",
      issuerKey: evilIssuerKey, // mock issuer signs with evil key
      subject: { given_name: "X" },
      selectivelyDisclosable: ["given_name"],
    });

    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    const url = offerUrl({
      credential_issuer: ISSUER_URL,
      credential_configuration_ids: ["pid"],
      grants: {
        [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "x" },
      },
    });

    // Holder trusts only the GOOD key — credential signed by EVIL must be rejected.
    await expect(
      holder.offers.accept(url, {
        trustedIssuers: [goodIssuerKey.pub],
        fetcher,
      }),
    ).rejects.toThrow(/issuer signature/);
  });
});

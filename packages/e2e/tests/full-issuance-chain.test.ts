/**
 * Top-to-bottom E2E with @gramota/oid4vci as the transport for issuance:
 *
 *   Issuer publishes offer URL                                         (mock HTTP)
 *     → Holder.offers.parse                                             (preview)
 *     → Holder.offers.accept (parses, fetches metadata, exchanges      (full flow)
 *        token, builds proof, requests credential, validates, stores)
 *     → Holder.respond (with OID4VP request)                            (presentation)
 *     → Verifier.response                                                (verification)
 *
 * Every public class method exercised. No network. Proves OID4VCI receive
 * + storage + later presentation work end-to-end across the SDK.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Issuer } from "@gramota/issuer";
import { Holder } from "@gramota/holder";
import { Verifier } from "@gramota/verifier";
import { PRE_AUTHORIZED_CODE_GRANT, type Fetcher } from "@gramota/oid4vci";

const ISSUER_URL = "https://gov.example.com";
const VCT = "https://credentials.example.com/national_id";
const NOW_S = 1_700_000_050;

async function newKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

function buildIssuerHttpServer(opts: {
  preAuthCode: string;
  issuerKey: { pub: JsonWebKey; priv: JsonWebKey };
  subject: Record<string, unknown>;
  selectivelyDisclosable: readonly string[];
}): Fetcher {
  return async (url, init) => {
    if (url === `${ISSUER_URL}/.well-known/openid-credential-issuer`) {
      return ok({
        credential_issuer: ISSUER_URL,
        credential_endpoint: `${ISSUER_URL}/credential`,
        token_endpoint: `${ISSUER_URL}/token`,
        credential_configurations_supported: {
          national_id: {
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
    if (url === `${ISSUER_URL}/token`) {
      return ok({
        access_token: "tok",
        token_type: "Bearer",
        c_nonce: "n",
        c_nonce_expires_in: 60,
      });
    }
    if (url === `${ISSUER_URL}/credential`) {
      const proofJwt = JSON.parse(init!.body as string).proof.jwt as string;
      const jwk = JSON.parse(
        Buffer.from(proofJwt.split(".")[0]!, "base64url").toString("utf-8"),
      ).jwk as JsonWebKey;

      const issuer = new Issuer({
        privateKey: opts.issuerKey.priv,
        publicKey: opts.issuerKey.pub,
        alg: "ES256",
        issuerId: ISSUER_URL,
      });
      const { token } = await issuer.issue({
        subject: opts.subject,
        selectivelyDisclosable: opts.selectivelyDisclosable,
        holderKey: jwk,
        vct: VCT,
      });
      return ok({ credential: token });
    }
    return notFound();
  };
}

function ok(body: object): Awaited<ReturnType<Fetcher>> {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}
function notFound(): Awaited<ReturnType<Fetcher>> {
  return {
    ok: false,
    status: 404,
    json: async () => ({}),
    text: async () => "",
  };
}

function offerUrl(offer: object): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

describe("Full issuance + presentation chain through every package", () => {
  it("issuance via OID4VCI → presentation via OID4VP → verification — green", async () => {
    const issuerKey = await newKey();
    const holderKey = await newKey();

    const fetcher = buildIssuerHttpServer({
      preAuthCode: "pa-1",
      issuerKey,
      subject: {
        given_name: "Iva",
        family_name: "Chained",
        birthdate: "1985-01-01",
        nationality: "BG",
      },
      selectivelyDisclosable: [
        "given_name",
        "family_name",
        "birthdate",
        "nationality",
      ],
    });

    // ---- HOLDER receives credential via OID4VCI ----
    const holder = new Holder({
      privateKey: holderKey.priv,
      publicKey: holderKey.pub,
      alg: "ES256",
    });

    const offer = offerUrl({
      credential_issuer: ISSUER_URL,
      credential_configuration_ids: ["national_id"],
      grants: {
        [PRE_AUTHORIZED_CODE_GRANT]: { "pre-authorized_code": "pa-1" },
      },
    });

    // Preview the offer
    const preview = holder.offers.parse(offer);
    expect(preview.credential_issuer).toBe(ISSUER_URL);

    // Accept it (full OID4VCI flow → validate → store)
    const stored = await holder.offers.accept(offer, {
      trustedIssuers: [issuerKey.pub],
      fetcher,
    });
    expect(stored.parsed.disclosures).toHaveLength(4);

    // ---- VERIFIER builds an OID4VP request ----
    const audience = "https://my-bank.example.com";
    const verifier = new Verifier({
      audience,
      issuerKey: issuerKey.pub,
    });
    const created = verifier.requests.create({
      baseUrl: "openid4vp://authorize",
      nonce: "chain-nonce",
      state: "chain-state",
      responseUri: `${audience}/oid4vp/cb`,
      presentationDefinition: {
        id: "pd-chain",
        input_descriptors: [
          {
            id: "id",
            format: { "vc+sd-jwt": { alg: ["ES256"] } },
            constraints: {
              limit_disclosure: "required",
              fields: [
                { path: ["$.given_name"] },
                { path: ["$.birthdate"] },
              ],
            },
          },
        ],
      },
    });

    // ---- HOLDER responds ----
    const response = await holder.respond(created.url, {
      now: () => NOW_S - 5,
    });

    // ---- VERIFIER verifies ----
    const result = await verifier.responses.verify(response.body, {
      expectedNonce: "chain-nonce",
      expectedState: "chain-state",
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.claims).toEqual({
      given_name: "Iva",
      birthdate: "1985-01-01",
    });
    // Withheld claims should NOT appear.
    expect(result.claims).not.toHaveProperty("family_name");
    expect(result.claims).not.toHaveProperty("nationality");
    expect(result.checks).toHaveLength(11);
  });
});

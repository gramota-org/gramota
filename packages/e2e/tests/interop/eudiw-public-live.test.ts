/**
 * Live E2E tests that drive @gramota/* libraries against the EU
 * Commission's public dev verifier (https://dev.verifier-backend.eudiw.dev).
 *
 * Skipped by default. Run with EUDI_LIVE=1 to enable:
 *
 *   EUDI_LIVE=1 pnpm test
 *
 * What this proves: our parser correctly handles the EXACT bytes the EU
 * verifier emits when called for real, not just the example response in
 * their published openapi.json. Catches upstream spec drift.
 *
 * Why opt-in: outbound network in CI is not appropriate for gating regular
 * builds on the EU's hosted instance uptime. Best run as a periodic
 * interop job (nightly cron / Renovate trigger).
 */

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import {
  parseAuthorizationRequestSearchParams,
  type AuthorizationRequest,
} from "@gramota/oid4vp";
import { verifyJwsWithX5c } from "@gramota/jose";
import { selectForDcql, type DcqlQuery } from "@gramota/dcql";
import { issueSdJwt, parseSdJwt, stubSignature } from "@gramota/sd-jwt";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

const VERIFIER_BACKEND = "https://dev.verifier-backend.eudiw.dev";
const INIT_ENDPOINT = `${VERIFIER_BACKEND}/ui/presentations`;

async function initTransaction(): Promise<{
  transaction_id: string;
  client_id: string;
  request: string;
}> {
  // Ask the EU verifier for an SD-JWT-VC PID instead of mso_mdoc — both
  // formats are supported by their dev verifier, and SD-JWT-VC is what
  // our SDK natively handles. This unlocks a fully-green roundtrip when
  // we bring our own structurally-correct credential to the test.
  //
  // Per IETF SD-JWT-VC §3.2.2.1 (EU profile): vct = "urn:eudi:pid:1"
  // for the EU PID — referenced from the EU verifier's own
  // application.properties (vcts[0].url).
  const initBody = {
    dcql_query: {
      credentials: [
        {
          id: "eu-pid-live",
          // OID4VP 2.0 / IETF SD-JWT-VC: the newer format identifier is
          // "dc+sd-jwt" (older drafts used "vc+sd-jwt"). The EU verifier
          // accepts the newer one.
          format: "dc+sd-jwt",
          meta: { vct_values: ["urn:eudi:pid:1"] },
          claims: [{ path: ["family_name"] }],
        },
      ],
      credential_sets: [
        {
          options: [["eu-pid-live"]],
          purpose: "Live smoke from @gateway SDK",
        },
      ],
    },
    nonce: `live-${Date.now()}`,
    jar_mode: "by_value",
    profile: "openid4vp",
  };

  const response = await fetch(INIT_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(initBody),
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(
      `init-transaction failed: HTTP ${response.status} ${response.statusText}\nbody: ${body.slice(0, 1000)}`,
    );
  }
  return (await response.json()) as {
    transaction_id: string;
    client_id: string;
    request: string;
  };
}

function decodeJarPayload(jar: string): Record<string, unknown> {
  const payloadB64 = jar.split(".")[1]!;
  return JSON.parse(
    Buffer.from(payloadB64, "base64url").toString("utf-8"),
  ) as Record<string, unknown>;
}

function asParams(payload: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(payload)) {
    if (v === undefined) continue;
    out[k] = typeof v === "string" ? v : JSON.stringify(v);
  }
  return out;
}

dlive("EUDIW public dev verifier — live E2E driving @gramota/*", () => {
  it("@gramota/jose cryptographically verifies the LIVE JAR signature via x5c", async () => {
    const txn = await initTransaction();

    // GAP-CLOSING assertion: our SDK verifies the signature on a real,
    // freshly-emitted EU JAR using the cert chain in the x5c header.
    const verified = await verifyJwsWithX5c(txn.request);

    expect(verified.alg).toBe("ES256");
    expect(verified.header["typ"]).toBe("oauth-authz-req+jwt");
    expect(verified.payload["response_type"]).toBe("vp_token");

    // OID4VP 2.0: client_id embeds the scheme (e.g. "x509_hash:<hash>" or
    // "x509_san_dns:<dns>"). We don't pin a specific scheme here — just
    // assert it's a non-empty string.
    expect(typeof verified.payload["client_id"]).toBe("string");
    expect(
      (verified.payload["client_id"] as string).length,
    ).toBeGreaterThan(0);
  }, 20_000);

  it("@gramota/oid4vp accepts the LIVE JAR payload as an AuthorizationRequest", async () => {
    const txn = await initTransaction();

    // Verify signature first — never trust a parsed-but-unverified request.
    const verified = await verifyJwsWithX5c(txn.request);

    // Drive the OID4VP parser against the verified payload. With OID4VP 2.0
    // there's no `presentation_definition` (DCQL takes its place); the parser
    // must still accept the request structurally.
    const parsed: AuthorizationRequest =
      parseAuthorizationRequestSearchParams(asParams(verified.payload));

    expect(parsed.response_type).toBe("vp_token");
    expect(typeof parsed.client_id).toBe("string");
    expect(typeof parsed.nonce).toBe("string");
  }, 20_000);

  it("@gramota/dcql parses the LIVE DCQL query (we asked for SD-JWT-VC)", async () => {
    const txn = await initTransaction();
    const verified = await verifyJwsWithX5c(txn.request);

    // OID4VP 2.0: the EU verifier emits dcql_query, not presentation_definition.
    expect(verified.payload["dcql_query"]).toBeDefined();
    expect(verified.payload["presentation_definition"]).toBeUndefined();

    const dcql = verified.payload["dcql_query"] as DcqlQuery;

    // The EU echoes the format we asked for in the init-transaction body.
    expect(dcql.credentials[0]?.format).toBe("dc+sd-jwt");
    const meta = dcql.credentials[0]?.meta as
      | { vct_values?: readonly string[] }
      | undefined;
    expect(meta?.vct_values).toContain("urn:eudi:pid:1");

    // selectForDcql against an EMPTY wallet → unmatched, but with the
    // semantically-correct reason ("no credential satisfies"), not "no matcher".
    // That's the difference between "we don't speak this language" and
    // "we speak it; just don't have what was asked for."
    const sel = selectForDcql({
      query: dcql,
      credentials: [],
    });
    expect(sel.fullySatisfied).toBe(false);
    expect(sel.unmatched[0]?.reason).toMatch(/no credential satisfies/);
  }, 20_000);

  it("@gramota/dcql FULLY MATCHES the live EU DCQL query when given a structurally-correct PID", async () => {
    // The killer test: bring our own SD-JWT-VC PID (synthetic — it won't
    // verify against an EU trust anchor, but the matcher only checks
    // structure) and prove our DCQL matcher correctly identifies it as
    // satisfying the LIVE EU query.
    const txn = await initTransaction();
    const verified = await verifyJwsWithX5c(txn.request);
    const dcql = verified.payload["dcql_query"] as DcqlQuery;

    // Synthesize a holder key + a PID-shaped SD-JWT-VC.
    const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true,
    });
    const holderPub = (await exportJWK(publicKey)) as JsonWebKey;
    void privateKey;

    const { token } = await issueSdJwt({
      payload: {
        iss: "https://test-issuer.example.com",
        iat: Math.floor(Date.now() / 1000),
        vct: "urn:eudi:pid:1", // matches what the EU asked for
        cnf: { jwk: holderPub },
      },
      sdClaims: {
        family_name: "TestUser",
        given_name: "Live",
        birthdate: "1990-01-01",
      },
      alg: "ES256",
      signer: stubSignature, // matcher doesn't verify signature
    });

    const credentialView = { parsed: parseSdJwt(token) };
    const sel = selectForDcql({
      query: dcql,
      credentials: [credentialView],
    });

    // The matcher correctly identifies our credential as satisfying the
    // EU's live query.
    expect(sel.fullySatisfied).toBe(true);
    expect(sel.matches).toHaveLength(1);
    expect(sel.matches[0]?.query.id).toBe("eu-pid-live");
    expect(sel.matches[0]?.disclose).toEqual(["family_name"]);
  }, 20_000);
});

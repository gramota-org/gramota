/**
 * Live E2E tests that drive @gateway/* libraries against the EU
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
import {
  parseAuthorizationRequestSearchParams,
  type AuthorizationRequest,
} from "@gateway/oid4vp";
import { verifyJwsWithX5c } from "@gateway/jose";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

const VERIFIER_BACKEND = "https://dev.verifier-backend.eudiw.dev";
const INIT_ENDPOINT = `${VERIFIER_BACKEND}/ui/presentations`;

async function initTransaction(): Promise<{
  transaction_id: string;
  client_id: string;
  request: string;
}> {
  // Per the EU verifier's current OpenAPI spec, the API accepts DCQL queries
  // (Digital Credentials Query Language, OID4VP 2.0) — `presentation_definition`
  // has been retired. Body shape mirrors their openapi.json example
  // `InitVpTokenTransactionByValueCrossDevice`.
  const initBody = {
    dcql_query: {
      credentials: [
        {
          id: "eu-pid-live",
          format: "mso_mdoc",
          meta: { doctype_value: "eu.europa.ec.eudi.pid.1" },
          claims: [
            {
              path: ["eu.europa.ec.eudi.pid.1", "family_name"],
            },
          ],
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

dlive("EUDIW public dev verifier — live E2E driving @gateway/*", () => {
  it("@gateway/jose cryptographically verifies the LIVE JAR signature via x5c", async () => {
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

  it("@gateway/oid4vp accepts the LIVE JAR payload as an AuthorizationRequest", async () => {
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

  it("LIVE: documents the DCQL gap — EU now uses dcql_query, not presentation_definition", async () => {
    const txn = await initTransaction();
    const verified = await verifyJwsWithX5c(txn.request);

    // The EU verifier has migrated to OID4VP 2.0 / DCQL. Our SDK currently
    // implements the OID4VP 1.0 presentation_definition profile via
    // @gateway/presentation-exchange. This test documents the gap and acts
    // as the canary: when we ship DCQL support, this assertion flips.
    expect(verified.payload["dcql_query"]).toBeDefined();
    expect(verified.payload["presentation_definition"]).toBeUndefined();

    const dcql = verified.payload["dcql_query"] as {
      credentials: { id: string; format: string }[];
    };
    expect(Array.isArray(dcql.credentials)).toBe(true);
    expect(dcql.credentials[0]?.format).toBe("mso_mdoc");
  }, 20_000);
});

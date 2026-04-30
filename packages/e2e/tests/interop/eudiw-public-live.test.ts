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
import {
  selectForDefinition,
  type PresentationDefinition,
} from "@gateway/presentation-exchange";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

const VERIFIER_BACKEND = "https://dev.verifier-backend.eudiw.dev";
const INIT_ENDPOINT = `${VERIFIER_BACKEND}/ui/presentations`;

async function initTransaction(): Promise<{
  transaction_id: string;
  client_id: string;
  request: string;
}> {
  const initBody = {
    type: "vp_token",
    presentation_definition: {
      id: `live-smoke-${Date.now()}`,
      input_descriptors: [
        {
          id: "eu.europa.ec.eudi.pid.1",
          name: "EUDI PID",
          purpose: "Live smoke from @gateway SDK",
          format: { mso_mdoc: { alg: ["ES256"] } },
          constraints: {
            fields: [
              {
                path: ["$['eu.europa.ec.eudi.pid.1']['family_name']"],
                intent_to_retain: false,
              },
            ],
          },
        },
      ],
    },
    nonce: `live-${Date.now()}`,
    jar_mode: "by_value",
    presentation_definition_mode: "by_value",
    wallet_response_redirect_uri_template:
      "https://example.com/cb?response_code={RESPONSE_CODE}",
  };

  const response = await fetch(INIT_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(initBody),
  });
  expect(response.ok).toBe(true);
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
  it("@gateway/oid4vp parses the live JAR payload as a valid AuthorizationRequest", async () => {
    const txn = await initTransaction();

    expect(typeof txn.transaction_id).toBe("string");
    expect(typeof txn.request).toBe("string");

    const jarPayload = decodeJarPayload(txn.request);
    const parsed: AuthorizationRequest = parseAuthorizationRequestSearchParams(
      asParams(jarPayload),
    );

    expect(parsed.response_type).toBe("vp_token");
    expect(parsed.client_id).toContain("verifier-backend.eudiw.dev");
    expect(typeof parsed.nonce).toBe("string");
    expect(parsed.presentation_definition).toBeDefined();
  }, 15_000);

  it("@gateway/presentation-exchange selectForDefinition handles the live PD", async () => {
    const txn = await initTransaction();
    const jarPayload = decodeJarPayload(txn.request);
    const pd = jarPayload["presentation_definition"] as PresentationDefinition;

    // No SD-JWT-VC credentials on hand → selector should report unmatched
    // (the EU PD requests mso_mdoc, which our SD-JWT-VC matcher can't satisfy).
    const sel = selectForDefinition({
      definition: pd,
      credentials: [],
    });
    expect(sel.fullySatisfied).toBe(false);
    expect(sel.unmatched.length).toBeGreaterThan(0);
  }, 15_000);
});

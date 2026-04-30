/**
 * Live E2E tests against the EU Commission's public dev verifier:
 *   https://dev.verifier-backend.eudiw.dev
 *
 * Skipped by default. Run with EUDI_LIVE=1 to enable:
 *
 *   EUDI_LIVE=1 pnpm test
 *
 * Why opt-in:
 *   - Requires outbound network in CI.
 *   - Depends on EU's hosted instance being up; not appropriate for gating
 *     normal CI on someone else's uptime.
 *   - When enabled, catches upstream spec drift early — useful for a
 *     periodic interop job (nightly cron, Renovate-triggered, etc.).
 */

import { describe, it, expect } from "vitest";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

const VERIFIER_BACKEND = "https://dev.verifier-backend.eudiw.dev";
const INIT_ENDPOINT = `${VERIFIER_BACKEND}/ui/presentations`;

dlive("EUDIW public dev verifier — live E2E", () => {
  it("init-transaction returns a parseable transaction object", async () => {
    const initBody = {
      type: "vp_token",
      presentation_definition: {
        id: "live-smoke-pd-1",
        input_descriptors: [
          {
            id: "eu.europa.ec.eudi.pid.1",
            name: "EUDI PID",
            purpose: "Live smoke test from @gateway SDK",
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
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(initBody),
    });

    expect(response.ok).toBe(true);
    const txn = (await response.json()) as Record<string, unknown>;

    // The EU verifier returns a transaction object with these stable fields.
    expect(typeof txn.transaction_id).toBe("string");
    expect(typeof txn.client_id).toBe("string");
    expect(txn.client_id).toMatch(/^x509_san_dns:/);

    // EITHER `request` (by_value JAR) OR `request_uri` (by_reference) is set.
    const hasJar = typeof txn.request === "string";
    const hasJarUri = typeof txn.request_uri === "string";
    expect(hasJar || hasJarUri).toBe(true);
  }, 15_000);

  it("init-transaction supports DCQL queries (newer API)", async () => {
    const initBody = {
      dcql_query: {
        credentials: [
          {
            id: "c-dcql-1",
            format: "mso_mdoc",
            meta: { doctype_value: "eu.europa.ec.eudi.pid.1" },
            claims: [
              { path: ["eu.europa.ec.eudi.pid.1", "family_name"] },
            ],
          },
        ],
      },
      jar_mode: "by_value",
      nonce: `live-dcql-${Date.now()}`,
      profile: "openid4vp",
    };

    const response = await fetch(INIT_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(initBody),
    });
    expect(response.ok).toBe(true);
    const txn = (await response.json()) as Record<string, unknown>;
    expect(typeof txn.transaction_id).toBe("string");
  }, 15_000);
});

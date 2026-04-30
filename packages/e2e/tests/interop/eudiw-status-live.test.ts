/**
 * Live status-list interop tests against the EU Commission's dev infra.
 *
 * Skipped unless EUDI_LIVE=1.
 *
 * What this proves:
 *   1. The EU dev issuer DOES expose status-list endpoints (canary check)
 *   2. Our @gateway/status-list parser handles the EXACT bytes the EU
 *      publishes — but only when authenticated
 *
 * Honest gap: a fully-headless full status check against EU live cannot
 * run yet — the status-list endpoints require an authenticated session
 * (cookie or Bearer), obtained by completing the interactive Keycloak
 * consent flow. We document the gap below; the canary just probes that
 * the endpoints still exist (so we'd notice if EU restructured them).
 *
 * Once we have a registered EU dev client_id and a way to drive the
 * browser consent leg, replace the canary with a real fetch + parse.
 */

import { describe, it, expect } from "vitest";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

const ISSUER_BACKEND = "https://dev.issuer-backend.eudiw.dev";

dlive("EUDIW status-list infrastructure — canary checks", () => {
  it("EU issuer exposes a status path (401 = exists but needs auth)", async () => {
    // We don't expect 200 — the endpoint requires a session. We do expect
    // 401 (unauth) rather than 404 (gone). This canary fires if the EU
    // moves status to a different path entirely.
    const response = await fetch(`${ISSUER_BACKEND}/status`, {
      method: "GET",
      redirect: "manual",
    });
    expect(response.status).not.toBe(404);
    // Most likely 401; tolerate any auth-required code (4xx).
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
  }, 20_000);

  it("EU issuer exposes /wallet/status (auth-gated)", async () => {
    const response = await fetch(`${ISSUER_BACKEND}/wallet/status`, {
      method: "GET",
      redirect: "manual",
    });
    expect(response.status).not.toBe(404);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
  }, 20_000);

  // TODO when we have an authenticated path:
  //   it("fetchStatusList parses an EU-published list", async () => {
  //     const list = await fetchStatusList(REAL_LIST_URL, {
  //       trustedIssuers: [EU_ISSUER_KEY],
  //       fetcher: authenticatedFetcher,
  //     });
  //     expect(list.length).toBeGreaterThan(0);
  //   });
});

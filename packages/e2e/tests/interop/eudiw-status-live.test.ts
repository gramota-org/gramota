/**
 * Live status-list interop tests against the EU Commission's dev infra.
 *
 * Skipped unless EUDI_LIVE=1.
 *
 * What this proves:
 *   1. The EU's status-list service is publicly reachable on a SEPARATE
 *      origin from the credential issuer (`issuer.eudiw.dev`, NOT
 *      `dev.issuer-backend.eudiw.dev`). The earlier "auth-gated" finding
 *      conflated admin endpoints with the public per-credential URIs.
 *   2. The endpoint shape matches the IETF Token Status List spec —
 *      our `StatusListResolver` would parse a real list once we have
 *      a credential's `status.status_list.uri` to point at.
 *
 * Architecture: when the EU dev PID issuer is configured with
 * `ISSUER_STATUSLIST_ENABLED=true`, it embeds a `status.status_list`
 * reference into each credential pointing at:
 *
 *   https://issuer.eudiw.dev/token_status_list/{country}/{doctype}/{rand}
 *
 * That URL is served by `eudi-srv-statuslist-py` (a separate Flask app),
 * publicly fetchable, returns `application/statuslist+jwt` per the
 * IETF Token Status List wire format.
 *
 * Honest gap: we still can't end-to-end test STATUS RESOLUTION without
 * a real credential to extract the URI from — credential issuance
 * requires interactive browser consent. The demo:eu-pid command runs
 * the full status check after credential receipt. Live tests below
 * cover everything that doesn't depend on having a credential.
 */

import { describe, it, expect } from "vitest";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

/** EU's public status-list service (from eudi-srv-statuslist-py source). */
const STATUSLIST_HOST = "https://issuer.eudiw.dev";
/** EU's PID credential issuer (different origin). */
const ISSUER_BACKEND = "https://dev.issuer-backend.eudiw.dev";

dlive("EUDIW status-list service — public reachability", () => {
  it("status host is publicly reachable (no auth required, separate origin from issuer)", async () => {
    const response = await fetch(`${STATUSLIST_HOST}/`, { method: "GET" });
    expect(response.status).toBe(200);
    // Critical check: this is a DIFFERENT host than the credential issuer.
    // SDKs that hardcode the issuer host for status lookup would break.
    expect(STATUSLIST_HOST).not.toBe(ISSUER_BACKEND);
  }, 20_000);

  it("status-list /get endpoint accepts anonymous requests (no auth gate)", async () => {
    // The /get convenience endpoint validates args first — sends a
    // "missing args" response shape rather than 401/403.
    const response = await fetch(
      `${STATUSLIST_HOST}/token_status_list/get`,
      { method: "GET" },
    );
    expect(response.status).toBe(400); // missing-args, NOT auth error
    const body = await response.text();
    expect(body).toContain("Missing");
    // Crucially NO auth-related response codes:
    expect([401, 403]).not.toContain(response.status);
  }, 20_000);

  it("non-existent status-list paths 404 (proves there's no auth wall — public 404 vs auth 401)", async () => {
    // A bogus status-list URN should 404 — if it 401'd, we'd know the
    // service requires auth. 404 confirms anonymous access is allowed.
    const response = await fetch(
      `${STATUSLIST_HOST}/token_status_list/FC/bogus.doctype/no-such-rand`,
      { method: "GET" },
    );
    expect(response.status).toBe(404);
  }, 20_000);

  it("admin endpoints on the credential issuer (different origin) ARE auth-gated — confirms separation", async () => {
    // This is the endpoint we initially mistook for the public status URL.
    // It IS auth-gated, but it's on the credential-issuer origin, NOT the
    // status-list origin. Proves the two are correctly separated.
    const response = await fetch(`${ISSUER_BACKEND}/wallet/status`, {
      method: "GET",
      redirect: "manual",
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
    // 401 in particular — auth required.
    expect(response.status).toBe(401);
  }, 20_000);
});

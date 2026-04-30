/**
 * Live E2E tests against the EU Commission's public dev issuer:
 *   https://dev.issuer-backend.eudiw.dev
 *
 * Skipped by default. Run with EUDI_LIVE=1 to enable.
 *
 * What this proves: our @gateway/oid4vci metadata parser correctly handles
 * the EXACT bytes the EU issuer publishes, not just our mocks.
 *
 * Honest gap: receiving an actual credential from the EU issuer requires
 * an interactive consent flow (user picks claims, enters PIN, etc.) so a
 * fully-headless full-loop is not possible against the EU public issuer
 * yet — we'd need either a pre-staged credential_offer URL or our own
 * test issuer to drive the receive path. That gap is documented as a
 * canary test below.
 */

import { describe, it, expect } from "vitest";
import {
  fetchIssuerMetadata,
  validateMetadata,
  resolveTokenEndpoint,
  type IssuerMetadata,
} from "@gateway/oid4vci";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

const ISSUER_BACKEND = "https://dev.issuer-backend.eudiw.dev";

dlive("EUDIW public dev issuer — live E2E driving @gateway/oid4vci", () => {
  it("@gateway/oid4vci.fetchIssuerMetadata succeeds against the EU public issuer", async () => {
    let metadata: IssuerMetadata;
    try {
      metadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    } catch (err) {
      // Diagnostic — surface what the EU issuer actually returned.
      throw new Error(
        `metadata fetch failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }

    expect(typeof metadata.credential_issuer).toBe("string");
    expect(metadata.credential_issuer).toContain("eudiw.dev");
    expect(typeof metadata.credential_endpoint).toBe("string");
    expect(metadata.credential_endpoint).toMatch(/^https:\/\//);

    // The EU issuer publishes a non-empty configurations map.
    const configs = metadata.credential_configurations_supported;
    expect(typeof configs).toBe("object");
    expect(Object.keys(configs).length).toBeGreaterThan(0);
  }, 20_000);

  it("validateMetadata accepts the EU issuer's published metadata", async () => {
    // Fetch raw, then run our validator independently — proves the metadata
    // shape we encounter live conforms to the parser's expectations.
    const url = `${ISSUER_BACKEND}/.well-known/openid-credential-issuer`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
    });
    expect(response.ok).toBe(true);
    const raw = (await response.json()) as unknown;

    const validated = validateMetadata(raw, url);
    expect(validated.credential_issuer.length).toBeGreaterThan(0);
    expect(validated.credential_endpoint.length).toBeGreaterThan(0);
  }, 20_000);

  it("resolveTokenEndpoint returns a usable token endpoint", async () => {
    const metadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const tokenEndpoint = resolveTokenEndpoint(metadata);
    expect(tokenEndpoint).toMatch(/^https:\/\//);
  }, 20_000);

  it("EU issuer advertises at least one SD-JWT-VC credential configuration", async () => {
    const metadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const configs = metadata.credential_configurations_supported;
    const sdJwtVcConfigs = Object.entries(configs).filter(
      ([, c]) => c.format === "vc+sd-jwt" || c.format === "dc+sd-jwt",
    );

    // EU's dev issuer offers PID + several other SD-JWT-VC credentials —
    // if this assertion ever fails, the EU has migrated their dev issuer
    // away from SD-JWT-VC (mso_mdoc only would be a regression).
    expect(sdJwtVcConfigs.length).toBeGreaterThan(0);
  }, 20_000);

  it("CANARY: full credential receipt requires interactive consent (documented)", async () => {
    // We do NOT actually request a credential here — that path requires
    // either a pre-authorized code obtained interactively from the EU's
    // issuer UI, or auth-code flow with PKCE (not yet implemented).
    //
    // When we ship auth-code flow + a way to drive the EU's interactive
    // consent (or an opt-in cred offer captured from a manual session),
    // this test should be replaced with the real round-trip.
    //
    // For now: this assertion just proves the issuer is reachable.
    const metadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    expect(metadata.credential_issuer).toContain("eudiw.dev");
  }, 20_000);
});

/**
 * Live E2E tests against the EU Commission's public dev issuer:
 *   https://dev.issuer-backend.eudiw.dev
 *
 * Skipped by default. Run with EUDI_LIVE=1 to enable.
 *
 * What this proves:
 *   1. our @gateway/oid4vci metadata parser correctly handles the EXACT
 *      bytes the EU issuer publishes, not just our mocks
 *   2. @gateway/oid4vci follows OID4VCI §11.2.2 delegated-authorization
 *      to the EU's Keycloak realm — pulling the right token + authorize
 *      endpoints from the AS metadata
 *   3. Oid4vciClient.authorize() builds an authorization URL the EU's
 *      AS actually accepts (not a 4xx response) — proving the auth-code
 *      flow's wire format is correct against the live infrastructure
 *
 * Honest gap: a fully-headless full receive cannot run here — the EU's
 * authorization server requires interactive user consent (mock-IDP login,
 * claim picker). We exercise everything up to that point and document
 * the manual leg in the test that drives the live AS endpoint.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gateway/jose";
import {
  AUTHORIZATION_CODE_GRANT,
  fetchAuthorizationServerMetadata,
  fetchIssuerMetadata,
  Oid4vciClient,
  resolveTokenEndpoint,
  validateMetadata,
  type IssuerMetadata,
} from "@gateway/oid4vci";

const LIVE = process.env["EUDI_LIVE"] === "1";
const dlive = LIVE ? describe : describe.skip;

const ISSUER_BACKEND = "https://dev.issuer-backend.eudiw.dev";
/** EU dev issuer delegates auth to this Keycloak realm. */
const EU_AS_URL =
  "https://dev.authenticate.eudiw.dev/realms/pid-issuer-realm";

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

  it("EU issuer delegates authorization to a Keycloak realm (authorization_servers[0])", async () => {
    const metadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const ases = metadata.authorization_servers;
    expect(Array.isArray(ases)).toBe(true);
    expect(ases!.length).toBeGreaterThan(0);
    // Sanity-check the AS URL points into the EU dev infra.
    expect(ases![0]).toContain("eudiw.dev");
  }, 20_000);

  it("@gateway/oid4vci.fetchAuthorizationServerMetadata follows §11.2.2 delegation", async () => {
    const issuerMetadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const asMetadata =
      await fetchAuthorizationServerMetadata(issuerMetadata);

    // The AS issuer URL must match what the credential issuer delegates to.
    expect(asMetadata.issuer).toBe(EU_AS_URL);
    expect(asMetadata.authorization_endpoint).toMatch(/^https:\/\//);
    expect(asMetadata.token_endpoint).toMatch(/^https:\/\//);
    // The AS must support PKCE S256 (otherwise our flow is incompatible).
    expect(asMetadata.code_challenge_methods_supported).toContain("S256");
    // The AS must support the auth-code grant (or the flow can't work).
    expect(asMetadata.grant_types_supported).toContain("authorization_code");
  }, 20_000);

  it("EU AS metadata advertises the RFC 9126 PAR endpoint", async () => {
    const issuerMetadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const asMetadata =
      await fetchAuthorizationServerMetadata(issuerMetadata);
    expect(typeof asMetadata.pushed_authorization_request_endpoint).toBe(
      "string",
    );
    expect(asMetadata.pushed_authorization_request_endpoint!).toMatch(
      /^https:\/\//,
    );
  }, 20_000);

  it("Oid4vciClient.authorize() pushes a PAR request to the EU AS and gets back a request_uri (full live PAR roundtrip)", async () => {
    // What this proves end-to-end against live EU infrastructure:
    //   1. We resolve issuer metadata
    //   2. We follow §11.2.2 delegation to the AS (Keycloak realm)
    //   3. We discover the PAR endpoint
    //   4. We POST our authorization parameters to it
    //   5. The EU AS validates them (client_id + redirect_uri + PKCE +
    //      authorization_details), mints a request_uri URN, returns it
    //   6. We build the post-PAR redirect URL using that URN
    //
    // This was previously blocked: the EU `wallet-dev` client requires PAR
    // per-client policy. Without PAR our auth requests bounced with
    // "Pushed Authorization Request is only allowed".
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
    });

    const issuerMetadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const sdJwtConfigId = Object.entries(
      issuerMetadata.credential_configurations_supported,
    ).find(
      ([, c]) => c.format === "vc+sd-jwt" || c.format === "dc+sd-jwt",
    )?.[0]!;

    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER_BACKEND,
        credential_configuration_ids: [sdJwtConfigId],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      {
        // Public, registered EU dev client. Documented in
        // eudi-srv-pid-issuer realm export + eudi-lib-jvm-openid4vci-kt.
        clientId: "wallet-dev",
        // OOB redirect — one of the four whitelisted values for wallet-dev.
        redirectUri: "urn:ietf:wg:oauth:2.0:oob",
      },
    );

    // Post-PAR URL has only client_id + request_uri.
    const u = new URL(start.authorizationUrl);
    expect(u.origin).toBe("https://dev.authenticate.eudiw.dev");
    expect(u.pathname).toContain("/protocol/openid-connect/auth");
    expect(u.searchParams.get("client_id")).toBe("wallet-dev");
    expect(u.searchParams.get("request_uri")).toMatch(
      /^urn:ietf:params:oauth:request_uri:/,
    );
    // No PKCE/redirect_uri/state on the post-PAR URL — that's the whole point.
    expect(u.searchParams.get("code_challenge")).toBeNull();
    expect(u.searchParams.get("redirect_uri")).toBeNull();
  }, 20_000);

  it("the EU AS accepts our PAR-built authorization URL (302 to login, NOT a 4xx)", async () => {
    // The previous canary asserted "rejects only at registration step".
    // Now with PAR + correct OOB redirect, we expect the EU AS to fully
    // accept our auth request and redirect us to the Keycloak login page.
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
    });

    const issuerMetadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const sdJwtConfigId = Object.entries(
      issuerMetadata.credential_configurations_supported,
    ).find(
      ([, c]) => c.format === "vc+sd-jwt" || c.format === "dc+sd-jwt",
    )?.[0]!;

    const start = await client.authorize(
      offerUrl({
        credential_issuer: ISSUER_BACKEND,
        credential_configuration_ids: [sdJwtConfigId],
        grants: { [AUTHORIZATION_CODE_GRANT]: {} },
      }),
      {
        clientId: "wallet-dev",
        redirectUri: "urn:ietf:wg:oauth:2.0:oob",
      },
    );

    const response = await fetch(start.authorizationUrl, {
      method: "GET",
      redirect: "manual",
      headers: { Accept: "text/html" },
    });

    // 200 (HTML login page rendered) OR 302 (redirect to login) — both
    // mean the AS fully accepted our request. The previous "Invalid
    // parameter: redirect_uri" 400 must NOT appear.
    expect(response.status).toBeLessThan(400);
    if (response.status >= 300) {
      // 302 → login URL is somewhere in the AS realm.
      const location = response.headers.get("location") ?? "";
      expect(location).toContain("authenticate.eudiw.dev");
    }

    // Honest documented gap: the next leg requires a human to authenticate
    // at Keycloak with `tneal` / `password` (documented test creds), then
    // consent, then the AS displays the auth code on an OOB page. That's
    // out of scope for this headless test — but the demo CLI runner can
    // automate the Keycloak login programmatically.
  }, 20_000);
});

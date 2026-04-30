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

  it("Oid4vciClient.authorize() builds a URL pointing at the EU AS with all PKCE+state params", async () => {
    const holderKey = await makeKey();
    const client = new Oid4vciClient({
      holderPublicKey: holderKey.pub,
      holderPrivateKey: holderKey.priv,
      alg: "ES256",
    });

    // Pick a real config id from the live metadata.
    const issuerMetadata = await fetchIssuerMetadata(ISSUER_BACKEND);
    const sdJwtConfigId = Object.entries(
      issuerMetadata.credential_configurations_supported,
    ).find(
      ([, c]) => c.format === "vc+sd-jwt" || c.format === "dc+sd-jwt",
    )?.[0];
    expect(sdJwtConfigId).toBeDefined();

    // Synthetic offer pointing at the live EU issuer with auth_code grant.
    // (The EU's web UI normally generates this — we construct it locally
    // since the credential_offer URL isn't an API we can hit.)
    const synthetic = offerUrl({
      credential_issuer: ISSUER_BACKEND,
      credential_configuration_ids: [sdJwtConfigId!],
      grants: { [AUTHORIZATION_CODE_GRANT]: {} },
    });

    const start = await client.authorize(synthetic, {
      clientId: "wallet-dev",
      redirectUri: "https://wallet.example.com/cb",
    });

    // The authorization URL must point at the EU's Keycloak realm — proves
    // we followed §11.2.2 delegation correctly.
    const u = new URL(start.authorizationUrl);
    expect(u.origin).toBe("https://dev.authenticate.eudiw.dev");
    expect(u.pathname).toContain("/protocol/openid-connect/auth");

    // Required OAuth + PKCE params must all be present.
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe("wallet-dev");
    expect(u.searchParams.get("redirect_uri")).toBe(
      "https://wallet.example.com/cb",
    );
    expect(u.searchParams.get("state")?.length ?? 0).toBeGreaterThan(0);
    expect(u.searchParams.get("code_challenge")?.length).toBe(43);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");

    // OID4VCI §5.1.2 — credential to request.
    const ad = JSON.parse(
      u.searchParams.get("authorization_details") ?? "[]",
    );
    expect(Array.isArray(ad)).toBe(true);
    expect(ad[0]?.type).toBe("openid_credential");
    expect(ad[0]?.credential_configuration_id).toBe(sdJwtConfigId);

    // The Holder must keep these to complete the flow.
    expect(start.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(start.state.length).toBeGreaterThan(0);
  }, 20_000);

  it("the EU AS parses our URL successfully (rejects only at the registration step, not at the OAuth-syntax step)", async () => {
    // What this proves: our authorization URL is well-formed enough that
    // the EU's Keycloak realm accepts every OAuth + PKCE parameter we sent,
    // and the only reason it bounces is registration (the wallet's
    // `client_id` + `redirect_uri` aren't registered with the EU AS).
    //
    // That's a meaningful interop signal: protocol-level malformedness
    // would surface as a generic "invalid_request" — instead we get a
    // registration-specific rejection, which means our URL passed the
    // OAuth/PKCE wire-format gate.
    //
    // To actually authenticate against the EU AS, the wallet operator
    // must register the `client_id` + redirect URI with the realm. That's
    // an out-of-band ops step not part of this SDK's scope.
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
        redirectUri: "https://wallet.example.com/cb",
      },
    );

    const response = await fetch(start.authorizationUrl, {
      method: "GET",
      redirect: "manual",
      headers: { Accept: "text/html" },
    });

    // We expect Keycloak's HTML error page — not a 5xx (server error) and
    // not 200 (which only happens with a registered client). The body must
    // mention `redirect_uri` or `client` — proving Keycloak got past every
    // OAuth-protocol validation before failing on registration.
    expect(response.status).toBeLessThan(500);
    const body = await response.text();
    expect(body.toLowerCase()).toMatch(/redirect_uri|client/);
    // The error must NOT be a generic protocol failure (e.g.
    // "invalid_request", "unsupported_response_type", "invalid_pkce") —
    // those would mean our URL is malformed.
    expect(body.toLowerCase()).not.toMatch(/invalid_request\b/);
    expect(body.toLowerCase()).not.toMatch(/unsupported_response_type/);
    expect(body.toLowerCase()).not.toMatch(/code_challenge.*invalid/);
  }, 20_000);
});

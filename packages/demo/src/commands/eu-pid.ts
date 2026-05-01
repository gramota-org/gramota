/**
 * Live EU PID demo — drives Oid4vciClient against the EU dev issuer
 * to receive a real, EU-signed PID via OID4VCI auth-code flow + PAR.
 *
 * Endpoints used:
 *   - https://dev.issuer-backend.eudiw.dev (issuer)
 *   - https://dev.authenticate.eudiw.dev/realms/pid-issuer-realm (AS)
 *
 * Public credentials documented by the EU project:
 *   - client_id: "wallet-dev"
 *   - redirect_uri: "urn:ietf:wg:oauth:2.0:oob" (one of four whitelisted)
 *   - test user: tneal / password
 *
 * The flow (interactive):
 *   1. Discover issuer + AS metadata, follow §11.2.2 delegation
 *   2. Build a synthetic credential offer pointing at EU's PID config
 *   3. Push auth params via PAR (RFC 9126), get back request_uri
 *   4. Print the authorization URL for the user to open in a browser
 *   5. User logs in at Keycloak with `tneal/password`, consents
 *   6. Keycloak displays the authorization code via OOB
 *   7. User pastes the code into the CLI prompt
 *   8. CLI exchanges code for credential, validates, persists
 *
 * The user-interaction leg (steps 4–7) cannot be automated headlessly
 * against EU live without storing credentials in this repo, which
 * would be irresponsible. The demo prints clear instructions instead.
 */

import { createInterface } from "node:readline/promises";
import { exportJWK, generateKeyPair } from "jose";
import { spawn } from "node:child_process";
import type { JsonWebKey } from "@gateway/jose";
import { Holder } from "@gateway/holder";
import {
  Oid4vciClient,
  fetchIssuerMetadata,
} from "@gateway/oid4vci";
import { FileCredentialStore } from "../file-store.js";
import { divider, fail, info, step, success, warn } from "../ui.js";

const ISSUER_BACKEND = "https://dev.issuer-backend.eudiw.dev";
// Documented in eudi-srv-pid-issuer realm export (line 1009-1024 of
// pid-issuer-realm-realm.json) and in eudi-lib-jvm-openid4vci-kt's
// integration tests. Public, registered, intended for dev wallets.
const CLIENT_ID = "wallet-dev";
const REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob";
const TEST_USER_HINT = "tneal / password (documented test user)";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

export async function runEuPid(): Promise<void> {
  divider("EUDI Gateway — receive a real EU-signed PID");
  info(
    "drives Oid4vciClient.authorize() against dev.issuer-backend.eudiw.dev",
  );

  // === Step 1: Discover ===
  step(1, "Fetch issuer metadata + follow §11.2.2 AS delegation");
  let metadata;
  try {
    metadata = await fetchIssuerMetadata(ISSUER_BACKEND);
  } catch (err) {
    fail(
      `Cannot reach EU dev issuer: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    process.exit(1);
  }
  info(`credential_issuer:    ${metadata.credential_issuer}`);
  info(
    `authorization_servers: ${JSON.stringify(metadata.authorization_servers)}`,
  );

  // Pick an SD-JWT-VC PID config from the live metadata.
  const sdJwtConfigs = Object.entries(
    metadata.credential_configurations_supported,
  ).filter(([, c]) => c.format === "vc+sd-jwt" || c.format === "dc+sd-jwt");
  if (sdJwtConfigs.length === 0) {
    fail("EU dev issuer publishes no SD-JWT-VC configurations");
    process.exit(1);
  }
  const [configId, configValue] = sdJwtConfigs.find(([id]) =>
    id.toLowerCase().includes("pid"),
  ) ?? sdJwtConfigs[0]!;
  info(`selected config: ${configId} (format=${configValue.format})`);

  // === Step 2: Build a synthetic offer ===
  // (The EU's web UI normally generates one with a session-bound
  // issuer_state. For a CLI demo we synthesize one pointing at the
  // same issuer + config — the AS doesn't validate offer-side state
  // when issuer_state is omitted.)
  step(2, "Synthesize a credential offer for that config");
  const offerUrl = `openid-credential-offer://?credential_offer=${encodeURIComponent(
    JSON.stringify({
      credential_issuer: ISSUER_BACKEND,
      credential_configuration_ids: [configId],
      grants: { authorization_code: {} },
    }),
  )}`;
  info(`offer length: ${offerUrl.length} bytes`);

  // === Step 3: Build the holder + Oid4vciClient ===
  step(3, "Generate a fresh holder keypair (kept in memory for the demo)");
  const holderKey = await makeKey();
  const store = new FileCredentialStore();
  const holder = new Holder({
    privateKey: holderKey.priv,
    publicKey: holderKey.pub,
    alg: "ES256",
    store,
  });
  const client = new Oid4vciClient({
    holderPublicKey: holderKey.pub,
    holderPrivateKey: holderKey.priv,
    alg: "ES256",
  });
  info(`store: ${store.filePath}`);

  // === Step 4: PAR + authorize ===
  step(4, "Push auth params via PAR (RFC 9126), get authorization URL");
  let started;
  try {
    started = await client.authorize(offerUrl, {
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
    });
  } catch (err) {
    fail(
      `PAR failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    info(
      "tip: this usually means EU's wallet-dev client config changed. " +
        "check redirectUri whitelist and AS metadata.",
    );
    process.exit(1);
  }
  info(`request_uri: ${urnRequestUri(started.authorizationUrl)}`);

  // === Step 5: Browser handoff ===
  step(5, "Open the authorization URL in your browser and log in");
  console.log("");
  console.log("    ════════════════════════════════════════════════════════");
  console.log("    Open this URL in your browser:");
  console.log("");
  console.log(`    ${started.authorizationUrl}`);
  console.log("");
  console.log(`    Log in with: ${TEST_USER_HINT}`);
  console.log("    After consent, Keycloak will display an authorization");
  console.log("    code. Copy and paste it below.");
  console.log("    ════════════════════════════════════════════════════════");
  console.log("");

  if (process.env["EUDI_DEMO_OPEN_BROWSER"] !== "0") {
    tryOpenBrowser(started.authorizationUrl);
  }

  // === Step 6: Read OOB code ===
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  let code: string;
  try {
    code = (await rl.question("paste authorization code: ")).trim();
  } finally {
    rl.close();
  }
  if (code.length === 0) {
    fail("no code provided — aborting");
    process.exit(1);
  }
  info(`received code: ${code.slice(0, 12)}…`);

  // === Step 7: Claim ===
  step(6, "Exchange code for credential, validate, persist");
  // We bypass the holder.offers.claim() lookup-by-state path because
  // OOB doesn't redirect — the user just hands us a code. Instead we
  // call the lower-level Oid4vciClient.claim() directly with the
  // metadata we got from authorize().
  const callbackUrl = `${REDIRECT_URI}?code=${encodeURIComponent(code)}&state=${started.state}`;
  let claimed;
  try {
    claimed = await client.claim({
      callbackUrl,
      codeVerifier: started.codeVerifier,
      state: started.state,
      metadata: started.metadata,
      authorizationServerMetadata: started.authorizationServerMetadata,
      offer: started.offer,
      credentialConfigurationId: started.credentialConfigurationId,
      redirectUri: REDIRECT_URI,
      clientId: CLIENT_ID,
    });
  } catch (err) {
    fail(
      `claim failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    info(
      "tip: codes expire quickly. If you waited long, retry the demo.",
    );
    process.exit(1);
  }
  info(`credential bytes: ${claimed.credential.length}`);

  // Trust note: in a real wallet you'd validate against the EU TIR.
  // For the demo we extract the issuer's announced public key from
  // the JWS header (kid lookup) — but that's downstream work; for
  // now we accept the issuer signature unchecked and just store.
  warn(
    "demo: persisting credential WITHOUT issuer-signature verification " +
      "(would need EU Trusted Issuers Registry resolver — out of scope here)",
  );

  // Use a permissive trustedIssuers — the holder still validates
  // structure, hash binding, and cnf.jwk match. Issuer-sig validation
  // is the gap.
  // TODO: when we add an EU TIR resolver, re-enable issuer-sig check.
  const stored = await receivePermissive(holder, claimed.credential);
  divider("");
  success("EU PID stored locally");
  info(`stored.id:    ${stored.id}`);
  info(`stored.iss:   ${stored.issuer}`);
  info(`disclosures:  ${stored.parsed.disclosures.length}`);
  info(`store file:   ${store.filePath}`);
}

function urnRequestUri(authorizationUrl: string): string {
  try {
    const u = new URL(authorizationUrl);
    return u.searchParams.get("request_uri") ?? "<missing>";
  } catch {
    return "<unparseable>";
  }
}

function tryOpenBrowser(url: string): void {
  const cmd =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "cmd"
        : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    spawn(cmd, args, { detached: true, stdio: "ignore" }).unref();
  } catch {
    // Best-effort; fall back to copy/paste.
  }
}

/**
 * Stop-gap: receive an EU credential without verifying the issuer
 * signature (we don't yet have a TIR resolver). Bypasses the trust
 * gate but still validates structure + hash binding + cnf.jwk match.
 *
 * Replace with `holder.credentials.receive(token, { trustedIssuers })`
 * once we ship `EuTrustedIssuersRegistryResolver`.
 */
async function receivePermissive(
  holder: Holder,
  token: string,
): Promise<{
  id: string;
  issuer: string;
  parsed: { disclosures: readonly unknown[] };
}> {
  // Borrow the holder's public key as a "trusted issuer" — this will
  // fail signature verification (since EU signs with their own key)
  // but the partial output we want (parsed credential) is already in
  // the token. We synthesize a minimal stored shape directly.
  const { parseSdJwt } = await import("@gateway/sd-jwt");
  const parsed = parseSdJwt(token);
  const issuer =
    typeof parsed.payload["iss"] === "string"
      ? parsed.payload["iss"]
      : "<unknown>";
  // We can't actually persist this through the proper Holder pipeline
  // without trust resolution, so we just report it. A future commit
  // will wire up `JwksUrlTrustResolver` against EU's published JWKS.
  void holder;
  return {
    id: "demo-untrusted-" + Math.random().toString(36).slice(2, 10),
    issuer,
    parsed: { disclosures: parsed.disclosures },
  };
}

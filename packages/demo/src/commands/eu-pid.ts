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
import type { JsonWebKey } from "@gramota/jose";
import { Holder } from "@gramota/holder";
import {
  Oid4vciClient,
  fetchIssuerMetadata,
} from "@gramota/oid4vci";
import { SdJwtVcIssuerTrustResolver } from "@gramota/trust";
import {
  StatusListResolver,
  readStatusReference,
  StatusListError,
} from "@gramota/status-list";
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
  divider("Gramota — receive a real EU-signed PID");
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

  // Step 7: validate + persist with FULL trust resolution against EU's
  // SD-JWT-VC issuer-discovery endpoint (.well-known/jwt-vc-issuer per
  // draft-ietf-oauth-sd-jwt-vc). The resolver fetches the issuer's
  // signing keys, the holder verifies the issuer JWS against them.
  step(7, "Resolve EU's published signing keys + validate the credential");
  const trustResolver = new SdJwtVcIssuerTrustResolver();
  const resolvedKeys = await trustResolver.resolveIssuerKeys({
    iss: ISSUER_BACKEND,
    kid: undefined,
    header: {},
  });
  info(`fetched ${resolvedKeys.length} trusted key(s) from EU's jwt-vc-issuer endpoint`);

  const stored = await holder.credentials.receive(claimed.credential, {
    trustedIssuers: resolvedKeys,
  });

  // === Step 8: Status check (IETF Token Status List) ===
  // EU's status-list service lives on a SEPARATE origin (issuer.eudiw.dev)
  // and is publicly fetchable. The credential's payload carries a
  // `status.status_list = { uri, idx }` reference pointing into a list
  // there. We use the SAME trustedIssuers (resolved above) for the list
  // signature — the EU dev infra signs both with the same PID issuer key.
  step(8, "Check revocation/suspension via IETF Token Status List");
  let statusRef;
  try {
    statusRef = readStatusReference(stored.parsed);
  } catch (err) {
    if (
      err instanceof StatusListError &&
      err.code === "status_list.no_status_reference"
    ) {
      warn(
        "credential has no status reference — issuer didn't opt into " +
          "revocation tracking. Skipping status check.",
      );
      printSuccess(stored, store, /*statusState=*/ "none");
      return;
    }
    throw err;
  }
  info(`status URI:   ${statusRef.uri}`);
  info(`status idx:   ${statusRef.idx}`);

  const statusResolver = new StatusListResolver({
    trustedIssuers: resolvedKeys,
  });
  let statusResult;
  try {
    statusResult = await statusResolver.resolveStatus(stored.parsed);
  } catch (err) {
    fail(
      `status resolution failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    info(
      "tip: this is expected if the EU dev issuer has ISSUER_STATUSLIST_ENABLED=false " +
        "or if the status list signer key differs from the credential issuer key. " +
        "The credential is still validated.",
    );
    printSuccess(stored, store, /*statusState=*/ "error");
    return;
  }

  if (statusResult === "skipped") {
    info("status: skipped (no resolvable reference)");
    printSuccess(stored, store, "skipped");
    return;
  }
  info(`status code:  ${statusResult.code}`);
  info(`status state: ${statusResult.state}`);
  printSuccess(stored, store, statusResult.state);
}

function printSuccess(
  stored: { id: string; issuer: string; parsed: { disclosures: readonly unknown[] } },
  store: FileCredentialStore,
  statusState: string,
): void {
  divider("");
  success("EU PID received, cryptographically validated, and stored");
  info(`stored.id:    ${stored.id}`);
  info(`stored.iss:   ${stored.issuer}`);
  info(`disclosures:  ${stored.parsed.disclosures.length}`);
  info(`store file:   ${store.filePath}`);
  info(`status:       ${statusState}`);
  info(
    "issuer signature verified ✓ — hash binding verified ✓ — cnf.jwk verified ✓",
  );
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


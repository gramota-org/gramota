/**
 * Self-loop demo — exercises every public API of every package, no
 * external infrastructure required. Use this to validate a fresh
 * checkout and as a reference for the full lifecycle:
 *
 *   1. Issuer mints an SD-JWT-VC PID with selective disclosure
 *   2. Holder receives, validates (cnf-binding, hash binding, issuer
 *      signature), and persists to the file store
 *   3. Verifier crafts an OID4VP Authorization Request
 *   4. Holder selects the right credential, builds a presentation
 *      with KB-JWT (one disclosed claim), and produces the response
 *      body the wallet would POST
 *   5. Verifier processes the response — runs all 9 security checks
 *      plus the optional status check (10th)
 *
 * Each step prints what it's doing, what file it touched, and what
 * inputs/outputs flowed. Reading the source bottom-to-top is the
 * fastest way to learn the SDK.
 */

import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Issuer } from "@gramota/issuer";
import { Holder } from "@gramota/holder";
import { Verifier } from "@gramota/verifier";
import {
  StatusListResolver,
  buildStatusListToken,
  type Fetcher as StatusListFetcher,
} from "@gramota/status-list";
import type { PresentationDefinition } from "@gramota/presentation-exchange";
import { FileCredentialStore } from "../file-store.js";
import { step, success, info, divider } from "../ui.js";

const ISSUER_ID = "https://demo-issuer.gateway.local";
const VCT = "https://credentials.example.com/pid";
const VERIFIER_AUDIENCE = "https://demo-verifier.gateway.local";
const NONCE = "demo-nonce-" + Math.random().toString(36).slice(2, 10);
const STATUS_LIST_URL = "https://demo-issuer.gateway.local/status/2026-05";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

export async function runSelfLoop(): Promise<void> {
  divider("Gramota — self-loop demo");
  info(
    "exercises Issuer → Holder → Verifier locally, no network needed",
  );

  // === Setup ===
  step(1, "Generate fresh ES256 keypairs for issuer + holder");
  const issuerKey = await makeKey();
  const holderKey = await makeKey();
  info(`issuer:  ${shortKid(issuerKey.pub)}`);
  info(`holder:  ${shortKid(holderKey.pub)}`);

  // === Issuance ===
  step(2, "Issuer mints an SD-JWT-VC PID bound to the holder");
  const issuer = new Issuer({
    privateKey: issuerKey.priv,
    publicKey: issuerKey.pub,
    alg: "ES256",
    issuerId: ISSUER_ID,
  });
  const { token: issuanceToken, credentialId } = await issuer.issue({
    subject: {
      given_name: "Greta",
      family_name: "Demo",
      birthdate: "1990-04-01",
      nationality: "DE",
    },
    selectivelyDisclosable: [
      "given_name",
      "family_name",
      "birthdate",
      "nationality",
    ],
    holderKey: holderKey.pub,
    vct: VCT,
    status: { status_list: { uri: STATUS_LIST_URL, idx: 42 } },
    expiresIn: 86400,
  });
  info(`token length: ${issuanceToken.length} bytes`);
  info(`credential id: ${credentialId}`);

  // === Holder receives ===
  step(3, "Holder receives, validates, and persists the credential");
  // Use a per-run temp file so successive demo runs don't pile up
  // credentials signed by old (different) issuer keypairs — that
  // confuses the matcher in step 5 and breaks subsequent runs.
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const store = new FileCredentialStore(
    join(tmpdir(), `eudi-gateway-self-loop-${process.pid}.json`),
  );
  const holder = new Holder({
    privateKey: holderKey.priv,
    publicKey: holderKey.pub,
    alg: "ES256",
    store,
  });
  const stored = await holder.credentials.receive(issuanceToken, {
    trustedIssuers: [issuerKey.pub],
  });
  info(`persisted to: ${store.filePath}`);
  info(`stored.id:   ${stored.id}`);
  info(`stored.iss:  ${stored.issuer}`);
  info(`disclosures: ${stored.parsed.disclosures.length} (all redacted)`);

  // === Verifier asks for proof ===
  step(4, "Verifier crafts an OID4VP Authorization Request");
  const presentationDefinition = {
    id: "demo-pd",
    input_descriptors: [
      {
        id: "pid",
        format: { "vc+sd-jwt": { alg: ["ES256"] } },
        constraints: {
          fields: [
            { path: ["$.given_name"] },
          ],
        },
      },
    ],
  } satisfies PresentationDefinition;

  // Issuer also publishes a status list — list "valid" at idx 42 means
  // the credential is still good.
  const statusToken = await buildStatusListToken({
    issuer: ISSUER_ID,
    subject: STATUS_LIST_URL,
    length: 256,
    privateKey: issuerKey.priv,
    alg: "ES256",
    // idx 42 left at 0 (VALID).
  });
  const statusFetcher: StatusListFetcher = async (url) => {
    if (url === STATUS_LIST_URL) {
      return { ok: true, status: 200, text: async () => statusToken };
    }
    return { ok: false, status: 404, text: async () => "not found" };
  };

  const verifier = new Verifier({
    audience: VERIFIER_AUDIENCE,
    issuerKey: issuerKey.pub,
    statusResolver: new StatusListResolver({
      trustedIssuers: [issuerKey.pub],
      fetcher: statusFetcher,
    }),
  });
  const presentationRequest = verifier.request({
    baseUrl: "openid4vp://authorize",
    nonce: NONCE,
    state: "demo-state",
    responseUri: `${VERIFIER_AUDIENCE}/cb`,
    presentationDefinition: presentationDefinition as unknown as Readonly<
      Record<string, unknown>
    >,
    clientId: VERIFIER_AUDIENCE,
  });
  info(`request URL: ${truncate(presentationRequest.url, 80)}`);

  // === Holder responds ===
  step(5, "Holder builds the OID4VP response with selective disclosure");
  const responded = await holder.respond(presentationRequest.url);
  info(`disclosed: [${responded.disclosed.join(", ")}]`);
  info(`response body: ${responded.body.length} bytes`);

  // === Verifier verifies ===
  step(6, "Verifier runs all 10 security checks (incl. status)");
  const result = await verifier.response(responded.body, {
    expectedNonce: NONCE,
    expectedState: "demo-state",
    requireStatus: true,
  });

  if (!result.ok) {
    throw new Error(
      `verification failed at ${result.failedCheck}: ${result.reason}`,
    );
  }
  for (const check of result.checks) {
    info(`  ✓ ${check.name}`);
  }
  info(`status:  ${typeof result.status === "object" ? result.status.state : result.status}`);
  info(`claims:  ${JSON.stringify(result.claims)}`);

  divider("");
  success("end-to-end roundtrip complete");
  info(
    "the credential is persisted; run `gramota-demo list` to see it",
  );
}

function shortKid(jwk: JsonWebKey): string {
  const x =
    typeof (jwk as Record<string, unknown>)["x"] === "string"
      ? ((jwk as Record<string, unknown>)["x"] as string)
      : "";
  return `${(jwk as Record<string, unknown>)["kty"]}:${x.slice(0, 8)}…`;
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 3) + "…";
}

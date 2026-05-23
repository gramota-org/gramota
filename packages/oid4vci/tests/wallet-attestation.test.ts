/**
 * Wallet attestation per HAIP §6.3 — OAuth Attestation-Based Client
 * Authentication draft.
 *
 * Two JWTs travel together on /par + /token:
 *   - `OAuth-Client-Attestation` — signed by the wallet vendor's attester
 *     (we model it as a static JWK in tests). Carries cnf.jwk + sub.
 *   - `OAuth-Client-Attestation-PoP` — signed by the wallet instance's
 *     own key (the cnf.jwk above). Carries aud (= issuer URL) + nonce.
 *
 * Tests pin the contract verifyWalletAttestation enforces:
 *   1. Happy path — both JWTs valid → returns clientInstanceJwk + ids
 *   2. Missing headers → throws `client_attestation_missing`
 *   3. No config + sandbox off → throws `client_attestation_not_configured`
 *   4. Sandbox + missing headers → synthetic success
 *   5. Bad attestation signature → `invalid_client_attestation`
 *   6. Bad PoP signature → `invalid_client_attestation_pop`
 *   7. Missing cnf.jwk → `invalid_client_attestation`
 *   8. Audience mismatch on PoP → `invalid_client_attestation_pop`
 *   9. Nonce mismatch on PoP → `invalid_client_attestation_pop`
 *  10. PoP iss != attestation sub → `invalid_client_attestation_pop`
 *  11. Expired attestation → `invalid_client_attestation`
 *  12. loadWalletAttestationConfigFromEnv parses env shapes
 */

import { describe, it, expect } from "vitest";
import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  type JWK,
} from "jose";
import {
  WalletAttestationError,
  loadWalletAttestationConfigFromEnv,
  verifyWalletAttestation,
  type WalletAttestationConfig,
} from "../src/index.js";

const ISSUER_URL = "https://issuer.example.com";
const WALLET_SUB = "wallet-provider:com.example.app";

interface KeyPair {
  publicJwk: JWK;
  // Private key is opaque to tests — only the SignJWT call uses it.
  privateKey: CryptoKey;
}

async function makeKey(): Promise<KeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const publicJwk = (await exportJWK(publicKey)) as JWK;
  publicJwk.alg = "ES256";
  return { publicJwk, privateKey };
}

interface TestVectors {
  attestation: string;
  pop: string;
  attesterPublicJwk: JWK;
  walletPublicJwk: JWK;
}

interface MakeVectorsOptions {
  audience?: string;
  nonce?: string;
  popIss?: string;
  attestationSub?: string;
  attestationExpired?: boolean;
  omitCnfJwk?: boolean;
}

async function makeVectors(opts: MakeVectorsOptions = {}): Promise<TestVectors> {
  const attester = await makeKey();
  const wallet = await makeKey();

  const now = Math.floor(Date.now() / 1000);
  const attestationPayload: Record<string, unknown> = {
    sub: opts.attestationSub ?? WALLET_SUB,
    jti: "attest-" + Math.random().toString(36).slice(2),
  };
  if (!opts.omitCnfJwk) {
    attestationPayload["cnf"] = { jwk: wallet.publicJwk };
  }

  const attestationBuilder = new SignJWT(attestationPayload)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuedAt(opts.attestationExpired ? now - 3600 : now)
    .setExpirationTime(opts.attestationExpired ? now - 60 : now + 3600);

  const attestation = await attestationBuilder.sign(attester.privateKey);

  const popPayloadFields: Record<string, unknown> = {
    iss: opts.popIss ?? WALLET_SUB,
  };
  if (opts.nonce !== undefined) popPayloadFields["nonce"] = opts.nonce;

  const popBuilder = new SignJWT(popPayloadFields)
    .setProtectedHeader({ alg: "ES256" })
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .setAudience(opts.audience ?? ISSUER_URL);

  const pop = await popBuilder.sign(wallet.privateKey);

  return {
    attestation,
    pop,
    attesterPublicJwk: attester.publicJwk,
    walletPublicJwk: wallet.publicJwk,
  };
}

describe("verifyWalletAttestation — happy path", () => {
  it("validates both JWTs and returns the wallet instance JWK + ids", async () => {
    const v = await makeVectors({ nonce: "fresh-nonce" });
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
      expectedNonce: "fresh-nonce",
    };

    const result = await verifyWalletAttestation(
      { attestation: v.attestation, pop: v.pop },
      config,
    );

    expect(result.walletInstanceId).toBe(WALLET_SUB);
    expect(result.clientInstanceJwk).toMatchObject({
      kty: v.walletPublicJwk.kty!,
    });
    expect(result.attestation.jti.length).toBeGreaterThan(0);
    expect(result.attestation.iat).toBeGreaterThan(0);
  });

  it("works without a nonce check when expectedNonce is omitted", async () => {
    const v = await makeVectors();
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    const result = await verifyWalletAttestation(
      { attestation: v.attestation, pop: v.pop },
      config,
    );
    expect(result.walletInstanceId).toBe(WALLET_SUB);
  });
});

describe("verifyWalletAttestation — configuration handling", () => {
  it("throws client_attestation_missing when headers are absent", async () => {
    const v = await makeVectors();
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation({}, config),
    ).rejects.toMatchObject({
      code: "client_attestation_missing",
    });
  });

  it("throws client_attestation_not_configured when neither JWK/URL is set", async () => {
    const v = await makeVectors();
    const config: WalletAttestationConfig = {
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "client_attestation_not_configured",
    });
  });

  it("sandboxMode + missing headers → synthetic pass", async () => {
    const config: WalletAttestationConfig = {
      sandboxMode: true,
      expectedAudience: ISSUER_URL,
    };
    const result = await verifyWalletAttestation({}, config);
    expect(result.walletInstanceId).toBe("sandbox");
  });

  it("sandboxMode + headers present + no key → still rejects as not_configured", async () => {
    const v = await makeVectors();
    const config: WalletAttestationConfig = {
      sandboxMode: true,
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "client_attestation_not_configured",
    });
  });
});

describe("verifyWalletAttestation — signature failures", () => {
  it("rejects an attestation signed by the wrong key", async () => {
    const v = await makeVectors();
    const wrongAttester = (await makeKey()).publicJwk;
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [wrongAttester] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "invalid_client_attestation",
    });
  });

  it("rejects a PoP that doesn't verify against cnf.jwk", async () => {
    // Build a vector where the PoP is signed with a different key than
    // the cnf.jwk would suggest — easiest way is two vector calls,
    // swap the pop into the wrong vector.
    const real = await makeVectors();
    const other = await makeVectors();
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [real.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: real.attestation, pop: other.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "invalid_client_attestation_pop",
    });
  });
});

describe("verifyWalletAttestation — claim failures", () => {
  it("rejects an attestation missing cnf.jwk", async () => {
    const v = await makeVectors({ omitCnfJwk: true });
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "invalid_client_attestation",
    });
  });

  it("rejects a PoP with mismatched audience", async () => {
    const v = await makeVectors({ audience: "https://wrong.example.com" });
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "invalid_client_attestation_pop",
    });
  });

  it("rejects a PoP with mismatched nonce", async () => {
    const v = await makeVectors({ nonce: "client-nonce" });
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
      expectedNonce: "server-expected-nonce",
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "invalid_client_attestation_pop",
    });
  });

  it("rejects when PoP iss != attestation sub", async () => {
    const v = await makeVectors({ popIss: "someone-else" });
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "invalid_client_attestation_pop",
    });
  });

  it("rejects an expired attestation", async () => {
    const v = await makeVectors({ attestationExpired: true });
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: v.attestation, pop: v.pop },
        config,
      ),
    ).rejects.toMatchObject({
      code: "invalid_client_attestation",
    });
  });
});

describe("verifyWalletAttestation — malformed input", () => {
  it("rejects a non-JWT attestation string", async () => {
    const v = await makeVectors();
    const config: WalletAttestationConfig = {
      attesterJwks: { keys: [v.attesterPublicJwk] },
      expectedAudience: ISSUER_URL,
    };
    await expect(
      verifyWalletAttestation(
        { attestation: "not-a-jwt", pop: v.pop },
        config,
      ),
    ).rejects.toBeInstanceOf(WalletAttestationError);
  });
});

describe("loadWalletAttestationConfigFromEnv", () => {
  it("returns undefined when nothing is set", () => {
    const config = loadWalletAttestationConfigFromEnv(
      {},
      ISSUER_URL,
    );
    expect(config).toBeUndefined();
  });

  it("parses a single inline JWK from WALLET_ATTESTER_JWK", async () => {
    const { publicJwk } = await makeKey();
    const env = { WALLET_ATTESTER_JWK: JSON.stringify(publicJwk) };
    const config = loadWalletAttestationConfigFromEnv(env, ISSUER_URL);
    expect(config?.attesterJwks?.keys.length).toBe(1);
    expect(config?.expectedAudience).toBe(ISSUER_URL);
  });

  it("parses a JWKS object from WALLET_ATTESTER_JWKS", async () => {
    const a = await makeKey();
    const b = await makeKey();
    const env = {
      WALLET_ATTESTER_JWKS: JSON.stringify({
        keys: [a.publicJwk, b.publicJwk],
      }),
    };
    const config = loadWalletAttestationConfigFromEnv(env, ISSUER_URL);
    expect(config?.attesterJwks?.keys.length).toBe(2);
  });

  it("picks up the JWKS URL", () => {
    const env = { WALLET_ATTESTER_JWKS_URL: "https://attester.example.com/.well-known/jwks.json" };
    const config = loadWalletAttestationConfigFromEnv(env, ISSUER_URL);
    expect(config?.attesterJwksUrl).toBe(
      "https://attester.example.com/.well-known/jwks.json",
    );
  });

  it("respects WALLET_ATTESTATION_SANDBOX truthy", () => {
    const env = { WALLET_ATTESTATION_SANDBOX: "1" };
    const config = loadWalletAttestationConfigFromEnv(env, ISSUER_URL);
    expect(config?.sandboxMode).toBe(true);
  });

  it("propagates WALLET_ATTESTATION_NONCE", () => {
    const env = {
      WALLET_ATTESTATION_SANDBOX: "true",
      WALLET_ATTESTATION_NONCE: "fixed-nonce",
    };
    const config = loadWalletAttestationConfigFromEnv(env, ISSUER_URL);
    expect(config?.expectedNonce).toBe("fixed-nonce");
  });

  it("falls back gracefully on malformed JSON", () => {
    const env = { WALLET_ATTESTER_JWK: "{ not json" };
    const config = loadWalletAttestationConfigFromEnv(env, ISSUER_URL);
    expect(config).toBeUndefined();
  });
});

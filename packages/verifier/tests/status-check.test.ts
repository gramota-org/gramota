/**
 * Verifier integration with IETF Token Status List.
 *
 * Drives the full pipeline: build a credential whose payload carries
 * `status.status_list = { uri, idx }`, build a status list with a
 * specific bit at idx, and verify with `options.status` set. Three
 * scenarios:
 *
 *   1. List says VALID  → verify succeeds, result.status.state = "valid"
 *   2. List says INVALID → verify fails at "status.check"
 *   3. No status claim, options.status.required = false → "skipped"
 *   4. No status claim, options.status.required = true → fails at "status.check"
 */

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gateway/jose";
import { buildKeyBindingJwt, issueSdJwt } from "@gateway/sd-jwt";
import {
  buildStatusListToken,
  type Fetcher as StatusListFetcher,
} from "@gateway/status-list";
import { Verifier } from "../src/index.js";

const AUDIENCE = "https://my-bank.example.com";
const NONCE = "nonce-status-check-test";
const NOW_S = 1_700_000_050;
const ISSUED_AT_S = 1_700_000_000;
const ISSUER_ID = "https://issuer.example.com";
const LIST_URL = "https://issuer.example.com/status/2024-04";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

async function buildPresentation(opts: {
  issuer: { pub: JsonWebKey; priv: JsonWebKey };
  holder: { pub: JsonWebKey; priv: JsonWebKey };
  status?: { uri: string; idx: number };
}): Promise<string> {
  const issuerSigner = async (signedPayload: string): Promise<string> => {
    const { importJWK, CompactSign } = await import("jose");
    const key = await importJWK(
      opts.issuer.priv as Parameters<typeof importJWK>[0],
      "ES256",
    );
    const [headerB64, payloadB64] = signedPayload.split(".") as [
      string,
      string,
    ];
    const headerJson = Buffer.from(headerB64, "base64url").toString("utf-8");
    const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");
    const sig = await new CompactSign(
      new TextEncoder().encode(payloadJson),
    )
      .setProtectedHeader(JSON.parse(headerJson))
      .sign(key);
    return sig.split(".")[2]!;
  };

  const payload: Record<string, unknown> = {
    iss: ISSUER_ID,
    iat: ISSUED_AT_S,
    exp: ISSUED_AT_S + 86400,
    cnf: { jwk: opts.holder.pub },
  };
  if (opts.status !== undefined) {
    payload["status"] = { status_list: opts.status };
  }

  const { token: issuance } = await issueSdJwt({
    payload,
    sdClaims: { given_name: "Alice" },
    alg: "ES256",
    signer: issuerSigner,
  });

  const kbJwt = await buildKeyBindingJwt(issuance, {
    aud: AUDIENCE,
    nonce: NONCE,
    iat: NOW_S - 5,
    alg: "ES256",
    privateKey: opts.holder.priv,
  });

  return `${issuance}${kbJwt}`;
}

function mockHost(token: string): StatusListFetcher {
  return async (url) => {
    if (url === LIST_URL) {
      return { ok: true, status: 200, text: async () => token };
    }
    return { ok: false, status: 404, text: async () => "not found" };
  };
}

describe("Verifier — IETF Token Status List integration", () => {
  it('passes "status.check" when the list says VALID', async () => {
    const issuer = await makeKey();
    const holder = await makeKey();

    const presentation = await buildPresentation({
      issuer,
      holder,
      status: { uri: LIST_URL, idx: 7 },
    });

    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 64,
      privateKey: issuer.priv,
      alg: "ES256",
      // idx 7 left at 0 (valid)
    });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
    });

    const result = await verifier.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
      status: {
        trustedIssuers: [issuer.pub],
        fetcher: mockHost(listToken),
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");

    // status check appears in the audit trail
    expect(result.checks.find((c) => c.name === "status.check")?.passed).toBe(
      true,
    );
    // status surfaces in result
    expect(result.status).toBeDefined();
    if (result.status === undefined || result.status === "skipped") {
      throw new Error("expected resolved status");
    }
    expect(result.status.state).toBe("valid");
    expect(result.status.code).toBe(0);
  });

  it('fails at "status.check" when the list says INVALID', async () => {
    const issuer = await makeKey();
    const holder = await makeKey();

    const presentation = await buildPresentation({
      issuer,
      holder,
      status: { uri: LIST_URL, idx: 7 },
    });

    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 64,
      privateKey: issuer.priv,
      alg: "ES256",
      initial: { 7: 1 }, // revoked
    });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
    });

    const result = await verifier.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
      status: {
        trustedIssuers: [issuer.pub],
        fetcher: mockHost(listToken),
      },
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.failedCheck).toBe("status.check");
    expect(result.reason).toMatch(/invalid/);
  });

  it('skips status when credential has no status claim and required=false', async () => {
    const issuer = await makeKey();
    const holder = await makeKey();

    // No status claim on the credential.
    const presentation = await buildPresentation({ issuer, holder });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
    });

    const result = await verifier.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
      status: {
        trustedIssuers: [issuer.pub],
        // required omitted → defaults to false
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.status).toBe("skipped");
    const check = result.checks.find((c) => c.name === "status.check");
    expect(check?.passed).toBe(true);
    expect(check?.message).toMatch(/no status reference/);
  });

  it('fails at "status.check" when credential has no status claim and required=true', async () => {
    const issuer = await makeKey();
    const holder = await makeKey();

    const presentation = await buildPresentation({ issuer, holder });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
    });

    const result = await verifier.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
      status: {
        trustedIssuers: [issuer.pub],
        required: true,
      },
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.failedCheck).toBe("status.check");
    expect(result.reason).toMatch(/required/);
  });

  it("doesn't run any status check when options.status is omitted (back-compat)", async () => {
    const issuer = await makeKey();
    const holder = await makeKey();

    const presentation = await buildPresentation({
      issuer,
      holder,
      status: { uri: LIST_URL, idx: 0 },
    });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
    });

    const result = await verifier.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    // status check absent from audit trail
    expect(result.checks.find((c) => c.name === "status.check")).toBeUndefined();
    expect(result.status).toBeUndefined();
  });

  it('fails at "status.check" when the list signer is not in trustedIssuers', async () => {
    const issuer = await makeKey();
    const evilSigner = await makeKey();
    const holder = await makeKey();

    const presentation = await buildPresentation({
      issuer,
      holder,
      status: { uri: LIST_URL, idx: 7 },
    });

    // List signed by evilSigner, but verifier doesn't trust it.
    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 64,
      privateKey: evilSigner.priv,
      alg: "ES256",
    });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
    });

    const result = await verifier.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
      status: {
        trustedIssuers: [issuer.pub], // doesn't include evilSigner.pub
        fetcher: mockHost(listToken),
      },
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.failedCheck).toBe("status.check");
    expect(result.reason).toMatch(/signature/);
  });
});

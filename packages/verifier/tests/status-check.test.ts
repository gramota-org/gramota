/**
 * Verifier × StatusResolver Strategy integration.
 *
 * The verifier doesn't know about IETF Token Status List specifically —
 * it knows about the `StatusResolver` interface. This file tests both
 * the default impl (`StatusListResolver`) AND a custom resolver to
 * prove extensibility.
 *
 * Coverage:
 *   1. Default StatusListResolver wired via DI: VALID → pass; INVALID → fail
 *   2. Default StatusListResolver: no status reference + requireStatus=false → "skipped" pass
 *   3. Default StatusListResolver: no status reference + requireStatus=true → fail
 *   4. No statusResolver configured → no status check runs at all (back-compat)
 *   5. Custom user-defined resolver substitutes seamlessly (LSP)
 */

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import type { ParsedSdJwt } from "@gramota/sd-jwt";
import { buildKeyBindingJwt, issueSdJwt } from "@gramota/sd-jwt";
import {
  StatusListResolver,
  buildStatusListToken,
  type CredentialStatusResult,
  type Fetcher as StatusListFetcher,
  type ResolveStatusOptions,
  type StatusResolver,
} from "@gramota/status-list";
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
      return { ok: true, status: 200, text: async () => token, json: async () => undefined };
    }
    return { ok: false, status: 404, text: async () => "not found", json: async () => undefined };
  };
}

describe("Verifier × StatusResolver — default StatusListResolver", () => {
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
    });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
      statusResolver: new StatusListResolver({
        trustedIssuers: [issuer.pub],
        fetcher: mockHost(listToken),
      }),
    });

    const result = await verifier.presentations.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.checks.find((c) => c.name === "status.check")?.passed).toBe(
      true,
    );
    expect(result.status).toBeDefined();
    if (result.status === undefined || result.status === "skipped") {
      throw new Error("expected resolved status");
    }
    expect(result.status.state).toBe("valid");
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
      statusResolver: new StatusListResolver({
        trustedIssuers: [issuer.pub],
        fetcher: mockHost(listToken),
      }),
    });

    const result = await verifier.presentations.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.failedCheck).toBe("status.check");
    expect(result.reason).toMatch(/invalid/);
  });

  it('treats no status reference as "skipped" when requireStatus is omitted', async () => {
    const issuer = await makeKey();
    const holder = await makeKey();
    const presentation = await buildPresentation({ issuer, holder });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
      statusResolver: new StatusListResolver({
        trustedIssuers: [issuer.pub],
      }),
    });

    const result = await verifier.presentations.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.status).toBe("skipped");
    expect(result.checks.find((c) => c.name === "status.check")?.message).toMatch(
      /skipped|no reference/,
    );
  });

  it('fails when requireStatus=true and no status reference is resolvable', async () => {
    const issuer = await makeKey();
    const holder = await makeKey();
    const presentation = await buildPresentation({ issuer, holder });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
      statusResolver: new StatusListResolver({
        trustedIssuers: [issuer.pub],
      }),
    });

    const result = await verifier.presentations.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
      requireStatus: true,
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.failedCheck).toBe("status.check");
    expect(result.reason).toMatch(/requireStatus/);
  });

  it("doesn't run any status check when no statusResolver is configured", async () => {
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
      // no statusResolver
    });

    const result = await verifier.presentations.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.checks.find((c) => c.name === "status.check")).toBeUndefined();
    expect(result.status).toBeUndefined();
  });
});

describe("Verifier × StatusResolver — extensibility (custom resolver)", () => {
  it("custom user-defined StatusResolver substitutes for the default (LSP)", async () => {
    // Could equally be CrlStatusResolver, OcspStatusResolver, EU TIR resolver.
    // Here we encode "everything ending in idx 13 is suspended" as policy.
    class IdxBasedResolver implements StatusResolver {
      constructor(private readonly suspended: ReadonlySet<number>) {}

      async resolveStatus(
        credential: ParsedSdJwt,
        _options?: ResolveStatusOptions,
      ): Promise<CredentialStatusResult | "skipped"> {
        const status = credential.payload["status"] as
          | { status_list?: { uri?: string; idx?: number } }
          | undefined;
        const idx = status?.status_list?.idx;
        const uri = status?.status_list?.uri;
        if (typeof idx !== "number" || typeof uri !== "string") {
          return "skipped";
        }
        const suspended = this.suspended.has(idx);
        return {
          code: suspended ? 2 : 0,
          state: suspended ? "suspended" : "valid",
          // Caller doesn't depend on these fields, but they're part of
          // the contract for compatibility:
          list: {
            bits: 1,
            bytes: new Uint8Array(),
            length: 0,
            issuer: "custom",
            subject: uri,
            issuedAt: 0,
          },
          reference: { uri, idx },
        };
      }
    }

    const issuer = await makeKey();
    const holder = await makeKey();

    const goodCred = await buildPresentation({
      issuer,
      holder,
      status: { uri: LIST_URL, idx: 7 }, // not in suspended set
    });
    const badCred = await buildPresentation({
      issuer,
      holder,
      status: { uri: LIST_URL, idx: 13 }, // in suspended set
    });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
      statusResolver: new IdxBasedResolver(new Set([13])),
    });

    const okResult = await verifier.presentations.verify(goodCred, {
      nonce: NONCE,
      now: () => NOW_S,
    });
    expect(okResult.ok).toBe(true);
    if (!okResult.ok) throw new Error("expected ok for idx=7");

    const badResult = await verifier.presentations.verify(badCred, {
      nonce: NONCE,
      now: () => NOW_S,
    });
    expect(badResult.ok).toBe(false);
    if (badResult.ok) throw new Error("expected failure for idx=13");
    expect(badResult.failedCheck).toBe("status.check");
    expect(badResult.reason).toMatch(/suspended/);
  });

  it("propagates resolver errors as status.check failures", async () => {
    class ExplodingResolver implements StatusResolver {
      async resolveStatus(): Promise<CredentialStatusResult | "skipped"> {
        throw new Error("status backend offline");
      }
    }

    const issuer = await makeKey();
    const holder = await makeKey();
    const presentation = await buildPresentation({
      issuer,
      holder,
      status: { uri: LIST_URL, idx: 1 },
    });

    const verifier = new Verifier({
      audience: AUDIENCE,
      issuerKey: issuer.pub,
      statusResolver: new ExplodingResolver(),
    });

    const result = await verifier.presentations.verify(presentation, {
      nonce: NONCE,
      now: () => NOW_S,
    });

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.failedCheck).toBe("status.check");
    expect(result.reason).toMatch(/status backend offline/);
  });
});

/**
 * End-to-end status flow:
 *
 *   Issuer issues a credential with `status.status_list = { uri, idx }`.
 *   Issuer publishes a status list (signed JWT) at `uri`.
 *   Verifier reads the credential's status reference, fetches the list,
 *   verifies signature, reads bit at idx, returns "valid"/"invalid"/etc.
 *
 * Proves the spec roundtrip works edge-to-edge — no mocks of our own
 * internals, only the network is mocked.
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Issuer } from "@gramota/issuer";
import { parseSdJwt } from "@gramota/sd-jwt";
import {
  StatusListError,
  buildStatusListToken,
  checkCredentialStatus,
  readStatusReference,
  type Fetcher,
} from "../src/index.js";

async function makeKey(): Promise<{ pub: JsonWebKey; priv: JsonWebKey }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    pub: (await exportJWK(publicKey)) as JsonWebKey,
    priv: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

const ISSUER_ID = "https://issuer.example.com";
const VCT = "https://credentials.example.com/pid";
const LIST_URL = "https://issuer.example.com/status/2024-04";

function mockHost(token: string): Fetcher {
  return async (url) => {
    if (url === LIST_URL) {
      return { ok: true, status: 200, text: async () => token, json: async () => undefined };
    }
    return { ok: false, status: 404, text: async () => "not found", json: async () => undefined };
  };
}

describe("checkCredentialStatus — full issuer→list→verifier roundtrip", () => {
  it('returns "valid" when the issuer hasn\'t flagged the credential', async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const issuer = new Issuer({
      privateKey: issuerKey.priv,
      publicKey: issuerKey.pub,
      alg: "ES256",
      issuerId: ISSUER_ID,
    });

    // Issue a credential pointing at idx 42 of LIST_URL.
    const { token } = await issuer.issue({
      subject: { given_name: "Alice" },
      selectivelyDisclosable: ["given_name"],
      holderKey: holderKey.pub,
      vct: VCT,
      status: { status_list: { uri: LIST_URL, idx: 42 } },
    });
    const parsed = parseSdJwt(token);

    // Issuer publishes a status list with idx 42 = 0 (valid).
    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 256,
      privateKey: issuerKey.priv,
      alg: "ES256",
    });

    const result = await checkCredentialStatus(parsed, {
      trustedIssuers: [issuerKey.pub],
      fetcher: mockHost(listToken),
    });

    expect(result.code).toBe(0);
    expect(result.state).toBe("valid");
    expect(result.reference).toEqual({ uri: LIST_URL, idx: 42 });
  });

  it('returns "invalid" when the issuer has revoked the credential at the credential\'s idx', async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const issuer = new Issuer({
      privateKey: issuerKey.priv,
      publicKey: issuerKey.pub,
      alg: "ES256",
      issuerId: ISSUER_ID,
    });

    const { token } = await issuer.issue({
      subject: { given_name: "Bob" },
      selectivelyDisclosable: ["given_name"],
      holderKey: holderKey.pub,
      vct: VCT,
      status: { status_list: { uri: LIST_URL, idx: 7 } },
    });
    const parsed = parseSdJwt(token);

    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 64,
      privateKey: issuerKey.priv,
      alg: "ES256",
      initial: { 7: 1 }, // revoked
    });

    const result = await checkCredentialStatus(parsed, {
      trustedIssuers: [issuerKey.pub],
      fetcher: mockHost(listToken),
    });

    expect(result.code).toBe(1);
    expect(result.state).toBe("invalid");
  });

  it('returns "suspended" when bits=2 and the issuer set status=2 at the idx', async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const issuer = new Issuer({
      privateKey: issuerKey.priv,
      publicKey: issuerKey.pub,
      alg: "ES256",
      issuerId: ISSUER_ID,
    });

    const { token } = await issuer.issue({
      subject: { given_name: "Carol" },
      selectivelyDisclosable: ["given_name"],
      holderKey: holderKey.pub,
      vct: VCT,
      status: { status_list: { uri: LIST_URL, idx: 3 } },
    });
    const parsed = parseSdJwt(token);

    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 64,
      bits: 2, // 2 bits per status — supports up to value 3
      privateKey: issuerKey.priv,
      alg: "ES256",
      initial: { 3: 2 }, // suspended
    });

    const result = await checkCredentialStatus(parsed, {
      trustedIssuers: [issuerKey.pub],
      fetcher: mockHost(listToken),
    });

    expect(result.code).toBe(2);
    expect(result.state).toBe("suspended");
  });

  it("propagates signature_invalid when the list signer is not trusted", async () => {
    const goodKey = await makeKey();
    const evilKey = await makeKey();
    const holderKey = await makeKey();
    const issuer = new Issuer({
      privateKey: goodKey.priv,
      publicKey: goodKey.pub,
      alg: "ES256",
      issuerId: ISSUER_ID,
    });

    const { token } = await issuer.issue({
      subject: { given_name: "Dave" },
      selectivelyDisclosable: ["given_name"],
      holderKey: holderKey.pub,
      vct: VCT,
      status: { status_list: { uri: LIST_URL, idx: 1 } },
    });
    const parsed = parseSdJwt(token);

    // List signed by an UNTRUSTED key.
    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 8,
      privateKey: evilKey.priv,
      alg: "ES256",
    });

    try {
      await checkCredentialStatus(parsed, {
        trustedIssuers: [goodKey.pub],
        fetcher: mockHost(listToken),
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe(
        "status_list.signature_invalid",
      );
    }
  });
});

describe("readStatusReference — credential parsing", () => {
  it("extracts uri+idx from a credential payload", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const issuer = new Issuer({
      privateKey: issuerKey.priv,
      publicKey: issuerKey.pub,
      alg: "ES256",
      issuerId: ISSUER_ID,
    });

    const { token } = await issuer.issue({
      subject: { x: 1 },
      holderKey: holderKey.pub,
      vct: VCT,
      status: { status_list: { uri: LIST_URL, idx: 99 } },
    });
    const parsed = parseSdJwt(token);
    expect(readStatusReference(parsed)).toEqual({ uri: LIST_URL, idx: 99 });
  });

  it('throws "no_status_reference" when the issuer didn\'t set a status', async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const issuer = new Issuer({
      privateKey: issuerKey.priv,
      publicKey: issuerKey.pub,
      alg: "ES256",
      issuerId: ISSUER_ID,
    });

    const { token } = await issuer.issue({
      subject: { x: 1 },
      holderKey: holderKey.pub,
      vct: VCT,
      // no status here
    });
    const parsed = parseSdJwt(token);
    try {
      readStatusReference(parsed);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe(
        "status_list.no_status_reference",
      );
    }
  });

  it("can use a pre-fetched list (skips network)", async () => {
    const issuerKey = await makeKey();
    const holderKey = await makeKey();
    const issuer = new Issuer({
      privateKey: issuerKey.priv,
      publicKey: issuerKey.pub,
      alg: "ES256",
      issuerId: ISSUER_ID,
    });

    const { token } = await issuer.issue({
      subject: { x: 1 },
      holderKey: holderKey.pub,
      vct: VCT,
      status: { status_list: { uri: LIST_URL, idx: 5 } },
    });
    const parsed = parseSdJwt(token);

    // Build the list once — caller passes it in directly.
    const listToken = await buildStatusListToken({
      issuer: ISSUER_ID,
      subject: LIST_URL,
      length: 8,
      privateKey: issuerKey.priv,
      alg: "ES256",
      initial: { 5: 1 },
    });
    // Parse it so we can pass the parsed StatusList in.
    const { parseStatusListToken } = await import("../src/index.js");
    const list = parseStatusListToken(listToken);

    const result = await checkCredentialStatus(parsed, {
      trustedIssuers: [issuerKey.pub],
      list,
      // No fetcher — must not hit the network.
      fetcher: () => {
        throw new Error("network must not be touched");
      },
    });

    expect(result.state).toBe("invalid");
  });
});

/**
 * fetchStatusList — exercises:
 *   - mock-fetcher happy path (token returned, parsed, returned)
 *   - signature verification against trusted issuers
 *   - subject mismatch rejection (sub != fetched URL)
 *   - expiry rejection
 *   - HTTP error handling
 */

import { describe, it, expect } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import {
  StatusListError,
  buildStatusListToken,
  fetchStatusList,
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

const ISSUER = "https://issuer.example.com";
const LIST_URL = "https://issuer.example.com/status/1";

function mockServer(map: Record<string, string>): Fetcher {
  return async (url) => {
    const body = map[url];
    if (body === undefined) {
      return {
        ok: false,
        status: 404,
        text: async () => `not found: ${url}`,
      };
    }
    return {
      ok: true,
      status: 200,
      text: async () => body,
    };
  };
}

describe("fetchStatusList — happy path", () => {
  it("fetches, parses, and returns a valid list", async () => {
    const { pub, priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 16,
      privateKey: priv,
      alg: "ES256",
      initial: { 4: 1 },
    });
    const list = await fetchStatusList(LIST_URL, {
      fetcher: mockServer({ [LIST_URL]: token }),
      trustedIssuers: [pub],
    });
    expect(list.subject).toBe(LIST_URL);
    expect(list.issuer).toBe(ISSUER);
  });

  it("works without trustedIssuers (signature unchecked — diagnostic only)", async () => {
    const { priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: priv,
      alg: "ES256",
    });
    const list = await fetchStatusList(LIST_URL, {
      fetcher: mockServer({ [LIST_URL]: token }),
    });
    expect(list.length).toBe(8);
  });
});

describe("fetchStatusList — security guards", () => {
  it("rejects when the list signature doesn't verify against any trusted key", async () => {
    const goodKey = await makeKey();
    const evilKey = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: evilKey.priv, // signed by evil
      alg: "ES256",
    });
    try {
      await fetchStatusList(LIST_URL, {
        fetcher: mockServer({ [LIST_URL]: token }),
        trustedIssuers: [goodKey.pub], // verifier only trusts good
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe(
        "status_list.signature_invalid",
      );
    }
  });

  it("rejects when sub claim doesn't match the fetched URL (substitution attack)", async () => {
    const { pub, priv } = await makeKey();
    // List signed for a DIFFERENT URL than where we fetch it from.
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: "https://benign.example.com/status/1",
      length: 8,
      privateKey: priv,
      alg: "ES256",
    });
    try {
      await fetchStatusList(LIST_URL, {
        fetcher: mockServer({ [LIST_URL]: token }),
        trustedIssuers: [pub],
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe(
        "status_list.subject_mismatch",
      );
    }
  });

  it("rejects when the list has expired (per exp claim)", async () => {
    const { pub, priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: priv,
      alg: "ES256",
      issuedAt: 1000,
      expiresAt: 2000,
    });
    try {
      await fetchStatusList(LIST_URL, {
        fetcher: mockServer({ [LIST_URL]: token }),
        trustedIssuers: [pub],
        now: () => 5000, // way past expiry
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe("status_list.expired");
    }
  });

  it("accepts unexpired lists (now < exp)", async () => {
    const { pub, priv } = await makeKey();
    const token = await buildStatusListToken({
      issuer: ISSUER,
      subject: LIST_URL,
      length: 8,
      privateKey: priv,
      alg: "ES256",
      issuedAt: 1000,
      expiresAt: 5000,
    });
    const list = await fetchStatusList(LIST_URL, {
      fetcher: mockServer({ [LIST_URL]: token }),
      trustedIssuers: [pub],
      now: () => 2000,
    });
    expect(list.expiresAt).toBe(5000);
  });
});

describe("fetchStatusList — HTTP errors", () => {
  it("surfaces HTTP errors from the fetcher", async () => {
    try {
      await fetchStatusList(LIST_URL, {
        fetcher: mockServer({}), // 404 for everything
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe("status_list.fetch_failed");
    }
  });

  it("rejects empty url", async () => {
    try {
      await fetchStatusList("");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as StatusListError).code).toBe("status_list.invalid_input");
    }
  });
});

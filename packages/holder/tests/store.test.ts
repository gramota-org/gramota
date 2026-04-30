// CredentialStore interface contract: any implementation must pass these.
// To test a future FileCredentialStore / EncryptedCredentialStore, run the
// same suite by parametrising `makeStore`.

import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryCredentialStore } from "../src/store/memory.js";
import type {
  CredentialStore,
  StoredCredential,
} from "../src/types.js";
import { parseSdJwt } from "@gateway/sd-jwt";

function fakeCredential(
  id: string,
  issuer: string,
  claimNames: string[] = ["given_name"],
): StoredCredential {
  // Parse a synthetic but spec-shaped SD-JWT just to get a valid `parsed`.
  const headerB64 = Buffer.from('{"alg":"ES256","typ":"vc+sd-jwt"}', "utf-8").toString("base64url");
  const payloadB64 = Buffer.from(
    JSON.stringify({
      iss: issuer,
      iat: 1700000000,
      _sd_alg: "sha-256",
    }),
    "utf-8",
  ).toString("base64url");
  let token = `${headerB64}.${payloadB64}.AAAA~`;
  for (const name of claimNames) {
    const d = Buffer.from(JSON.stringify(["salt-x", name, "v"]), "utf-8").toString("base64url");
    token += `${d}~`;
  }
  return {
    id,
    token,
    parsed: parseSdJwt(token),
    issuer,
    receivedAt: 1700000000,
  };
}

describe("CredentialStore contract — InMemoryCredentialStore", () => {
  let store: CredentialStore;

  beforeEach(() => {
    store = new InMemoryCredentialStore();
  });

  it("returns undefined for an unknown id", async () => {
    expect(await store.get("missing")).toBeUndefined();
  });

  it("add → get returns the same credential", async () => {
    const c = fakeCredential("abc-1", "https://issuer.example.com");
    await store.add(c);
    expect(await store.get("abc-1")).toEqual(c);
  });

  it("rejects adding a duplicate id", async () => {
    const c = fakeCredential("abc-1", "https://issuer.example.com");
    await store.add(c);
    await expect(store.add(c)).rejects.toThrow();
  });

  it("list() returns all stored credentials", async () => {
    await store.add(fakeCredential("a", "https://x.com"));
    await store.add(fakeCredential("b", "https://y.com"));
    const all = await store.list();
    expect(all).toHaveLength(2);
  });

  it("list({ issuer }) filters by issuer", async () => {
    await store.add(fakeCredential("a", "https://x.com"));
    await store.add(fakeCredential("b", "https://y.com"));
    await store.add(fakeCredential("c", "https://x.com"));
    const xs = await store.list({ issuer: "https://x.com" });
    expect(xs.map((c) => c.id).sort()).toEqual(["a", "c"]);
  });

  it("list({ withClaim }) filters by available disclosures", async () => {
    await store.add(fakeCredential("a", "https://x.com", ["given_name"]));
    await store.add(fakeCredential("b", "https://x.com", ["birthdate"]));
    await store.add(
      fakeCredential("c", "https://x.com", ["given_name", "birthdate"]),
    );
    const withGiven = await store.list({ withClaim: "given_name" });
    expect(withGiven.map((c) => c.id).sort()).toEqual(["a", "c"]);
  });

  it("remove() returns true when credential existed", async () => {
    const c = fakeCredential("abc-1", "https://x.com");
    await store.add(c);
    expect(await store.remove("abc-1")).toBe(true);
    expect(await store.get("abc-1")).toBeUndefined();
  });

  it("remove() returns false when credential did not exist", async () => {
    expect(await store.remove("never-was")).toBe(false);
  });
});

import { describe, it, expect } from "vitest";
import { parseSdJwt } from "@gramota/sd-jwt";
import {
  DcqlSdJwtVcMatcher,
  isPidExtensionOf,
  type DcqlCredentialQuery,
} from "../src/index.js";

function fakeCredential(opts: {
  vct?: string;
  claims: string[];
}): { parsed: ReturnType<typeof parseSdJwt> } {
  const headerB64 = Buffer.from(
    '{"alg":"ES256","typ":"vc+sd-jwt"}',
    "utf-8",
  ).toString("base64url");
  const payload: Record<string, unknown> = {
    iss: "https://issuer.example.com",
    iat: 1700000000,
    _sd_alg: "sha-256",
  };
  if (opts.vct !== undefined) payload["vct"] = opts.vct;
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString(
    "base64url",
  );
  let token = `${headerB64}.${payloadB64}.AAAA~`;
  for (const name of opts.claims) {
    const value =
      name === "age_over_18"
        ? true
        : name === "age"
          ? 30
          : `value-${name}`;
    const d = Buffer.from(
      JSON.stringify(["salt-x", name, value]),
      "utf-8",
    ).toString("base64url");
    token += `${d}~`;
  }
  return { parsed: parseSdJwt(token) };
}

describe("DcqlSdJwtVcMatcher.match — format gating", () => {
  const matcher = new DcqlSdJwtVcMatcher();

  it("matches vc+sd-jwt format", () => {
    const result = matcher.match(
      fakeCredential({ claims: ["given_name"] }),
      {
        id: "x",
        format: "vc+sd-jwt",
        claims: [{ path: ["given_name"] }],
      },
    );
    expect(result).not.toBeNull();
  });

  it("matches dc+sd-jwt format (newer alias)", () => {
    const result = matcher.match(fakeCredential({ claims: ["x"] }), {
      id: "y",
      format: "dc+sd-jwt",
      claims: [{ path: ["x"] }],
    });
    expect(result).not.toBeNull();
  });

  it("rejects unrelated formats (mso_mdoc, jwt_vc, etc.)", () => {
    const desc: DcqlCredentialQuery = {
      id: "x",
      format: "mso_mdoc",
      claims: [{ path: ["given_name"] }],
    };
    expect(matcher.match(fakeCredential({ claims: ["given_name"] }), desc)).toBeNull();
  });
});

describe("DcqlSdJwtVcMatcher — meta.vct_values filtering", () => {
  const matcher = new DcqlSdJwtVcMatcher();

  it("requires the credential's vct to be in meta.vct_values", () => {
    const cred = fakeCredential({
      vct: "https://credentials.example.com/pid_v1",
      claims: ["family_name"],
    });
    const ok = matcher.match(cred, {
      id: "pid",
      format: "vc+sd-jwt",
      meta: { vct_values: ["https://credentials.example.com/pid_v1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(ok).not.toBeNull();
  });

  it("rejects when vct doesn't match any vct_values entry", () => {
    const cred = fakeCredential({
      vct: "https://credentials.example.com/some_other",
      claims: ["family_name"],
    });
    const result = matcher.match(cred, {
      id: "pid",
      format: "vc+sd-jwt",
      meta: { vct_values: ["https://credentials.example.com/pid_v1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(result).toBeNull();
  });

  it("ignores meta.vct_values when absent", () => {
    const cred = fakeCredential({ claims: ["family_name"] });
    const result = matcher.match(cred, {
      id: "pid",
      format: "vc+sd-jwt",
      claims: [{ path: ["family_name"] }],
    });
    expect(result).not.toBeNull();
  });
});

describe("DcqlSdJwtVcMatcher — claim resolution", () => {
  const matcher = new DcqlSdJwtVcMatcher();

  it("returns the disclosure name for a single-segment path", () => {
    const cred = fakeCredential({ claims: ["given_name", "family_name"] });
    const result = matcher.match(cred, {
      id: "x",
      format: "vc+sd-jwt",
      claims: [{ path: ["given_name"] }],
    });
    expect(result?.disclose).toEqual(["given_name"]);
  });

  it("returns multiple disclosures when claim list is multi", () => {
    const cred = fakeCredential({ claims: ["given_name", "birthdate"] });
    const result = matcher.match(cred, {
      id: "x",
      format: "vc+sd-jwt",
      claims: [{ path: ["given_name"] }, { path: ["birthdate"] }],
    });
    expect([...(result?.disclose ?? [])].sort()).toEqual([
      "birthdate",
      "given_name",
    ]);
  });

  it("matches direct payload claims (non-SD) without adding to disclose", () => {
    const cred = fakeCredential({ claims: [] });
    // iss is a direct payload claim
    const result = matcher.match(cred, {
      id: "x",
      format: "vc+sd-jwt",
      claims: [{ path: ["iss"] }],
    });
    expect(result?.disclose).toEqual([]);
  });

  it("returns null when a required claim is missing", () => {
    const cred = fakeCredential({ claims: ["given_name"] });
    const result = matcher.match(cred, {
      id: "x",
      format: "vc+sd-jwt",
      claims: [{ path: ["given_name"] }, { path: ["birthdate"] }],
    });
    expect(result).toBeNull();
  });
});

describe("DcqlSdJwtVcMatcher — value constraints", () => {
  const matcher = new DcqlSdJwtVcMatcher();

  it("matches when the disclosed value is in the allowed values list", () => {
    const cred = fakeCredential({ claims: ["age_over_18"] });
    const result = matcher.match(cred, {
      id: "x",
      format: "vc+sd-jwt",
      claims: [{ path: ["age_over_18"], values: [true] }],
    });
    expect(result).not.toBeNull();
  });

  it("rejects when the disclosed value isn't in the allowed list", () => {
    const cred = fakeCredential({ claims: ["age_over_18"] });
    const result = matcher.match(cred, {
      id: "x",
      format: "vc+sd-jwt",
      claims: [{ path: ["age_over_18"], values: [false] }],
    });
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ARF Annex 3.01 §3 — domestic PID extensions.
//
// Audit fix (Tier 1): when configured with `vctMatchMode: "eudi-pid-extensions"`,
// a query asking for the cross-border base vct `urn:eudi:pid:1` must
// also accept a credential whose vct is `urn:eudi:pid:<cc>:1` (e.g.
// `urn:eudi:pid:de:1`). The strict-equality default still has to work
// — we don't break verifiers that key off bytewise vct equality today.
// ---------------------------------------------------------------------------
describe("isPidExtensionOf — ARF Annex 3.01 §3 helper", () => {
  it("accepts a country-coded PID urn against the base type", () => {
    expect(isPidExtensionOf("urn:eudi:pid:de:1", "urn:eudi:pid:1")).toBe(true);
    expect(isPidExtensionOf("urn:eudi:pid:fr:1", "urn:eudi:pid:1")).toBe(true);
    expect(isPidExtensionOf("urn:eudi:pid:bg:1", "urn:eudi:pid:1")).toBe(true);
  });

  it("rejects when the version segment doesn't match", () => {
    expect(isPidExtensionOf("urn:eudi:pid:de:1", "urn:eudi:pid:2")).toBe(false);
    expect(isPidExtensionOf("urn:eudi:pid:de:2", "urn:eudi:pid:1")).toBe(false);
  });

  it("rejects the base itself (strict equality is handled separately)", () => {
    // The function is for *extensions* only; equality is handled by the
    // direct `vctValues.includes(...)` check upstream.
    expect(isPidExtensionOf("urn:eudi:pid:1", "urn:eudi:pid:1")).toBe(false);
  });

  it("rejects unrelated vct urns", () => {
    expect(
      isPidExtensionOf(
        "https://credentials.example/pid/v1",
        "urn:eudi:pid:1",
      ),
    ).toBe(false);
    expect(isPidExtensionOf("urn:other:thing:de:1", "urn:eudi:pid:1")).toBe(
      false,
    );
  });

  it("rejects country codes that aren't 2 lowercase letters", () => {
    // ISO-3166-1-alpha-2 only — no upper case, no length-3, no digits.
    expect(isPidExtensionOf("urn:eudi:pid:DE:1", "urn:eudi:pid:1")).toBe(false);
    expect(isPidExtensionOf("urn:eudi:pid:deu:1", "urn:eudi:pid:1")).toBe(false);
    expect(isPidExtensionOf("urn:eudi:pid:1a:1", "urn:eudi:pid:1")).toBe(false);
  });
});

describe("DcqlSdJwtVcMatcher — vctMatchMode (ARF Annex 3.01 §3)", () => {
  it("strict mode (default) rejects a domestic PID against the base type", () => {
    const matcher = new DcqlSdJwtVcMatcher(); // default = "strict"
    const cred = fakeCredential({
      vct: "urn:eudi:pid:de:1",
      claims: ["family_name"],
    });
    const result = matcher.match(cred, {
      id: "pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eudi:pid:1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(result).toBeNull();
    expect(matcher.vctMatchMode).toBe("strict");
  });

  it("strict mode is preserved when explicitly set", () => {
    const matcher = new DcqlSdJwtVcMatcher({ vctMatchMode: "strict" });
    expect(matcher.vctMatchMode).toBe("strict");
  });

  it("eudi-pid-extensions mode accepts a domestic PID for the base type", () => {
    const matcher = new DcqlSdJwtVcMatcher({
      vctMatchMode: "eudi-pid-extensions",
    });
    const cred = fakeCredential({
      vct: "urn:eudi:pid:de:1",
      claims: ["family_name"],
    });
    const result = matcher.match(cred, {
      id: "pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eudi:pid:1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(result).not.toBeNull();
    expect(result?.disclose).toEqual(["family_name"]);
  });

  it("eudi-pid-extensions mode also accepts the strict-equality base type", () => {
    const matcher = new DcqlSdJwtVcMatcher({
      vctMatchMode: "eudi-pid-extensions",
    });
    const cred = fakeCredential({
      vct: "urn:eudi:pid:1",
      claims: ["family_name"],
    });
    const result = matcher.match(cred, {
      id: "pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eudi:pid:1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(result).not.toBeNull();
  });

  it("eudi-pid-extensions mode rejects an unrelated vct urn", () => {
    const matcher = new DcqlSdJwtVcMatcher({
      vctMatchMode: "eudi-pid-extensions",
    });
    const cred = fakeCredential({
      vct: "https://credentials.example/pid/v1",
      claims: ["family_name"],
    });
    const result = matcher.match(cred, {
      id: "pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eudi:pid:1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(result).toBeNull();
  });

  it("eudi-pid-extensions mode preserves strict equality for the listed value", () => {
    const matcher = new DcqlSdJwtVcMatcher({
      vctMatchMode: "eudi-pid-extensions",
    });
    // Query lists `urn:eudi:pid:de:1` explicitly — only that country
    // code matches; another country shouldn't sneak through.
    const cred = fakeCredential({
      vct: "urn:eudi:pid:fr:1",
      claims: ["family_name"],
    });
    const result = matcher.match(cred, {
      id: "pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eudi:pid:de:1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(result).toBeNull();
  });

  it("eudi-pid-extensions mode is a no-op for non-PID vct urns (strict equality only)", () => {
    // Make sure we don't accidentally relax matching for unrelated
    // urn schemes. A query asking for `urn:my-org:foo:1` should not
    // accept `urn:my-org:foo:de:1` — only the urn:eudi:pid carve-out applies.
    const matcher = new DcqlSdJwtVcMatcher({
      vctMatchMode: "eudi-pid-extensions",
    });
    const cred = fakeCredential({
      vct: "urn:my-org:foo:de:1",
      claims: ["family_name"],
    });
    const result = matcher.match(cred, {
      id: "x",
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:my-org:foo:1"] },
      claims: [{ path: ["family_name"] }],
    });
    expect(result).toBeNull();
  });
});

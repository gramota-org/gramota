import { describe, it, expect } from "vitest";
import { parseSdJwt } from "@gramota/sd-jwt";
import {
  DcqlSdJwtVcMatcher,
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

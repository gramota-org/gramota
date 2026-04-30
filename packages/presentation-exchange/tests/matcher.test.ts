// SdJwtVcMatcher tests — descriptor evaluation against a parsed credential.

import { describe, it, expect } from "vitest";
import { parseSdJwt } from "@gateway/sd-jwt";
import { SdJwtVcMatcher } from "../src/index.js";
import type { InputDescriptor } from "../src/index.js";

function fakeCredential(claimNames: string[]): { parsed: ReturnType<typeof parseSdJwt> } {
  const headerB64 = Buffer.from(
    '{"alg":"ES256","typ":"vc+sd-jwt"}',
    "utf-8",
  ).toString("base64url");
  const payloadB64 = Buffer.from(
    JSON.stringify({
      iss: "https://issuer.example.com",
      iat: 1700000000,
      _sd_alg: "sha-256",
    }),
    "utf-8",
  ).toString("base64url");
  let token = `${headerB64}.${payloadB64}.AAAA~`;
  for (const name of claimNames) {
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

describe("SdJwtVcMatcher.appliesTo", () => {
  const matcher = new SdJwtVcMatcher();

  it("applies when descriptor has no format (PD-level format applies)", () => {
    const desc: InputDescriptor = {
      id: "x",
      constraints: { fields: [] },
    };
    expect(matcher.appliesTo(desc)).toBe(true);
  });

  it("applies when descriptor explicitly lists vc+sd-jwt", () => {
    const desc: InputDescriptor = {
      id: "x",
      format: { "vc+sd-jwt": { alg: ["ES256"] } },
      constraints: { fields: [] },
    };
    expect(matcher.appliesTo(desc)).toBe(true);
  });

  it("applies when descriptor lists dc+sd-jwt (newer alias)", () => {
    const desc: InputDescriptor = {
      id: "x",
      format: { "dc+sd-jwt": {} },
      constraints: { fields: [] },
    };
    expect(matcher.appliesTo(desc)).toBe(true);
  });

  it("does not apply for unrelated formats", () => {
    const desc: InputDescriptor = {
      id: "x",
      format: { mso_mdoc: {} },
      constraints: { fields: [] },
    };
    expect(matcher.appliesTo(desc)).toBe(false);
  });
});

describe("SdJwtVcMatcher.match — required fields", () => {
  const matcher = new SdJwtVcMatcher();

  it("matches and returns the disclosures needed", () => {
    const cred = fakeCredential(["given_name", "family_name", "birthdate"]);
    const desc: InputDescriptor = {
      id: "id-card",
      constraints: {
        limit_disclosure: "required",
        fields: [
          { path: ["$.given_name"] },
          { path: ["$.birthdate"] },
        ],
      },
    };
    const result = matcher.match(cred, desc);
    expect(result).not.toBeNull();
    expect([...(result!.disclose)].sort()).toEqual([
      "birthdate",
      "given_name",
    ]);
  });

  it("returns null when a required field is missing", () => {
    const cred = fakeCredential(["given_name"]);
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [
          { path: ["$.given_name"] },
          { path: ["$.birthdate"] }, // missing
        ],
      },
    };
    expect(matcher.match(cred, desc)).toBeNull();
  });
});

describe("SdJwtVcMatcher.match — optional fields", () => {
  const matcher = new SdJwtVcMatcher();

  it("does not require optional fields to match", () => {
    const cred = fakeCredential(["given_name"]);
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [
          { path: ["$.given_name"] },
          { path: ["$.email"], optional: true }, // missing → ok
        ],
      },
    };
    const result = matcher.match(cred, desc);
    expect(result).not.toBeNull();
    expect(result!.disclose).toEqual(["given_name"]);
  });

  it("includes optional fields when they match", () => {
    const cred = fakeCredential(["given_name", "email"]);
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [
          { path: ["$.given_name"] },
          { path: ["$.email"], optional: true },
        ],
      },
    };
    const result = matcher.match(cred, desc);
    expect([...(result!.disclose)].sort()).toEqual(["email", "given_name"]);
  });
});

describe("SdJwtVcMatcher.match — alternative paths", () => {
  const matcher = new SdJwtVcMatcher();

  it("any of the field's paths satisfies it", () => {
    const cred = fakeCredential(["family_name"]);
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [{ path: ["$.surname", "$.family_name", "$.last_name"] }],
      },
    };
    const result = matcher.match(cred, desc);
    expect(result).not.toBeNull();
    expect(result!.disclose).toEqual(["family_name"]);
  });
});

describe("SdJwtVcMatcher.match — filters", () => {
  const matcher = new SdJwtVcMatcher();

  it("respects filter type=string", () => {
    const cred = fakeCredential(["given_name"]);
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [{ path: ["$.given_name"], filter: { type: "string" } }],
      },
    };
    expect(matcher.match(cred, desc)).not.toBeNull();
  });

  it("rejects when filter type doesn't match", () => {
    const cred = fakeCredential(["age_over_18"]); // boolean
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [
          { path: ["$.age_over_18"], filter: { type: "string" } }, // expects string
        ],
      },
    };
    expect(matcher.match(cred, desc)).toBeNull();
  });

  it("filter type=integer accepts integer", () => {
    const cred = fakeCredential(["age"]);
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [{ path: ["$.age"], filter: { type: "integer" } }],
      },
    };
    expect(matcher.match(cred, desc)).not.toBeNull();
  });
});

describe("SdJwtVcMatcher.match — non-SD claims in payload", () => {
  const matcher = new SdJwtVcMatcher();

  it("matches a top-level non-SD claim like iss", () => {
    const cred = fakeCredential(["given_name"]);
    const desc: InputDescriptor = {
      id: "id",
      constraints: {
        fields: [{ path: ["$.iss"] }],
      },
    };
    const result = matcher.match(cred, desc);
    expect(result).not.toBeNull();
    // iss is in the JWT body, not SD — no need to disclose.
    expect(result!.disclose).toEqual([]);
  });
});

import { describe, it, expect } from "vitest";
import { parseSdJwt } from "@gramota/sd-jwt";
import {
  DcqlError,
  selectForDcql,
  type DcqlQuery,
} from "../src/index.js";

function cred(id: string, claimNames: string[], vct?: string): { id: string; parsed: ReturnType<typeof parseSdJwt> } {
  const headerB64 = Buffer.from('{"alg":"ES256"}', "utf-8").toString("base64url");
  const payload: Record<string, unknown> = {
    iss: "https://issuer.example.com",
    iat: 1700000000,
    _sd_alg: "sha-256",
  };
  if (vct !== undefined) payload["vct"] = vct;
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString("base64url");
  let token = `${headerB64}.${payloadB64}.SIG~`;
  for (const name of claimNames) {
    const d = Buffer.from(
      JSON.stringify(["salt", name, "v"]),
      "utf-8",
    ).toString("base64url");
    token += `${d}~`;
  }
  return { id, parsed: parseSdJwt(token) };
}

describe("selectForDcql — basic credential matching", () => {
  it("matches a single credential against a single query", () => {
    const query: DcqlQuery = {
      credentials: [
        {
          id: "id-card",
          format: "vc+sd-jwt",
          claims: [{ path: ["given_name"] }],
        },
      ],
    };
    const sel = selectForDcql({
      query,
      credentials: [cred("c1", ["given_name", "family_name"])],
    });
    expect(sel.fullySatisfied).toBe(true);
    expect(sel.matches).toHaveLength(1);
    expect(sel.matches[0]?.disclose).toEqual(["given_name"]);
  });

  it("reports unmatched when no credential satisfies the query", () => {
    const query: DcqlQuery = {
      credentials: [
        {
          id: "passport",
          format: "vc+sd-jwt",
          claims: [{ path: ["passport_number"] }],
        },
      ],
    };
    const sel = selectForDcql({
      query,
      credentials: [cred("c1", ["given_name"])],
    });
    expect(sel.fullySatisfied).toBe(false);
    expect(sel.unmatched).toHaveLength(1);
    expect(sel.unmatched[0]?.query.id).toBe("passport");
  });

  it("rejects credentials whose format is not handled by any matcher", () => {
    const query: DcqlQuery = {
      credentials: [
        {
          id: "mdoc",
          format: "mso_mdoc",
          claims: [{ path: ["family_name"] }],
        },
      ],
    };
    const sel = selectForDcql({
      query,
      credentials: [cred("c1", ["family_name"])],
    });
    expect(sel.fullySatisfied).toBe(false);
    expect(sel.unmatched[0]?.reason).toMatch(/no matcher/);
  });
});

describe("selectForDcql — credential_sets", () => {
  it("requires every credential id in a required set's option to be matched", () => {
    const query: DcqlQuery = {
      credentials: [
        {
          id: "id",
          format: "vc+sd-jwt",
          claims: [{ path: ["given_name"] }],
        },
        {
          id: "edu",
          format: "vc+sd-jwt",
          claims: [{ path: ["degree"] }],
        },
      ],
      credential_sets: [
        {
          options: [["id", "edu"]],
          required: true,
        },
      ],
    };
    const sel = selectForDcql({
      query,
      credentials: [
        cred("c1", ["given_name"]),
        cred("c2", ["degree"]),
      ],
    });
    expect(sel.fullySatisfied).toBe(true);
  });

  it("OR semantics: any option whose ids are all matched satisfies the set", () => {
    const query: DcqlQuery = {
      credentials: [
        {
          id: "id",
          format: "vc+sd-jwt",
          claims: [{ path: ["given_name"] }],
        },
        {
          id: "passport",
          format: "vc+sd-jwt",
          claims: [{ path: ["passport_number"] }],
        },
      ],
      credential_sets: [
        {
          options: [["passport"], ["id"]], // passport OR id
          required: true,
        },
      ],
    };
    const sel = selectForDcql({
      query,
      credentials: [cred("c1", ["given_name"])],
    });
    // passport unmatched, id matched → set satisfied via the [id] option
    expect(sel.fullySatisfied).toBe(true);
  });

  it("treats required:false sets as best-effort, not blocking", () => {
    const query: DcqlQuery = {
      credentials: [
        { id: "id", format: "vc+sd-jwt", claims: [{ path: ["given_name"] }] },
        {
          id: "optional-edu",
          format: "vc+sd-jwt",
          claims: [{ path: ["degree"] }],
        },
      ],
      credential_sets: [
        { options: [["id"]], required: true },
        { options: [["optional-edu"]], required: false },
      ],
    };
    const sel = selectForDcql({
      query,
      credentials: [cred("c1", ["given_name"])],
    });
    expect(sel.fullySatisfied).toBe(true);
  });
});

describe("selectForDcql — query validation", () => {
  it("rejects empty credentials array", () => {
    try {
      selectForDcql({ query: { credentials: [] }, credentials: [] });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(DcqlError);
      expect((err as DcqlError).code).toBe("dcql.invalid_query");
    }
  });

  it("rejects duplicate credential ids", () => {
    try {
      selectForDcql({
        query: {
          credentials: [
            { id: "x", format: "vc+sd-jwt" },
            { id: "x", format: "vc+sd-jwt" },
          ],
        },
        credentials: [],
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as DcqlError).message).toMatch(/duplicate/);
    }
  });

  it("rejects missing format on a credential entry", () => {
    try {
      selectForDcql({
        query: {
          // @ts-expect-error: missing required field
          credentials: [{ id: "x" }],
        },
        credentials: [],
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as DcqlError).code).toBe("dcql.invalid_query");
    }
  });

  it("rejects malformed claim paths", () => {
    try {
      selectForDcql({
        query: {
          credentials: [
            {
              id: "x",
              format: "vc+sd-jwt",
              claims: [
                {
                  // @ts-expect-error: testing runtime guard
                  path: [true],
                },
              ],
            },
          ],
        },
        credentials: [],
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as DcqlError).code).toBe("dcql.invalid_path");
    }
  });
});

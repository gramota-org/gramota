import { describe, it, expect } from "vitest";
import { parseSdJwt } from "@gateway/sd-jwt";
import {
  buildPresentationSubmission,
  PresentationExchangeError,
  selectForDefinition,
  type PresentationDefinition,
} from "../src/index.js";

function cred(id: string, claimNames: string[]): { id: string; parsed: ReturnType<typeof parseSdJwt> } {
  const headerB64 = Buffer.from('{"alg":"ES256"}', "utf-8").toString("base64url");
  const payloadB64 = Buffer.from(
    JSON.stringify({
      iss: "https://issuer.example.com",
      iat: 1700000000,
      _sd_alg: "sha-256",
    }),
    "utf-8",
  ).toString("base64url");
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

describe("selectForDefinition", () => {
  it("matches a single descriptor against a single matching credential", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        {
          id: "id-card",
          constraints: { fields: [{ path: ["$.given_name"] }] },
        },
      ],
    };
    const credentials = [cred("c1", ["given_name", "family_name"])];

    const sel = selectForDefinition({ definition, credentials });
    expect(sel.fullySatisfied).toBe(true);
    expect(sel.matches).toHaveLength(1);
    expect(sel.matches[0]?.descriptor.id).toBe("id-card");
    expect(sel.matches[0]?.credential.id).toBe("c1");
    expect(sel.matches[0]?.disclose).toEqual(["given_name"]);
  });

  it("reports unmatched descriptors when no credential satisfies them", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        {
          id: "id-card",
          constraints: { fields: [{ path: ["$.passport_number"] }] },
        },
      ],
    };
    const credentials = [cred("c1", ["given_name"])];

    const sel = selectForDefinition({ definition, credentials });
    expect(sel.fullySatisfied).toBe(false);
    expect(sel.matches).toEqual([]);
    expect(sel.unmatched).toHaveLength(1);
    expect(sel.unmatched[0]?.descriptor.id).toBe("id-card");
  });

  it("matches multiple descriptors using different credentials", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        {
          id: "identity",
          constraints: { fields: [{ path: ["$.given_name"] }] },
        },
        {
          id: "education",
          constraints: { fields: [{ path: ["$.degree"] }] },
        },
      ],
    };
    const credentials = [
      cred("c1", ["given_name"]),
      cred("c2", ["degree", "university"]),
    ];

    const sel = selectForDefinition({ definition, credentials });
    expect(sel.fullySatisfied).toBe(true);
    expect(sel.matches).toHaveLength(2);
    expect(sel.matches[0]?.credential.id).toBe("c1");
    expect(sel.matches[1]?.credential.id).toBe("c2");
  });

  it("by default picks the first matching credential when multiple satisfy", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        {
          id: "id",
          constraints: { fields: [{ path: ["$.given_name"] }] },
        },
      ],
    };
    const credentials = [
      cred("c1", ["given_name", "family_name"]),
      cred("c2", ["given_name"]),
    ];

    const sel = selectForDefinition({ definition, credentials });
    expect(sel.matches[0]?.credential.id).toBe("c1");
  });

  it("supports a custom pickCredential strategy (minimal-credential picker)", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        {
          id: "id",
          constraints: { fields: [{ path: ["$.given_name"] }] },
        },
      ],
    };
    const credentials = [
      cred("c1", ["given_name", "extra"]),
      cred("c2", ["given_name"]),
    ];

    // Privacy-preserving wallet behavior: prefer the credential with the
    // smallest total disclosure surface (fewer "available but not asked"
    // claims means less linkability if disclosures ever leak).
    const sel = selectForDefinition({
      definition,
      credentials,
      pickCredential: (cands) =>
        cands.reduce((best, cur) =>
          cur.credential.parsed.disclosures.length <
          best.credential.parsed.disclosures.length
            ? cur
            : best,
        ),
    });
    expect(sel.matches[0]?.credential.id).toBe("c2");
  });
});

describe("buildPresentationSubmission", () => {
  it("builds a submission with $.path for a single match", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        {
          id: "id-card",
          constraints: { fields: [{ path: ["$.given_name"] }] },
        },
      ],
    };
    const sel = selectForDefinition({
      definition,
      credentials: [cred("c1", ["given_name"])],
    });

    const submission = buildPresentationSubmission(definition, sel);
    expect(submission.definition_id).toBe("pd-1");
    expect(submission.descriptor_map).toHaveLength(1);
    expect(submission.descriptor_map[0]).toEqual({
      id: "id-card",
      format: "vc+sd-jwt",
      path: "$",
    });
  });

  it("builds a submission with $[i] paths for multiple matches", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        { id: "a", constraints: { fields: [{ path: ["$.foo"] }] } },
        { id: "b", constraints: { fields: [{ path: ["$.bar"] }] } },
      ],
    };
    const sel = selectForDefinition({
      definition,
      credentials: [cred("c1", ["foo"]), cred("c2", ["bar"])],
    });

    const submission = buildPresentationSubmission(definition, sel);
    expect(submission.descriptor_map.map((d) => d.path)).toEqual([
      "$[0]",
      "$[1]",
    ]);
  });

  it("throws when the selection is not fully satisfied", () => {
    const definition: PresentationDefinition = {
      id: "pd-1",
      input_descriptors: [
        {
          id: "x",
          constraints: { fields: [{ path: ["$.missing"] }] },
        },
      ],
    };
    const sel = selectForDefinition({
      definition,
      credentials: [cred("c1", ["other"])],
    });
    expect(() => buildPresentationSubmission(definition, sel)).toThrow(
      PresentationExchangeError,
    );
  });
});

// EU PID helpers: claim constants, default subject builder, status helper.
//
// PID Rulebook §2.2 + §2.4 enumerate the mandatory claims for an EU PID;
// §4.1.1 fixes the canonical claim names (note: `birthdate`, one word).
// The defaults are validation-shape-only — production callers MUST
// override every field with real identity data.

import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { parseSdJwt, sd, verifyHashBinding } from "@gramota/sd-jwt";
import {
  EU_PID_CREDENTIAL_CONFIGURATION_ID,
  EU_PID_VCT,
  Issuer,
  PID_MANDATORY_CLAIM_NAMES,
  PidClaim,
  defaultPidSubject,
  statusListReference,
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

describe("EU PID claim constants", () => {
  it("VCT base value matches ARF Annex 2 PID_14", () => {
    expect(EU_PID_VCT).toBe("urn:eudi:pid:1");
  });

  it("credential-configuration-id matches EU reference wallet convention", () => {
    expect(EU_PID_CREDENTIAL_CONFIGURATION_ID).toBe("urn:eudi:pid:1_sd_jwt_vc");
  });

  it("canonical claim names from PID Rulebook §4.1.1", () => {
    // The single most common typo: birth_date (OIDC custom) vs birthdate
    // (Rulebook spelling). Verify the constant uses the Rulebook form.
    expect(PidClaim.birthdate).toBe("birthdate");
    // Plural form: nationalities (array), not singular `nationality`.
    expect(PidClaim.nationalities).toBe("nationalities");
    // Other mandatory fields per §2.4 metadata block.
    expect(PidClaim.issuing_country).toBe("issuing_country");
    expect(PidClaim.issuing_authority).toBe("issuing_authority");
    expect(PidClaim.expiry_date).toBe("expiry_date");
  });

  it("the mandatory-claim list covers Rulebook §2.2 + §2.4", () => {
    expect(new Set(PID_MANDATORY_CLAIM_NAMES)).toEqual(
      new Set([
        "family_name",
        "given_name",
        "birthdate",
        "birth_place",
        "nationalities",
        "issuing_country",
        "issuing_authority",
        "expiry_date",
      ]),
    );
  });
});

describe("defaultPidSubject — Rulebook §2.2/§2.4 shape", () => {
  it("produces every mandatory claim by default", () => {
    const subject = defaultPidSubject();
    for (const claim of PID_MANDATORY_CLAIM_NAMES) {
      expect(subject).toHaveProperty(claim);
      // No undefined / null defaults — every field must be a valid value.
      expect(subject[claim]).not.toBeNull();
      expect(subject[claim]).not.toBeUndefined();
    }
  });

  it("uses `birthdate` (one word) — NOT `birth_date`", () => {
    const subject = defaultPidSubject();
    expect(subject).toHaveProperty("birthdate");
    expect(subject).not.toHaveProperty("birth_date");
  });

  it("uses `nationalities` (plural array) — NOT `nationality`", () => {
    const subject = defaultPidSubject();
    expect(subject).toHaveProperty("nationalities");
    expect(subject).not.toHaveProperty("nationality");
    expect(Array.isArray(subject["nationalities"])).toBe(true);
  });

  it("callers can override individual fields", () => {
    const subject = defaultPidSubject({
      family_name: "Müller",
      given_name: "Max",
      birthdate: "1985-06-15",
      nationalities: ["DE", "AT"],
      issuing_country: "AT",
      issuing_authority: "AT-IDS",
    });

    expect(subject["family_name"]).toBe("Müller");
    expect(subject["given_name"]).toBe("Max");
    expect(subject["birthdate"]).toBe("1985-06-15");
    expect(subject["nationalities"]).toEqual(["DE", "AT"]);
    expect(subject["issuing_country"]).toBe("AT");
    expect(subject["issuing_authority"]).toBe("AT-IDS");
  });

  it("nationalitiesPerElementSd=true wraps each element with sd()", async () => {
    const subject = defaultPidSubject({
      nationalities: ["DE", "FR"],
      nationalitiesPerElementSd: true,
    });

    // The shape is structurally opaque (sd() uses a symbol-keyed object).
    // Issue a credential through the real Issuer and verify the wire
    // encoding produces array-element disclosures — that's what
    // SD-JWT §4.2.5 specifies and what the EU reference wallet expects.
    const { pub: ipub, priv: ipriv } = await makeKey();
    const { pub: hpub } = await makeKey();
    const issuer = new Issuer({
      privateKey: ipriv,
      publicKey: ipub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    const result = await issuer.issue({
      subject,
      holderKey: hpub,
      vct: EU_PID_VCT,
    });

    const parsed = parseSdJwt(result.token);
    const nats = parsed.payload["nationalities"] as unknown[];
    expect(nats).toHaveLength(2);
    // Both array slots are `{"...": digest}` objects per §4.2.5.
    for (const n of nats) {
      expect(typeof n).toBe("object");
      expect(n).toHaveProperty("...");
    }
    // Both disclosures are arity-2 (name === null).
    const natDiscs = result.disclosures.filter(
      (d) => d.value === "DE" || d.value === "FR",
    );
    expect(natDiscs).toHaveLength(2);
    expect(natDiscs.every((d) => d.name === null)).toBe(true);
  });

  it("birthPlaceNestedSd=true wraps sub-fields of birth_place object with sd()", async () => {
    const subject = defaultPidSubject({
      birth_place: { country: "DE", locality: "Berlin" },
      birthPlaceNestedSd: true,
    });

    const { pub: ipub, priv: ipriv } = await makeKey();
    const { pub: hpub } = await makeKey();
    const issuer = new Issuer({
      privateKey: ipriv,
      publicKey: ipub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    const result = await issuer.issue({
      subject,
      holderKey: hpub,
      vct: EU_PID_VCT,
    });

    const parsed = parseSdJwt(result.token);
    const bp = parsed.payload["birth_place"] as Record<string, unknown>;
    // Sub-fields are NOT visible — they're in `_sd`.
    expect(bp).not.toHaveProperty("country");
    expect(bp).not.toHaveProperty("locality");
    expect(Array.isArray(bp["_sd"])).toBe(true);
    expect((bp["_sd"] as unknown[]).length).toBe(2);
  });
});

describe("statusListReference", () => {
  it("builds the canonical `{ status_list: { uri, idx } }` shape", () => {
    const status = statusListReference("https://issuer.example.com/status/1", 42);
    expect(status).toEqual({
      status_list: { uri: "https://issuer.example.com/status/1", idx: 42 },
    });
  });

  it("works as input to IssueOptions.status — status claim appears in the payload", async () => {
    const { pub: ipub, priv: ipriv } = await makeKey();
    const { pub: hpub } = await makeKey();
    const issuer = new Issuer({
      privateKey: ipriv,
      publicKey: ipub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    const result = await issuer.issue({
      subject: defaultPidSubject(),
      holderKey: hpub,
      vct: EU_PID_VCT,
      status: statusListReference("https://issuer.example.com/status/2026", 7),
    });

    const parsed = parseSdJwt(result.token);
    expect(parsed.payload["status"]).toEqual({
      status_list: {
        uri: "https://issuer.example.com/status/2026",
        idx: 7,
      },
    });
  });

  it("omitting the status option produces a credential with NO status claim", async () => {
    // The audit's preferred behavior: rather than emit `status: {}`, OMIT
    // the claim entirely so the verifier treats the credential as
    // non-revocable rather than "revocable-but-no-list-configured".
    const { pub: ipub, priv: ipriv } = await makeKey();
    const { pub: hpub } = await makeKey();
    const issuer = new Issuer({
      privateKey: ipriv,
      publicKey: ipub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    const result = await issuer.issue({
      subject: defaultPidSubject(),
      holderKey: hpub,
      vct: EU_PID_VCT,
      // status: undefined — intentional
    });

    const parsed = parseSdJwt(result.token);
    expect(parsed.payload).not.toHaveProperty("status");
  });
});

describe("EU PID end-to-end: defaults + issuer → parse + verify", () => {
  it("a default PID with all 8 mandatory claims SD verifies cleanly", async () => {
    const { pub: ipub, priv: ipriv } = await makeKey();
    const { pub: hpub } = await makeKey();
    const issuer = new Issuer({
      privateKey: ipriv,
      publicKey: ipub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });

    const subject = defaultPidSubject({
      family_name: "Sample",
      given_name: "Alice",
      birthdate: "1990-04-15",
      nationalities: ["DE"],
      issuing_country: "DE",
      issuing_authority: "DE-IDS",
      expiry_date: "2030-01-01",
    });

    const result = await issuer.issue({
      subject,
      selectivelyDisclosable: [...PID_MANDATORY_CLAIM_NAMES],
      holderKey: hpub,
      vct: EU_PID_VCT,
      status: statusListReference("https://issuer.example.com/status/2026", 1),
    });

    const verified = verifyHashBinding(parseSdJwt(result.token));
    expect(verified.unmatchedDisclosures).toHaveLength(0);

    // Every mandatory claim is recovered.
    for (const claim of PID_MANDATORY_CLAIM_NAMES) {
      expect(verified.claims).toHaveProperty(claim);
    }
    expect(verified.claims["family_name"]).toBe("Sample");
    expect(verified.claims["given_name"]).toBe("Alice");
    expect(verified.claims["birthdate"]).toBe("1990-04-15");
    expect(verified.claims["nationalities"]).toEqual(["DE"]);
    expect(verified.claims["issuing_country"]).toBe("DE");
    expect(verified.claims["issuing_authority"]).toBe("DE-IDS");
    expect(verified.claims["expiry_date"]).toBe("2030-01-01");
    // status claim is direct (not SD).
    expect(verified.claims["status"]).toEqual({
      status_list: { uri: "https://issuer.example.com/status/2026", idx: 1 },
    });
  });

  it("verifies the issued credential uses `dc+sd-jwt` typ header per SD-JWT-VC §3.2.1", async () => {
    const { pub: ipub, priv: ipriv } = await makeKey();
    const { pub: hpub } = await makeKey();
    const issuer = new Issuer({
      privateKey: ipriv,
      publicKey: ipub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });
    const result = await issuer.issue({
      subject: defaultPidSubject(),
      holderKey: hpub,
      vct: EU_PID_VCT,
    });
    expect(parseSdJwt(result.token).header.typ).toBe("dc+sd-jwt");
  });

  it("can mix nested SD (birth_place.*) with top-level SD claims", async () => {
    const { pub: ipub, priv: ipriv } = await makeKey();
    const { pub: hpub } = await makeKey();
    const issuer = new Issuer({
      privateKey: ipriv,
      publicKey: ipub,
      alg: "ES256",
      issuerId: "https://issuer.example.com",
    });

    // Top-level SD via `selectivelyDisclosable` on simple claims;
    // nested SD via `sd()` inside the `birth_place` object.
    const subject = {
      given_name: "Alice",
      family_name: "Smith",
      birthdate: "1990-04-15",
      birth_place: {
        country: sd("DE"),
        locality: sd("Berlin"),
      },
      nationalities: ["DE", "FR"],
      issuing_country: "DE",
      issuing_authority: "DE-IDS",
      expiry_date: "2030-01-01",
    };

    const result = await issuer.issue({
      subject,
      selectivelyDisclosable: ["given_name", "family_name", "birthdate"],
      holderKey: hpub,
      vct: EU_PID_VCT,
    });

    // 3 top-level + 2 nested = 5 disclosures
    expect(result.disclosures).toHaveLength(5);

    const verified = verifyHashBinding(parseSdJwt(result.token));
    expect(verified.unmatchedDisclosures).toHaveLength(0);
    expect(verified.claims["birth_place"]).toEqual({
      country: "DE",
      locality: "Berlin",
    });
  });
});

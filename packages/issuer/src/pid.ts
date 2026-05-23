// EU Digital Identity (EUDI) Person Identification Data (PID) — claim
// helpers + status-list helper for the SD-JWT-VC encoding profile.
//
// Spec drivers
// ------------
// - PID Rulebook (Attestation Rulebooks Catalog, current main) §2.2 and §2.4
//   enumerate the mandatory claims for a PID attestation.
// - PID Rulebook §4.1.1 lists the canonical SD-JWT-VC claim names — note
//   `birthdate` is one word (no underscore), aligned with OpenID Connect
//   Core §5.1.
// - PID Rulebook §4.1 specifies `address` as a nested object and
//   `nationalities` as a JSON array; both can be encoded with nested
//   selective disclosure via `sd()` from `@gramota/sd-jwt`.
// - ARF Annex 2 PID_14 fixes the base `vct = "urn:eudi:pid:1"`.
//
// This module exposes the constants + default-subject shape so callers
// (the SaaS issuer route, the SDK demo, integration tests) can produce
// a rulebook-conformant credential without hand-keying the claim names.

import { sd, type SdValue } from "@gramota/sd-jwt";

/** Base `vct` value for an EU PID per ARF Annex 2 PID_14. Country-specific
 * variants (`urn:eudi:pid:de:1`, etc.) extend this — callers can pass
 * their own VCT string to {@link Issuer.issue} if a country profile is
 * required. */
export const EU_PID_VCT = "urn:eudi:pid:1";

/** OID4VCI credential-configuration-id convention used by the EU
 * reference wallet for the SD-JWT-VC PID. */
export const EU_PID_CREDENTIAL_CONFIGURATION_ID = "urn:eudi:pid:1_sd_jwt_vc";

/**
 * Canonical PID claim names per PID Rulebook §4.1.1.
 *
 * Held as constants rather than free-form strings so that the inevitable
 * one-character typo (`birth_date` vs `birthdate`, `nationality` vs
 * `nationalities`) is a compile-time error, not a silent rejection by an
 * EU verifier.
 */
export const PidClaim = {
  /** Family name (surname). PID Rulebook §2.2 mandatory. */
  family_name: "family_name" as const,
  /** Given (first) name. PID Rulebook §2.2 mandatory. */
  given_name: "given_name" as const,
  /** ISO 8601 birthdate. Note: ONE WORD, no underscore, per Rulebook §4.1.1
   * and OIDC Core §5.1 (NOT `birth_date`). */
  birthdate: "birthdate" as const,
  /** Birth place — string or nested object per Rulebook §4.1.1. PID Rulebook
   * §2.2 mandatory. */
  birth_place: "birth_place" as const,
  /** ISO 3166-1 alpha-2 country codes — JSON array per Rulebook §4.1.1.
   * Note: PLURAL, not `nationality`. PID Rulebook §2.2 mandatory. */
  nationalities: "nationalities" as const,
  /** ISO 3166-1 alpha-2 — issuing-country metadata. PID Rulebook §2.4
   * mandatory. */
  issuing_country: "issuing_country" as const,
  /** Issuing-authority identifier (string). PID Rulebook §2.4 mandatory. */
  issuing_authority: "issuing_authority" as const,
  /** ISO 8601 PID-domain expiry-date (YYYY-MM-DD). PID Rulebook §2.4
   * mandatory. NOT a substitute for the JWT `exp` claim — they encode
   * different concepts. */
  expiry_date: "expiry_date" as const,
} as const;

/** Tuple of names from {@link PidClaim} for the PID Rulebook §2.2/§2.4
 * mandatory set. Useful to pass as `selectivelyDisclosable` when every
 * mandatory claim should be SD (the HAIP profile expectation). */
export const PID_MANDATORY_CLAIM_NAMES = [
  PidClaim.family_name,
  PidClaim.given_name,
  PidClaim.birthdate,
  PidClaim.birth_place,
  PidClaim.nationalities,
  PidClaim.issuing_country,
  PidClaim.issuing_authority,
  PidClaim.expiry_date,
] as const;

/**
 * Shape of a fully-populated PID subject per PID Rulebook §2.2 + §2.4.
 *
 * Every field listed is REQUIRED for a Rulebook-conformant PID. Defaults
 * (e.g. test/dev) should fill all of these — see {@link defaultPidSubject}.
 *
 * Fields are typed loosely (`unknown`) to allow callers to pass either
 * plain values or `sd()`-wrapped values for nested selective disclosure.
 */
export interface PidSubject {
  readonly family_name: unknown;
  readonly given_name: unknown;
  /** Canonical spelling per Rulebook §4.1.1 — one word. */
  readonly birthdate: unknown;
  /** String or nested object per Rulebook §4.1.1 (`{country, locality}`
   * pattern is common). */
  readonly birth_place: unknown;
  /** Array of ISO 3166-1 alpha-2 codes. Can be a plain array OR an array
   * containing `sd()` markers for per-element selective disclosure. */
  readonly nationalities: unknown;
  readonly issuing_country: unknown;
  readonly issuing_authority: unknown;
  /** YYYY-MM-DD per Rulebook §4.1.1 (distinct from JWT `exp`). */
  readonly expiry_date: unknown;
  /** Extra non-mandatory claims (resident_address, sex, age_over_18, …)
   * are permitted by the Rulebook §4.1.1 list — callers can include any
   * of them via string-keyed access. */
  readonly [extra: string]: unknown;
}

/** Inputs to {@link defaultPidSubject}. All optional — every field has a
 * test-defaulting fallback so a zero-config caller (e.g. an integration
 * test that just wants "any valid PID") produces a Rulebook-shaped
 * credential without typing eight strings by hand. */
export interface DefaultPidSubjectOptions {
  readonly family_name?: string;
  readonly given_name?: string;
  /** ISO 8601 birthdate (one-word claim name). */
  readonly birthdate?: string;
  /** Plain string or `{country, locality}` object. */
  readonly birth_place?: string | Record<string, unknown>;
  /** ISO 3166-1 alpha-2 codes. */
  readonly nationalities?: readonly string[];
  /** ISO 3166-1 alpha-2 — the issuing country. */
  readonly issuing_country?: string;
  /** String identifier — IACA, IDS, ministry code, etc. */
  readonly issuing_authority?: string;
  /** YYYY-MM-DD attribute expiry (distinct from JWT exp). */
  readonly expiry_date?: string;
  /** Pass true to wrap individual `nationalities` array elements in `sd()`
   * so each one is selectively disclosable. Default `false` (plain
   * array) — top-level SD via `selectivelyDisclosable` still works.
   *
   * Per PID Rulebook §4.1.1 either encoding is acceptable; the SD-per-
   * element form is more privacy-preserving when a holder wants to
   * disclose "I have at least one nationality" without revealing which. */
  readonly nationalitiesPerElementSd?: boolean;
  /** Pass true to wrap individual `birth_place` sub-fields in `sd()` when
   * `birth_place` is a nested object. Default `false`. */
  readonly birthPlaceNestedSd?: boolean;
}

/**
 * Build a PID Rulebook §2.2/§2.4-conformant default subject for testing
 * and dev. Every mandatory claim is present; callers can override any
 * field individually.
 *
 * Production callers SHOULD supply real values via the options bag rather
 * than relying on the defaults — defaults are "valid shape" only, not
 * meaningful identity data.
 *
 * Returns a `PidSubject` ready to pass directly as the `subject` field
 * of {@link IssueOptions} or {@link BatchIssueOptions}.
 */
export function defaultPidSubject(
  options: DefaultPidSubjectOptions = {},
): Record<string, unknown> {
  const nationalitiesArray = options.nationalities ?? ["DE"];

  // Per-element SD wrapping: each entry becomes `sd("DE")` so the holder
  // can disclose individual codes. The verifier sees `{"...": digest}`
  // slots in the array; absent disclosures are silently withheld.
  const nationalities: readonly (string | SdValue<string>)[] =
    options.nationalitiesPerElementSd === true
      ? nationalitiesArray.map((n) => sd(n))
      : nationalitiesArray;

  // birth_place: plain string OR object. Nested-SD only applies to the
  // object form (you can't SD-wrap individual chars of a string).
  let birthPlace: unknown = options.birth_place ?? "Berlin";
  if (
    options.birthPlaceNestedSd === true &&
    typeof birthPlace === "object" &&
    birthPlace !== null
  ) {
    const wrapped: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(birthPlace)) {
      wrapped[k] = sd(v);
    }
    birthPlace = wrapped;
  }

  return {
    [PidClaim.family_name]: options.family_name ?? "Doe",
    [PidClaim.given_name]: options.given_name ?? "John",
    [PidClaim.birthdate]: options.birthdate ?? "1990-01-01",
    [PidClaim.birth_place]: birthPlace,
    [PidClaim.nationalities]: nationalities,
    [PidClaim.issuing_country]: options.issuing_country ?? "DE",
    [PidClaim.issuing_authority]: options.issuing_authority ?? "DE-PID-AUTH",
    [PidClaim.expiry_date]: options.expiry_date ?? "2030-01-01",
  };
}

// ---------------------------------------------------------------------------
// Token Status List helper
// ---------------------------------------------------------------------------

/**
 * Canonical SD-JWT-VC `status` claim shape per IETF
 * draft-ietf-oauth-status-list (Token Status List) §3.1.
 *
 * Use this when you want the type system to enforce the `{ status_list:
 * { uri, idx } }` shape; pass the result to {@link IssueOptions.status}
 * (the option is loosely typed as `Record<string, unknown>` to leave
 * room for future status schemes).
 *
 * Skipping the helper and the `status` option entirely produces a
 * credential without a `status` claim — see {@link IssueOptions.status}
 * for the semantics of that choice.
 */
export interface StatusListReference {
  readonly status_list: {
    /** Resolvable URL pointing at a Token Status List JWT/CWT published
     * by the issuer. */
    readonly uri: string;
    /** Zero-based index of this credential's slot inside the list. */
    readonly idx: number;
  };
}

/**
 * Build a Token Status List `status` reference for {@link IssueOptions.status}.
 *
 * Trivial shape — the helper exists primarily so callers don't repeat the
 * `{ status_list: { uri, idx } }` literal at every issuance site and so
 * `uri` / `idx` typos surface at compile time, not at verification.
 */
export function statusListReference(
  uri: string,
  idx: number,
): StatusListReference {
  return { status_list: { uri, idx } };
}

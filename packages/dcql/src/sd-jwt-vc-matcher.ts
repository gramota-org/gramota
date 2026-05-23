import type { ParsedSdJwt } from "@gramota/sd-jwt";
import type { DcqlClaimQuery, DcqlCredentialQuery } from "./types.js";
import { evaluateDcqlPath, leafPropertyName } from "./path.js";

/** A holder-side credential view the matcher consumes. Decoupled from
 * `@gramota/holder`'s StoredCredential for testability. */
export interface SdJwtVcCredentialView {
  parsed: ParsedSdJwt;
}

export const SD_JWT_VC_FORMAT = "vc+sd-jwt";
export const DC_SD_JWT_VC_FORMAT = "dc+sd-jwt";

/**
 * VCT matching strategy.
 *
 * - `strict` (default, backwards-compatible): the credential's `vct`
 *   claim MUST appear byte-for-byte in `meta.vct_values`. This is the
 *   spec-literal reading of OID4VP §6.1 and DCQL `vct_values`.
 *
 * - `eudi-pid-extensions`: like `strict`, plus the credential's `vct`
 *   may be a domestic extension of a queried base PID type. That is, a
 *   query asking for `urn:eudi:pid:1` is satisfied by a credential
 *   whose `vct` is `urn:eudi:pid:<cc>:1` (e.g. `urn:eudi:pid:de:1`,
 *   `urn:eudi:pid:fr:1`).
 *
 *   Rationale: ARF Annex 3.01 §3 defines a base cross-border PID type
 *   `urn:eudi:pid:1` plus member-state-specific extensions of the form
 *   `urn:eudi:pid:<ISO-3166-1-alpha-2-lowercase>:1`. A relying party
 *   querying for the base type should — by policy, when configured —
 *   accept either, since the extension is a superset and the base
 *   claims are guaranteed to be present.
 *
 * Verifiers that want spec-literal strictness leave this at the
 * default. Verifiers that want to interop with member-state PID
 * issuers without re-encoding their query opt in.
 */
export type DcqlVctMatchMode = "strict" | "eudi-pid-extensions";

export interface DcqlSdJwtVcMatcherOptions {
  /** VCT match strategy. Default `"strict"`. */
  vctMatchMode?: DcqlVctMatchMode;
}

/** Regex for member-state PID extensions per ARF Annex 3.01 §3:
 * `urn:eudi:pid:<cc>:<version>`, where `<cc>` is a 2-letter
 * lowercase ISO-3166-1-alpha-2 country code. We accept any 2-letter
 * lowercase code so the matcher doesn't bake an enum that has to
 * track ISO updates; downstream policy can constrain further. */
const PID_EXTENSION_RE = /^urn:eudi:pid:([a-z]{2}):([\w.-]+)$/;
/** Regex for the base PID urn: `urn:eudi:pid:<version>`. */
const PID_BASE_RE = /^urn:eudi:pid:([\w.-]+)$/;

/** True iff `candidate` is a PID extension of `base` per ARF Annex
 * 3.01 §3 — same version, with a member-state country code inserted.
 *
 * Example:
 *   isPidExtensionOf("urn:eudi:pid:de:1", "urn:eudi:pid:1") === true
 *   isPidExtensionOf("urn:eudi:pid:de:1", "urn:eudi:pid:2") === false  (version mismatch)
 *   isPidExtensionOf("urn:eudi:pid:1",    "urn:eudi:pid:1") === false  (not an *extension*; falls under strict-equality match)
 */
export function isPidExtensionOf(candidate: string, base: string): boolean {
  const ext = PID_EXTENSION_RE.exec(candidate);
  if (ext === null) return false;
  const baseMatch = PID_BASE_RE.exec(base);
  if (baseMatch === null) return false;
  // ext[2] is the candidate's version; baseMatch[1] is the base's version.
  return ext[2] === baseMatch[1];
}

export interface DcqlMatchResult {
  /** Names of selectively-disclosable claims required to satisfy the query. */
  disclose: readonly string[];
  /** Per-claim detail for audit. */
  satisfiedClaims: readonly {
    id: string | undefined;
    path: readonly (string | number | null)[];
  }[];
}

/** Match an SD-JWT-VC credential against a DCQL credential query.
 *
 * Returns `null` if the credential cannot satisfy the query.
 *
 * Match rules (v1):
 *   - format must be "vc+sd-jwt" or "dc+sd-jwt"
 *   - meta.vct_values (if present) — credential's `vct` claim must be
 *     matched per the configured {@link DcqlVctMatchMode} (`strict`
 *     equality by default; or domestic PID extensions accepted when
 *     `eudi-pid-extensions` is set).
 *   - every claim in `claims[]` must be available either as a disclosure
 *     (single-segment path) or directly in the JWT payload (multi-segment)
 *   - claim values, when specified via `values: [...]`, must equal one of them
 */
export class DcqlSdJwtVcMatcher {
  readonly #vctMatchMode: DcqlVctMatchMode;

  constructor(options: DcqlSdJwtVcMatcherOptions = {}) {
    this.#vctMatchMode = options.vctMatchMode ?? "strict";
  }

  match(
    credential: SdJwtVcCredentialView,
    query: DcqlCredentialQuery,
  ): DcqlMatchResult | null {
    if (
      query.format !== SD_JWT_VC_FORMAT &&
      query.format !== DC_SD_JWT_VC_FORMAT
    ) {
      return null;
    }

    if (query.meta !== undefined) {
      const vctValues = (query.meta as { vct_values?: unknown }).vct_values;
      if (Array.isArray(vctValues) && vctValues.length > 0) {
        const credVct = (credential.parsed.payload as Record<string, unknown>)[
          "vct"
        ];
        if (typeof credVct !== "string" || !this.#vctMatches(credVct, vctValues)) {
          return null;
        }
      }
    }

    const claims = query.claims ?? [];
    const disclose = new Set<string>();
    const satisfiedClaims: {
      id: string | undefined;
      path: readonly (string | number | null)[];
    }[] = [];

    for (const claim of claims) {
      const ok = matchClaim(credential, claim, disclose);
      if (!ok) return null;
      satisfiedClaims.push({ id: claim.id, path: claim.path });
    }

    return { disclose: [...disclose], satisfiedClaims };
  }

  /** Format identifiers this matcher handles. */
  get formats(): readonly string[] {
    return [SD_JWT_VC_FORMAT, DC_SD_JWT_VC_FORMAT];
  }

  /** Active VCT match mode. Exposed for tests + diagnostics. */
  get vctMatchMode(): DcqlVctMatchMode {
    return this.#vctMatchMode;
  }

  #vctMatches(credVct: string, vctValues: readonly unknown[]): boolean {
    if (vctValues.includes(credVct)) return true;
    if (this.#vctMatchMode !== "eudi-pid-extensions") return false;
    // ARF Annex 3.01 §3: accept a domestic PID extension when the
    // query asked for the cross-border base type.
    for (const v of vctValues) {
      if (typeof v === "string" && isPidExtensionOf(credVct, v)) return true;
    }
    return false;
  }
}

function matchClaim(
  credential: SdJwtVcCredentialView,
  claim: DcqlClaimQuery,
  disclose: Set<string>,
): boolean {
  const leaf = leafPropertyName(claim.path);
  if (leaf !== null) {
    const disc = credential.parsed.disclosures.find((d) => d.name === leaf);
    if (disc !== undefined && passesValueConstraint(disc.value, claim)) {
      disclose.add(leaf);
      return true;
    }
    const direct = (credential.parsed.payload as Record<string, unknown>)[leaf];
    if (direct !== undefined && passesValueConstraint(direct, claim)) {
      return true;
    }
    return false;
  }

  const value = evaluateDcqlPath(claim.path, credential.parsed.payload);
  if (value === undefined) return false;
  if (!passesValueConstraint(value, claim)) return false;
  return true;
}

function passesValueConstraint(
  value: unknown,
  claim: DcqlClaimQuery,
): boolean {
  if (claim.values === undefined) return true;
  if (claim.values.length === 0) return true;
  return claim.values.includes(value);
}

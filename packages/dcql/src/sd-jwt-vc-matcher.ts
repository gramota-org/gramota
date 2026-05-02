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
 *   - meta.vct_values (if present) — credential's `vct` claim must be in the list
 *   - every claim in `claims[]` must be available either as a disclosure
 *     (single-segment path) or directly in the JWT payload (multi-segment)
 *   - claim values, when specified via `values: [...]`, must equal one of them
 */
export class DcqlSdJwtVcMatcher {
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
        if (typeof credVct !== "string" || !vctValues.includes(credVct)) {
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

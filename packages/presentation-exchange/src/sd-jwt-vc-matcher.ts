import type { ParsedSdJwt } from "@gateway/sd-jwt";
import { leafClaimName, evaluateJsonPath } from "./jsonpath.js";
import type { CredentialMatcher, MatchResult } from "./matcher.js";
import type { Field, InputDescriptor } from "./types.js";

/** Convenience: a holder-stored credential exposes its parsed form. We
 * accept either the full StoredCredential shape or just the parsed view —
 * keeping the matcher decoupled from `@gateway/holder`'s internals. */
export interface SdJwtVcCredentialView {
  parsed: ParsedSdJwt;
}

export const SD_JWT_VC_FORMAT = "vc+sd-jwt";

/** Match SD-JWT-VC credentials against a Presentation Definition descriptor. */
export class SdJwtVcMatcher
  implements CredentialMatcher<SdJwtVcCredentialView>
{
  readonly format = SD_JWT_VC_FORMAT;

  appliesTo(descriptor: InputDescriptor): boolean {
    if (descriptor.format === undefined) return true; // PD-level format applies
    return Object.keys(descriptor.format).some(
      (f) => f === SD_JWT_VC_FORMAT || f === "dc+sd-jwt",
    );
  }

  match(
    credential: SdJwtVcCredentialView,
    descriptor: InputDescriptor,
  ): MatchResult | null {
    const fields = descriptor.constraints.fields ?? [];
    const required = fields.filter((f) => !f.optional);
    const optional = fields.filter((f) => !!f.optional);

    const disclose = new Set<string>();
    const satisfiedFields: {
      fieldId: string | undefined;
      path: string;
    }[] = [];

    for (const field of required) {
      const sat = matchField(credential, field, disclose);
      if (sat === null) return null; // a required field failed → no match
      satisfiedFields.push({ fieldId: field.id, path: sat });
    }
    for (const field of optional) {
      const sat = matchField(credential, field, disclose);
      if (sat !== null) {
        satisfiedFields.push({ fieldId: field.id, path: sat });
      }
    }

    return {
      disclose: [...disclose],
      satisfiedFields,
    };
  }
}

/** Try each path in a field; return the first matching path string, or null. */
function matchField(
  credential: SdJwtVcCredentialView,
  field: Field,
  discloseAccumulator: Set<string>,
): string | null {
  for (const path of field.path) {
    // First try: leaf claim name in the disclosures (most common SD-JWT-VC case).
    const leaf = leafClaimName(path);
    if (leaf !== null) {
      const disc = credential.parsed.disclosures.find(
        (d) => d.name === leaf,
      );
      if (disc !== undefined && passesFilter(disc.value, field)) {
        discloseAccumulator.add(leaf);
        return path;
      }
      // Also accept claims directly present in the JWT payload (non-SD).
      const direct = (credential.parsed.payload as Record<string, unknown>)[
        leaf
      ];
      if (direct !== undefined && passesFilter(direct, field)) {
        return path;
      }
    } else {
      // Nested or complex path — evaluate against payload (post-disclosure
      // expansion is the verifier's concern; here we approximate by walking
      // the parsed payload).
      const value = evaluateJsonPath(path, credential.parsed.payload);
      if (value !== undefined && passesFilter(value, field)) {
        return path;
      }
    }
  }
  return null;
}

function passesFilter(value: unknown, field: Field): boolean {
  if (field.filter === undefined) return true;
  const expected = field.filter.type;
  if (expected === undefined) return true;
  switch (expected) {
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    default:
      return true;
  }
}

/**
 * DCQL path evaluator.
 *
 * Per OID4VP 2.0 DCQL §6.4, claim paths are arrays of segments:
 *   - string  → property key
 *   - number  → array index
 *   - null    → wildcard (any element of an array)
 *
 * Returns the matched value (single match) or undefined.
 *
 * For SD-JWT-VC, "any element" matching is rare — most paths are single
 * property keys (top-level claims). Multi-value wildcard semantics
 * (returning the cross product of matches) are deferred to v2.
 */

import { DcqlError } from "./types.js";

export type DcqlPathSegment = string | number | null;

/** Evaluate a DCQL path against a value. */
export function evaluateDcqlPath(
  path: readonly DcqlPathSegment[],
  root: unknown,
): unknown {
  let current: unknown = root;
  for (const seg of path) {
    if (current === null || current === undefined) return undefined;
    if (seg === null) {
      if (!Array.isArray(current)) return undefined;
      // Single-value evaluator: take the first element. True wildcard
      // (cross product) is v2.
      current = current[0];
      continue;
    }
    if (typeof seg === "number") {
      if (!Array.isArray(current)) return undefined;
      current = current[seg];
      continue;
    }
    if (typeof seg === "string") {
      if (typeof current !== "object" || Array.isArray(current)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[seg];
      continue;
    }
    throw new DcqlError(
      "dcql.invalid_path",
      `DCQL path segment must be string, number, or null; got ${typeof seg}`,
    );
  }
  return current;
}

/** Validate a DCQL path is well-formed. Throws on invalid input. */
export function validateDcqlPath(path: unknown): void {
  if (!Array.isArray(path) || path.length === 0) {
    throw new DcqlError(
      "dcql.invalid_path",
      "DCQL path must be a non-empty array",
    );
  }
  for (const seg of path) {
    if (
      seg !== null &&
      typeof seg !== "string" &&
      typeof seg !== "number"
    ) {
      throw new DcqlError(
        "dcql.invalid_path",
        `DCQL path segment must be string, number, or null; got ${typeof seg}`,
      );
    }
  }
}

/** When the path is a single string segment, return that string —
 * the most common SD-JWT-VC case (top-level disclosure name). */
export function leafPropertyName(
  path: readonly DcqlPathSegment[],
): string | null {
  if (path.length === 1 && typeof path[0] === "string") return path[0];
  return null;
}

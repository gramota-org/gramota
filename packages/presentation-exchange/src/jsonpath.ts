/**
 * Minimal JSONPath subset sufficient for SD-JWT-VC presentation queries.
 *
 * Supported:
 *   $                  — the root
 *   $.foo              — property
 *   $.foo.bar          — nested property
 *   $['foo']           — bracket notation
 *   $['foo']['bar']    — chained bracket
 *   $.foo[0]           — array index
 *
 * NOT supported (v1):
 *   $..foo             — recursive descent
 *   $.foo[*]           — wildcards
 *   $[?(@.x>0)]        — filters
 *
 * Returns the matched value, or `undefined` if no match. Throws only on
 * malformed expressions.
 */

import { PresentationExchangeError } from "./types.js";

export type JsonPathSegment =
  | { kind: "property"; name: string }
  | { kind: "index"; index: number };

export function parseJsonPath(expr: string): readonly JsonPathSegment[] {
  if (typeof expr !== "string" || expr.length === 0) {
    throw new PresentationExchangeError("pe.jsonpath_invalid", "JSONPath: empty expression");
  }
  if (expr === "$") return [];
  if (!expr.startsWith("$")) {
    throw new PresentationExchangeError(
      "pe.jsonpath_invalid",
      `JSONPath: expression must start with '$', got: ${expr}`,
    );
  }

  const segments: JsonPathSegment[] = [];
  let i = 1; // past the leading $
  while (i < expr.length) {
    const ch = expr.charAt(i);
    if (ch === ".") {
      i++;
      // Read property name up to next '.', '[' or end.
      let j = i;
      while (j < expr.length && expr.charAt(j) !== "." && expr.charAt(j) !== "[") j++;
      const name = expr.slice(i, j);
      if (name.length === 0) {
        throw new PresentationExchangeError(
          "pe.jsonpath_invalid",
          `JSONPath: empty property name at position ${i}`,
        );
      }
      segments.push({ kind: "property", name });
      i = j;
    } else if (ch === "[") {
      i++;
      // Bracket: index ([0]) or quoted property (['foo']).
      if (expr.charAt(i) === "'" || expr.charAt(i) === '"') {
        const quote = expr.charAt(i);
        const end = expr.indexOf(quote, i + 1);
        if (end === -1) {
          throw new PresentationExchangeError(
            "pe.jsonpath_invalid",
            `JSONPath: unterminated quote at position ${i}`,
          );
        }
        const name = expr.slice(i + 1, end);
        if (expr.charAt(end + 1) !== "]") {
          throw new PresentationExchangeError(
            "pe.jsonpath_invalid",
            `JSONPath: expected ']' after quoted name at position ${end + 1}`,
          );
        }
        segments.push({ kind: "property", name });
        i = end + 2;
      } else {
        const end = expr.indexOf("]", i);
        if (end === -1) {
          throw new PresentationExchangeError(
            "pe.jsonpath_invalid",
            `JSONPath: unterminated '[' at position ${i - 1}`,
          );
        }
        const idxStr = expr.slice(i, end);
        const idx = Number.parseInt(idxStr, 10);
        if (!Number.isInteger(idx) || idx < 0 || String(idx) !== idxStr) {
          throw new PresentationExchangeError(
            "pe.jsonpath_invalid",
            `JSONPath: invalid array index '${idxStr}' at position ${i}`,
          );
        }
        segments.push({ kind: "index", index: idx });
        i = end + 1;
      }
    } else {
      throw new PresentationExchangeError(
        "pe.jsonpath_invalid",
        `JSONPath: unexpected character '${ch}' at position ${i}`,
      );
    }
  }
  return segments;
}

/** Evaluate a JSONPath against a value. Returns the matched leaf or undefined. */
export function evaluateJsonPath(expr: string, root: unknown): unknown {
  const segments = parseJsonPath(expr);
  let current: unknown = root;
  for (const seg of segments) {
    if (current === null || current === undefined) return undefined;
    if (seg.kind === "property") {
      if (typeof current !== "object" || Array.isArray(current)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[seg.name];
    } else {
      if (!Array.isArray(current)) return undefined;
      current = current[seg.index];
    }
  }
  return current;
}

/** Return the leaf claim name for a single-segment path like `$.given_name`,
 * or null for longer or non-property paths. Useful for SD-JWT-VC where a
 * top-level disclosure name == the JSONPath leaf. */
export function leafClaimName(expr: string): string | null {
  const segments = parseJsonPath(expr);
  if (segments.length === 1 && segments[0]?.kind === "property") {
    return segments[0].name;
  }
  return null;
}

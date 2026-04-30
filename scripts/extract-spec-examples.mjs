#!/usr/bin/env node
/**
 * Extracts the canonical IETF SD-JWT spec test vectors from the EU Kotlin
 * reference library (refs/eudi-lib-jvm-sdjwt-kt) and writes them as plain-text
 * fixtures into packages/sd-jwt/tests/fixtures/ietf-spec/.
 *
 * Run from repo root:
 *   node scripts/extract-spec-examples.mjs
 *
 * The fixtures get committed; this script is the provenance trail.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(
  root,
  "refs/eudi-lib-jvm-sdjwt-kt/src/test/kotlin/eu/europa/ec/eudi/sdjwt/SpecExamples.kt",
);
const outDir = resolve(
  root,
  "packages/sd-jwt/tests/fixtures/ietf-spec",
);
mkdirSync(outDir, { recursive: true });

const content = readFileSync(src, "utf-8");

// SpecExamples.kt embeds each canonical SD-JWT as a Kotlin triple-quoted
// raw string. We split on `"""` and take the odd-indexed parts (the contents).
const parts = content.split('"""');
const tokens = [];
for (let i = 1; i < parts.length; i += 2) {
  const cleaned = parts[i].replace(/\s+/g, "");
  if (cleaned.length > 100) tokens.push(cleaned);
}

if (tokens.length !== 3) {
  console.error(
    `expected 3 spec examples, found ${tokens.length} — SpecExamples.kt may have changed`,
  );
  process.exit(1);
}

const slugs = [
  "spec-example-1-all-disclosed",
  "spec-example-1-selective",
  "spec-example-3-complex",
];

slugs.forEach((slug, i) => {
  const path = join(outDir, `${slug}.txt`);
  writeFileSync(path, tokens[i] + "\n");
  console.log(`wrote ${path} (${tokens[i].length} chars)`);
});

console.log(`Extracted ${tokens.length} IETF spec examples.`);

import { createHash, randomBytes } from "node:crypto";
import {
  SdJwtError,
  type SdJwtDisclosure,
  type SdJwtHeader,
} from "./types.js";

export interface IssueSdJwtOptions {
  /** Non-selectively-disclosable claims placed directly in the JWT payload.
   *
   * May contain {@link sd}-wrapped values at any nesting depth to produce
   * nested object-property disclosures and array-element disclosures per
   * IETF SD-JWT §4.2.4–4.2.5. See {@link sd}. */
  payload: Record<string, unknown>;
  /** Top-level selectively-disclosable object-property claims.
   *
   * Each entry produces one top-level disclosure whose digest appears in
   * the top-level `_sd` array. Values may themselves contain nested
   * {@link sd}-wrapped fragments — those are encoded as nested disclosures
   * referenced from nested `_sd` arrays inside the value. */
  sdClaims?: Record<string, unknown>;
  /** JWT signing algorithm (placed in header `alg`). The signature itself is
   * produced by `signer` — this library does not perform cryptographic signing
   * (that is `@gramota/jose`'s job). */
  alg: string;
  /** Optional `typ` header claim (e.g. "dc+sd-jwt", "vc+sd-jwt"). */
  typ?: string;
  /** Async (or sync) signer. Receives `header.payload` (the bytes to sign) and
   * returns the base64url-encoded signature. Use `stubSignature` for tests. */
  signer: (signedPayload: string) => Promise<string> | string;
  /** Hash algorithm (default "sha-256"). Sets `_sd_alg` when sdClaims present. */
  hashAlg?: HashAlg;
  /** Salt generator returning a base64url string. Pluggable for deterministic
   * testing. Default: 128-bit random salt. */
  saltGenerator?: () => string;
  /** Additional header parameters (kid, x5c, etc.). */
  extraHeader?: Record<string, unknown>;
}

export type HashAlg = "sha-256" | "sha-384" | "sha-512";

export interface IssuanceResult {
  token: string;
  disclosures: SdJwtDisclosure[];
}

// Failure codes raised by `issueSdJwt` are namespaced `sd_jwt.issue.*`.
// See `SdJwtErrorCode` in `./types.ts` for the full union.

/** Constant placeholder for tests where the signature is not verified. */
export const stubSignature = (): string => "stub-signature";

// ---------------------------------------------------------------------------
// `sd()` — marker for nested and array-element selective disclosure
// ---------------------------------------------------------------------------

/** Unique brand symbol — non-exported on purpose; the only way to make an
 * `SdValue` is via {@link sd}. Using a symbol (rather than a string property
 * name) prevents any user-supplied data shape from being mistaken for an
 * SD marker — JSON.parse can't synthesise symbol keys. */
const SD_MARKER: unique symbol = Symbol.for("@gramota/sd-jwt/sd-marker");

/** Brand object returned by {@link sd}. The encoder walks the input and
 * replaces any node tagged with this brand with a hash-bound disclosure.
 *
 * The shape is intentionally minimal — one symbol-keyed property holding
 * the underlying value. Walking code uses {@link isSdValue} to recognise
 * the marker. */
export interface SdValue<T = unknown> {
  readonly [SD_MARKER]: T;
}

/**
 * Mark a value as selectively disclosable.
 *
 * Where you place `sd(value)` determines the disclosure shape:
 *
 *   - Inside an **object** as a property value:
 *       `{ given_name: sd("Alice"), country: "DE" }`
 *     The encoder emits an object-property disclosure (`[salt, "given_name",
 *     "Alice"]`), drops the property from the visible object, and adds the
 *     digest to that object's `_sd` array. The `country: "DE"` pair stays
 *     visible. This is the nested-SD case from IETF SD-JWT §4.2.4.
 *
 *   - Inside an **array** as an element:
 *       `[sd("DE"), "FR"]`
 *     The encoder emits an array-element disclosure (`[salt, "DE"]`, arity
 *     2) and replaces the element with `{"...": digest}`. The `"FR"` element
 *     stays plain. This is the array-element case from IETF SD-JWT §4.2.5.
 *
 *   - At the **top level**, prefer the `sdClaims` option — equivalent shape
 *     but reads more directly at the call site for the common case.
 *
 * Nesting is unrestricted: an `sd()`-wrapped value can itself be an object
 * containing more `sd()` markers, and so on. The encoder walks all the way
 * down and produces one disclosure per `sd()` marker found.
 *
 * Per IETF SD-JWT §4.1.1, each disclosure gets its own fresh salt.
 */
export function sd<T>(value: T): SdValue<T> {
  return { [SD_MARKER]: value };
}

/** True iff `node` was produced by {@link sd}. */
function isSdValue(node: unknown): node is SdValue {
  return (
    node !== null &&
    typeof node === "object" &&
    SD_MARKER in (node as object)
  );
}

/** Unwrap an `SdValue` to its underlying raw value. */
function unwrap(node: SdValue): unknown {
  return (node as { [SD_MARKER]: unknown })[SD_MARKER];
}

/**
 * Build a compact-serialized SD-JWT-VC.
 *
 * The encoder produces three kinds of disclosure per IETF SD-JWT §4.2:
 *
 *  1. **Top-level object-property** — for every entry in `sdClaims`. The
 *     disclosure is `[salt, name, value]`; its digest goes into the
 *     top-level `_sd` array. The matching property is omitted from the
 *     visible payload.
 *
 *  2. **Nested object-property** — wherever {@link sd} wraps a value inside
 *     an object, anywhere in `payload` or inside an `sdClaims` value. Same
 *     `[salt, name, value]` disclosure shape; digest goes into a *nested*
 *     `_sd` array on the same parent object. The other (non-SD) properties
 *     of that parent remain visible.
 *
 *  3. **Array-element** — wherever {@link sd} wraps a value used as an
 *     array entry. The disclosure is `[salt, value]` (arity 2, no name);
 *     the array slot is replaced with `{"...": digest}`. Sibling plain
 *     entries remain visible.
 *
 * The walker is recursive — nesting is unrestricted in either direction
 * (SD inside SD inside arrays inside SD …).
 *
 * `_sd_alg` is set on the top-level payload exactly when at least one
 * disclosure is produced. Per spec, the algorithm is shared across the
 * whole credential.
 */
export async function issueSdJwt(
  opts: IssueSdJwtOptions,
): Promise<IssuanceResult> {
  const hashAlg = opts.hashAlg ?? "sha-256";
  const nodeHashAlg = toNodeHashAlg(hashAlg);
  const salt = opts.saltGenerator ?? defaultSaltGenerator;

  if (typeof opts.signer !== "function") {
    throw new SdJwtError("sd_jwt.issue.signer_required", "signer is required");
  }
  if (typeof opts.alg !== "string" || opts.alg.length === 0) {
    throw new SdJwtError("sd_jwt.issue.alg_required", "alg is required");
  }

  // Shared encoding context — disclosures accumulate here as the walker
  // recurses through both `payload` and each `sdClaims` value.
  const ctx: EncodeContext = {
    disclosures: [],
    salt,
    nodeHashAlg,
  };

  // First, recursively encode the `payload` tree. Any `sd()` markers inside
  // produce nested disclosures and rewrite the visible tree (digests into
  // local `_sd` arrays, `{...: digest}` into arrays).
  const visiblePayload = encodeContainer(opts.payload, ctx);

  // Then, encode top-level `sdClaims`. Each entry becomes an object-
  // property disclosure attached to the top-level `_sd` array. The
  // VALUE of each entry is itself recursively walked, so an entry like
  // `address: { street_address: sd("..."), country: "DE" }` produces one
  // top-level disclosure for `address` whose disclosed value carries a
  // nested `_sd` array — exactly the encoding from IETF SD-JWT §4.2.4.
  const topLevelDigests: string[] = [];
  for (const [name, rawValue] of Object.entries(opts.sdClaims ?? {})) {
    const visibleValue = encodeValue(rawValue, ctx);
    const digest = emitObjectDisclosure(name, visibleValue, ctx);
    topLevelDigests.push(digest);
  }

  // Build header.
  const header: SdJwtHeader = { alg: opts.alg, ...opts.extraHeader };
  if (opts.typ !== undefined) {
    header.typ = opts.typ;
  }
  const headerB64 = Buffer.from(JSON.stringify(header), "utf-8").toString(
    "base64url",
  );

  // Build payload: start from the visible-payload tree (nested SD already
  // rewritten in place), then merge in the top-level _sd array if any.
  const payload: Record<string, unknown> = { ...visiblePayload };
  if (topLevelDigests.length > 0) {
    // If the caller already placed nested SD inside `payload`, merge.
    const existing = Array.isArray(payload["_sd"])
      ? (payload["_sd"] as unknown[]).filter(
          (e): e is string => typeof e === "string",
        )
      : [];
    payload["_sd"] = [...existing, ...topLevelDigests];
  }
  if (ctx.disclosures.length > 0) {
    payload["_sd_alg"] = hashAlg;
  }
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString(
    "base64url",
  );

  // Sign.
  const signedPayload = `${headerB64}.${payloadB64}`;
  const signature = await opts.signer(signedPayload);
  if (typeof signature !== "string" || signature.length === 0) {
    throw new SdJwtError("sd_jwt.issue.signer_returned_empty", "signer returned an empty signature");
  }

  // Concatenate JWT + disclosures + trailing tilde.
  const jwt = `${signedPayload}.${signature}`;
  const token =
    ctx.disclosures.length === 0
      ? `${jwt}~`
      : `${jwt}~${ctx.disclosures.map((d) => d.raw).join("~")}~`;

  return { token, disclosures: ctx.disclosures };
}

// ---------------------------------------------------------------------------
// Recursive walker
// ---------------------------------------------------------------------------

interface EncodeContext {
  /** Disclosures emitted so far — mutated in place by the walker. */
  readonly disclosures: SdJwtDisclosure[];
  /** Per-disclosure salt generator. Called once per emitted disclosure. */
  readonly salt: () => string;
  /** Node-shaped hash algorithm string (e.g. "sha256"). */
  readonly nodeHashAlg: string;
}

/**
 * Encode a "container" — a payload-shaped object that should keep its own
 * keys but have any `sd()`-wrapped property values rewritten into a nested
 * `_sd` array.
 *
 * Used for the top-level payload and recursively for any nested object
 * encountered during the walk.
 */
function encodeContainer(
  node: Record<string, unknown>,
  ctx: EncodeContext,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const nestedDigests: string[] = [];

  for (const [key, value] of Object.entries(node)) {
    if (isSdValue(value)) {
      // Nested object-property disclosure: name=key, value=unwrap(value).
      // The unwrapped value itself is recursively walked so SD-wrapped
      // sub-values inside it are also emitted (e.g. nested objects).
      const innerVisible = encodeValue(unwrap(value), ctx);
      const digest = emitObjectDisclosure(key, innerVisible, ctx);
      nestedDigests.push(digest);
      // The property name disappears from the visible object — only its
      // digest in `_sd` indicates the slot existed.
      continue;
    }
    out[key] = encodeValue(value, ctx);
  }

  if (nestedDigests.length > 0) {
    // Preserve any caller-supplied `_sd` digests already on the object
    // (rare but valid — a caller could pre-mix raw digest strings) plus
    // the digests this pass produced.
    const existing = Array.isArray(out["_sd"])
      ? (out["_sd"] as unknown[]).filter(
          (e): e is string => typeof e === "string",
        )
      : [];
    out["_sd"] = [...existing, ...nestedDigests];
  }

  return out;
}

/**
 * Encode a value of unknown kind:
 *
 *  - `sd()`-wrapped at this level — caller already handled the wrapping
 *    in the parent (object property or array element). If we still see
 *    one here it means it was at an unsupported position (e.g. as a JSON
 *    root); we throw rather than silently emit a structurally-wrong
 *    disclosure.
 *  - plain object — recurse via {@link encodeContainer}.
 *  - array — walk each element; `sd()`-wrapped elements become
 *    `{"...": digest}` slots, plain elements pass through.
 *  - primitive (string/number/boolean/null) — pass through unchanged.
 */
function encodeValue(value: unknown, ctx: EncodeContext): unknown {
  if (isSdValue(value)) {
    throw new SdJwtError(
      "sd_jwt.issue.sd_marker_misplaced",
      "sd() marker can only appear as an object property value, an array element, or a top-level sdClaims entry",
    );
  }
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const el of value) {
      if (isSdValue(el)) {
        // Array-element disclosure: arity-2 `[salt, value]` (no name).
        const innerVisible = encodeValue(unwrap(el), ctx);
        const digest = emitArrayDisclosure(innerVisible, ctx);
        out.push({ "...": digest });
        continue;
      }
      out.push(encodeValue(el, ctx));
    }
    return out;
  }
  if (value !== null && typeof value === "object") {
    return encodeContainer(value as Record<string, unknown>, ctx);
  }
  return value;
}

/**
 * Build, hash, and record an object-property disclosure: `[salt, name, value]`.
 * Returns the base64url digest to be placed in some `_sd` array.
 */
function emitObjectDisclosure(
  name: string,
  value: unknown,
  ctx: EncodeContext,
): string {
  const saltStr = ctx.salt();
  const json = JSON.stringify([saltStr, name, value]);
  const raw = Buffer.from(json, "utf-8").toString("base64url");
  const digest = createHash(ctx.nodeHashAlg).update(raw).digest("base64url");
  ctx.disclosures.push({ raw, salt: saltStr, name, value });
  return digest;
}

/**
 * Build, hash, and record an array-element disclosure: `[salt, value]`.
 * Per IETF SD-JWT §4.2.5 the array-element form is arity-2 (no name
 * field — the position in the array is its identity).
 */
function emitArrayDisclosure(
  value: unknown,
  ctx: EncodeContext,
): string {
  const saltStr = ctx.salt();
  const json = JSON.stringify([saltStr, value]);
  const raw = Buffer.from(json, "utf-8").toString("base64url");
  const digest = createHash(ctx.nodeHashAlg).update(raw).digest("base64url");
  ctx.disclosures.push({ raw, salt: saltStr, name: null, value });
  return digest;
}

function toNodeHashAlg(alg: HashAlg): string {
  switch (alg) {
    case "sha-256":
      return "sha256";
    case "sha-384":
      return "sha384";
    case "sha-512":
      return "sha512";
    default: {
      const exhaustive: never = alg;
      throw new SdJwtError("sd_jwt.issue.unsupported_hash_alg", `unsupported hash alg: ${exhaustive}`);
    }
  }
}

function defaultSaltGenerator(): string {
  return randomBytes(16).toString("base64url");
}

/** Build a deterministic salt generator from an array of pre-chosen salts.
 *  Useful for tests that need byte-stable output. */
export function deterministicSalts(salts: readonly string[]): () => string {
  let i = 0;
  return () => {
    const s = salts[i++];
    if (s === undefined) {
      throw new SdJwtError("sd_jwt.issue.salt_generator_exhausted", "deterministic salt generator exhausted");
    }
    return s;
  };
}

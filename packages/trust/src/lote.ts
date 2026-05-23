/**
 * LoTE (List of Trusted Entities) trust resolver — ARF §6.6.5.
 *
 * Background. The EU Digital Identity framework anchors trust in a
 * pyramid of curated lists:
 *
 *   LoTL  — List of Trusted Lists, published by the European Commission.
 *           Points at one TSL per member state.
 *   TSL   — Trust Service Status List (eIDAS Article 22), one per
 *           member state. Lists the qualified trust service providers
 *           and (per ARF §6.6.5) the registered PID/(Q)EAA issuers.
 *   LoTE  — List of Trusted Entities. A relying-party-facing aggregation
 *           of the trusted issuer set, typically materialised by
 *           walking the LoTL → TSL → issuer-entry graph.
 *
 * The skeleton we ship here is the relying-party plumbing — a
 * {@link LoTeTrustResolver} that pins each issuer URL to one or more
 * trusted JWKs without going to the network. It plugs into the
 * existing {@link TrustResolver} contract so the verifier code path
 * (`@gramota/verifier`) gets transitive pinning for free.
 *
 * Today's flow before this resolver:
 *
 *   verifier ─ JWS payload says iss=X ──►
 *            ─ SdJwtVcIssuerTrustResolver fetches X/.well-known/jwt-vc-issuer ──►
 *            ─ trusts whatever JWKS is hosted there ──►
 *
 * Transitive trust by URL. The attacker who can publish at
 * `https://attacker.example/.well-known/jwt-vc-issuer` and have the
 * verifier dereference the URL (e.g. by tricking the wallet into
 * presenting an SD-JWT-VC with `iss: "https://attacker.example"`)
 * compromises the verifier.
 *
 * Flow with LoTE pinning:
 *
 *   verifier ─ JWS payload says iss=X ──►
 *            ─ LoTeTrustResolver checks X is in the allow-list ──►
 *               ├─ NO:  hard reject with trust.issuer_not_configured
 *               └─ YES: serve the pinned keys for X
 *                       (optionally refresh via wrapped resolver)
 *
 * Real EU deployments wire the allow-list to a fetcher that walks
 * the LoTL / TSL graph periodically. This skeleton stops at the
 * static allow-list — wiring the LoTL fetch is a follow-up.
 *
 * Spec citation. ARF v2.9.0 §6.6.5 ("Trust model for PID and (Q)EAA
 * Issuers") + Annex 4 (LoTL / TSL schema references).
 */

import type { JsonWebKey } from "@gramota/jose";
import {
  TrustResolutionError,
  type TrustContext,
  type TrustResolver,
} from "./types.js";

/** One entry in a LoTE: a trusted issuer URL plus the JWKs the
 * verifier should pin to. JWKs are the public keys that verify the
 * issuer's SD-JWT-VC signatures. */
export interface LoTeEntry {
  /** The canonical issuer URL — exactly the `iss` claim that issued
   * SD-JWT-VCs from this issuer will carry. Compared byte-for-byte. */
  readonly iss: string;
  /** Trusted public keys for this issuer. Multiple supported so the
   * issuer can rotate keys without a LoTE update — verifier tries
   * each in order. */
  readonly keys: readonly JsonWebKey[];
  /** Optional issuer display name — for diagnostics + audit logs. */
  readonly name?: string;
  /** Optional country code (ISO 3166-1 alpha-2 lowercase) — for
   * member-state PID issuers per ARF §6.6.5. Diagnostics only; the
   * trust decision is based on `iss` byte-for-byte. */
  readonly country?: string;
  /** Optional notBefore — wall-clock seconds since epoch. When set,
   * resolutions before this time are rejected (the entry hasn't
   * activated yet — useful when staging future keys). */
  readonly notBefore?: number;
  /** Optional notAfter — wall-clock seconds since epoch. When set,
   * resolutions after this time are rejected (the entry has expired —
   * the upstream TSL marked it withdrawn / superseded). */
  readonly notAfter?: number;
}

export interface LoTeTrustResolverOptions {
  /** The trusted-issuer allow-list — must be non-empty. Real
   * deployments build this by walking the LoTL / TSL graph; the
   * skeleton accepts a static list. */
  readonly entries: readonly LoTeEntry[];
  /** Optional inner resolver. When set + the iss is on the allow-list,
   * the inner resolver is consulted first; its keys are intersected
   * with the LoTE's pinned set. The inner resolver allows fresh-JWKS
   * fetches (e.g. {@link SdJwtVcIssuerTrustResolver}) while keeping the
   * LoTE as the source of truth for which iss URLs are trusted at all.
   * Omit for strict-pinned mode (LoTE keys are the only keys). */
  readonly inner?: TrustResolver;
  /** Clock override for tests, in seconds-since-epoch. Default
   * `Math.floor(Date.now() / 1000)`. */
  readonly now?: () => number;
}

/**
 * `TrustResolver` that gates by an allow-list of issuer URLs + pinned
 * JWKs per ARF §6.6.5.
 *
 * Behaviour:
 *   1. If `context.iss` is missing → `trust.iss_required`.
 *   2. If `context.iss` is not in the allow-list →
 *      `trust.issuer_not_configured`. The verifier rejects the JWS.
 *   3. If the matched entry has `notBefore`/`notAfter` set and now is
 *      outside the window → `trust.issuer_not_configured` (the entry
 *      is staged or withdrawn).
 *   4. Otherwise:
 *      - With no inner resolver: return the pinned keys.
 *      - With an inner resolver: call it; intersect its returned keys
 *        with the LoTE-pinned set (by JWK thumbprint, fields-only
 *        equality — RFC 7638's canonical JSON). If the intersection
 *        is empty, fall through to the LoTE-pinned set so the
 *        verifier still gets candidates to try; the audit trail will
 *        show that the upstream JWKS drifted from the LoTE.
 *
 * `kid` filtering matches the other resolvers: when both the JWT
 * header and the pinned JWK carry a `kid`, prefer matching keys; on
 * no match, fall back to the full set.
 */
export class LoTeTrustResolver implements TrustResolver {
  readonly #byIss: ReadonlyMap<string, LoTeEntry>;
  readonly #inner: TrustResolver | undefined;
  readonly #now: () => number;

  constructor(options: LoTeTrustResolverOptions) {
    if (
      options === null ||
      typeof options !== "object" ||
      !Array.isArray(options.entries) ||
      options.entries.length === 0
    ) {
      throw new TrustResolutionError(
        "trust.invalid_input",
        "LoTeTrustResolver: entries must be a non-empty array",
      );
    }
    const byIss = new Map<string, LoTeEntry>();
    for (const entry of options.entries) {
      if (
        entry === null ||
        typeof entry !== "object" ||
        typeof entry.iss !== "string" ||
        entry.iss.length === 0
      ) {
        throw new TrustResolutionError(
          "trust.invalid_input",
          "LoTeTrustResolver: every entry must have a non-empty iss string",
        );
      }
      if (!Array.isArray(entry.keys) || entry.keys.length === 0) {
        throw new TrustResolutionError(
          "trust.invalid_input",
          `LoTeTrustResolver: entry for ${JSON.stringify(entry.iss)} must have at least one key`,
        );
      }
      if (byIss.has(entry.iss)) {
        throw new TrustResolutionError(
          "trust.invalid_input",
          `LoTeTrustResolver: duplicate iss ${JSON.stringify(entry.iss)}`,
        );
      }
      byIss.set(entry.iss, entry);
    }
    this.#byIss = byIss;
    this.#inner = options.inner;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async resolveIssuerKeys(
    context: TrustContext,
  ): Promise<readonly JsonWebKey[]> {
    if (context.iss === undefined) {
      throw new TrustResolutionError(
        "trust.iss_required",
        "LoTeTrustResolver requires iss but JWT has no iss claim",
      );
    }
    const entry = this.#byIss.get(context.iss);
    if (entry === undefined) {
      throw new TrustResolutionError(
        "trust.issuer_not_configured",
        `LoTeTrustResolver: issuer ${JSON.stringify(
          context.iss,
        )} is not on the List of Trusted Entities (ARF §6.6.5)`,
      );
    }

    const nowSec = this.#now();
    if (entry.notBefore !== undefined && nowSec < entry.notBefore) {
      throw new TrustResolutionError(
        "trust.issuer_not_configured",
        `LoTeTrustResolver: issuer ${JSON.stringify(
          context.iss,
        )} entry has notBefore=${entry.notBefore} but now=${nowSec} — entry not yet active`,
      );
    }
    if (entry.notAfter !== undefined && nowSec >= entry.notAfter) {
      throw new TrustResolutionError(
        "trust.issuer_not_configured",
        `LoTeTrustResolver: issuer ${JSON.stringify(
          context.iss,
        )} entry expired at notAfter=${entry.notAfter} (now=${nowSec}) — withdrawn / superseded`,
      );
    }

    let candidates: readonly JsonWebKey[] = entry.keys;

    if (this.#inner !== undefined) {
      let innerKeys: readonly JsonWebKey[] = [];
      try {
        innerKeys = await this.#inner.resolveIssuerKeys(context);
      } catch {
        // The inner resolver failing (e.g. fetch failed) doesn't
        // un-trust the issuer — we still have the LoTE-pinned set as
        // the floor. Fall through with `entry.keys` as candidates.
      }
      const intersected = intersectByThumbprintFields(innerKeys, entry.keys);
      if (intersected.length > 0) candidates = intersected;
      // If the inner resolver disagrees entirely with the LoTE-pinned
      // set, we still return the pinned set (above) — the LoTE is
      // the source of truth.
    }

    if (context.kid !== undefined) {
      const matching = candidates.filter((k) => {
        const ckid = (k as Record<string, unknown>)["kid"];
        return typeof ckid === "string" && ckid === context.kid;
      });
      if (matching.length > 0) return matching;
    }
    return candidates;
  }

  /** Inspect the entry for an iss without going through resolveIssuerKeys.
   * Useful for diagnostics + audit logging in upstream callers.
   * Returns `undefined` if the iss isn't on the LoTE. */
  lookup(iss: string): LoTeEntry | undefined {
    return this.#byIss.get(iss);
  }

  /** All iss URLs on the LoTE — for diagnostics + admin UIs. */
  listIssuers(): readonly string[] {
    return [...this.#byIss.keys()];
  }
}

/** Intersect two JWK sets by canonical key material (RFC 7638-style
 * fields). We don't compute a real JWK thumbprint to avoid pulling in
 * crypto here — we compare on the spec's required-membership fields
 * for each key type: EC `{kty, crv, x, y}`, RSA `{kty, n, e}`, OKP
 * `{kty, crv, x}`, oct `{kty, k}`. Two JWKs that agree on those are
 * the same key regardless of other annotations (kid, alg, use). */
function intersectByThumbprintFields(
  a: readonly JsonWebKey[],
  b: readonly JsonWebKey[],
): JsonWebKey[] {
  const bKeys = b.map(canonicalKeyId);
  return a.filter((k) => bKeys.includes(canonicalKeyId(k)));
}

function canonicalKeyId(jwk: JsonWebKey): string {
  const rec = jwk as Record<string, unknown>;
  const kty = rec["kty"];
  switch (kty) {
    case "EC":
      return JSON.stringify([kty, rec["crv"], rec["x"], rec["y"]]);
    case "RSA":
      return JSON.stringify([kty, rec["n"], rec["e"]]);
    case "OKP":
      return JSON.stringify([kty, rec["crv"], rec["x"]]);
    case "oct":
      return JSON.stringify([kty, rec["k"]]);
    default:
      return JSON.stringify(rec);
  }
}

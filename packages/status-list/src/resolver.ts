/**
 * GoF Strategy pattern for resolving credential revocation/suspension.
 *
 * The verifier's status check (10th security check) consults a
 * `StatusResolver` injected at construction. Different revocation
 * mechanisms — IETF Token Status List (default), CRL, OCSP, EU Trusted
 * Issuers Registry, application-specific deny-lists — implement the
 * same interface and plug in without modifying the verifier.
 *
 *     class CrlStatusResolver implements StatusResolver { ... }
 *     class OcspStatusResolver implements StatusResolver { ... }
 *     class CompositeResolver implements StatusResolver {
 *       // Tries multiple resolvers in order
 *     }
 *
 * The default impl, `StatusListResolver`, wraps the IETF Token Status
 * List logic — same wire format we've been using all along.
 */

import type { JsonWebKey } from "@gramota/jose";
import type { ParsedSdJwt } from "@gramota/sd-jwt";
import { checkCredentialStatus } from "./check.js";
import { StatusListError, type CredentialStatusResult, type StatusList } from "./types.js";
import type { Fetcher } from "./fetch.js";

/** Per-call options that may vary independently of resolver config. */
export interface ResolveStatusOptions {
  /** Override "now" — for tests + frozen-time environments. */
  now?: () => number;
}

/**
 * Strategy interface for resolving a credential's status.
 *
 * Returns "skipped" when the credential carries no status reference and
 * the resolver couldn't (or wasn't asked to) infer one. The verifier
 * decides how to interpret "skipped" — fail or pass — based on policy
 * (`requireStatus` per call).
 *
 * Implementations are pure (no per-flow state); a single instance can
 * serve many concurrent verifications.
 */
export interface StatusResolver {
  resolveStatus(
    credential: ParsedSdJwt,
    options?: ResolveStatusOptions,
  ): Promise<CredentialStatusResult | "skipped">;
}

// ---------------------------------------------------------------------------
// Default concrete: IETF Token Status List
// ---------------------------------------------------------------------------

export interface StatusListResolverConfig {
  /** Trusted JWKs the status-list signature must verify against. */
  trustedIssuers: readonly JsonWebKey[];
  /** Optional fetcher override. */
  fetcher?: Fetcher;
  /** Pre-fetched / cached list — skip the network when supplied. The
   * `sub` of the list must match the credential's status URI. */
  list?: StatusList;
}

/**
 * IETF Token Status List resolver — the default resolver.
 *
 * Pure delegation to `checkCredentialStatus`; the only thing this class
 * adds is the Strategy shape so it composes through DI.
 */
export class StatusListResolver implements StatusResolver {
  constructor(private readonly config: StatusListResolverConfig) {
    if (
      !Array.isArray(config.trustedIssuers) ||
      config.trustedIssuers.length === 0
    ) {
      throw new TypeError(
        "StatusListResolver: trustedIssuers must be a non-empty array",
      );
    }
  }

  async resolveStatus(
    credential: ParsedSdJwt,
    options: ResolveStatusOptions = {},
  ): Promise<CredentialStatusResult | "skipped"> {
    const opts: Parameters<typeof checkCredentialStatus>[1] = {
      trustedIssuers: this.config.trustedIssuers,
    };
    if (this.config.fetcher !== undefined) opts.fetcher = this.config.fetcher;
    if (this.config.list !== undefined) opts.list = this.config.list;
    if (options.now !== undefined) opts.now = options.now;

    try {
      return await checkCredentialStatus(credential, opts);
    } catch (err) {
      // No status reference is a "skipped" signal, not an error — let
      // the caller decide whether that's acceptable.
      if (
        err instanceof StatusListError &&
        err.code === "status_list.no_status_reference"
      ) {
        return "skipped";
      }
      throw err;
    }
  }
}

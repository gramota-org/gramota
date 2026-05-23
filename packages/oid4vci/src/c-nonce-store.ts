/**
 * OID4VCI `c_nonce` store — proof-of-possession nonces.
 *
 * Background
 * ──────────
 * OID4VCI 1.0 Final §7 splits c_nonce issuance into a dedicated Nonce
 * Endpoint (`POST /oid4vci/nonce`). Draft 13 returned the c_nonce inside
 * the `/token` response. Final wallets fetch from `/nonce` first.
 *
 * Per OID4VCI §8.2 the proof JWT in `POST /oid4vci/credential` MUST carry
 * a `nonce` claim that equals a still-fresh `c_nonce` previously issued
 * to that wallet, and the issuer MUST reject mismatches. This module
 * owns that lifecycle:
 *
 *   1. mint() — called by the host's /nonce and /token routes. Returns
 *      a base64url string with a 5-min TTL by default.
 *   2. consume() — called by the host's /credential route. Checks the
 *      nonce is present + not expired, then deletes it (single-use
 *      replay protection).
 *
 * The interface ({@link CNonceStoreLike}) is what the host wires; the
 * in-memory default ({@link CNonceStore}) is fine for single-replica
 * deployments. Production scale-out wants a Redis-backed implementation
 * — the host plugs that in by satisfying the interface.
 */

import { randomBytes } from "node:crypto";

/** Per OID4VCI §7.2 the c_nonce_expires_in is in seconds; default 5min. */
export const C_NONCE_TTL_SECONDS = 300;

/** Hard cap on the in-memory size — defensive against runaway minting. */
const DEFAULT_MAX_ENTRIES = 100_000;

export interface CNonceMintOptions {
  /** Override the default TTL. */
  ttlSeconds?: number;
}

export interface CNonceMintResult {
  /** Opaque value the wallet binds into its proof JWT's `nonce` claim. */
  nonce: string;
  /** Lifetime in seconds — surface to the wallet as `c_nonce_expires_in`. */
  expiresInSeconds: number;
}

/**
 * Host-facing c_nonce store interface. Implementations may be backed by
 * memory (the default), Redis, Postgres, etc.
 */
export interface CNonceStoreLike {
  /** Mint a fresh c_nonce; persist its expiry; return the value + lifetime. */
  mint(options?: CNonceMintOptions): Promise<CNonceMintResult>;
  /** Look up + single-use-consume a c_nonce. Returns false if not found,
   *  expired, or already used. */
  consume(nonce: string): Promise<boolean>;
  /** Prune expired entries. Hosts may call this on a timer. */
  prune(): void;
}

export interface CNonceStoreOptions {
  /** Default TTL applied when `mint()` doesn't override. Default: 300s. */
  ttlSeconds?: number;
  /** Soft cap on entries. When exceeded, the oldest 10% are dropped.
   *  Default: 100_000. */
  maxEntries?: number;
}

/**
 * In-memory default implementation of {@link CNonceStoreLike}. Map-backed,
 * size-capped, with a separate `prune()` sweep for expired entries.
 */
export class CNonceStore implements CNonceStoreLike {
  /** nonce → expiresAtMs */
  private readonly nonces = new Map<string, number>();
  private readonly defaultTtlSeconds: number;
  private readonly maxEntries: number;

  constructor(options: CNonceStoreOptions = {}) {
    this.defaultTtlSeconds = options.ttlSeconds ?? C_NONCE_TTL_SECONDS;
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
  }

  async mint(options: CNonceMintOptions = {}): Promise<CNonceMintResult> {
    this.trimIfOversized();
    const ttl = options.ttlSeconds ?? this.defaultTtlSeconds;
    const nonce = randomBytes(16).toString("base64url");
    const expiresAtMs = Date.now() + ttl * 1000;
    this.nonces.set(nonce, expiresAtMs);
    return { nonce, expiresInSeconds: ttl };
  }

  /**
   * Single-use consume. Returns true iff the nonce was present and not
   * expired. A successful match removes the nonce so a stolen proof JWT
   * can't be replayed.
   *
   * Per OID4VCI §8.2 the corresponding response on mismatch is
   * `error: invalid_nonce`; callers translate the boolean.
   */
  async consume(nonce: string): Promise<boolean> {
    const expiresAt = this.nonces.get(nonce);
    if (expiresAt === undefined) return false;
    this.nonces.delete(nonce);
    if (Date.now() > expiresAt) return false;
    return true;
  }

  /** Periodic sweep — remove expired entries. Idempotent. */
  prune(): void {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.nonces) {
      if (now > expiresAt) this.nonces.delete(nonce);
    }
  }

  /** Overflow defense — when the map gets unreasonably large, drop the
   * oldest 10% by insertion order. Map preserves insertion order so this
   * is O(n) but the watermark is high enough we won't hit it on real
   * traffic. */
  private trimIfOversized(): void {
    if (this.nonces.size < this.maxEntries) return;
    const dropCount = Math.floor(this.maxEntries * 0.1);
    let i = 0;
    for (const k of this.nonces.keys()) {
      if (i++ >= dropCount) break;
      this.nonces.delete(k);
    }
  }
}

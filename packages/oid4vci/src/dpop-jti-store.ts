/**
 * DPoP `jti` replay-store interface (RFC 9449 §11.1).
 *
 * Background
 * ──────────
 * RFC 9449 §11.1 requires the resource server / authorization server to
 * track seen `jti` values for the maximum DPoP age and reject any reuse
 * — across all replicas. An in-process Set works on a single pod; with
 * horizontal scale a jti recorded on pod A is invisible to pod B and the
 * wallet can replay against pod B.
 *
 * This module exports just the *interface* the SDK's {@link verifyDpopJwt}
 * needs. The actual implementations (Postgres, Redis, in-memory) live in
 * host code — they depend on host-specific connection pools the SDK
 * shouldn't pull in. The `InMemoryDpopJtiStore` below is provided as a
 * default for single-replica deployments and tests.
 *
 * Sizing
 * ──────
 * Typical TTL is 90 seconds — RFC 9449's iat window is 60s; allow 30s
 * slack for clock skew. Wallets generate one jti per request so traffic
 * is proportional to /token + /credential rate.
 */

/**
 * Host-facing DPoP jti replay store. A single method that atomically
 * checks-and-claims a jti — returning true if it was previously seen
 * (the request MUST be rejected as a replay).
 *
 * Why a combined check-and-record rather than separate `hasSeen` +
 * `record`: a race-window between the two would let two concurrent
 * requests with the same jti both pass. The atomic shape pushes the
 * race resolution to the backend (Postgres ON CONFLICT, Redis SETNX,
 * Map.set on a single thread).
 */
export interface DpopJtiStoreLike {
  /**
   * Atomically check whether `jti` was previously seen, and if not,
   * claim it. Returns true iff the jti was already recorded (i.e. this
   * is a replay and the request MUST be rejected). False on first sight.
   *
   * `expiresAt` is the deadline at which the jti should be considered
   * forgotten — typically `iat + maxAge + skew`. Implementations use
   * it both as the TTL on the stored entry and as the basis for
   * background pruning.
   */
  checkAndRecord(jti: string, expiresAt: Date): Promise<boolean>;
}

export interface InMemoryDpopJtiStoreOptions {
  /** Prune interval in milliseconds. Default: 60_000. Set to 0 to disable. */
  pruneIntervalMs?: number;
}

/**
 * Single-process default implementation of {@link DpopJtiStoreLike}. Map-
 * backed with TTL-based eviction; a background timer prunes expired
 * entries. Suitable for tests + single-replica hosts. Multi-replica
 * deployments should provide a Postgres/Redis-backed impl.
 */
export class InMemoryDpopJtiStore implements DpopJtiStoreLike {
  private readonly seen = new Map<string, number>(); // jti → expiresAtMs
  private readonly pruner?: NodeJS.Timeout;

  constructor(options: InMemoryDpopJtiStoreOptions = {}) {
    const interval = options.pruneIntervalMs ?? 60_000;
    if (interval > 0) {
      this.pruner = setInterval(() => this.prune(), interval);
      // Background timers shouldn't keep the event loop alive during shutdown.
      this.pruner.unref?.();
    }
  }

  async checkAndRecord(jti: string, expiresAt: Date): Promise<boolean> {
    const existing = this.seen.get(jti);
    const now = Date.now();
    if (existing !== undefined && existing > now) {
      // Replay — known and still within its window.
      return true;
    }
    this.seen.set(jti, expiresAt.getTime());
    return false;
  }

  /** Manual prune sweep. Idempotent. */
  prune(): void {
    const now = Date.now();
    for (const [jti, expiresAtMs] of this.seen) {
      if (now > expiresAtMs) this.seen.delete(jti);
    }
  }

  /** Stop the background pruner. Call on shutdown. */
  stop(): void {
    if (this.pruner) clearInterval(this.pruner);
  }
}

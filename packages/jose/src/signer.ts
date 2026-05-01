/**
 * GoF Strategy pattern for JWS signing.
 *
 * The naive design — pass `privateKey: JsonWebKey` everywhere — leaks
 * raw key material throughout the JS heap. **Production wallets never
 * have raw private keys.** Real keys live in:
 *
 *   - WebAuthn / PassKeys (browser)
 *   - Android Keystore / iOS Secure Enclave (mobile)
 *   - HSMs / KMS (server-side issuers/verifiers)
 *   - YubiKey (hardware tokens)
 *
 * The `Signer` interface abstracts "produce a JWS signature for this
 * `header.payload`" without exposing how. Concrete impls bind to:
 *
 *   - `JwkSigner` (default) — wraps a raw JWK, uses the `jose` library.
 *     Safe for tests and dev; not safe for production secret material.
 *   - `WebAuthnSigner` (future) — defers to `navigator.credentials`.
 *   - `HsmSigner` (future) — RPCs to a KMS; never sees the key bytes.
 *
 * Adding a new signer requires implementing the three-member interface
 * and passing the instance via `signer:` to the orchestrator (Holder,
 * Issuer, Oid4vciClient). No changes to the orchestrators — Open/Closed.
 */

import { makeSigner } from "./make-signer.js";
import type { JsonWebKey, SupportedAlg } from "./types.js";

/**
 * A pluggable signing strategy.
 *
 * `sign()` takes the JWS-canonical "header.payload" string (two
 * base64url-encoded segments joined by a dot) and returns just the
 * base64url-encoded signature segment. This shape matches what
 * `@gateway/sd-jwt`'s `issueSdJwt` `signer` callback expects, so a
 * `Signer` instance can drop in as that callback via `signer.sign`.
 *
 * Implementations are expected to be stateless from the caller's
 * perspective — concurrent `sign()` calls must not interfere.
 */
export interface Signer {
  /** Public counterpart — verifiers use this. Must always be extractable
   * (not in an HSM), since it's needed downstream for `cnf.jwk` etc. */
  readonly publicKey: JsonWebKey;

  /** JWS algorithm this signer produces. Must match `publicKey`'s
   * algorithm capabilities (e.g. ES256 with a P-256 EC key). */
  readonly alg: SupportedAlg;

  /** Sign a "header.payload" string, return base64url(signature). */
  sign(signedPayload: string): Promise<string>;
}

// ---------------------------------------------------------------------------
// Default impl — JwkSigner
// ---------------------------------------------------------------------------

export interface JwkSignerOptions {
  /** Public counterpart — also used to bind the signer to its alg. */
  publicKey: JsonWebKey;
  /** Private JWK. Held in memory — see file header. Not for production
   * secret-material storage; use `WebAuthnSigner`/`HsmSigner` there. */
  privateKey: JsonWebKey;
  /** JWS alg. */
  alg: SupportedAlg;
}

/**
 * Default `Signer` implementation backed by an in-memory JWK.
 *
 * Handy for tests, dev environments, and server-side issuers that hold
 * their signing key in a secret-manager-fetched env var. For mobile
 * wallets and high-assurance flows, swap in a hardware-backed Signer.
 */
export class JwkSigner implements Signer {
  readonly publicKey: JsonWebKey;
  readonly alg: SupportedAlg;
  private readonly privateKey: JsonWebKey;
  /** Cached jose-imported signer; built on first sign(). */
  private cachedSign: ((s: string) => Promise<string>) | undefined;

  constructor(options: JwkSignerOptions) {
    if (
      options.publicKey === null ||
      typeof options.publicKey !== "object"
    ) {
      throw new TypeError("JwkSigner: publicKey is required");
    }
    if (
      options.privateKey === null ||
      typeof options.privateKey !== "object"
    ) {
      throw new TypeError("JwkSigner: privateKey is required");
    }
    if (typeof options.alg !== "string" || options.alg.length === 0) {
      throw new TypeError("JwkSigner: alg is required");
    }
    this.publicKey = options.publicKey;
    this.privateKey = options.privateKey;
    this.alg = options.alg;
  }

  async sign(signedPayload: string): Promise<string> {
    if (this.cachedSign === undefined) {
      this.cachedSign = await makeSigner(this.privateKey, this.alg);
    }
    return await this.cachedSign(signedPayload);
  }
}

/**
 * Promote a raw JWK config to a Signer, or pass through an existing one.
 *
 * Used by orchestrators (Holder, Issuer, Oid4vciClient) to accept
 * either form on their config and normalize internally. Stripe-style
 * "shorthand" pattern — ergonomic for tests/dev, principled for prod.
 */
export function asSigner(
  input:
    | Signer
    | { publicKey: JsonWebKey; privateKey: JsonWebKey; alg: SupportedAlg },
): Signer {
  if (
    typeof (input as Signer).sign === "function" &&
    (input as Signer).publicKey !== undefined &&
    (input as Signer).alg !== undefined
  ) {
    return input as Signer;
  }
  const k = input as JwkSignerOptions;
  return new JwkSigner({
    publicKey: k.publicKey,
    privateKey: k.privateKey,
    alg: k.alg,
  });
}

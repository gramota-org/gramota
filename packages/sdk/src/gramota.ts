/**
 * `Gramota` — top-level Stripe-shaped facade over the SDK.
 *
 * The individual packages (`@gramota/verifier`, `@gramota/issuer`,
 * `@gramota/holder`, `@gramota/qr`) work fine on their own. This
 * facade exists when you want the *Stripe ergonomics*:
 *
 *   ```ts
 *   import { Gramota } from "@gramota/sdk";
 *
 *   const gramota = new Gramota({ audience: "https://my-bank.com", trust });
 *
 *   // verify a presentation
 *   await gramota.verifier.presentations.verify(token, { nonce });
 *
 *   // mint a QR for an authorization request
 *   const code = gramota.qr.fromAuthorizationRequest(req);
 *   ```
 *
 * What you get over importing the packages directly:
 *
 *   1. **One config object.** `audience`, `trust`, `issuerKey` flow
 *      to the verifier without you wiring them. Future shared options
 *      (telemetry, fetcher, retry policy) plug in here once.
 *
 *   2. **Lazy instantiation.** Properties construct their underlying
 *      client on first access. If you only use `.verifier`, the
 *      issuer code never loads.
 *
 *   3. **One mental model.** Mirrors `new Stripe(key).customers.create()`
 *      → `new Gramota(opts).verifier.presentations.verify()`.
 *
 * The facade is *additive*. Importing `@gramota/verifier` directly
 * still works and stays the supported low-level path for advanced
 * use (custom subclassing, picking a single package).
 */
import { Verifier, type VerifierConfig } from "@gramota/verifier";
import { Issuer, type IssuerConfig } from "@gramota/issuer";
import { Holder, type HolderConfig } from "@gramota/holder";
import { QrClient, type QrClientOptions } from "@gramota/qr";
import type { Fetcher } from "@gramota/core";

/**
 * Construction-time options for {@link Gramota}.
 *
 * `verifier`, `issuer`, `holder`, and `qr` are the per-client config
 * objects. They're optional — only the clients you reference get
 * instantiated lazily, and only their config keys are required.
 */
export interface GramotaOptions {
  /** Verifier config — required if you call `gramota.verifier`. */
  readonly verifier?: VerifierConfig;
  /** Issuer config — required if you call `gramota.issuer`. */
  readonly issuer?: IssuerConfig;
  /** Holder config — required if you call `gramota.holder`. */
  readonly holder?: HolderConfig;
  /** QR client options. Defaults to a vanilla {@link QrClient} when
   * not provided. */
  readonly qr?: QrClientOptions;
  /**
   * Fetcher applied to every client that supports one and doesn't
   * specify its own. Useful for app-wide concerns like retry,
   * timeout, telemetry, or a request-id header. Per-client `fetcher`
   * still wins when set.
   */
  readonly fetcher?: Fetcher;
}

export class Gramota {
  private readonly options: GramotaOptions;

  private _verifier?: Verifier;
  private _issuer?: Issuer;
  private _holder?: Holder;
  private _qr?: QrClient;

  constructor(options: GramotaOptions = {}) {
    this.options = options;
  }

  /** Verify presentation tokens and OID4VP responses, build OID4VP
   * authorization requests. Lazy — constructed on first access. */
  get verifier(): Verifier {
    if (!this._verifier) {
      const cfg = this.options.verifier;
      if (!cfg) {
        throw new TypeError(
          "Gramota: pass `verifier` config when constructing the facade if you intend to use gramota.verifier.",
        );
      }
      this._verifier = new Verifier(cfg);
    }
    return this._verifier;
  }

  /** Issue OID4VCI credentials. Lazy — constructed on first access. */
  get issuer(): Issuer {
    if (!this._issuer) {
      const cfg = this.options.issuer;
      if (!cfg) {
        throw new TypeError(
          "Gramota: pass `issuer` config when constructing the facade if you intend to use gramota.issuer.",
        );
      }
      this._issuer = new Issuer(cfg);
    }
    return this._issuer;
  }

  /** Receive credentials, build presentations. Lazy — constructed on first access. */
  get holder(): Holder {
    if (!this._holder) {
      const cfg = this.options.holder;
      if (!cfg) {
        throw new TypeError(
          "Gramota: pass `holder` config when constructing the facade if you intend to use gramota.holder.",
        );
      }
      this._holder = new Holder(cfg);
    }
    return this._holder;
  }

  /** QR code rendering. Always available — has no required config. */
  get qr(): QrClient {
    if (!this._qr) {
      this._qr = new QrClient(this.options.qr ?? {});
    }
    return this._qr;
  }
}

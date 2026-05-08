/**
 * `QrClient` — Stripe-shaped class entry point for `@gramota/qr`.
 *
 * Three factory methods (Factory Method, GoF), each accepting a
 * different shape of input and all returning a {@link QrCode}:
 *
 *   - {@link QrClient.fromUrl} — a raw deep-link URL.
 *   - {@link QrClient.fromAuthorizationRequest} — an OID4VP request.
 *   - {@link QrClient.fromCredentialOffer} — an OID4VCI offer.
 *
 * The renderer (Strategy, GoF) and default {@link QrOptions} are
 * carried by the instance. Pass them once at construction; every
 * `from*` call layers per-call overrides on top:
 *
 *   ```ts
 *   const qr = new QrClient({
 *     errorCorrection: "H",                      // default for all codes
 *     renderer: new DefaultQrRenderer(),         // strategy override
 *   });
 *
 *   const code = qr.fromUrl("openid4vp://…", { width: 512 }); // call-level override
 *   const dataUrl = await code.toDataUrl();
 *   ```
 *
 * Adding a new input shape (e.g. `fromMdocPresentationRequest`) means
 * adding a new method here without touching the existing ones (Open/
 * Closed). The orchestrator depends only on {@link QrRenderer},
 * never on the `qrcode` npm package directly.
 */
import { buildAuthorizationRequestUrl } from "@gramota/oid4vp";
import type { AuthorizationRequest } from "@gramota/oid4vp";
import { buildCredentialOfferUrl } from "@gramota/oid4vci";
import type { CredentialOffer } from "@gramota/oid4vci";

import { QrError, type QrOptions } from "./types.js";
import { DefaultQrRenderer, type QrRenderer } from "./renderer.js";
import { QrCode } from "./qr-code.js";

/** Construction-time options for {@link QrClient}. */
export interface QrClientOptions extends QrOptions {
  /** Override the rendering Strategy. Defaults to a singleton
   * {@link DefaultQrRenderer} backed by the `qrcode` npm package. */
  readonly renderer?: QrRenderer;
}

/** Module-level default renderer — created once, reused by every
 * QrClient instance that doesn't pass its own. */
const defaultRenderer = new DefaultQrRenderer();

export class QrClient {
  private readonly renderer: QrRenderer;
  private readonly defaults: QrOptions;

  constructor(options?: QrClientOptions) {
    this.renderer = options?.renderer ?? defaultRenderer;
    const { renderer: _renderer, ...defaults } = options ?? {};
    void _renderer;
    this.defaults = defaults;
  }

  /**
   * Render any URL as a QR code.
   *
   * @example
   * ```ts
   * const code = qr.fromUrl("openid4vp://?client_id=…");
   * const dataUrl = await code.toDataUrl();
   * ```
   *
   * @throws {@link QrError} with `qr.invalid_url` if the input isn't a
   *   non-empty string with a `<scheme>:` prefix.
   */
  fromUrl(url: string, options?: QrOptions): QrCode {
    if (typeof url !== "string" || url.length === 0) {
      throw new QrError(
        "qr.invalid_url",
        "qr.fromUrl: url must be a non-empty string",
      );
    }
    if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) {
      throw new QrError(
        "qr.invalid_url",
        `qr.fromUrl: "${url.slice(0, 40)}…" doesn't look like a URI`,
      );
    }
    return new QrCode(url, this.renderer, this.merge(options));
  }

  /**
   * Render an OID4VP {@link AuthorizationRequest} as a QR code. Default
   * scheme is `openid4vp://`. Override via `{ scheme }` for HAIP /
   * country-specific wallet schemes.
   */
  fromAuthorizationRequest(
    request: AuthorizationRequest,
    options?: QrOptions & { readonly scheme?: string },
  ): QrCode {
    const scheme = options?.scheme ?? "openid4vp://";
    const url = buildAuthorizationRequestUrl(scheme, request);
    return new QrCode(url, this.renderer, this.merge(options));
  }

  /**
   * Render an OID4VCI {@link CredentialOffer} as a QR code. Default
   * scheme is `openid-credential-offer://` per OID4VCI §4.1.
   */
  fromCredentialOffer(
    offer: CredentialOffer,
    options?: QrOptions & { readonly scheme?: string },
  ): QrCode {
    const url = buildCredentialOfferUrl(
      offer,
      options?.scheme !== undefined ? { scheme: options.scheme } : {},
    );
    return new QrCode(url, this.renderer, this.merge(options));
  }

  private merge(options?: QrOptions & { readonly scheme?: string }): QrOptions {
    if (!options) return this.defaults;
    const { scheme: _scheme, ...rest } = options;
    void _scheme;
    return { ...this.defaults, ...rest };
  }
}

/**
 * Default singleton {@link QrClient} with the default renderer.
 *
 * Most consumers want this — no construction, no options, just
 * `qr.fromUrl(deepLink)`. Pass a custom renderer or default options
 * by constructing your own `new QrClient({...})`.
 */
export const qr: QrClient = new QrClient();

/* ------------------------------------------------------------------
 * Back-compat re-exports.
 *
 * Pre-0.2.0 the public surface was three named functions plus a
 * frozen `qr` object literal. Both shapes still work — the named
 * functions delegate to the singleton, and `qr` is now a class
 * instance with the same method names.
 * ------------------------------------------------------------------ */
export const fromUrl: QrClient["fromUrl"] = (url, options) =>
  qr.fromUrl(url, options);
export const fromAuthorizationRequest: QrClient["fromAuthorizationRequest"] = (
  request,
  options,
) => qr.fromAuthorizationRequest(request, options);
export const fromCredentialOffer: QrClient["fromCredentialOffer"] = (
  offer,
  options,
) => qr.fromCredentialOffer(offer, options);

/** @deprecated alias for {@link QrClientOptions} — kept for source compat. */
export type QrFactoryOptions = QrClientOptions;

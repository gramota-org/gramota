/**
 * The `qr` namespace — Stripe-shaped factory entry point.
 *
 * Three Factory Methods (GoF), each accepting a different shape of
 * input but all returning the same {@link QrCode}:
 *
 *   - {@link fromUrl} — a raw deep-link URL (the most general case).
 *   - {@link fromAuthorizationRequest} — an OID4VP authorization
 *     request object; this composes with `@gramota/oid4vp`'s
 *     `buildAuthorizationRequestUrl` so verifiers don't have to.
 *   - {@link fromCredentialOffer} — an OID4VCI credential offer; this
 *     composes with `@gramota/oid4vci`'s `buildCredentialOfferUrl` so
 *     issuers don't have to.
 *
 * Adding a new input shape (e.g. `fromMdocPresentationRequest`) means
 * adding a new factory next to these — without touching the existing
 * ones (Open/Closed). The orchestrator depends only on
 * {@link QrRenderer} (Strategy), never on `qrcode` directly.
 */
import { buildAuthorizationRequestUrl } from "@gramota/oid4vp";
import type { AuthorizationRequest } from "@gramota/oid4vp";
import { buildCredentialOfferUrl } from "@gramota/oid4vci";
import type { CredentialOffer } from "@gramota/oid4vci";

import { QrError, type QrOptions } from "./types.js";
import { DefaultQrRenderer, type QrRenderer } from "./renderer.js";
import { QrCode } from "./qr-code.js";

/** Options accepted by every `qr.from*` factory. */
export interface QrFactoryOptions extends QrOptions {
  /** Override the rendering Strategy. Defaults to a singleton
   * {@link DefaultQrRenderer} backed by the `qrcode` npm package. */
  readonly renderer?: QrRenderer;
}

/** Module-level default renderer — created once, reused everywhere.
 * Custom renderers passed via {@link QrFactoryOptions.renderer}
 * override this without mutating it. */
const defaultRenderer = new DefaultQrRenderer();

function pickRenderer(options?: QrFactoryOptions): QrRenderer {
  return options?.renderer ?? defaultRenderer;
}

function pickQrOptions(options?: QrFactoryOptions): QrOptions {
  if (!options) return {};
  // Strip the `renderer` key — the renderer should not see itself
  // in the options it receives.
  const { renderer: _renderer, ...rest } = options;
  void _renderer;
  return rest;
}

/**
 * Render any URL as a QR code.
 *
 * The most general factory — accepts any non-empty string that parses
 * as a URI (custom schemes like `openid4vp://` and `haip://` are
 * accepted alongside `https://`). Use this when you've already built
 * the deep link yourself and just want the QR.
 *
 * @example
 * ```ts
 * const code = qr.fromUrl("openid4vp://?client_id=…&request_uri=…");
 * const dataUrl = await code.toDataUrl();   // for <img src>
 * ```
 *
 * @throws {@link QrError} with `qr.invalid_url` if the input isn't a
 *   non-empty string with a `<scheme>:` prefix.
 */
export function fromUrl(url: string, options?: QrFactoryOptions): QrCode {
  if (typeof url !== "string" || url.length === 0) {
    throw new QrError(
      "qr.invalid_url",
      "qr.fromUrl: url must be a non-empty string",
    );
  }
  // Cheap scheme check — covers https:// and any custom URI scheme
  // (RFC 3986 §3.1). We don't validate the entire URL because deep
  // links sometimes carry exotic query encodings.
  if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) {
    throw new QrError(
      "qr.invalid_url",
      `qr.fromUrl: "${url.slice(0, 40)}…" doesn't look like a URI`,
    );
  }
  return new QrCode(url, pickRenderer(options), pickQrOptions(options));
}

/**
 * Render an OID4VP {@link AuthorizationRequest} as a QR code.
 *
 * Composes with `@gramota/oid4vp`'s
 * {@link buildAuthorizationRequestUrl} — you pass the typed object,
 * we serialise it to the wallet deep-link form and produce the QR.
 *
 * The `scheme` defaults to `openid4vp://`. Override for HAIP /
 * country-specific wallet schemes (`haip://`, `eudi-openid4vp://`,
 * etc.) by passing `{ scheme }`.
 *
 * @example
 * ```ts
 * const code = qr.fromAuthorizationRequest({
 *   response_type: "vp_token",
 *   client_id: "x509_san_dns:my-bank.com",
 *   nonce, state,
 *   dcql_query: { credentials: [...] },
 * });
 * const svg = await code.toSvg();
 * ```
 */
export function fromAuthorizationRequest(
  request: AuthorizationRequest,
  options?: QrFactoryOptions & { readonly scheme?: string },
): QrCode {
  const scheme = options?.scheme ?? "openid4vp://";
  const url = buildAuthorizationRequestUrl(scheme, request);
  return new QrCode(url, pickRenderer(options), pickQrOptions(options));
}

/**
 * Render an OID4VCI {@link CredentialOffer} as a QR code.
 *
 * Composes with `@gramota/oid4vci`'s {@link buildCredentialOfferUrl}.
 * Default scheme is `openid-credential-offer://` per OID4VCI §4.1;
 * override for vendor-specific schemes via `{ scheme }`.
 *
 * @example
 * ```ts
 * const code = qr.fromCredentialOffer({
 *   credential_issuer: "https://acme.gramota.dev",
 *   credential_configuration_ids: ["urn:eudi:pid:1_sd_jwt_vc"],
 *   grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "abc123" } },
 * });
 * const png = await code.toPng();           // Uint8Array
 * ```
 */
export function fromCredentialOffer(
  offer: CredentialOffer,
  options?: QrFactoryOptions & { readonly scheme?: string },
): QrCode {
  const url = buildCredentialOfferUrl(offer, { ...(options?.scheme !== undefined ? { scheme: options.scheme } : {}) });
  return new QrCode(url, pickRenderer(options), pickQrOptions(options));
}

/**
 * Stripe-shaped namespace export. `qr.fromUrl(...)`, etc. Same
 * functions are also available as named exports for tree-shaking.
 */
export const qr = {
  fromUrl,
  fromAuthorizationRequest,
  fromCredentialOffer,
} as const;

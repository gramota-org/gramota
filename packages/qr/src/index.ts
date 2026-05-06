/**
 * `@gramota/qr` public API.
 *
 * Most consumers want the namespaced object:
 *
 *   import { qr } from "@gramota/qr";
 *   const code = qr.fromUrl("openid4vp://...");
 *   const dataUrl = await code.toDataUrl();
 *
 * Tree-shakers and people swapping renderers want the named exports
 * (factories, `QrCode`, `DefaultQrRenderer`, `QrRenderer` interface).
 */
export {
  qr,
  fromUrl,
  fromAuthorizationRequest,
  fromCredentialOffer,
  type QrFactoryOptions,
} from "./qr.js";
export { QrCode } from "./qr-code.js";
export {
  DefaultQrRenderer,
  type QrRenderer,
} from "./renderer.js";
export {
  QrError,
  type QrErrorCode,
  type QrFormat,
  type QrOptions,
} from "./types.js";

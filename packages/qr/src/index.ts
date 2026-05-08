/**
 * `@gramota/qr` public API.
 *
 * Two patterns work — pick whichever fits:
 *
 *   1. **Default singleton** (zero config):
 *      ```ts
 *      import { qr } from "@gramota/qr";
 *      const code = qr.fromUrl("openid4vp://…");
 *      ```
 *
 *   2. **Custom client** (custom renderer, default options):
 *      ```ts
 *      import { QrClient } from "@gramota/qr";
 *      const qr = new QrClient({ errorCorrection: "H", width: 512 });
 *      const code = qr.fromUrl("openid4vp://…");
 *      ```
 *
 * Tree-shakers can also import the named factories directly
 * (`fromUrl`, `fromAuthorizationRequest`, `fromCredentialOffer`) —
 * they delegate to the singleton.
 */
export {
  QrClient,
  qr,
  fromUrl,
  fromAuthorizationRequest,
  fromCredentialOffer,
  type QrClientOptions,
  type QrFactoryOptions,
} from "./client.js";
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

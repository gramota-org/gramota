# @gramota/qr

> QR-code rendering for EUDIW deep links. Strategy-pluggable renderer, three input shapes (any URL, OID4VP authorization request, OID4VCI credential offer), three output formats (data URL, SVG, raw PNG bytes).

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet.

## Install

```bash
pnpm add @gramota/qr
# or: npm install @gramota/qr
```

## Quick example

```ts
import { qr } from "@gramota/qr";

const code = qr.fromUrl("openid4vp://?client_id=...&request_uri=...");

const dataUrl = await code.toDataUrl();   // <img src={dataUrl} />
const svg     = await code.toSvg();       // for innerHTML / SSR
const png     = await code.toPng();       // Uint8Array — fs.writeFile, multipart upload
```

## Three input shapes

`qr.fromUrl(url, options?)` — most general. Any string with a `<scheme>:` prefix.

`qr.fromAuthorizationRequest(request, options?)` — composes with
`@gramota/oid4vp`. Takes a typed `AuthorizationRequest`, builds the
`openid4vp://` deep link, renders the QR. Override the scheme via
`{ scheme: "haip://" }` for vendor-specific wallets.

`qr.fromCredentialOffer(offer, options?)` — composes with
`@gramota/oid4vci`. Takes a typed `CredentialOffer`, builds the
`openid-credential-offer://` deep link, renders the QR.

## Three output formats — lazy + memoised

`code.toDataUrl()`, `code.toSvg()`, `code.toPng()` each invoke the
configured renderer on first call and cache the result. Concurrent
first-callers share the in-flight render — no thundering herd. Pay
the encode cost once per format, only for the formats you actually use.

## Pluggable renderer (Strategy pattern)

The default is `DefaultQrRenderer` — an Adapter over the [`qrcode`](https://www.npmjs.com/package/qrcode)
npm package. Want logo embedding, branded colours, a browser-native
canvas renderer? Implement `QrRenderer`:

```ts
import type { QrRenderer, QrFormat, QrOptions } from "@gramota/qr";

class BrandedQrRenderer implements QrRenderer {
  async render(url: string, format: QrFormat, opts: QrOptions) {
    // …your renderer (e.g. with a logo overlaid in the centre)…
  }
}

const code = qr.fromUrl(url, { renderer: new BrandedQrRenderer() });
```

The orchestrator depends only on the `QrRenderer` interface, never on
`qrcode` directly. You can swap the rendering backend without touching
your verifier or issuer code.

## Design

`@gramota/qr` is small but follows the same patterns as the rest of the SDK:

- **Strategy** (GoF) — `QrRenderer` interface with a default Adapter
  over `qrcode`. Add new renderers by implementing the interface.
- **Factory Method** (GoF) — `qr.from*` family creates `QrCode`
  instances from different input shapes; new sources add as siblings,
  no existing factory changes.
- **Adapter** (GoF) — `DefaultQrRenderer` adapts `qrcode`'s API to
  ours. Replacing `qrcode` later means a one-file change here, zero
  changes for consumers.
- **Lazy + memoisation** — output formats render on first call only;
  concurrent first-callers share the promise.
- **Open/Closed, Dependency Inversion** — the orchestrator depends
  on the abstraction; concrete implementations plug in via DI.

For the high-level wallet + verifier counterparts, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

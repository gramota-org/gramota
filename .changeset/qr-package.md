---
"@gramota/qr": minor
"@gramota/oid4vci": minor
---

New package: **`@gramota/qr`** — QR-code rendering for EUDIW deep links
with a Strategy-pluggable renderer.

Three Factory Methods accept the common protocol artifacts:

- `qr.fromUrl(url, options?)` — any deep-link URL.
- `qr.fromAuthorizationRequest(authzRequest, options?)` — composes
  with `@gramota/oid4vp`'s `buildAuthorizationRequestUrl`.
- `qr.fromCredentialOffer(offer, options?)` — composes with
  `@gramota/oid4vci`'s new `buildCredentialOfferUrl`.

Each returns a `QrCode` whose three output formats (`toDataUrl`,
`toSvg`, `toPng`) render lazily and memoise: pay the encode cost once
per format, share the in-flight Promise across concurrent callers.

The default renderer adapts the `qrcode` npm package; swap it via
`{ renderer: customRenderer }` to embed logos, brand colours, or use
a browser-native canvas backend without touching the orchestrator.

```ts
import { qr } from "@gramota/qr";

const code = qr.fromAuthorizationRequest({
  response_type: "vp_token",
  client_id: "x509_san_dns:my-bank.com",
  nonce, state,
  dcql_query: { credentials: [...] },
});
const dataUrl = await code.toDataUrl();   // <img src=...>
```

Also: `@gramota/oid4vci` now exports `buildCredentialOfferUrl` — the
inverse of `parseCredentialOffer`. Used internally by
`qr.fromCredentialOffer`, useful directly for any issuer that builds
offer deep links by hand.

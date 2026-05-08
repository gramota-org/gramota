# @gramota/dcql

## 0.1.2

### Patch Changes

- cb462fa: **Stripe-shaped public surface across every package.**

  This release is a structural pass — the runtime behaviour of every
  package is unchanged, but the API shape has been consolidated to match
  the Stripe TypeScript SDK conventions used by the rest of the
  ecosystem. Two new packages, two reshaped clients, one shared base
  class.

  ### New: `@gramota/core`

  Foundation package every other `@gramota/*` package now depends on.
  Two exports:

  - `Fetcher`, `FetcherResponse`, `mockFetcherResponse` — the HTTP
    transport interface, moved here from `@gramota/jose` (it was always
    about HTTP, not crypto). `@gramota/jose` re-exports for back-compat
    through 1.0.
  - `GramotaError` (+ `isGramotaError`) — the base class every package's
    error type now extends. App-level catch sites can now use one
    `instanceof GramotaError` check instead of importing every package's
    error class. `error.code` is preserved as a stable string.

  ### New: `@gramota/sdk`

  Top-level facade. One import, one config, lazy-instantiated clients:

  ```ts
  import { Gramota } from "@gramota/sdk";

  const gramota = new Gramota({
    verifier: { audience: "https://my-bank.com", trust },
    qr: { errorCorrection: "H" },
  });

  await gramota.verifier.presentations.verify(token, { nonce });
  const code = gramota.qr.fromAuthorizationRequest(req);
  ```

  The individual packages still work standalone — the facade is
  additive. Use whichever fits.

  ### Reshape: `@gramota/verifier@0.3.0`

  New Stripe-shaped namespaces on the `Verifier` instance:

  ```ts
  verifier.presentations.verify(token, opts); // was verifier.verify(token, opts)
  verifier.responses.verify(rawBody, opts); // was verifier.response(rawBody, opts)
  verifier.requests.create(opts); // was verifier.request(opts)
  ```

  The flat methods (`verify`, `response`, `request`) are kept for back-
  compat and marked `@deprecated`. They will be removed in 1.0. Both
  shapes call into the same implementation; migrate at your pace.

  ### Reshape: `@gramota/qr@0.2.0`

  New `QrClient` class for advanced use:

  ```ts
  import { QrClient } from "@gramota/qr";
  const qr = new QrClient({
    renderer: customRenderer,
    errorCorrection: "H",
    width: 512,
  });
  const code = qr.fromUrl("openid4vp://…");
  ```

  The default `qr` singleton (`qr.fromUrl(...)`) is now an instance of
  `QrClient` with the default renderer. Existing `qr.fromUrl(...)`
  callers keep working without change. The flat factory functions
  (`fromUrl`, `fromAuthorizationRequest`, `fromCredentialOffer`) are
  preserved for tree-shaking.

  ### Per-package error class refactor (patch bump)

  Every per-package error now extends `GramotaError`:

  ```ts
  import { isGramotaError } from "@gramota/core";

  try {
    await verifier.presentations.verify(token, opts);
  } catch (err) {
    if (isGramotaError(err)) {
      telemetry.recordError(err.name, err.code);
    }
    throw err;
  }
  ```

  Constructor signatures and the `code` field shapes are unchanged —
  existing `instanceof VerifierError` / `instanceof IssuerError` /
  `error.code === "..."` checks all still work. Type-only change for
  most consumers.

- Updated dependencies [cb462fa]
  - @gramota/core@0.2.0
  - @gramota/sd-jwt@0.2.1

## 0.1.1

### Patch Changes

- Updated dependencies [bbbe647]
  - @gramota/sd-jwt@0.2.0

# @gramota/verifier

## 0.4.0

### Minor Changes

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

### Patch Changes

- Updated dependencies [cb462fa]
  - @gramota/core@0.2.0
  - @gramota/jose@0.2.1
  - @gramota/oid4vp@0.2.1
  - @gramota/sd-jwt@0.2.1
  - @gramota/status-list@0.1.2
  - @gramota/trust@0.1.2

## 0.2.0

### Minor Changes

- bbbe647: OID4VCI Draft 15 + DPoP server + OID4VP signed JAR / DCQL response support, plus an API surface tightening pass.

  ### New protocol primitives

  - **`@gramota/jose`** — `computeJwkThumbprint` (RFC 7638), unified `Fetcher` + `FetcherResponse` shared across the SDK, plus `mockFetcherResponse` helper for one-line test mocks.
  - **`@gramota/oid4vci`** — `verifyDpopJwt` (RFC 9449 §4.3 server-side verification), `parseCredentialRequest` (Draft 13 ↔ Draft 14/15 normaliser, accepts `proofs.jwt[]`), `buildSubdomainIssuerUrl` for multi-tenant issuer URLs. `CredentialRequest` type extended with `proofs.jwt[]` and `credential_identifier`.
  - **`@gramota/oid4vp`** — `generateSigningCert` (X.509 self-signed for `x509_san_dns` client_id_prefix), `signAuthorizationRequest` (RFC 9101 JAR with `x5c` header), `signingCertToJwks` (PEM bundle → JWK pair). `AuthorizationResponse.vp_token` now also accepts the DCQL response shape (`Record<string, string>` keyed by credential id), and `presentation_submission` is optional in that shape — production EU wallets send the DCQL form.
  - **`@gramota/verifier`** — new `additionalAudiences` config so the KB-JWT `aud` check accepts both the SD-JWT-VC URL form and the OID4VP `x509_san_dns:host` form production EU wallets send.
  - **`@gramota/issuer`** — `issuer.credentials.issue(...)` namespace alongside the existing flat `issuer.issue(...)`, symmetric with `holder.credentials.*`.

  ### Breaking renames

  - `JoseVerificationError` → **`JoseError`**.
  - `VerificationError` → **`VerifierError`** (no-prefix collision risk with other packages).
  - `GenerateSigningCertInput` → **`GenerateSigningCertOptions`** (matches the package's `Options` / `Config` / `Result` convention).
  - `preAuthorizedCodeFrom(...)` / `txCodeRequirementFrom(...)` → **`extractPreAuthorizedCode(...)`** / **`extractTxCodeRequirement(...)`**.
  - Free `verify(...)` function dropped from `@gramota/verifier` — `Verifier` class is the canonical entry point.
  - **`@gramota/sd-jwt`** — four error classes (`SdJwtParseError`, `SdJwtVerificationError`, `SdJwtIssuanceError`, `SdJwtKeyBindingError`) collapsed into one **`SdJwtError`** + `SdJwtErrorCode` union of 24 codes namespaced `sd_jwt.{parse,verify,kb,issue}.*`. Branch on `code` instead of `instanceof`.

  ### Docs

  - All package READMEs rewritten — previous templates referenced exports that didn't exist (e.g. `import { sign, verify } from "@gramota/jose"` against an SDK that exports `signJws`/`verifyJws`). Every snippet now compiles against real exports.
  - JSDoc parity sweep on older files (`oid4vci/offer.ts`, `oid4vp/request.ts`, `jose/verify.ts`) — examples + spec refs + enumerated `@throws` lists matching the newer modules.

  ### Tests

  599 total (~60 new across the new modules). 579 passing; 20 live-interop suites skipped by default. End-to-end verified against the EU reference wallet on Android (status=verified with disclosed claims).

### Patch Changes

- Updated dependencies [bbbe647]
  - @gramota/jose@0.2.0
  - @gramota/oid4vp@0.2.0
  - @gramota/sd-jwt@0.2.0
  - @gramota/status-list@0.1.1
  - @gramota/trust@0.1.1

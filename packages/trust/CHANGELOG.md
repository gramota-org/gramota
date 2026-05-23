# @gramota/trust

## 0.2.0

### Minor Changes

- 79a622e: EUDI HAIP conformance — Tier 1 + Tier 2 audit findings landed.

  Driven by the audit at `gramota-org/saas/docs/compliance/` (OID4VP, OID4VCI,
  SD-JWT-VC, and HAIP+ARF reports). Every item below has spec citations + tests.

  ## @gramota/oid4vci

  - `verifyProofJwt` — mandatory `typ === "openid4vci-proof+jwt"` check + `iat`
    window (60 s past, 5 s future, configurable) + ES256-pinned signature +
    optional nonce match + `cnf.jwk` extraction. New `oid4vci.invalid_proof`
    error code. Closes audit finding G4 (OID4VCI §7.2.1.1).

  ## @gramota/oid4vp

  - `client_id_scheme` now defaults to `x509_hash` (HAIP 1.0 Final §5).
    Legacy `x509_san_dns` remains available as an opt-in. New helpers
    `computeCertX509Hash` + `buildClientIdFromCert`.
  - `response_mode=direct_post.jwt` — JWE-encrypted authorization-response
    path per HAIP §5.1. ECDH-ES + A256GCM defaults, alg/enc allowlists,
    PEX + DCQL round-trip. Cleartext direct_post continues to work for
    back-compat. New `generateResponseEncryptionKey`,
    `encryptAuthorizationResponse`, `decryptAuthorizationResponse`,
    `oid4vp.response_encryption_failed` error code.

  ## @gramota/dcql

  - `DcqlSdJwtVcMatcher` gains a `vctMatchMode` option. Default `"strict"`
    is unchanged; `"eudi-pid-extensions"` accepts `urn:eudi:pid:<cc>:1`
    domestic variants against a query for the cross-border base
    `urn:eudi:pid:1` (ARF Annex 3.01 §3). Exposed `isPidExtensionOf`
    helper.

  ## @gramota/trust

  - New `LoTeTrustResolver` (List of Trusted Entities skeleton, ARF
    §6.6.5). In-memory allow-list of `iss` URLs with pinned JWKs +
    `notBefore`/`notAfter` validity windows. Composable with an inner
    `TrustResolver`; intersects fresh JWKS against the pinned set. Falls
    back to the pinned set on inner-resolver failure. Diagnostic
    `lookup` / `listIssuers` surface for ops.

  ## @gramota/issuer

  - JWS `typ` default flipped to `dc+sd-jwt` (SD-JWT-VC §3.2.1, since
    draft-08). Legacy `vc+sd-jwt` still available via `IssuerConfig.typ`;
    already-minted credentials remain verifiable.
  - New `packages/issuer/src/pid.ts` — `EU_PID_VCT`, canonical claim
    names (`birthdate` not `birth_date`), `PID_MANDATORY_CLAIM_NAMES`,
    `defaultPidSubject()` builder with all Rulebook §2.2/§2.4 mandatory
    claims (nationalities, issuing_country, issuing_authority,
    birth_place), `statusListReference(uri, idx)` helper for IETF Token
    Status List references.
  - `status` claim plumbed through `IssueOptions`. Omitted when
    undefined (verifier reads as non-revocable); present + structured
    when supplied. Full status-list integration is a follow-up; this
    lands the credential-side structure HAIP §6.1 requires.

  ## @gramota/sd-jwt

  - New `sd()` marker function + recursive `issueSdJwt` walker. Supports
    nested-object selective disclosure (`{address: {_sd: [...]}}`) and
    array-element disclosure (`{nationalities: [{"...": digest_DE}, "FR"]}`)
    per SD-JWT §4.2.4–4.2.5 — required for PID Rulebook §4.1.1's
    `address` and `nationalities` claims.
  - Defensive `sd_jwt.issue.sd_marker_misplaced` error: `sd(sd(x))`
    fails loudly at issue time rather than producing an invalid wire
    encoding.

  ## @gramota/credential-format

  - `dc+sd-jwt` listed first in the SD-JWT-VC `formats` array (the
    canonical typ since SD-JWT-VC draft-08). Patch-level — purely a
    registry ordering change.

  ## Tests

  72 new tests in protocol packages (`oid4vci`/`oid4vp`/`dcql`/`trust`),
  31 new in credential packages (`issuer`/`sd-jwt`/`credential-format`).
  Total monorepo: 749 passing, 20 skipped (live-interop only). No
  regressions in downstream consumers (`@gramota/verifier`,
  `@gramota/sdk`, `@gramota/e2e`).

## 0.1.3

### Patch Changes

- Updated dependencies
  - @gramota/jose@0.3.0
  - @gramota/core@0.2.1

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
  - @gramota/jose@0.2.1

## 0.1.1

### Patch Changes

- Updated dependencies [bbbe647]
  - @gramota/jose@0.2.0

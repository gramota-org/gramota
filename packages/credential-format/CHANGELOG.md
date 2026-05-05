# @gramota/credential-format

## 0.1.1

### Patch Changes

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

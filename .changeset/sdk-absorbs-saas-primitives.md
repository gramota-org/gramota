---
"@gramota/oid4vci": minor
"@gramota/oid4vp": minor
---

SDK absorbs OAuth/OID4VCI/OID4VP primitives that were duplicated in the SaaS host.

Principle: every byte of OID4VP / OID4VCI / OAuth 2.0 protocol logic belongs
in the SDK. Host applications wire HTTP, persistence, and tenancy on top —
they don't reinvent the protocol primitives. The previous round of HAIP
conformance work landed several primitives directly in the SaaS API where
they were inaccessible to other consumers (Shopify backend, Magento adapter,
custom verifiers). This changeset hoists them.

## @gramota/oid4vci — new exports

**Stores (interface + in-memory default).** Hosts can swap in Redis,
Postgres, or any other backing; the in-memory default is a Map with
TTL pruning.

- `CNonceStore` / `CNonceStoreLike` / `C_NONCE_TTL_SECONDS` — OID4VCI
  1.0 Final §7 dedicated nonce-endpoint pool. Mint, single-use consume,
  prune.
- `ParStore` / `ParStoreLike` / `PAR_DEFAULT_TTL_SECONDS` /
  `ParRequestPayload` / `PushedClientAttestation` — RFC 9126 Pushed
  Authorization Requests. `put(payload) → {requestUri, expiresInSeconds}`,
  `consume(requestUri)` single-use.
- `AuthCodeStore` / `AuthCodeStoreLike` / `AUTH_CODE_TTL_SECONDS` /
  `AuthCodeRequest` / `CodeChallengeMethod` — OID4VCI §3.4 + RFC 7636
  PKCE auth-code grant storage.
- `InMemoryDpopJtiStore` / `DpopJtiStoreLike` — RFC 9449 §11.1
  interface only. Single atomic `checkAndRecord(jti, expiresAt)`; the
  in-memory impl is the default; hosts plug in Postgres/Redis behind
  the same interface.

**Pure helpers.**

- `verifyPkceChallenge(verifier, challenge, method)` — RFC 7636 §4.6.
  Supports S256 + plain. Constant-time compare via `timingSafeEqual`.
- `verifyWalletAttestation(headers, config)` — HAIP §6.3 OAuth
  Attestation-Based Client Authentication. Validates both the
  attestation JWT (signed by an attester) and the PoP JWT (signed by
  the client instance). Returns the validated instance JWK +
  attestation metadata. Distinguishes 17 specific error codes
  (`WalletAttestationErrorCode`) so hosts can map onto HTTP status.
- `loadWalletAttestationConfigFromEnv(env)` — convenience parser
  for `WALLET_ATTESTER_JWK` / `WALLET_ATTESTER_JWKS` /
  `WALLET_ATTESTER_JWKS_URL` / `WALLET_ATTESTATION_SANDBOX` /
  `WALLET_ATTESTATION_NONCE`.

**Metadata builders.** Hosts no longer hand-roll the well-known
response shapes.

- `buildIssuerMetadata(input)` — emits the OID4VCI §11.2 shape with
  `credential_issuer`, `credential_endpoint`, `nonce_endpoint`,
  `batch_credential_issuance`, etc.
- `buildAuthorizationServerMetadata(input)` — emits the RFC 8414
  shape with `authorization_endpoint`, `token_endpoint`,
  `pushed_authorization_request_endpoint`,
  `require_pushed_authorization_requests`, PKCE methods, grant types,
  DPoP algs. Auth-code fields conditional on input.

**Code generators.** Match the existing primitives' shape.

- `generateAuthorizationCode({ byteLength? })` — base64url, default
  32 bytes.
- `generatePreAuthorizedCode({ byteLength? })` — base64url, default
  32 bytes.

**Runtime dep promoted.** `jose` moved from `devDependencies` to
`dependencies` — `verifyWalletAttestation` uses `createRemoteJWKSet`
when `attesterJwksUrl` is configured. No new transitive deps; `jose`
was already in the lockfile.

## @gramota/oid4vp — new + changed exports

- `signAuthorizationRequest` now emits standard JWT claims `aud`,
  `iat`, `exp` on the signed JAR by default. Previously these were
  missing — callers had to wrap the SDK signer to add them, which the
  SaaS was doing. (RFC 9101 + OID4VP §5.8.) New optional params
  `aud` (default `https://self-issued.me/v2` per HAIP), `jarLifetimeSeconds`
  (default 300), and an injectable `now` for tests. Payload-level
  values still win if set. **Non-breaking** for consumers that already
  set the claims; **additive** for consumers (like the SaaS) that
  weren't setting them at all.
- `DEFAULT_JAR_AUDIENCE` / `DEFAULT_JAR_LIFETIME_SECONDS` exported so
  hosts can reference the same defaults.
- `generateState()` — 128-bit hex (RFC 6749 §10.12 + OID4VP §5.3).
- `generateNonce()` — 128-bit base64url (OID4VP §5.3 + KB-JWT
  binding).

## Tests

103 new tests across the two packages (`@gramota/oid4vci` 131 → 217,
`@gramota/oid4vp` 75 → 92). RFC 7636 Appendix B.1 PKCE vector. All
17 `WalletAttestationError` codes covered. JAR claims defaults +
overrides + injectable clock. Random helpers' length + charset +
collision check (N=1000).

## Downstream impact

- `@gramota/verifier`, `@gramota/sdk`, `@gramota/e2e` tests all pass
  against the new exports. No call-site changes required.
- The hosted SaaS at `gramota-org/saas` (`apps/api`) will refactor in
  a sibling commit to delete its local copies of the primitives and
  consume these exports directly. Net `−538` lines.

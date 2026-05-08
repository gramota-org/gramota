# Gramota

> *гра́мота* — the Slavic word for an official charter or certificate of authority.
> Tsars issued *grammoty* of nobility. Schools issue *grammoty* of graduation.
> Today, governments issue digital *grammoty* under eIDAS. **This SDK builds them.**

The TypeScript SDK for the **EU Digital Identity Wallet (EUDIW)**.
Verify, issue, and integrate EUDIW credentials in 20 lines of code.

[![npm](https://img.shields.io/npm/v/@gramota/verifier?label=%40gramota%2Fverifier&color=cb3837&logo=npm)](https://www.npmjs.com/package/@gramota/verifier)
[![Tests](https://img.shields.io/badge/tests-579%20mock%20%2B%2031%20live-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue)]()
[![Node](https://img.shields.io/badge/Node-20%2B-brightgreen)]()
[![Provenance](https://img.shields.io/badge/npm-provenance%20signed-blue?logo=sigstore)](https://www.npmjs.com/package/@gramota/verifier)
[![Docs](https://img.shields.io/badge/docs-gramota--org.github.io-4f46e5)](https://gramota-org.github.io/site/)

> **v0.2 — verified end-to-end against the EU reference wallet.** Issuance
> (OID4VCI Draft 15 + DPoP) and verification (OID4VP Final 1.0 + DCQL +
> signed JAR) both round-trip cleanly with the official EUDIW Android wallet.
> See [v0.2 highlights](#v02-highlights) below — or jump straight to the
> [docs site](https://gramota-org.github.io/site/) for getting started,
> guides, and the auto-generated API reference.

---

## Why Gramota

The EU Digital Identity Wallet is mandatory by 2027. Every regulated digital
business — banks, telcos, fintech, age-gated commerce — needs to integrate.

The existing identity SDKs are heavy, Kotlin-first, and built for identity
specialists. Gramota is **TypeScript-native, opinionated, and built for the
millions of web developers** who'd otherwise have to read 80 pages of
EU ARF documentation just to verify a holder.

**Install:**

```bash
npm install @gramota/verifier @gramota/trust
# or: pnpm add @gramota/verifier @gramota/trust
# or: yarn add @gramota/verifier @gramota/trust
```

**Five-line verifier:**

```ts
import { Verifier } from "@gramota/verifier";
import { StaticTrustResolver } from "@gramota/trust";

const verifier = new Verifier({
  audience: "https://my-bank.com",
  trust: new StaticTrustResolver([issuerJwk]),
});
const result = await verifier.presentations.verify(presentationToken, { nonce });
if (result.ok) console.log(result.claims);  // { given_name: "Greta", ... }
```

**Or the top-level facade — one import, one config:**

```ts
import { Gramota } from "@gramota/sdk";
const gramota = new Gramota({
  verifier: { audience: "https://my-bank.com", trust },
});
await gramota.verifier.presentations.verify(token, { nonce });
const code = gramota.qr.fromAuthorizationRequest(req);
```

Every wire-format check, every spec corner. **Live-tested against the EU
Commission's reference infrastructure** (`dev.issuer-backend.eudiw.dev`,
`dev.verifier-backend.eudiw.dev`) and **end-to-end against the official
EUDIW Android reference wallet** for both issuance and verification.

---

## v0.2 highlights

The 0.2 release is the first version proven against a real EU wallet on a
real device. What landed:

- **End-to-end with the EU reference wallet (Android).** Both flows green:
  the wallet receives a credential from `@gramota/issuer` over OID4VCI, then
  presents it back to `@gramota/verifier` over OID4VP — `status: "verified"`,
  claims unpacked.
- **OID4VCI Draft 15 normalization.** `parseCredentialRequest()` accepts the
  current Draft 13 `proof.jwt` shape *and* Draft 15's `proofs.jwt[]` array
  and normalizes both into the same internal form. Wallets that haven't
  shipped Draft 15 yet keep working; ones that have, work too.
- **DPoP server-side (RFC 9449).** `verifyDpopJwt()` enforces `htm`/`htu`/
  `iat`/`jti`/`ath`/optional `nonce` and returns the `jkt` thumbprint for
  binding to the issued access token. Combined with the existing client-side
  DPoP signer, both halves of the protocol are now in-package.
- **OID4VP Final 1.0 with DCQL.** Response parsing accepts the
  `vp_token: Record<string, string>` shape that DCQL specifies (one entry
  per query id), with optional `presentation_submission` for back-compat.
- **Signed JAR over X.509 (RFC 9101).** `signAuthorizationRequest()` plus
  `generateSigningCert()` + `signingCertToJwks()` in `@gramota/oid4vp`
  produce a `client_id_prefix=x509_san_dns` request_uri that production
  wallets accept without the chicken-and-egg of pre-registering the verifier.
- **Stripe-shaped namespacing.** `holder.credentials.*`, `issuer.credentials.issue()`,
  unified `Fetcher` type across packages, `JoseError`/`SdJwtError`/`VerifierError`
  consistent naming. The library reads like one product, not eight.

Per-package release notes live in each package's `CHANGELOG.md`
(e.g. [`packages/verifier/CHANGELOG.md`](./packages/verifier/CHANGELOG.md)).
Migrating from 0.1? Most users won't touch anything — only error class
renames are breaking.

---

## Standards covered

| Spec | What | Status |
|---|---|---|
| **eIDAS 2 / EUDIW** (EU Reg. 2024/1183) | EU regulation for electronic identification | ✅ |
| **OID4VCI** (OpenID for Verifiable Credential Issuance) | Pre-auth + auth-code, Draft 13 + Draft 15 normalized | ✅ |
| **OID4VP** (OpenID for Verifiable Presentations) | Final 1.0 with DCQL responses | ✅ |
| **SD-JWT-VC** (IETF draft) | Selective-disclosure verifiable credentials | ✅ |
| **DCQL** (Digital Credentials Query Language) | OID4VP 2.0 query format | ✅ |
| **DIF Presentation Exchange v2** | Legacy OID4VP 1.0 query | ✅ |
| **IETF Token Status List** | Credential revocation/suspension | ✅ |
| **PAR (RFC 9126)** | Pushed Authorization Requests | ✅ |
| **JAR (RFC 9101)** | Signed Authorization Requests, `x509_san_dns` | ✅ |
| **DPoP (RFC 9449)** | Sender-constrained tokens (client + server) | ✅ |
| **PKCE (RFC 7636)** | Proof Key for Code Exchange | ✅ |
| **JOSE** (RFC 7515/7517/7518/7520) | JWS, JWK, JWA, JWS-JSON | ✅ |
| **x5c chain validation** (RFC 7515 §4.1.6) | X.509 certificate chain | ✅ |
| **mso_mdoc** (ISO 18013-5) | Mobile Document format | ⏳ Roadmap |

---

## Packages

All packages live on the [`@gramota` npm org](https://www.npmjs.com/org/gramota).
Every published tarball ships with a [signed provenance attestation](https://docs.npmjs.com/generating-provenance-statements)
linking it to a specific GitHub commit (Sigstore transparency log).

### Top-level facade

| Package | What it does |
|---|---|
| [`@gramota/sdk`](https://www.npmjs.com/package/@gramota/sdk) [![npm](https://img.shields.io/npm/v/@gramota/sdk?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/sdk) | Stripe-shaped facade: `new Gramota({...}).verifier.presentations.verify(...)` — one config, lazy-instantiated clients |

### High-level

| Package | What it does |
|---|---|
| [`@gramota/verifier`](https://www.npmjs.com/package/@gramota/verifier) [![npm](https://img.shields.io/npm/v/@gramota/verifier?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/verifier) | Relying-party verifier (12 security checks). Stripe-shaped: `presentations.verify`, `responses.verify`, `requests.create` |
| [`@gramota/issuer`](https://www.npmjs.com/package/@gramota/issuer) [![npm](https://img.shields.io/npm/v/@gramota/issuer?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/issuer) | High-level issuer for SD-JWT-VC (`credentials.*`) |
| [`@gramota/holder`](https://www.npmjs.com/package/@gramota/holder) [![npm](https://img.shields.io/npm/v/@gramota/holder?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/holder) | Headless holder / wallet (`credentials.*` + `offers.*`) |

### Protocol & transport

| Package | What it does |
|---|---|
| [`@gramota/oid4vp`](https://www.npmjs.com/package/@gramota/oid4vp) [![npm](https://img.shields.io/npm/v/@gramota/oid4vp?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/oid4vp) | OID4VP request + response wire format, signed JAR, `x509_san_dns` cert helpers |
| [`@gramota/oid4vci`](https://www.npmjs.com/package/@gramota/oid4vci) [![npm](https://img.shields.io/npm/v/@gramota/oid4vci?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/oid4vci) | OID4VCI client + server: Draft 13/15 normalized, PAR, DPoP both sides |
| [`@gramota/presentation-exchange`](https://www.npmjs.com/package/@gramota/presentation-exchange) [![npm](https://img.shields.io/npm/v/@gramota/presentation-exchange?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/presentation-exchange) | DIF Presentation Exchange v2 |
| [`@gramota/dcql`](https://www.npmjs.com/package/@gramota/dcql) [![npm](https://img.shields.io/npm/v/@gramota/dcql?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/dcql) | Digital Credentials Query Language (OID4VP 2.0) |
| [`@gramota/qr`](https://www.npmjs.com/package/@gramota/qr) [![npm](https://img.shields.io/npm/v/@gramota/qr?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/qr) | QR rendering for OID4VP / OID4VCI deep links — Strategy-pluggable renderer, three output formats |

### Cryptography & credentials

| Package | What it does |
|---|---|
| [`@gramota/jose`](https://www.npmjs.com/package/@gramota/jose) [![npm](https://img.shields.io/npm/v/@gramota/jose?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/jose) | JWS sign + verify + x5c chain validation; pluggable `Signer`; unified `Fetcher` type |
| [`@gramota/sd-jwt`](https://www.npmjs.com/package/@gramota/sd-jwt) [![npm](https://img.shields.io/npm/v/@gramota/sd-jwt?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/sd-jwt) | SD-JWT-VC parser, hash binding, KB-JWT |
| [`@gramota/credential-format`](https://www.npmjs.com/package/@gramota/credential-format) [![npm](https://img.shields.io/npm/v/@gramota/credential-format?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/credential-format) | Pluggable format-handler registry (SD-JWT-VC; mDoc TBD) |

### Trust & revocation

| Package | What it does |
|---|---|
| [`@gramota/trust`](https://www.npmjs.com/package/@gramota/trust) [![npm](https://img.shields.io/npm/v/@gramota/trust?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/trust) | `TrustResolver`: Static, JwksUrl, SdJwtVcIssuer (`.well-known/jwt-vc-issuer`) |
| [`@gramota/status-list`](https://www.npmjs.com/package/@gramota/status-list) [![npm](https://img.shields.io/npm/v/@gramota/status-list?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/status-list) | IETF Token Status List + `StatusResolver` Strategy |

### Foundation

| Package | What it does |
|---|---|
| [`@gramota/core`](https://www.npmjs.com/package/@gramota/core) [![npm](https://img.shields.io/npm/v/@gramota/core?label=&color=cb3837)](https://www.npmjs.com/package/@gramota/core) | Shared primitives — `Fetcher` transport interface, `GramotaError` base class. Imported by every other `@gramota/*` package |

### Internal (not published)

| Package | What it does |
|---|---|
| `@gramota/demo` | Runnable CLI demos: `self-loop`, `eu-pid`, `list` |
| `@gramota/e2e` | Cross-package integration test suite |

Architecture leans hard on **GoF Strategy + DI**:

- **`AuthorizationTransport`** Strategy — PAR (default) / Direct / custom (e.g. JAR)
- **`Signer`** Strategy — `JwkSigner` (default), or HSM/WebAuthn/KMS-backed
- **`TrustResolver`** Strategy — `Static`, `JwksUrl`, `SdJwtVcIssuer`, custom
- **`StatusResolver`** Strategy — IETF status list, or custom (CRL, OCSP, EU TIR)
- **`CredentialFormatHandler`** Registry — SD-JWT-VC default; mDoc plugs in later
- **`CredentialStore`** Strategy — `InMemory`, `File`, custom (SQLite, IndexedDB)

Adding a new transport, signer, trust mechanism, or credential format requires
implementing one interface and passing the instance to the orchestrator. No
core changes (Open/Closed Principle, verified by tests).

---

## Try the demo

```bash
git clone https://github.com/gramota-org/gramota.git
cd gramota
pnpm install
pnpm demo:self-loop      # local Issuer → Holder → Verifier in 1.5s
pnpm demo:eu-pid         # interactive: receive a real EU-signed PID via OID4VCI
pnpm demo:list           # show stored credentials
```

**`demo:self-loop`** mints a credential, validates 12 security checks, and
persists it locally. Reads as a tutorial.

**`demo:eu-pid`** drives `Oid4vciClient.authorize()` against the live EU
Commission dev issuer, opens your browser to the Keycloak login, prompts for
the OOB authorization code, exchanges it for a credential, and validates
the signature against EU's published keys via the IETF SD-JWT-VC issuer
discovery (`/.well-known/jwt-vc-issuer`).

---

## Testing

Two-tier convention: fast mock by default, opt-in live against EU.

```bash
pnpm test            # 579 mock tests, ~2s, no network
pnpm test:live       # 31 live tests against EU dev infra (~2s + network)
pnpm test:all        # both, in one run
```

Live tests gated by `EUDI_LIVE=1`. CI runs mock on every push, live nightly.

---

## Project status

- **Phase 0** (foundation): ✅ done — 14 packages (12 published, 2 internal), 579+31 tests
- **Phase 1** (public launch): 🟡 in progress — ✅ npm v0.2.0 published, ✅ EU reference wallet round-trip on Android, ✅ [docs site live](https://gramota-org.github.io/site/), ⏳ launch post
- **Phase 2** (downstream): 🗓 future — WordPress / Shopify / Stripe Connect

Strategy and roadmap: [MANIFEST.md](./MANIFEST.md).
Release flow: [PUBLISHING.md](./PUBLISHING.md).

---

## License

Apache 2.0. See [LICENSE](./LICENSE).

---

*Built in Sofia. Sold to the world in English.*

# Gramota

> *гра́мота* — the Slavic word for an official charter or certificate of authority.
> Tsars issued *grammoty* of nobility. Schools issue *grammoty* of graduation.
> Today, governments issue digital *grammoty* under eIDAS. **This SDK builds them.**

The TypeScript SDK for the **EU Digital Identity Wallet (EUDIW)**.
Verify, issue, and integrate EUDIW credentials in 20 lines of code.

[![Tests](https://img.shields.io/badge/tests-524%20mock%20%2B%2031%20live-brightgreen)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue)]()
[![Node](https://img.shields.io/badge/Node-20%2B-brightgreen)]()

---

## Why Gramota

The EU Digital Identity Wallet is mandatory by 2027. Every regulated digital
business — banks, telcos, fintech, age-gated commerce — needs to integrate.

The existing identity SDKs are heavy, Kotlin-first, and built for identity
specialists. Gramota is **TypeScript-native, opinionated, and built for the
millions of web developers** who'd otherwise have to read 80 pages of
EU ARF documentation just to verify a holder.

**Five-line verifier:**

```ts
import { Verifier } from "@gramota/verifier";

const verifier = new Verifier({ audience: "https://my-bank.com", issuerKey });
const result = await verifier.verify(presentationToken, { nonce });
if (result.ok) console.log(result.claims);  // { given_name: "Greta", ... }
```

Every wire-format check, every spec corner. **Live-tested against the EU
Commission's reference infrastructure** (`dev.issuer-backend.eudiw.dev`,
`dev.verifier-backend.eudiw.dev`).

---

## Standards covered

| Spec | What | Status |
|---|---|---|
| **eIDAS 2 / EUDIW** (EU Reg. 2024/1183) | EU regulation for electronic identification | ✅ |
| **OID4VCI** (OpenID for Verifiable Credential Issuance) | Pre-auth + auth-code flows | ✅ |
| **OID4VP** (OpenID for Verifiable Presentations) | Including OID4VP 2.0 with DCQL | ✅ |
| **SD-JWT-VC** (IETF draft) | Selective-disclosure verifiable credentials | ✅ |
| **DCQL** (Digital Credentials Query Language) | OID4VP 2.0 query format | ✅ |
| **DIF Presentation Exchange v2** | Legacy OID4VP 1.0 query | ✅ |
| **IETF Token Status List** | Credential revocation/suspension | ✅ |
| **PAR (RFC 9126)** | Pushed Authorization Requests | ✅ |
| **DPoP (RFC 9449)** | Sender-constrained tokens | ✅ |
| **PKCE (RFC 7636)** | Proof Key for Code Exchange | ✅ |
| **JOSE** (RFC 7515/7517/7518/7520) | JWS, JWK, JWA, JWS-JSON | ✅ |
| **x5c chain validation** (RFC 7515 §4.1.6) | X.509 certificate chain | ✅ |
| **mso_mdoc** (ISO 18013-5) | Mobile Document format | ⏳ Roadmap |

---

## Packages

```
@gramota/jose                  — JWS sign + verify + x5c chain validation; pluggable Signer
@gramota/sd-jwt                — SD-JWT-VC parser, hash binding, KB-JWT
@gramota/oid4vp                — OID4VP request + response wire format
@gramota/oid4vci               — OID4VCI: pre-auth, auth-code, PAR, DPoP, AS metadata
@gramota/presentation-exchange — DIF PE v2
@gramota/dcql                  — Digital Credentials Query Language (OID4VP 2.0)
@gramota/credential-format     — Pluggable format-handler registry (SD-JWT-VC; mDoc TBD)
@gramota/trust                 — TrustResolver: Static, JwksUrl, SdJwtVcIssuer (.well-known/jwt-vc-issuer)
@gramota/status-list           — IETF Token Status List + StatusResolver Strategy
@gramota/verifier              — High-level relying-party verifier (10 security checks)
@gramota/issuer                — High-level issuer for SD-JWT-VC
@gramota/holder                — High-level holder/wallet (credentials.* + offers.*)
@gramota/demo                  — Runnable CLI demos: self-loop, eu-pid, list
```

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

**`demo:self-loop`** mints a credential, validates 10 security checks, and
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
pnpm test            # 524 mock tests, ~1.5s, no network
pnpm test:live       # 31 live tests against EU dev infra (~2s + network)
pnpm test:all        # both, in one run
```

Live tests gated by `EUDI_LIVE=1`. CI runs mock on every push, live nightly.

---

## Project status

- **Phase 0** (foundation): ✅ done — 13 packages, 524+31 tests, EU-live verified
- **Phase 1** (public launch): 🟡 in progress — distribution, docs site, blog
- **Phase 2** (hosted SaaS): 📋 designed (see [SAAS.md](./SAAS.md))
- **Phase 3** (downstream): 🗓 future — WordPress / Shopify / Stripe Connect

Strategy and roadmap: [MANIFEST.md](./MANIFEST.md).
SaaS product spec: [SAAS.md](./SAAS.md).

---

## License

Apache 2.0. See [LICENSE](./LICENSE).

---

*Built in Sofia. Sold to the world in English.*

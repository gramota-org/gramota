# EUDI Gateway

> The EU Digital Identity Wallet SDK for the rest of us.
> Verify, issue, and integrate EUDIW in 20 lines of TypeScript.

---

## The idea in one paragraph

A best-in-class, open-source TypeScript/JavaScript SDK for the EU Digital Identity Wallet — verifier, issuer, and holder libraries — distributed via npm and GitHub, with a hosted SaaS that wraps the same library for buyers who don't want to self-host. Built solo from Sofia, sold to the world in English, monetized through self-serve subscriptions. Free OSS for developers; paid hosted tier for businesses.

---

## Why this exists

The EU Digital Identity Wallet (eIDAS 2) is mandatory acceptance for regulated digital businesses by **2027**. Every member state must ship a wallet by **end of 2026**. Banks, telcos, online platforms, age-gated commerce, fintech, and crypto all need to integrate.

Today, the available infrastructure is:

- **walt.id** — Apache 2, Kotlin/JVM-first, broad and complex, sells enterprise.
- **Procivis** — government-focused, enterprise sales motion, slow.
- **Sphereon** — Dutch, has TypeScript libraries but library-shop style, not productized.
- **Animo, MATTR, Dock** — niche, expensive, not EU-native.

What does **not** exist:

- A polished, opinionated, **TypeScript-native** EUDIW SDK with Stripe-quality docs.
- A **5-minute setup** path for a developer who has never heard of OID4VP.
- A **hosted/managed** version with a Stripe-Checkout-grade self-serve experience.
- A product that treats **JavaScript as the default**, not a second-class binding.

JavaScript is the dominant language of relying parties on the modern web. Most companies that need to accept EUDIW will reach for an npm package first. **Today, what they find is incomplete.** That gap is the wedge.

---

## The wedge against walt.id (and why this isn't a head-on fight)

walt.id is a horizontal, multi-ecosystem, multi-protocol, multi-language identity infrastructure company. They're three years and millions of euros ahead in horizontal infra. We will not catch them there.

We win by being **narrower, more polished, and more accessible**:

| | walt.id | EUDI Gateway |
|---|---|---|
| Language | Kotlin/JVM-first | **TypeScript/JavaScript-first** |
| Scope | Any ecosystem, any protocol | **EUDIW only, opinionated** |
| Onboarding | Self-host, configure, integrate | **5 lines of code, hosted by default** |
| Buyer | Identity engineer | **Any web developer** |
| Docs | Comprehensive, dense | **Stripe-grade, task-oriented** |
| Sales motion | Enterprise sales-led | **Self-serve, product-led** |
| Geography | Global | **Built in EU, for EU** |

We sit *next to* walt.id, not against. They sell to identity-platform teams. We sell to the much larger population of web developers who need to accept the wallet but don't want to read 80 pages of ARF documentation to do it.

---

## Strategic principles (the operating constraints we will not violate)

These principles fall out of the founder's reality (solo engineer, Sofia-based, no network, Claude Code leverage). They're not aspirational — they're the rules that make this winnable.

1. **No sales calls in the first 12 months.** Distribution must be built into the product. If we need a sales meeting to close a customer, we are not yet ready.
2. **Open source first.** Apache 2. The library is the marketing. The hosted version is the product.
3. **English-first.** EU-specific, but global in distribution language. Bulgarian/Romanian/Greek translations come once the English audience exists.
4. **Stripe-grade developer experience.** Docs, examples, error messages, types, sample apps. This is the actual moat — most identity tools have engineer-written docs that read like academic papers. Ours will read like Stripe's.
5. **Ship narrow, ship polished.** 80% of EUDIW use cases done perfectly beats 100% done partially. Mdoc-only features and exotic flows are post-PMF problems.
6. **Marketplaces and content, not outbound.** Distribution channels are GitHub, npm, Hacker News, ProductHunt, dev.to, Indie Hackers, the EUDI GitHub discussions, X, LinkedIn, EU LSP communities. We do not cold-email. We never will.
7. **Use Claude Code as a force multiplier.** Solo throughput approaches a 4–6 person team. Use it on docs, examples, tests, plugin variants, integration sample apps — the polish surfaces that distinguish us from competitors with more headcount but less time per pixel.
8. **The forks are fixtures, not foundation.** `eudi-srv-verifier-endpoint`, `eudi-web-verifier`, `eudi-srv-pid-issuer` stay on disk as reference implementations and CI test fixtures. They are not our codebase. They are the impartial truth our library is tested against.

---

## What we are building

### Open-source layer (the lead magnet)

npm packages under a single scope:

- `@gateway/verifier` — relying-party SDK. Verify OID4VP presentations, SD-JWT-VC and mdoc credentials, against configurable EU trust lists.
- `@gateway/issuer` — issuance SDK. Issue SD-JWT-VC credentials via OID4VCI, with key management abstractions.
- `@gateway/holder` — wallet/holder logic for downstream wallets and test harnesses.
- `@gateway/types` — shared TypeScript types for OID4VC, OID4VP, SD-JWT-VC, mdoc, EUDI ARF data structures.
- `@gateway/trust` — EU Trusted List parsing, fetching, and certificate validation.

Plus framework adapters as users ask for them:

- `@gateway/express`, `@gateway/fastify`, `@gateway/hono`, `@gateway/nextjs`
- `@gateway/react`, `@gateway/vue`, `@gateway/svelte` for the holder/relying-party UI

License: **Apache 2.0**.
Repos: GitHub. CI tested against the EU reference verifier and issuer.

### Hosted SaaS layer (the monetization)

A managed version of the same library at `api.[name].dev`:

- Drop-in REST/JSON API mirroring the SDK shape.
- Hosted trust list management (we keep the EU trusted lists fresh; you don't).
- Hosted key management for issuance flows (KMS-backed, EU data residency).
- Audit logs, webhooks, dashboards, API keys, multi-environment (test/live).
- Stripe Checkout for self-serve signup.

**Pricing tiers (self-serve, no calls):**

| Tier | Price | Verifications/month | Features |
|---|---|---|---|
| Free | €0 | 1,000 | OSS-only features, community support |
| Starter | €49 | 10,000 | Hosted trust lists, audit log, email support |
| Growth | €299 | 100,000 | Webhooks, multi-env, priority support |
| Enterprise | Custom | Unlimited | SLA, dedicated infra, SOC 2, custom contracts |

The Free tier is genuinely useful. The Starter tier is where most paying users land. Growth and Enterprise are the multipliers.

### Downstream products (later)

Once OSS authority and hosted SaaS revenue exist:

- **WordPress plugin** for age + identity verification (huge SMB distribution channel).
- **Shopify app** for age-gated commerce.
- **Stripe Connect / Auth0 / Clerk integrations**.
- **OpenCart / PrestaShop plugins** for the Balkan SMB long tail.
- Eventually: native mobile holder SDKs (iOS/Android) for businesses that want to ship their own wallet experience.

---

## Distribution strategy

The product is the marketing. The marketing is the product.

**Inbound channels, in order of expected impact:**

1. **GitHub stars + npm downloads.** Permanent leverage. Every star is forever.
2. **Long-form technical content.** One post a week, English, on the project blog and dev.to. Topics chosen for SEO traps: *"How to verify EUDIW in TypeScript", "OID4VP explained for JS developers", "Selective disclosure with SD-JWT-VC", "EUDIW vs Persona vs Stripe Identity: cost breakdown", "What MiCA-licensed crypto firms need to know about EUDIW"*.
3. **Hacker News + ProductHunt + Indie Hackers** launches at major milestones.
4. **EUDI Wallet ecosystem participation.** Comment on the EU GitHub discussions. Open issues against the reference implementations when we find bugs. Join LSP working groups where they're public.
5. **Twitter/X + LinkedIn presence** under the founder's name + the project handle. Build in public.
6. **Conference talks** when invited — not a primary channel, but reinforces authority once we exist.

**No outbound. No cold email. No SDR. No sales team. Ever, until traction makes it obvious.**

---

## Architecture (high level)

- **Language:** TypeScript everywhere. Node 20+. Bun-compatible.
- **Monorepo:** pnpm workspaces, Turborepo for build orchestration.
- **Crypto:** `@noble/hashes`, `@noble/curves`, `jose` for JWS/JWE, `@panva/oauth4webapi` for OID4VC flows. Pure-JS where possible for portability.
- **Mdoc/CBOR:** `cbor-x` or `cbor2`, ISO/IEC 18013-5 implementation built on top.
- **SD-JWT-VC:** following IETF draft, tested against EU reference suite.
- **Hosted backend:** Node + Fastify, Postgres, Redis, S3-compatible blob storage for credential schemas. Hetzner or AWS Frankfurt for EU data residency.
- **Hosted KMS:** AWS KMS or Hashicorp Vault for issuance keys. Eventually our own HSM tier for QSCD-equivalent flows.
- **Docs site:** Nextra or Astro Starlight. The docs are first-class infrastructure.
- **Landing/marketing site:** Next.js + shadcn/ui + Vercel.
- **CI:** GitHub Actions. Tested against `eudi-srv-verifier-endpoint`, `eudi-srv-pid-issuer`, and `eudi-web-verifier` running in Docker as ground-truth conformance fixtures.

---

## Roadmap

### Phase 0 — Foundation (Weeks 1–4)

- Monorepo scaffolded with pnpm workspaces.
- `@gateway/types` and `@gateway/verifier` v0.1: minimal OID4VP + SD-JWT-VC verification. Tested against the EU reference verifier in CI.
- Docs site live at the chosen domain.
- Landing page with email capture.
- GitHub repo public, MIT/Apache 2 licensed.

**Success signal:** v0.1 published to npm, verifier passes against EU reference test vectors.

### Phase 1 — Public launch (Weeks 5–10)

- `@gateway/issuer` v0.1: OID4VCI issuance flow.
- `@gateway/trust` v0.1: EU Trusted List fetch + validate.
- 6 long-form blog posts published.
- ProductHunt launch.
- Hacker News launch (timed to a meaningful technical post, not a "we exist" post).

**Success signal:** 500+ GitHub stars, 100+ devs in the Discord/community, 10k+ npm downloads/month.

### Phase 2 — Hosted SaaS launch (Months 3–6)

- `api.[name].dev` live with the four pricing tiers.
- Self-serve signup, Stripe Checkout, API keys, dashboard.
- Hosted trust list service, webhook system.
- First 10 paying customers.
- One framework adapter (`@gateway/nextjs` first — biggest dev population).

**Success signal:** 5–25 paying customers, €1k–€10k MRR, organic GitHub growth.

### Phase 3 — Downstream products (Months 6–12)

- WordPress plugin in the WP marketplace.
- Shopify app in the Shopify App Store.
- Mdoc / ISO 18013-5 proximity flow support (NFC/BLE).
- One reference customer in each of: fintech, age-gated e-commerce, crypto/MiCA.

**Success signal:** 100–500 paying customers, €10k–€50k MRR, inbound enterprise leads starting to arrive.

### Phase 4 — Optionality (Months 12–18)

- SOC 2 Type I in flight.
- Decide: stay indie, raise pre-seed (€500k–€1M from local EU funds), or accept early acquisition interest.
- Localization to Bulgarian, Romanian, Greek, German, French, Spanish.
- Native mobile holder SDKs (iOS Swift, Android Kotlin).

**Success signal:** €100k–€600k ARR, 1,000+ paying customers, recognized authority position in the EU EUDIW dev community.

---

## Realistic outcomes

This is not a unicorn play. We're being honest about ceilings.

**18-month base case:**
- 2k–10k GitHub stars
- 50k+ monthly npm downloads
- 200–1,000 paying hosted-SaaS customers
- €100k–€600k ARR
- Authority position as "the JS person for EUDIW" in EU dev community
- Full optionality: stay indie, raise, or accept acquisition

**3-year good case:**
- €2M–€8M ARR
- Series A optional (only if pan-EU horizontal expansion is the chosen horizon)
- Acquisition interest from walt.id, Sphereon, Procivis, IDnow, or one of the KYC heavyweights
- 5,000+ paying customers across EU + global

**3-year downside case:**
- Walt.id ships a polished JS SDK and squeezes the OSS layer.
- We earn the consultancy / integration support business — €200k–€500k/year, comfortable but capped, not scaling.
- We pivot into a vertical (fintech KYC, age verification) using earned authority. Plan B is real and not bad.

The downside is not zero, but it is bounded and survivable. The upside compounds for years on permanent leverage (stars, downloads, posts, docs).

---

## What we will NOT do

Equally important. The discipline is in the deletions.

- **No QTSP path.** Capital prohibitive. We integrate QTSPs, never become one.
- **No consumer wallet.** EU mandates multiple wallets, free national wallet. No moat possible.
- **No enterprise sales motion in year one.** No SDR, no AE, no demos-with-pricing-not-shown.
- **No vertical SaaS in year one.** We're horizontal infra (in our narrow lane). Vertical packaging is post-PMF.
- **No Balkan-only positioning.** We're built in Sofia, sold globally. Localization is a year-2 moat extension.
- **No multi-protocol/multi-ecosystem expansion.** EUDIW only, until EUDIW is a category-king business.
- **No premature scale.** Single-region hosting until €100k+ ARR, single-tier pricing until customers ask for differentiation.
- **No raising capital before traction.** Bootstrap to €10k MRR before considering pre-seed, and only raise if the chosen horizon needs it.

---

## Founding constraints (the truth about who builds this)

- One engineer (full-stack + mobile capable).
- Sofia, Bulgaria.
- No network in regulated digital businesses.
- Claude Code as a productivity multiplier (~4–6× engineering throughput).
- Bootstrap budget: ~€5k–€20k to first revenue. No external capital required for Phase 0–2.
- English as the working language; Bulgarian as the back-pocket asset.
- Honest about what works in the Balkans (cold outreach doesn't) and what doesn't (academic customer-development playbooks).

This is an indie-to-platform path, not a venture path. Optionality preserves both endings.

---

## Status

- Repo initialized: `/Users/petromilpavlov/Work/eudi-gateway`
- Reference forks cloned as conformance fixtures: `eudi-srv-verifier-endpoint`, `eudi-web-verifier`, `eudi-srv-pid-issuer`
- This manifest committed.
- Phase 0 Week 1 scope: monorepo scaffold + `@gateway/types` skeleton + `@gateway/verifier` v0.1 against EU reference vectors.

Next concrete action: scaffold the monorepo and ship the verifier v0.1 against the EU reference test fixtures.

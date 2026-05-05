# @gramota/trust

> Pluggable trust resolution for EUDIW issuers — static lists, JWKS URLs, IETF SD-JWT-VC issuer metadata. Strategy pattern: the verifier takes a `TrustResolver`, you pick / write whichever fits. Future: EU Trust List Registry adapter.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/trust
# or: npm install @gramota/trust
# or: yarn add @gramota/trust
```

## Quick example — pin known issuer keys

```ts
import { Verifier } from "@gramota/verifier";
import { StaticTrustResolver } from "@gramota/trust";

const verifier = new Verifier({
  audience: "https://verifier.example",
  trust: new StaticTrustResolver([issuerJwk]),
});
```

## Quick example — fetch JWKS at runtime

```ts
import { JwksUrlTrustResolver } from "@gramota/trust";

const trust = new JwksUrlTrustResolver({
  // Default: `${iss}/.well-known/jwks.json` (override for SD-JWT-VC's
  // `/.well-known/jwt-vc-issuer/...` shape)
  cacheMs: 5 * 60_000,
});
```

## Quick example — IETF SD-JWT-VC `/.well-known/jwt-vc-issuer`

```ts
import { SdJwtVcIssuerTrustResolver } from "@gramota/trust";

const trust = new SdJwtVcIssuerTrustResolver();
// Resolves issuer keys via the IETF-standard discovery URL:
//   <iss>/.well-known/jwt-vc-issuer
```

## What's inside

- `TrustResolver` interface — implement `.resolveIssuerKeys({ iss, kid, header })`
- `StaticTrustResolver` — hard-coded JWK list (tests, pinned-trust deployments)
- `JwksUrlTrustResolver` — fetch JWKS over HTTPS with TTL cache
- `SdJwtVcIssuerTrustResolver` — IETF SD-JWT-VC §5.1 discovery
- `TrustResolutionError` with stable `code` for failure cases

For the verifier that consumes these, see
[`@gramota/verifier`](../verifier).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

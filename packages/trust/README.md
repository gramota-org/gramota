# @gramota/trust

> Pluggable trust resolution for EUDIW issuers — static lists, JWKS URLs, future EU Trusted List support.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/trust
# or: npm install @gramota/trust
# or: yarn add @gramota/trust
```

## Usage

```ts
import { StaticTrustResolver, JwksUrlTrustResolver } from "@gramota/trust";

const resolver = new JwksUrlTrustResolver({ url: "https://issuer.example/jwks" });
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

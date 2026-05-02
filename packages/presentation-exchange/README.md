# @gramota/presentation-exchange

> DIF Presentation Exchange v2 — match credentials against a verifier's presentation_definition.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/presentation-exchange
# or: npm install @gramota/presentation-exchange
# or: yarn add @gramota/presentation-exchange
```

## Usage

```ts
import { matchPresentationDefinition } from "@gramota/presentation-exchange";

const matches = matchPresentationDefinition(definition, credentials);
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

# @gramota/credential-format

> Pluggable credential-format handler registry — Strategy + Registry pattern for SD-JWT-VC, mDoc, and future formats.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/credential-format
# or: npm install @gramota/credential-format
# or: yarn add @gramota/credential-format
```

## Usage

```ts
import { CredentialFormatRegistry, sdJwtVcHandler } from "@gramota/credential-format";

const registry = new CredentialFormatRegistry();
registry.register(sdJwtVcHandler);
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

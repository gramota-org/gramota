# @gramota/status-list

> IETF Token Status List — credential revocation/suspension checks for SD-JWT-VC.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/status-list
# or: npm install @gramota/status-list
# or: yarn add @gramota/status-list
```

## Usage

```ts
import { StatusListResolver } from "@gramota/status-list";

const resolver = new StatusListResolver({ fetch });
const status = await resolver.check(credential);
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

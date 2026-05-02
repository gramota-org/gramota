# @gramota/holder

> Headless EUDIW holder/wallet — receive credentials, store them, build presentations. Pure Node, no UI, IETF SD-JWT-VC §6 compliant.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/holder
# or: npm install @gramota/holder
# or: yarn add @gramota/holder
```

## Usage

```ts
import { Holder } from "@gramota/holder";

const holder = new Holder({ store });
await holder.credentials.add(credential);
const presentation = await holder.presentations.build({ request });
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

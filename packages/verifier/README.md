# @gramota/verifier

> Relying-party verifier for the EU Digital Identity Wallet. One client, one method, full IETF SD-JWT-VC + KB-JWT spec compliance.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/verifier
# or: npm install @gramota/verifier
# or: yarn add @gramota/verifier
```

## Usage

```ts
import { Verifier } from "@gramota/verifier";

const verifier = new Verifier({ audience, trustResolver });
const result = await verifier.verify(presentationToken, { nonce });
if (result.ok) console.log(result.claims);
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

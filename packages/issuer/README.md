# @gramota/issuer

> EUDIW credential issuer — sign SD-JWT-VC credentials with selective disclosure and key binding.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/issuer
# or: npm install @gramota/issuer
# or: yarn add @gramota/issuer
```

## Usage

```ts
import { Issuer } from "@gramota/issuer";

const issuer = new Issuer({ signer, issuerUri });
const credential = await issuer.issue({ vct, claims, holderKey });
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

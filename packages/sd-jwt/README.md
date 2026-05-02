# @gramota/sd-jwt

> SD-JWT-VC parser and verifier for the EU Digital Identity Wallet.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/sd-jwt
# or: npm install @gramota/sd-jwt
# or: yarn add @gramota/sd-jwt
```

## Usage

```ts
import { parseSdJwt, verifySdJwt } from "@gramota/sd-jwt";

const parsed = parseSdJwt(token);
const result = await verifySdJwt(token, { resolver });
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

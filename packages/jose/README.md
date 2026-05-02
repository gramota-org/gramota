# @gramota/jose

> JWS signing and verification for the EU Digital Identity Wallet, ES256/EdDSA/RS256/PS256 with strict algorithm allowlists.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/jose
# or: npm install @gramota/jose
# or: yarn add @gramota/jose
```

## Usage

```ts
import { sign, verify } from "@gramota/jose";

const jws = await sign({ payload, alg: "ES256", signer });
const result = await verify(jws, { resolver });
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

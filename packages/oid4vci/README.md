# @gramota/oid4vci

> OpenID for Verifiable Credential Issuance — pre-authorized code flow for receiving SD-JWT-VC credentials.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/oid4vci
# or: npm install @gramota/oid4vci
# or: yarn add @gramota/oid4vci
```

## Usage

```ts
import { Oid4vciClient } from "@gramota/oid4vci";

const client = new Oid4vciClient({ ... });
const credential = await client.authorize(offer);
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

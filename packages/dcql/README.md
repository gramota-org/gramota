# @gramota/dcql

> Digital Credentials Query Language (OID4VP 2.0) — match credentials against a verifier's dcql_query.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/dcql
# or: npm install @gramota/dcql
# or: yarn add @gramota/dcql
```

## Usage

```ts
import { matchDcqlQuery } from "@gramota/dcql";

const matches = matchDcqlQuery(query, credentials);
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

# @gramota/oid4vp

> OpenID for Verifiable Presentations transport — authorization request/response wire format for EUDIW.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/oid4vp
# or: npm install @gramota/oid4vp
# or: yarn add @gramota/oid4vp
```

## Usage

```ts
import { buildAuthorizationRequest, parseAuthorizationResponse } from "@gramota/oid4vp";

const req = buildAuthorizationRequest({ client_id, nonce, ... });
const res = parseAuthorizationResponse(formData);
```

For full docs, examples, and the high-level Verifier/Issuer/Holder API,
see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

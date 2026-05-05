# @gramota/credential-format

> Pluggable credential-format handler registry — Strategy + Registry pattern. Default registry ships with `dc+sd-jwt`; add custom handlers for mDoc, W3C-VC-JWT, or proprietary formats without forking the wallet.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/credential-format
# or: npm install @gramota/credential-format
# or: yarn add @gramota/credential-format
```

## Quick example

```ts
import {
  createDefaultCredentialFormatRegistry,
  SdJwtVcFormatHandler,
} from "@gramota/credential-format";

const registry = createDefaultCredentialFormatRegistry();
const handler = registry.get("dc+sd-jwt");
```

## What's inside

- `CredentialFormatRegistry` — register, look up, and dispatch by format string
- `SdJwtVcFormatHandler` — default handler for `dc+sd-jwt` / `vc+sd-jwt`
- `createDefaultCredentialFormatRegistry` — pre-populated registry
- `CredentialFormatHandler` interface — implement for new formats (mDoc, etc.)
- `hasIssuanceCapability`, `IssuanceCapableHandler` — capability flag for handlers that also issue (not just present / verify)

For the high-level Holder / Verifier API that consumes the registry, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

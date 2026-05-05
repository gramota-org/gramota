# @gramota/status-list

> IETF Token Status List — credential revocation / suspension checks. Drop-in `StatusResolver` for `@gramota/verifier`; primitives for issuers building / serving their own status lists.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/status-list
# or: npm install @gramota/status-list
# or: yarn add @gramota/status-list
```

## Quick example — verifier with status checks

```ts
import { Verifier } from "@gramota/verifier";
import { StatusListResolver } from "@gramota/status-list";

const verifier = new Verifier({
  audience: "https://verifier.example",
  trust: trustResolver,
  statusResolver: new StatusListResolver({
    trustedIssuers: [issuerJwk],
  }),
});

const result = await verifier.verify(vpToken, { nonce, requireStatus: true });
// result.status: { state: "valid" | "invalid" | "suspended", ... } | "skipped"
```

## Quick example — issuer publishes a status list

```ts
import { buildStatusListToken } from "@gramota/status-list";

const token = await buildStatusListToken({
  issuer: "https://issuer.example",
  subject: "https://issuer.example/status/1",
  length: 1024,
  privateKey: issuerPrivJwk,
  alg: "ES256",
  // Mark indices 5 + 12 invalid, the rest valid.
  states: { 5: "invalid", 12: "invalid" },
});
// Serve `token` from the URL referenced by your credentials' `status.status_list.uri`
```

## What's inside

- `StatusListResolver` — drop-in `StatusResolver` for `@gramota/verifier`
- `buildStatusListToken` — issuer-side status list publishing
- `parseStatusListToken`, `parseStatusListPayload`, `getStatus` — read-side primitives
- `fetchStatusList` — fetch + verify a status list over HTTPS
- `checkCredentialStatus`, `readStatusReference` — helpers used by the resolver
- Constants: `STATUS_VALID` (0), `STATUS_INVALID` (1), `STATUS_SUSPENDED` (2)

For the verifier that consumes the resolver, see
[`@gramota/verifier`](../verifier).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

# @gramota/holder

> Headless EUDIW holder/wallet — receive credentials, store them, build presentations. Pure TypeScript, no UI, IETF SD-JWT-VC + OID4VP-compliant. Pluggable `CredentialStore` so the same Holder runs against in-memory, SQLite, or React Native MMKV.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/holder
# or: npm install @gramota/holder
# or: yarn add @gramota/holder
```

## Quick example — receive + present

```ts
import { Holder, InMemoryCredentialStore } from "@gramota/holder";
import { exportJWK, generateKeyPair } from "jose";

// Holder's binding key (production: HSM / device keystore)
const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
const holder = new Holder({
  publicKey: await exportJWK(publicKey),
  privateKey: await exportJWK(privateKey),
  alg: "ES256",
  store: new InMemoryCredentialStore(),
});

// Receive a credential (validates issuer signature against trusted JWKs)
const stored = await holder.credentials.receive(sdJwtVc, {
  trustedIssuers: [issuerJwk],
});

// Present it to a verifier — pick which claims to disclose
const vpToken = await holder.present({
  credentialId: stored.id,
  disclose: ["given_name", "family_name", "birth_date"],
  audience: "https://verifier.example",
  nonce: "n-from-verifier",
});
```

## What's inside

- `Holder` — stateful façade around the protocol primitives
  - `holder.credentials.receive(...)` / `.list(...)` / `.get(...)` / `.delete(...)`
  - `holder.present(...)` — build a vp_token (selective disclosure + KB-JWT)
  - `holder.offers.accept(...)` — full OID4VCI offer flow (pre-auth + auth code)
  - `holder.respond(...)` — answer an OID4VP authorization request
- `InMemoryCredentialStore` — reference store for tests + getting started
- `CredentialStore` interface — implement once for SQLite / MMKV / encrypted backends

For the underlying primitives, see the [main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

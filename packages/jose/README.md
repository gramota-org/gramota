# @gramota/jose

> JOSE primitives for the EU Digital Identity Wallet — JWS sign / verify, X.509 chain validation, JWK thumbprints. ES256 / EdDSA / RS256 / PS256 with strict algorithm allowlists.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/jose
# or: npm install @gramota/jose
# or: yarn add @gramota/jose
```

## Quick example

```ts
import { signJws, verifyJws, JwkSigner } from "@gramota/jose";
import { exportJWK, generateKeyPair } from "jose";

const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
const signer = new JwkSigner({
  publicKey: await exportJWK(publicKey),
  privateKey: await exportJWK(privateKey),
  alg: "ES256",
});

const jws = await signJws({ payload: { hello: "world" }, signer });
const verified = await verifyJws(jws, signer.publicKey);
console.log(verified.payload); // { hello: "world" }
```

`alg=none` is rejected unconditionally; the algorithm allowlist defaults
to every IETF asymmetric alg and can be narrowed per call.

## What's inside

- `signJws` / `verifyJws` — compact-serialised JWS with strict alg gating
- `verifyJwsWithX5c` — verify a JWS whose key is supplied via the `x5c` header
- `JwkSigner`, `makeSigner` — `Signer` interface for HSM / KMS-backed keys
- `computeJwkThumbprint` — RFC 7638 thumbprints (used as `jkt` in DPoP, cnf binding)
- `validateX5cChain`, `extractPublicKeyFromX5c`, `parseX5cEntry`, `x5cToPem`
- `Fetcher` / `FetcherResponse` / `mockFetcherResponse` — shared HTTP-adapter type used across `@gramota/*`

For the high-level Verifier / Issuer / Holder API, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

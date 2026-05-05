# @gramota/issuer

> EUDIW credential issuer — sign SD-JWT-VC credentials with selective disclosure and holder-key binding (cnf claim). One method, fully configurable, ES256 by default.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/issuer
# or: npm install @gramota/issuer
# or: yarn add @gramota/issuer
```

## Quick example

```ts
import { Issuer } from "@gramota/issuer";
import { exportJWK, generateKeyPair } from "jose";

// Issuer's signing keypair (production: HSM / KMS — use makeSigner from @gramota/jose)
const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });

const issuer = new Issuer({
  issuerId: "https://issuer.example",
  publicKey: await exportJWK(publicKey),
  privateKey: await exportJWK(privateKey),
  alg: "ES256",
});

const result = await issuer.issue({
  vct: "urn:eudi:pid:1",
  subject: {
    given_name: "Greta",
    family_name: "Smith",
    birth_date: "1990-04-15",
  },
  selectivelyDisclosable: ["given_name", "family_name", "birth_date"],
  holderKey: holderJwk,                  // binds the credential to the holder
  expiresIn: 365 * 24 * 3600,            // 1 year
});

console.log(result.token); // SD-JWT-VC compact-serialised string
```

## What's inside

- `Issuer` — single class, stateless, configured once
- Two equivalent call shapes for the same operation:
  - `issuer.credentials.issue(options)` — Stripe-style namespacing, symmetric with `holder.credentials.*`, forward-compatible with future ops (revoke, suspend, list)
  - `issuer.issue(options)` — flat shorthand for the common case
- `IssuerError` with stable `code` for failure cases (`issuer.holder_key_required`, `issuer.vct_required`, `issuer.expiry_invalid`, ...)

The `cnf.jwk` claim is set automatically from `holderKey`, binding the
credential to the holder's key for the KB-JWT proof during presentation.

For the high-level Holder / Verifier API, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

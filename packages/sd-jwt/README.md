# @gramota/sd-jwt

> IETF SD-JWT-VC primitives — parse, issue, hash-binding verify, key-binding (KB-JWT) build / verify. Tight low-level layer; most consumers should reach for `@gramota/issuer`, `@gramota/holder`, or `@gramota/verifier` instead.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/sd-jwt
# or: npm install @gramota/sd-jwt
# or: yarn add @gramota/sd-jwt
```

## Quick example — parse + hash-binding verify

```ts
import { parseSdJwt, verifyHashBinding } from "@gramota/sd-jwt";

const parsed = parseSdJwt(presentationToken);
const verified = verifyHashBinding(parsed);
console.log(verified.disclosed);          // user claims
console.log(verified.unmatchedDisclosures); // expected []
```

## Quick example — KB-JWT (holder presentation binding)

```ts
import { buildKeyBindingJwt, computeSdHash } from "@gramota/sd-jwt";

const sdHash = computeSdHash(presentationPrefix); // <issuer-jws>~<d1>~...~<dN>~
const kbJwt = await buildKeyBindingJwt({
  signer,                       // holder's @gramota/jose Signer
  aud: "https://verifier.example",
  nonce: "n-from-verifier",
  sdHash,
});
const fullPresentation = `${presentationPrefix}${kbJwt}`;
```

## What's inside

- `parseSdJwt` — split `<issuer-jws>~<d1>~...~<dN>~<kb-jwt?>` and decode parts
- `issueSdJwt` — produce a fresh SD-JWT from claims + a list of selectively-disclosable paths
- `verifyHashBinding` — match disclosures to `_sd` digests; reject forgeries
- `buildKeyBindingJwt` / `verifyKeyBinding` — IETF SD-JWT §4.3 holder binding
- `computeSdHash` — RFC-aligned `sd_hash` claim used in KB-JWT
- One error class — `SdJwtError` — with codes namespaced by operation (`sd_jwt.parse.*`, `sd_jwt.verify.*`, `sd_jwt.kb.*`, `sd_jwt.issue.*`)

For the high-level Verifier / Issuer / Holder API, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

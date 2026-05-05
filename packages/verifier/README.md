# @gramota/verifier

> Relying-party verifier for the EU Digital Identity Wallet. One class, one method (`verify`), 12 named security checks, IETF SD-JWT-VC + KB-JWT + OID4VP-compliant. Discriminated `VerifyResult` so you destructure success vs failure cleanly.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/verifier
# or: npm install @gramota/verifier
# or: yarn add @gramota/verifier
```

## Quick example

```ts
import { Verifier } from "@gramota/verifier";
import { StaticTrustResolver } from "@gramota/trust";

const verifier = new Verifier({
  audience: "https://verifier.example",
  trust: new StaticTrustResolver([issuerJwk]),
});

const result = await verifier.verify(vpToken, { nonce: "n-12345" });

if (result.ok) {
  console.log(result.claims);   // { given_name: "Greta", ... }
  console.log(result.metadata); // { issuer, audience, issuedAt, expiresAt, ... }
} else {
  console.log(result.failedCheck); // e.g. "kb-jwt.audience"
  console.log(result.reason);
}
```

## What's inside

- `Verifier` — single class, configured once with `{ audience, trust, ... }`
- `Verifier.verify(token, { nonce })` → `VerifyResult` (success ∪ failure)
- 12 named security checks run in order (parse → trust → issuer signature → hash binding → KB-JWT presence/cnf/sig/aud/nonce/time/transcript → status). Result reports which one failed.
- `additionalAudiences` config — accepts both the SD-JWT-VC `aud=URL` form and the OID4VP `aud=x509_san_dns:host` form (production EU wallets send the latter)
- `inspect(token)` — peek at the parsed structure without verification (debugging)
- `VerifierError` carries the full failure record for logs / dashboards

For the high-level wallet + issuer counterparts, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

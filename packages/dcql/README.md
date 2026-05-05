# @gramota/dcql

> Digital Credentials Query Language (OID4VP Final 1.0) — select credentials from a holder's wallet that satisfy a verifier's `dcql_query`.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/dcql
# or: npm install @gramota/dcql
# or: yarn add @gramota/dcql
```

## Quick example — match a verifier's request

```ts
import { selectForDcql, DcqlSdJwtVcMatcher } from "@gramota/dcql";

const query = {
  credentials: [
    {
      id: "pid",
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eudi:pid:1"] },
      claims: [
        { path: ["given_name"] },
        { path: ["family_name"] },
        { path: ["birth_date"] },
      ],
    },
  ],
};

const selection = selectForDcql({
  query,
  credentials: walletCredentials,        // [{ id, view: { vct, claims } }, ...]
  matchers: [new DcqlSdJwtVcMatcher()],
});

if (selection.satisfiable) {
  for (const match of selection.matches) {
    console.log(match.credentialId, match.queryId, match.disclosablePaths);
  }
}
```

## What's inside

- `selectForDcql` — top-level matcher; returns a `DcqlSelection` (satisfiable + per-query matches, or unsatisfiable + reason)
- `DcqlSdJwtVcMatcher` — matcher for `format: "dc+sd-jwt"` credentials
- `DcqlMatcher` interface — write your own for mDoc / W3C-VC formats
- `evaluateDcqlPath`, `validateDcqlPath` — JSON-pointer-style path traversal used by matchers
- Constants: `SD_JWT_VC_FORMAT`, `DC_SD_JWT_VC_FORMAT`

For the OID4VP transport that carries the query, see
[`@gramota/oid4vp`](../oid4vp).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

# @gramota/presentation-exchange

> DIF Presentation Exchange v2 — select credentials that satisfy a verifier's `presentation_definition` and build the matching `presentation_submission`. Use this for OID4VP requests that don't use DCQL (newer wallets prefer [`@gramota/dcql`](../dcql)).

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/presentation-exchange
# or: npm install @gramota/presentation-exchange
# or: yarn add @gramota/presentation-exchange
```

## Quick example

```ts
import {
  selectForDefinition,
  buildPresentationSubmission,
  SdJwtVcMatcher,
} from "@gramota/presentation-exchange";

const definition = {
  id: "pid-request",
  input_descriptors: [
    {
      id: "pid",
      format: { "vc+sd-jwt": { alg: ["ES256"] } },
      constraints: {
        fields: [{ path: ["$.given_name"] }, { path: ["$.family_name"] }],
      },
    },
  ],
};

const selection = selectForDefinition({
  definition,
  credentials: walletCredentials,
  matchers: [new SdJwtVcMatcher()],
});

if (selection.satisfiable) {
  const submission = buildPresentationSubmission(definition, selection);
  // submission.descriptor_map[i].path → vp_token entry index
}
```

## What's inside

- `selectForDefinition` — top-level matcher; returns a `Selection`
- `buildPresentationSubmission` — produce the DIF `presentation_submission` mapping
- `SdJwtVcMatcher` — matcher for `vc+sd-jwt` credentials with JSONPath constraints
- `evaluateJsonPath`, `parseJsonPath`, `leafClaimName` — JSONPath primitives
- `CredentialMatcher` interface — write your own for mDoc / W3C-VC formats
- Constants: `SD_JWT_VC_FORMAT`

For the OID4VP transport that carries the definition, see
[`@gramota/oid4vp`](../oid4vp).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

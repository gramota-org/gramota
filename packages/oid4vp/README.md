# @gramota/oid4vp

> OpenID for Verifiable Presentations Final 1.0 — authorization request/response wire format, RFC 9101 JAR signing, X.509 verifier-identity certs. Accepts both DCQL and DIF Presentation Exchange response shapes.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/oid4vp
# or: npm install @gramota/oid4vp
# or: yarn add @gramota/oid4vp
```

## Quick example — verifier emits a signed JAR

```ts
import {
  generateSigningCert,
  signAuthorizationRequest,
  buildAuthorizationRequestUrl,
} from "@gramota/oid4vp";

// Self-signed cert with SAN-DNS = the verifier's hostname
const cert = await generateSigningCert({ sanDns: "verifier.example" });

// Build the OID4VP request, sign as a JAR (RFC 9101) embedded in the URL
const request = {
  response_type: "vp_token" as const,
  client_id: `x509_san_dns:${cert.sanDns}`,
  response_mode: "direct_post" as const,
  response_uri: "https://verifier.example/oid4vp/response",
  nonce: "n-12345",
  state: "s-67890",
  dcql_query: {
    credentials: [
      { id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] } },
    ],
  },
};
const jar = await signAuthorizationRequest({ request, cert });
const deepLink = `openid4vp://?client_id=${encodeURIComponent(request.client_id)}&request=${encodeURIComponent(jar)}`;
```

## Quick example — verifier parses the wallet's response

```ts
import { parseAuthorizationResponseFromParams } from "@gramota/oid4vp";

// req.body is { vp_token, presentation_submission?, state }
const response = parseAuthorizationResponseFromParams(req.body);
// vp_token can be a string (PEX, single), string[] (PEX, multi),
// or { [credentialId]: string } (DCQL, OID4VP Final 1.0)
```

## What's inside

- `buildAuthorizationRequestUrl` / `parseAuthorizationRequestUrl` — wire format (§5)
- `parseAuthorizationResponseFromParams` / `buildAuthorizationResponseBody` — wire format (§6); accepts both PEX and DCQL response shapes
- `generateSigningCert` — self-signed X.509 with SAN-DNS for `x509_san_dns` client_id_prefix
- `signAuthorizationRequest` — RFC 9101 JAR signing with cert in the JWS `x5c` header
- `signingCertToJwks` — convert the cert+key bundle into a JWK pair for `@gramota/issuer`

For the high-level Verifier API, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

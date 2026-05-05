# @gramota/oid4vci

> OpenID for Verifiable Credential Issuance — wire-format primitives + a high-level wallet client + server-side helpers. Supports pre-authorized code, authorization code, PAR, DPoP (RFC 9449), and OID4VCI Draft 13 / 14 / 15 credential request shapes.

Part of [Gramota](https://github.com/gramota-org/gramota) — the TypeScript
SDK for the EU Digital Identity Wallet (EUDIW).

## Install

```bash
pnpm add @gramota/oid4vci
# or: npm install @gramota/oid4vci
# or: yarn add @gramota/oid4vci
```

## Quick example — wallet redeems an offer

```ts
import { parseCredentialOffer, Oid4vciClient } from "@gramota/oid4vci";
import { JwkSigner } from "@gramota/jose";

// Wallet scans a QR / opens a deep link
const offer = parseCredentialOffer(offerUrl);

// Wallet signer (binds the credential to the holder's key)
const holderSigner = new JwkSigner({ publicKey, privateKey, alg: "ES256" });

const client = new Oid4vciClient({ holderSigner });
const result = await client.acceptOffer({ offer });
console.log(result.credential); // SD-JWT-VC string
```

## Quick example — issuer side (server)

```ts
import { parseCredentialRequest, verifyDpopJwt, buildSubdomainIssuerUrl } from "@gramota/oid4vci";

// Validate a DPoP-bound credential request from a wallet
const dpop = await verifyDpopJwt({
  jwt: req.headers.dpop,
  htm: "POST",
  htu: "https://acme.gramota.dev/oid4vci/credential",
  accessToken: req.headers.authorization.slice(7),
});
const parsed = parseCredentialRequest({ body: req.body, issuerMetadata });
// → { credentialConfigurationId, format, vct, proofJwt, proofJwts }
```

## What's inside

**Wallet (client)** — `Oid4vciClient`, `parseCredentialOffer`, `requestToken`,
`requestCredential`, `buildProofJwt`, `buildAuthorizationUrl`,
`pushAuthorizationRequest`, PKCE helpers.

**Issuer (server)** — `parseCredentialRequest` (Draft 13/14/15 normaliser),
`verifyDpopJwt` (RFC 9449 §4.3), `buildSubdomainIssuerUrl`.

**Transport** — `DirectAuthorizationTransport`, `ParAuthorizationTransport`,
`buildDpopJwt`, `computeAccessTokenHash`.

For the high-level Holder / Issuer API, see the
[main repo](https://github.com/gramota-org/gramota).

## License

[Apache 2.0](https://github.com/gramota-org/gramota/blob/main/LICENSE)

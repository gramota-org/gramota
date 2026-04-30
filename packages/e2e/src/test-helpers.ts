/** Shared helpers for E2E tests — keep tests focused on scenarios, not setup. */

import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import type { JsonWebKey, SupportedAlg } from "@gateway/jose";

export interface KeyPair {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

/** Generate a fresh ES256 keypair as JWKs. */
export async function newEs256KeyPair(): Promise<KeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  return {
    publicJwk: (await exportJWK(publicKey)) as JsonWebKey,
    privateJwk: (await exportJWK(privateKey)) as JsonWebKey,
  };
}

/** Build an issuer-side signer compatible with `issueSdJwt`. */
export async function makeIssuerSigner(
  privateJwk: JsonWebKey,
  alg: SupportedAlg = "ES256",
): Promise<(signedPayload: string) => Promise<string>> {
  const key = await importJWK(
    privateJwk as Parameters<typeof importJWK>[0],
    alg,
  );
  return async (signedPayload: string): Promise<string> => {
    const [headerB64, payloadB64] = signedPayload.split(".") as [
      string,
      string,
    ];
    const sig = await new CompactSign(
      new TextEncoder().encode(
        Buffer.from(payloadB64, "base64url").toString("utf-8"),
      ),
    )
      .setProtectedHeader(
        JSON.parse(Buffer.from(headerB64, "base64url").toString("utf-8")),
      )
      .sign(key);
    return sig.split(".")[2]!;
  };
}

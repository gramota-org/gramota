import { signJws, type JsonWebKey, type SupportedAlg } from "@gateway/jose";

/**
 * Build a Proof of Possession JWT per OID4VCI §7.2.1.
 *
 * The wallet signs this JWT with its holder-binding private key. The issuer
 * uses the embedded `jwk` to bind the issued credential to the holder.
 *
 * Header:
 *   - alg: matches the holder's key
 *   - typ: "openid4vci-proof+jwt"
 *   - jwk: the holder's public JWK (the issuer puts this in cnf.jwk)
 *
 * Payload:
 *   - aud: the credential_issuer URL (audience binding)
 *   - iat: now
 *   - nonce: c_nonce from the issuer's token response (replay protection)
 */
export interface BuildProofOptions {
  /** The audience — typically `credentialIssuer` from the metadata. */
  audience: string;
  /** Holder's PUBLIC JWK to embed in the JWT header (`jwk` parameter). */
  publicKey: JsonWebKey;
  /** Holder's PRIVATE JWK used to sign. */
  privateKey: JsonWebKey;
  /** JWS algorithm — must match the holder's key. */
  alg: SupportedAlg;
  /** Optional issuer-supplied nonce (`c_nonce`). Recommended; many issuers require it. */
  nonce?: string;
  /** Override iat — for tests. */
  iat?: number;
  /** Optional client_id of the wallet — `iss` claim of the proof. */
  iss?: string;
}

export async function buildProofJwt(
  options: BuildProofOptions,
): Promise<string> {
  const iat = options.iat ?? Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    aud: options.audience,
    iat,
  };
  if (options.nonce !== undefined) payload["nonce"] = options.nonce;
  if (options.iss !== undefined) payload["iss"] = options.iss;

  return await signJws(payload, options.privateKey, {
    alg: options.alg,
    typ: "openid4vci-proof+jwt",
    extraHeader: { jwk: options.publicKey },
  });
}

import { type Signer } from "@gateway/jose";

/**
 * Build a Proof of Possession JWT per OID4VCI §7.2.1.
 *
 * The wallet signs this JWT with its holder-binding signer. The issuer
 * uses the embedded `jwk` to bind the issued credential to the holder.
 *
 * Header:
 *   - alg: matches the signer
 *   - typ: "openid4vci-proof+jwt"
 *   - jwk: the holder's public JWK (the issuer puts this in cnf.jwk)
 *
 * Payload:
 *   - aud: the credential_issuer URL (audience binding)
 *   - iat: now
 *   - nonce: c_nonce from the issuer's token response (replay protection)
 *
 * Takes a {@link Signer} rather than a raw private JWK so production
 * wallets can plug in WebAuthn / iOS Secure Enclave / HSM backed signers
 * that never materialize the private key in JS heap.
 */
export interface BuildProofOptions {
  /** The audience — typically `credentialIssuer` from the metadata. */
  audience: string;
  /** Holder's signer — produces the proof JWT signature. The signer's
   * `publicKey` is embedded as the JOSE header `jwk` parameter. */
  signer: Signer;
  /** Optional issuer-supplied nonce (`c_nonce`). Recommended; many
   * issuers require it. */
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

  const header: Record<string, unknown> = {
    alg: options.signer.alg,
    typ: "openid4vci-proof+jwt",
    jwk: options.signer.publicKey,
  };

  // Compose the JWS canonical "header.payload" and hand it to the signer.
  // The signer returns just the base64url signature segment.
  const headerB64 = Buffer.from(JSON.stringify(header), "utf-8").toString(
    "base64url",
  );
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString(
    "base64url",
  );
  const signedPayload = `${headerB64}.${payloadB64}`;
  const signature = await options.signer.sign(signedPayload);
  return `${signedPayload}.${signature}`;
}

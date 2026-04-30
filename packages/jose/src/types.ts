/** JSON Web Key (RFC 7517). Minimum fields by key type. */
export interface JsonWebKey {
  kty: "RSA" | "EC" | "OKP" | "oct";
  alg?: string;
  kid?: string;
  use?: string;
  // RSA
  n?: string;
  e?: string;
  d?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
  // EC / OKP
  crv?: string;
  x?: string;
  y?: string;
  // oct
  k?: string;
  [key: string]: unknown;
}

/** Algorithms we accept by default. `alg: "none"` is never permitted. */
export type SupportedAlg =
  | "ES256"
  | "ES384"
  | "ES512"
  | "EdDSA"
  | "RS256"
  | "RS384"
  | "RS512"
  | "PS256"
  | "PS384"
  | "PS512";

export interface VerifyJwsOptions {
  /** Algorithm allowlist. Defaults to all supported algorithms above. */
  algorithms?: readonly SupportedAlg[];
}

export interface VerifiedJws {
  /** Decoded JWS protected header. */
  header: { alg: string; [key: string]: unknown };
  /** Decoded JWS payload (parsed as JSON). */
  payload: Record<string, unknown>;
  /** The exact algorithm that verified successfully. */
  alg: SupportedAlg;
}

export class JoseVerificationError extends Error {
  override readonly name = "JoseVerificationError";
}

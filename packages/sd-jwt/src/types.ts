export interface SdJwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  x5c?: string[];
  [key: string]: unknown;
}

export interface SdJwtPayload {
  iss?: string;
  sub?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  cnf?: { jwk?: unknown; kid?: string };
  vct?: string;
  status?: unknown;
  _sd?: string[];
  _sd_alg?: string;
  [key: string]: unknown;
}

export interface SdJwtDisclosure {
  raw: string;
  salt: string;
  name: string | null;
  value: unknown;
}

export interface ParsedSdJwt {
  header: SdJwtHeader;
  payload: SdJwtPayload;
  signature: string;
  signedPayload: string;
  disclosures: SdJwtDisclosure[];
  keyBindingJwt?: string;
  /** The exact bytes the KB-JWT's `sd_hash` is computed over: the issuer JWS
   * plus every presented disclosure plus separator tildes, ending with `~`.
   * Per IETF SD-JWT §4.3: `sd_hash = base64url(SHA-256(presentationPrefix))`. */
  presentationPrefix: string;
}

/** Verified Key Binding JWT contents per IETF SD-JWT §4.3. */
export interface VerifiedKeyBinding {
  header: { typ: "kb+jwt"; alg: string };
  payload: {
    iat: number;
    aud: string;
    nonce: string;
    sd_hash: string;
  };
  /** The holder JWK extracted from the parent SD-JWT's `cnf.jwk` claim. */
  holderKey: Record<string, unknown>;
}

export interface VerifiedSdJwt {
  parsed: ParsedSdJwt;
  /** The JWT payload with `_sd` arrays expanded into their disclosed claims and
   * `_sd_alg` stripped. Withheld digests and decoys disappear silently — that
   * is the privacy property of selective disclosure. */
  claims: Record<string, unknown>;
  /** Disclosures whose digest matched some `_sd` entry in the payload. */
  matchedDisclosures: SdJwtDisclosure[];
  /** Disclosures presented by the holder that did NOT match any digest. A
   * non-empty array here is a verification failure: the holder is presenting
   * material the issuer never signed. */
  unmatchedDisclosures: SdJwtDisclosure[];
  /** The hash algorithm used (from `_sd_alg`, defaults to "sha-256"). */
  hashAlgorithm: string;
}

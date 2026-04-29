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

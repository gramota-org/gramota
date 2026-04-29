export interface SdJwtHeader {
  typ: string;
  alg: string;
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

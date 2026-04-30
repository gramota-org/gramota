import type {
  ParsedSdJwt,
  SdJwtDisclosure,
  SdJwtHeader,
  SdJwtPayload,
} from "./types.js";

const TILDE = "~";
const DOT = ".";

export function parseSdJwt(token: string): ParsedSdJwt {
  if (typeof token !== "string" || token.length === 0) {
    throw new SdJwtParseError("sd_jwt.parse.invalid_input", "token must be a non-empty string");
  }
  if (!token.includes(TILDE)) {
    throw new SdJwtParseError("sd_jwt.parse.missing_separator", "token is missing the SD-JWT '~' separator");
  }

  const segments = token.split(TILDE);
  const jwtPart = segments[0];
  if (jwtPart === undefined) {
    throw new SdJwtParseError("sd_jwt.parse.malformed_jwt", "token is missing the JWT segment");
  }

  const trailingSegments = segments.slice(1);
  const { disclosureSegments, keyBindingJwt } =
    splitTrailingSegments(trailingSegments);

  const { header, payload, signature, signedPayload } = parseJwt(jwtPart);
  const disclosures = disclosureSegments.map(parseDisclosure);

  // Per IETF SD-JWT §4.3, sd_hash is computed over the presentation MINUS the
  // KB-JWT — i.e. <issuer-jws>~<d1>~...~<dN>~ (always ends with `~`).
  const presentationPrefix =
    keyBindingJwt !== undefined
      ? token.substring(0, token.length - keyBindingJwt.length)
      : token;

  const result: ParsedSdJwt = {
    header,
    payload,
    signature,
    signedPayload,
    disclosures,
    presentationPrefix,
  };
  if (keyBindingJwt !== undefined) {
    result.keyBindingJwt = keyBindingJwt;
  }
  return result;
}

/** Stable codes for `SdJwtParseError`. */
export type SdJwtParseErrorCode =
  | "sd_jwt.parse.invalid_input"
  | "sd_jwt.parse.missing_separator"
  | "sd_jwt.parse.malformed_jwt"
  | "sd_jwt.parse.malformed_header"
  | "sd_jwt.parse.malformed_payload"
  | "sd_jwt.parse.malformed_disclosure";

export class SdJwtParseError extends Error {
  override readonly name = "SdJwtParseError";
  readonly code: SdJwtParseErrorCode;
  constructor(
    code: SdJwtParseErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.code = code;
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

interface ParsedJwt {
  header: SdJwtHeader;
  payload: SdJwtPayload;
  signature: string;
  signedPayload: string;
}

function parseJwt(jwt: string): ParsedJwt {
  const components = jwt.split(DOT);
  if (components.length !== 3) {
    throw new SdJwtParseError("sd_jwt.parse.malformed_jwt", "malformed JWT: expected three '.'-separated segments");
  }
  const [headerB64, payloadB64, signature] = components as [
    string,
    string,
    string,
  ];
  if (headerB64.length === 0 || payloadB64.length === 0) {
    throw new SdJwtParseError("sd_jwt.parse.malformed_jwt", "malformed JWT: empty header or payload");
  }
  const header = decodeJson<SdJwtHeader>(headerB64, "header");
  const payload = decodeJson<SdJwtPayload>(payloadB64, "payload");
  return {
    header,
    payload,
    signature,
    signedPayload: `${headerB64}.${payloadB64}`,
  };
}

interface SplitResult {
  disclosureSegments: string[];
  keyBindingJwt: string | undefined;
}

function splitTrailingSegments(segments: string[]): SplitResult {
  if (segments.length === 0) {
    return { disclosureSegments: [], keyBindingJwt: undefined };
  }
  const last = segments[segments.length - 1];
  if (last === undefined || last === "") {
    return {
      disclosureSegments: segments.slice(0, -1).filter((s) => s.length > 0),
      keyBindingJwt: undefined,
    };
  }
  if (last.includes(DOT)) {
    return {
      disclosureSegments: segments.slice(0, -1).filter((s) => s.length > 0),
      keyBindingJwt: last,
    };
  }
  return {
    disclosureSegments: segments.filter((s) => s.length > 0),
    keyBindingJwt: undefined,
  };
}

function decodeJson<T>(b64: string, label: string): T {
  const json = decodeBase64UrlUtf8(b64, label);
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new SdJwtParseError(label === "header" ? "sd_jwt.parse.malformed_header" : "sd_jwt.parse.malformed_payload", `${label} is not valid JSON`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SdJwtParseError(label === "header" ? "sd_jwt.parse.malformed_header" : "sd_jwt.parse.malformed_payload", `${label} must be a JSON object`);
  }
  return parsed as T;
}

function decodeBase64UrlUtf8(b64: string, label: string): string {
  if (!isBase64Url(b64)) {
    throw new SdJwtParseError(label === "header" ? "sd_jwt.parse.malformed_header" : label === "payload" ? "sd_jwt.parse.malformed_payload" : "sd_jwt.parse.malformed_disclosure", `${label} is not valid base64url`);
  }
  return Buffer.from(b64, "base64url").toString("utf-8");
}

function isBase64Url(s: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(s);
}

function parseDisclosure(raw: string): SdJwtDisclosure {
  const json = decodeBase64UrlUtf8(raw, "disclosure");
  let arr: unknown;
  try {
    arr = JSON.parse(json);
  } catch {
    throw new SdJwtParseError("sd_jwt.parse.malformed_disclosure", "disclosure is not valid JSON");
  }
  if (!Array.isArray(arr)) {
    throw new SdJwtParseError("sd_jwt.parse.malformed_disclosure", "disclosure must be a JSON array");
  }
  if (arr.length === 3) {
    const [salt, name, value] = arr;
    if (typeof salt !== "string" || typeof name !== "string") {
      throw new SdJwtParseError(
        "sd_jwt.parse.malformed_disclosure",
        "object disclosure must be [salt:string, name:string, value]",
      );
    }
    return { raw, salt, name, value };
  }
  if (arr.length === 2) {
    const [salt, value] = arr;
    if (typeof salt !== "string") {
      throw new SdJwtParseError(
        "sd_jwt.parse.malformed_disclosure",
        "array-element disclosure must be [salt:string, value]",
      );
    }
    return { raw, salt, name: null, value };
  }
  throw new SdJwtParseError(
    "sd_jwt.parse.malformed_disclosure",
    "disclosure must have arity 2 (array element) or 3 (object property)",
  );
}

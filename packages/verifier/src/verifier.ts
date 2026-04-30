import {
  parseSdJwt,
  verifyHashBinding,
  verifyKeyBinding,
  SdJwtParseError,
  SdJwtVerificationError,
  SdJwtKeyBindingError,
  type ParsedSdJwt,
} from "@gateway/sd-jwt";
import {
  verifyJws,
  JoseVerificationError,
  type JsonWebKey,
  type SupportedAlg,
} from "@gateway/jose";
import {
  StaticTrustResolver,
  TrustResolutionError,
  type TrustResolver,
} from "@gateway/trust";
import {
  VerificationError,
  type FailureResult,
  type SecurityCheck,
  type SecurityCheckName,
  type SuccessResult,
  type VerifierConfig,
  type VerifyOptions,
  type VerifyResult,
} from "./types.js";

const DEFAULT_MAX_AGE_S = 60;
const DEFAULT_CLOCK_SKEW_S = 30;

export class Verifier {
  private readonly audience: string;
  private readonly trust: TrustResolver;
  private readonly algorithms: readonly SupportedAlg[] | undefined;
  private readonly maxKbJwtAgeSeconds: number;
  private readonly maxClockSkewSeconds: number;

  constructor(config: VerifierConfig) {
    if (typeof config.audience !== "string" || config.audience.length === 0) {
      throw new TypeError("Verifier: audience is required");
    }

    const hasKey =
      config.issuerKey !== undefined &&
      config.issuerKey !== null &&
      typeof config.issuerKey === "object";
    const hasTrust = config.trust !== undefined;

    if (hasKey && hasTrust) {
      throw new TypeError(
        "Verifier: pass exactly one of issuerKey (shorthand) OR trust (resolver), not both",
      );
    }
    if (!hasKey && !hasTrust) {
      throw new TypeError(
        "Verifier: one of issuerKey (shorthand) or trust (resolver) is required",
      );
    }

    this.audience = config.audience;
    this.trust = hasTrust
      ? (config.trust as TrustResolver)
      : new StaticTrustResolver([config.issuerKey as JsonWebKey]);
    this.algorithms = config.algorithms;
    this.maxKbJwtAgeSeconds =
      config.maxKbJwtAgeSeconds ?? DEFAULT_MAX_AGE_S;
    this.maxClockSkewSeconds =
      config.maxClockSkewSeconds ?? DEFAULT_CLOCK_SKEW_S;
  }

  /**
   * Verify an SD-JWT-VC presentation token end-to-end.
   *
   * Runs 9 security checks in order; stops at the first failure and reports
   * which check failed. On success, returns the disclosed claims plus
   * protocol metadata plus the full audit trail of checks performed.
   */
  async verify<TClaims = Record<string, unknown>>(
    presentationToken: string,
    options: VerifyOptions,
  ): Promise<VerifyResult<TClaims>> {
    if (typeof options.nonce !== "string" || options.nonce.length === 0) {
      throw new TypeError("verify: options.nonce is required");
    }

    const checks: SecurityCheck[] = [];

    // 1. Parse the token
    let parsed: ParsedSdJwt;
    try {
      parsed = parseSdJwt(presentationToken);
      record(checks, "structure.parse", true);
    } catch (err) {
      return makeFailure(checks, "structure.parse", describe(err));
    }

    // 2a. Resolve trusted issuer keys via the configured TrustResolver
    let candidateKeys;
    try {
      const iss =
        typeof parsed.payload["iss"] === "string"
          ? parsed.payload["iss"]
          : undefined;
      const kid =
        typeof parsed.header["kid"] === "string"
          ? parsed.header["kid"]
          : undefined;

      const trustContext: {
        iss: string | undefined;
        kid: string | undefined;
        header: Record<string, unknown>;
      } = {
        iss,
        kid,
        header: parsed.header as Record<string, unknown>,
      };
      candidateKeys = await this.trust.resolveIssuerKeys(trustContext);
      if (candidateKeys.length === 0) {
        return makeFailure(
          checks,
          "trust.resolution",
          "trust resolver returned no candidate keys",
        );
      }
      record(checks, "trust.resolution", true);
    } catch (err) {
      return makeFailure(checks, "trust.resolution", describe(err));
    }

    // 2b. Verify the issuer signature against any of the candidate keys
    const issuerJws = `${parsed.signedPayload}.${parsed.signature}`;
    const verifyOpts: { algorithms?: readonly SupportedAlg[] } = {};
    if (this.algorithms !== undefined) {
      verifyOpts.algorithms = this.algorithms;
    }
    let verifiedAny = false;
    let lastSignatureError: unknown;
    for (const key of candidateKeys) {
      try {
        await verifyJws(issuerJws, key, verifyOpts);
        verifiedAny = true;
        break;
      } catch (err) {
        lastSignatureError = err;
      }
    }
    if (!verifiedAny) {
      return makeFailure(
        checks,
        "issuer.signature",
        describe(lastSignatureError),
      );
    }
    record(checks, "issuer.signature", true);

    // 3. Verify hash binding (disclosures match _sd digests, no forgery)
    let verifiedSdJwt;
    try {
      verifiedSdJwt = verifyHashBinding(parsed);
      if (verifiedSdJwt.unmatchedDisclosures.length > 0) {
        const names = verifiedSdJwt.unmatchedDisclosures
          .map((d) => d.name ?? "<array element>")
          .join(", ");
        return makeFailure(
          checks,
          "hash-binding.disclosures",
          `forged disclosures detected: ${names}`,
        );
      }
      record(checks, "hash-binding.disclosures", true);
    } catch (err) {
      return makeFailure(checks, "hash-binding.disclosures", describe(err));
    }

    // 4-9. KB-JWT (presence, cnf, signature, aud, nonce, time, transcript)
    let verifiedKb;
    try {
      const kbOpts: Parameters<typeof verifyKeyBinding>[1] = {
        expectedAudience: this.audience,
        expectedNonce: options.nonce,
        maxAgeSeconds: this.maxKbJwtAgeSeconds,
        maxClockSkewSeconds: this.maxClockSkewSeconds,
      };
      if (this.algorithms !== undefined) {
        kbOpts.algorithms = this.algorithms;
      }
      if (options.now !== undefined) {
        kbOpts.now = options.now;
      }

      verifiedKb = await verifyKeyBinding(parsed, kbOpts);

      // KB-JWT verifyKeyBinding short-circuits on first failure; if it
      // returns successfully, all six sub-checks passed.
      record(checks, "kb-jwt.present", true);
      record(checks, "kb-jwt.cnf-binding", true);
      record(checks, "kb-jwt.signature", true);
      record(checks, "kb-jwt.audience", true);
      record(checks, "kb-jwt.nonce", true);
      record(checks, "kb-jwt.time", true);
      record(checks, "kb-jwt.transcript", true);
    } catch (err) {
      return makeFailure(
        checks,
        classifyKbFailure(err),
        describe(err),
      );
    }

    // All checks passed — assemble the success result.
    const claims = stripMetadata(verifiedSdJwt.claims) as TClaims;
    const metadata = extractMetadata(
      parsed,
      verifiedSdJwt.claims,
      this.audience,
      verifiedKb.holderKey,
    );

    const success: SuccessResult<TClaims> = {
      ok: true,
      claims,
      metadata,
      checks: Object.freeze(checks),
      unwrap: () => claims,
    };
    return success;
  }
}

/** Standalone one-off verification — same semantics as Verifier.verify, but
 * no instance to keep around. Pass everything inline. */
export async function verify<TClaims = Record<string, unknown>>(
  presentationToken: string,
  options: VerifyOptions & VerifierConfig,
): Promise<VerifyResult<TClaims>> {
  const { nonce, ...config } = options;
  const verifyOpts: VerifyOptions = { nonce };
  if (options.now !== undefined) verifyOpts.now = options.now;
  return new Verifier(config).verify<TClaims>(presentationToken, verifyOpts);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function record(
  checks: SecurityCheck[],
  name: SecurityCheckName,
  passed: boolean,
  message?: string,
): void {
  const c: SecurityCheck = { name, passed };
  if (message !== undefined) c.message = message;
  checks.push(c);
}

function makeFailure(
  checksSoFar: SecurityCheck[],
  failedCheck: SecurityCheckName,
  reason: string,
): FailureResult {
  const checks = [...checksSoFar];
  checks.push({ name: failedCheck, passed: false, message: reason });
  const failure: FailureResult = {
    ok: false,
    reason,
    failedCheck,
    checks: Object.freeze(checks),
    unwrap: () => {
      throw new VerificationError(reason, failure);
    },
  };
  return failure;
}

/** Map a thrown error from verifyKeyBinding to a specific check name based on
 * its message. We do this because verifyKeyBinding is a single function that
 * checks 6 things; we want to surface the precise step that failed. */
function classifyKbFailure(err: unknown): SecurityCheckName {
  const m = err instanceof Error ? err.message : String(err);
  if (/required but absent/.test(m)) return "kb-jwt.present";
  if (/cnf/.test(m)) return "kb-jwt.cnf-binding";
  if (/aud/.test(m) && !/audi(en)?ce/i.test("audience")) return "kb-jwt.audience";
  if (/aud/.test(m)) return "kb-jwt.audience";
  if (/nonce/.test(m)) return "kb-jwt.nonce";
  if (/iat|future|old/i.test(m)) return "kb-jwt.time";
  if (/sd_hash|transcript/i.test(m)) return "kb-jwt.transcript";
  // Default: signature/typ/alg failures bucketed under signature.
  return "kb-jwt.signature";
}

function describe(err: unknown): string {
  if (
    err instanceof SdJwtParseError ||
    err instanceof SdJwtVerificationError ||
    err instanceof SdJwtKeyBindingError ||
    err instanceof JoseVerificationError ||
    err instanceof TrustResolutionError ||
    err instanceof Error
  ) {
    return err.message;
  }
  return String(err);
}

function stripMetadata(claims: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(claims)) {
    if (
      key === "iss" ||
      key === "iat" ||
      key === "exp" ||
      key === "nbf" ||
      key === "cnf" ||
      key === "vct" ||
      key === "status"
    ) {
      continue;
    }
    out[key] = value;
  }
  return out;
}

function extractMetadata(
  parsed: ParsedSdJwt,
  resolvedClaims: Record<string, unknown>,
  audience: string,
  holderKey: Readonly<Record<string, unknown>>,
): {
  issuer: string;
  audience: string;
  issuedAt: number | undefined;
  expiresAt: number | undefined;
  holderKey: Readonly<Record<string, unknown>>;
} {
  return {
    issuer:
      typeof resolvedClaims["iss"] === "string"
        ? resolvedClaims["iss"]
        : typeof parsed.payload["iss"] === "string"
          ? parsed.payload["iss"]
          : "<unknown>",
    audience,
    issuedAt:
      typeof resolvedClaims["iat"] === "number"
        ? resolvedClaims["iat"]
        : typeof parsed.payload["iat"] === "number"
          ? parsed.payload["iat"]
          : undefined,
    expiresAt:
      typeof resolvedClaims["exp"] === "number"
        ? resolvedClaims["exp"]
        : typeof parsed.payload["exp"] === "number"
          ? parsed.payload["exp"]
          : undefined,
    holderKey,
  };
}

import {
  parseSdJwt,
  verifyHashBinding,
  verifyKeyBinding,
  SdJwtError,
  type ParsedSdJwt,
} from "@gramota/sd-jwt";
import {
  verifyJws,
  JoseError,
  type JsonWebKey,
  type SupportedAlg,
} from "@gramota/jose";
import {
  StaticTrustResolver,
  TrustResolutionError,
  type TrustResolver,
} from "@gramota/trust";
import {
  buildAuthorizationRequestUrl,
  parseAuthorizationResponseBody,
  type AuthorizationRequest,
  type AuthorizationResponse,
} from "@gramota/oid4vp";
import type {
  CredentialStatusResult,
  StatusResolver,
} from "@gramota/status-list";
import {
  VerifierError,
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
  private readonly additionalAudiences: readonly string[];
  private readonly trust: TrustResolver;
  private readonly statusResolver: StatusResolver | undefined;
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
    this.additionalAudiences = config.additionalAudiences ?? [];
    this.trust = hasTrust
      ? (config.trust as TrustResolver)
      : new StaticTrustResolver([config.issuerKey as JsonWebKey]);
    this.statusResolver = config.statusResolver;
    this.algorithms = config.algorithms;
    this.maxKbJwtAgeSeconds =
      config.maxKbJwtAgeSeconds ?? DEFAULT_MAX_AGE_S;
    this.maxClockSkewSeconds =
      config.maxClockSkewSeconds ?? DEFAULT_CLOCK_SKEW_S;

    // ────────────────────────────────────────────────────────────────
    // Stripe-shaped resource namespaces.
    //
    //   verifier.presentations.verify(token, opts)
    //   verifier.responses.verify(rawBody, opts)
    //   verifier.requests.create(opts)
    //
    // The flat methods (`verify`, `response`, `request`) were dropped
    // in 0.5.0 — this is the only public shape now.
    // ────────────────────────────────────────────────────────────────
    this.presentations = {
      verify: (token, opts) => this.verifyPresentationImpl(token, opts),
    };
    this.responses = {
      verify: (rawBody, opts) => this.verifyResponseImpl(rawBody, opts),
    };
    this.requests = {
      create: (opts) => this.createRequestImpl(opts),
    };
  }

  /** Verify a presentation token. Stripe-shaped surface. */
  readonly presentations: {
    verify<TClaims = Record<string, unknown>>(
      presentationToken: string,
      options: VerifyOptions<TClaims>,
    ): Promise<VerifyResult<TClaims>>;
  };

  /** Verify an OID4VP authorization response body. Stripe-shaped surface. */
  readonly responses: {
    verify<TClaims = Record<string, unknown>>(
      rawBody: string | URLSearchParams | Record<string, string>,
      options: VerifyResponseOptions<TClaims>,
    ): Promise<VerifyResponseResult<TClaims>>;
  };

  /** Build a signed presentation request for the wallet. Stripe-shaped surface. */
  readonly requests: {
    create(options: PresentationRequestOptions): PresentationRequest;
  };

  /**
   * Verify an SD-JWT-VC presentation token end-to-end.
   *
   * Runs 9 security checks in order; stops at the first failure and reports
   * which check failed. On success, returns the disclosed claims plus
   * protocol metadata plus the full audit trail of checks performed.
   *
   * @internal Public surface is `verifier.presentations.verify(token, opts)`.
   */
  private async verifyPresentationImpl<TClaims = Record<string, unknown>>(
    presentationToken: string,
    options: VerifyOptions<TClaims>,
  ): Promise<VerifyResult<TClaims>> {
    if (typeof options.nonce !== "string" || options.nonce.length === 0) {
      throw new TypeError("verifier.presentations.verify: options.nonce is required");
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
      const acceptedAud =
        this.additionalAudiences.length > 0
          ? [this.audience, ...this.additionalAudiences]
          : this.audience;
      const kbOpts: Parameters<typeof verifyKeyBinding>[1] = {
        expectedAudience: acceptedAud,
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

    // 10. Optional status check — delegated to the configured StatusResolver
    // Strategy. The verifier knows POLICY (requireStatus); the resolver
    // knows MECHANISM (status list, CRL, OCSP, ...).
    let statusResult: CredentialStatusResult | "skipped" | undefined;
    if (this.statusResolver !== undefined) {
      const resolveOpts: Parameters<StatusResolver["resolveStatus"]>[1] = {};
      if (options.now !== undefined) resolveOpts.now = options.now;

      try {
        statusResult = await this.statusResolver.resolveStatus(
          parsed,
          resolveOpts,
        );
      } catch (err) {
        return makeFailure(checks, "status.check", describe(err));
      }

      if (statusResult === "skipped") {
        if (options.requireStatus) {
          return makeFailure(
            checks,
            "status.check",
            "credential has no resolvable status but requireStatus=true",
          );
        }
        record(
          checks,
          "status.check",
          true,
          "credential status was skipped (no reference resolved)",
        );
      } else if (statusResult.state !== "valid") {
        return makeFailure(
          checks,
          "status.check",
          `credential status is '${statusResult.state}' (code=${statusResult.code})`,
        );
      } else {
        record(checks, "status.check", true);
      }
    }

    // All cryptographic checks passed. Extract the claims + metadata
    // before running the optional application-level predicate so the
    // predicate sees the same shape callers will see on success.
    const claims = stripMetadata(verifiedSdJwt.claims) as TClaims;
    const metadata = extractMetadata(
      parsed,
      verifiedSdJwt.claims,
      this.audience,
      verifiedKb.holderKey,
    );

    // 11. Application-level predicate (optional). Last gate, runs
    //     after every protocol check. Lets callers express business
    //     rules ("age ≥ 18", "EU resident", "credentialSubject.dob in
    //     a specific decade") without polluting the protocol layer.
    if (options.require !== undefined) {
      let predicateOutcome;
      try {
        predicateOutcome = await options.require({ claims, metadata });
      } catch (err) {
        // Predicate threw — surface the throw verbatim. We don't
        // silently treat it as failure: a buggy predicate is a
        // caller bug, not a verification result.
        throw err;
      }
      const passed =
        typeof predicateOutcome === "boolean"
          ? predicateOutcome
          : Boolean(predicateOutcome.passed);
      if (!passed) {
        const reason =
          typeof predicateOutcome === "boolean"
            ? "require predicate returned false"
            : (predicateOutcome.reason ?? "require predicate returned false");
        return makeFailure(checks, "require.predicate", reason);
      }
      record(checks, "require.predicate", true);
    }

    const success: SuccessResult<TClaims> = {
      ok: true,
      claims,
      metadata,
      checks: Object.freeze(checks),
      unwrap: () => claims,
    };
    if (statusResult !== undefined) success.status = statusResult;
    return success;
  }

  /**
   * Build an OID4VP Authorization Request URL to share with the wallet.
   *
   * @internal Public surface is `verifier.requests.create(opts)`.
   */
  private createRequestImpl(options: PresentationRequestOptions): PresentationRequest {
    if (typeof options.baseUrl !== "string" || options.baseUrl.length === 0) {
      throw new TypeError("verifier.requests.create: baseUrl is required");
    }
    if (typeof options.nonce !== "string" || options.nonce.length === 0) {
      throw new TypeError("verifier.requests.create: nonce is required");
    }
    if (
      options.presentationDefinition !== undefined &&
      options.presentationDefinitionUri !== undefined
    ) {
      throw new TypeError(
        "presentationDefinition and presentationDefinitionUri are mutually exclusive",
      );
    }

    const responseMode =
      options.responseMode ??
      (options.responseUri !== undefined ? "direct_post" : undefined);

    const request: AuthorizationRequest = {
      response_type: "vp_token",
      client_id: options.clientId ?? this.audience,
      client_id_scheme: options.clientIdScheme ?? "redirect_uri",
      nonce: options.nonce,
    };
    if (options.state !== undefined) request.state = options.state;
    if (responseMode !== undefined) request.response_mode = responseMode;
    if (options.responseUri !== undefined) {
      request.response_uri = options.responseUri;
    }
    if (options.presentationDefinition !== undefined) {
      request.presentation_definition = options.presentationDefinition;
    }
    if (options.presentationDefinitionUri !== undefined) {
      request.presentation_definition_uri = options.presentationDefinitionUri;
    }

    const url = buildAuthorizationRequestUrl(options.baseUrl, request);

    return {
      url,
      request,
      nonce: options.nonce,
      state: options.state,
    };
  }

  /**
   * Process an OID4VP Authorization Response body end-to-end:
   * parse the form body, enforce CSRF state matching, and verify the
   * vp_token cryptographically. Returns the same result shape as
   * `presentations.verify` plus the parsed transport envelope.
   *
   * @internal Public surface is `verifier.responses.verify(rawBody, opts)`.
   */
  private async verifyResponseImpl<TClaims = Record<string, unknown>>(
    rawBody: string | URLSearchParams | Record<string, string>,
    options: VerifyResponseOptions<TClaims>,
  ): Promise<VerifyResponseResult<TClaims>> {
    if (
      typeof options.expectedNonce !== "string" ||
      options.expectedNonce.length === 0
    ) {
      throw new TypeError("verifier.responses.verify: expectedNonce is required");
    }

    let response: AuthorizationResponse;
    try {
      response =
        typeof rawBody === "string"
          ? parseAuthorizationResponseBody(rawBody)
          : (await import("@gramota/oid4vp")).parseAuthorizationResponseFromParams(
              rawBody,
            );
    } catch (err) {
      const checks: SecurityCheck[] = [];
      return makeFailure(
        checks,
        "structure.parse",
        err instanceof Error ? err.message : String(err),
      ) as VerifyResponseResult<TClaims>;
    }

    // CSRF state matching is application-level but we offer it as a default
    // safety belt — opt out by omitting expectedState.
    if (
      options.expectedState !== undefined &&
      response.state !== options.expectedState
    ) {
      const checks: SecurityCheck[] = [];
      return makeFailure(
        checks,
        "structure.parse",
        `OID4VP state mismatch — expected '${options.expectedState}', got '${response.state ?? "<missing>"}'`,
      ) as VerifyResponseResult<TClaims>;
    }

    // v1 supports single-token responses; multi-token coming with full DIF PE.
    if (typeof response.vp_token !== "string") {
      const checks: SecurityCheck[] = [];
      return makeFailure(
        checks,
        "structure.parse",
        "multi-credential vp_token arrays are not yet supported in v1",
      ) as VerifyResponseResult<TClaims>;
    }
    const vpToken = response.vp_token;

    const verifyOpts: VerifyOptions<TClaims> = { nonce: options.expectedNonce };
    if (options.now !== undefined) verifyOpts.now = options.now;
    if (options.requireStatus !== undefined) {
      verifyOpts.requireStatus = options.requireStatus;
    }
    if (options.require !== undefined) verifyOpts.require = options.require;
    const baseResult = await this.verifyPresentationImpl<TClaims>(vpToken, verifyOpts);

    return Object.assign({}, baseResult, {
      response,
    }) as VerifyResponseResult<TClaims>;
  }
}

/** Result of `verifier.responses.verify()` — same shape as `VerifyResult`
 * plus the parsed OID4VP transport envelope. */
export type VerifyResponseResult<TClaims = Record<string, unknown>> =
  VerifyResult<TClaims> & { response?: AuthorizationResponse };

/** Options for `verifier.request()`. */
export interface PresentationRequestOptions {
  /** Base URL or scheme: `openid4vp://authorize`, `https://wallet.example.com/...` */
  baseUrl: string;
  /** OID4VP nonce. */
  nonce: string;
  /** Optional opaque CSRF state echoed back unchanged in the response. */
  state?: string;
  /** `direct_post` callback URL (required when response_mode=direct_post). */
  responseUri?: string;
  /** Inline DIF Presentation Definition. */
  presentationDefinition?: Readonly<Record<string, unknown>>;
  /** Or a URL the wallet can fetch the PD from. Mutually exclusive with above. */
  presentationDefinitionUri?: string;
  /** Override response_mode (default: direct_post when responseUri is set,
   * otherwise undefined). */
  responseMode?: "direct_post" | "direct_post.jwt" | "fragment" | "query";
  /** client_id_scheme (default: redirect_uri). */
  clientIdScheme?: string;
  /** Override the client_id (defaults to the verifier's audience). */
  clientId?: string;
}

/** Result of `verifier.request()`. */
export interface PresentationRequest {
  /** The full URL to share with the wallet (QR / deep link). */
  url: string;
  /** The structured AuthorizationRequest, useful for storage and logging. */
  request: AuthorizationRequest;
  /** Echoes the nonce so callers can persist it for later verification. */
  nonce: string;
  /** Echoes the state if one was supplied. */
  state: string | undefined;
}

/** Options for `verifier.response()`. */
export interface VerifyResponseOptions<TClaims = Record<string, unknown>> {
  /** Required — the nonce used in the original request. */
  expectedNonce: string;
  /** Optional — when supplied, response.state MUST equal this. */
  expectedState?: string;
  /** Override "now" — for tests. */
  now?: () => number;
  /** Forwarded to `verify()` — fail when credential has no resolvable
   * status. Has effect only when the Verifier was constructed with a
   * `statusResolver`. */
  requireStatus?: boolean;
  /** Forwarded to `verify()` — application-level predicate that runs
   * after all crypto + status checks pass. See {@link VerifyOptions.require}. */
  require?: VerifyOptions<TClaims>["require"];
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
      throw new VerifierError(reason, failure);
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
    err instanceof SdJwtError ||
    err instanceof JoseError ||
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

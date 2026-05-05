import { Oid4vpError, type AuthorizationRequest } from "./types.js";

/** Required fields per OID4VP §5. */
const REQUIRED_FIELDS = ["response_type", "client_id", "nonce"] as const;

/** Object-valued parameters that must be JSON-encoded in URL form. */
const JSON_FIELDS = new Set<string>([
  "presentation_definition",
  "dcql_query",
  "client_metadata",
]);

/**
 * Serialise an Authorization Request to a URL with query parameters per
 * OID4VP §5.1 (parameter encoding rules).
 *
 * The base URL is typically a custom scheme like `openid4vp://` for the
 * native wallet handoff, or `https://wallet.example.com/authorize` for
 * web flows — both work, the function just appends the query string.
 *
 * Object-valued parameters (`presentation_definition`, `dcql_query`,
 * `client_metadata`) are JSON-encoded into the query string per §5.1.
 *
 * For HAIP / EUDIW-compliant verifiers, this output is typically wrapped
 * in a signed JAR (RFC 9101) via {@link signAuthorizationRequest} and
 * delivered as `request=<jwt>` rather than as raw query params.
 *
 * @example
 * ```ts
 * const url = buildAuthorizationRequestUrl("openid4vp://", {
 *   response_type: "vp_token",
 *   client_id: "x509_san_dns:verifier.example",
 *   nonce: "n-12345",
 *   response_mode: "direct_post",
 *   response_uri: "https://verifier.example/oid4vp/response",
 *   dcql_query: { credentials: [{ id: "pid", format: "dc+sd-jwt", meta: {...} }] },
 * });
 * ```
 *
 * @throws {@link Oid4vpError} `oid4vp.required_field_missing`,
 *   `oid4vp.unsupported_response_type`, `oid4vp.mutually_exclusive_fields`,
 *   `oid4vp.response_uri_required`, or `oid4vp.invalid_value_type`.
 */
export function buildAuthorizationRequestUrl(
  baseUrl: string,
  request: AuthorizationRequest,
): string {
  validateRequest(request);

  const url = new URL(baseUrl);
  for (const [key, value] of Object.entries(request)) {
    if (value === undefined) continue;
    if (JSON_FIELDS.has(key)) {
      url.searchParams.set(key, JSON.stringify(value));
    } else if (typeof value === "string") {
      url.searchParams.set(key, value);
    } else {
      throw new Oid4vpError(
        "oid4vp.invalid_value_type",
        `unsupported value type for '${key}': ${typeof value}`,
      );
    }
  }
  return url.toString();
}

/**
 * Parse an OID4VP Authorization Request from a URL string.
 *
 * Inverse of {@link buildAuthorizationRequestUrl}. Validates required
 * fields and mutually-exclusive flag combinations; does NOT verify a
 * signed JAR (use the wallet's JWS verification step for that, then
 * call this function on the JAR's payload claims).
 *
 * @throws {@link Oid4vpError} with `oid4vp.invalid_url`,
 *   `oid4vp.required_field_missing`, or other field-validation codes.
 */
export function parseAuthorizationRequestUrl(
  rawUrl: string,
): AuthorizationRequest {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.invalid_url",
      `not a valid URL: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseAuthorizationRequestSearchParams(url.searchParams);
}

/**
 * Parse an OID4VP Authorization Request from URL query parameters.
 *
 * Useful when the verifier already has parsed query params from a web
 * framework (`req.query` from Express, Hono, Fastify, ...). Accepts
 * either a `URLSearchParams` instance or a plain `Record<string, string>`.
 *
 * Object-valued params (`presentation_definition`, `dcql_query`,
 * `client_metadata`) are JSON-decoded; everything else is left as-is.
 *
 * @throws {@link Oid4vpError} with `oid4vp.invalid_json` if a JSON-valued
 *   param is malformed, plus the standard field-validation codes.
 */
export function parseAuthorizationRequestSearchParams(
  params: URLSearchParams | Record<string, string>,
): AuthorizationRequest {
  const get = (k: string): string | undefined =>
    params instanceof URLSearchParams ? params.get(k) ?? undefined : params[k];

  const out: Record<string, unknown> = {};
  const known = [
    "response_type",
    "client_id",
    "client_id_scheme",
    "response_mode",
    "response_uri",
    "redirect_uri",
    "nonce",
    "state",
    "presentation_definition",
    "presentation_definition_uri",
    "dcql_query",
    "client_metadata",
    "scope",
  ];

  for (const key of known) {
    const value = get(key);
    if (value === undefined) continue;
    if (JSON_FIELDS.has(key)) {
      try {
        out[key] = JSON.parse(value);
      } catch (err) {
        throw new Oid4vpError(
          "oid4vp.invalid_json",
          `invalid JSON for parameter '${key}': ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    } else {
      out[key] = value;
    }
  }

  validateRequest(out as Partial<AuthorizationRequest>);
  return out as unknown as AuthorizationRequest;
}

function validateRequest(req: Partial<AuthorizationRequest>): void {
  for (const field of REQUIRED_FIELDS) {
    const v = req[field];
    if (typeof v !== "string" || v.length === 0) {
      throw new Oid4vpError(
        "oid4vp.required_field_missing",
        `Authorization Request is missing required parameter: ${field}`,
      );
    }
  }
  if (req.response_type !== "vp_token") {
    throw new Oid4vpError(
      "oid4vp.unsupported_response_type",
      `Authorization Request response_type must be 'vp_token', got '${req.response_type}'`,
    );
  }
  if (
    req.presentation_definition !== undefined &&
    req.presentation_definition_uri !== undefined
  ) {
    throw new Oid4vpError(
      "oid4vp.mutually_exclusive_fields",
      "presentation_definition and presentation_definition_uri are mutually exclusive (OID4VP §5.4)",
    );
  }
  if (
    req.presentation_definition !== undefined &&
    req.dcql_query !== undefined
  ) {
    throw new Oid4vpError(
      "oid4vp.mutually_exclusive_fields",
      "presentation_definition and dcql_query are mutually exclusive — pick one query language",
    );
  }
  if (req.response_mode === "direct_post" && req.response_uri === undefined) {
    throw new Oid4vpError(
      "oid4vp.response_uri_required",
      "response_mode=direct_post requires response_uri (OID4VP §6.2)",
    );
  }
}

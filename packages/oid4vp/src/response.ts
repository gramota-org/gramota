import { Oid4vpError, type AuthorizationResponse } from "./types.js";

/** Required fields per OID4VP §6.1. */
const REQUIRED_FIELDS = ["vp_token", "presentation_submission"] as const;

/**
 * Serialise an Authorization Response to a URL-encoded form body, suitable
 * for `direct_post` (POST application/x-www-form-urlencoded). Per OID4VP §6:
 *
 *  - `vp_token` is the raw presentation string, or a JSON-encoded array if
 *    multiple credentials are presented.
 *  - `presentation_submission` is JSON-encoded.
 *  - `state` (optional) and `iss` (optional) pass through as strings.
 */
export function buildAuthorizationResponseBody(
  response: AuthorizationResponse,
): string {
  validateResponse(response);

  const body = new URLSearchParams();

  if (Array.isArray(response.vp_token)) {
    body.set("vp_token", JSON.stringify(response.vp_token));
  } else if (typeof response.vp_token === "string") {
    body.set("vp_token", response.vp_token);
  } else {
    throw new Oid4vpError(
      "oid4vp.invalid_value_type",
      "vp_token must be a string or an array of strings",
    );
  }
  body.set(
    "presentation_submission",
    JSON.stringify(response.presentation_submission),
  );
  if (response.state !== undefined) body.set("state", response.state);
  if (response.iss !== undefined) body.set("iss", response.iss);

  return body.toString();
}

/** Parse an Authorization Response from a URL-encoded form body string. */
export function parseAuthorizationResponseBody(
  rawBody: string,
): AuthorizationResponse {
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(rawBody);
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.malformed_body",
      `Authorization Response body is not valid URL-encoded form data: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  return parseAuthorizationResponseFromParams(params);
}

/** Parse from URLSearchParams or a plain object — handy when frameworks have
 * already decoded the body. */
export function parseAuthorizationResponseFromParams(
  params: URLSearchParams | Record<string, string>,
): AuthorizationResponse {
  const get = (k: string): string | undefined =>
    params instanceof URLSearchParams ? params.get(k) ?? undefined : params[k];

  const vpRaw = get("vp_token");
  const submissionRaw = get("presentation_submission");

  if (vpRaw === undefined) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "Authorization Response is missing required parameter: vp_token",
    );
  }
  if (submissionRaw === undefined) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "Authorization Response is missing required parameter: presentation_submission",
    );
  }

  let submission: unknown;
  try {
    submission = JSON.parse(submissionRaw);
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.invalid_json",
      `presentation_submission is not valid JSON: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (
    submission === null ||
    typeof submission !== "object" ||
    Array.isArray(submission)
  ) {
    throw new Oid4vpError(
      "oid4vp.malformed_submission",
      "presentation_submission must be a JSON object (DIF Presentation Exchange v2)",
    );
  }

  // vp_token may be a string OR a JSON-encoded array of strings.
  let vp_token: string | string[] = vpRaw;
  if (vpRaw.trim().startsWith("[")) {
    try {
      const parsed = JSON.parse(vpRaw);
      if (
        Array.isArray(parsed) &&
        parsed.every((p) => typeof p === "string")
      ) {
        vp_token = parsed;
      }
    } catch {
      // Not a JSON array — treat as a literal string.
    }
  }

  const result: AuthorizationResponse = {
    vp_token,
    presentation_submission: submission as Record<string, unknown>,
  };
  const state = get("state");
  if (state !== undefined) result.state = state;
  const iss = get("iss");
  if (iss !== undefined) result.iss = iss;

  validateResponse(result);
  return result;
}

function validateResponse(resp: Partial<AuthorizationResponse>): void {
  for (const field of REQUIRED_FIELDS) {
    if (resp[field] === undefined) {
      throw new Oid4vpError(
        "oid4vp.required_field_missing",
        `Authorization Response is missing required parameter: ${field}`,
      );
    }
  }
  if (
    typeof resp.vp_token !== "string" &&
    !(
      Array.isArray(resp.vp_token) &&
      resp.vp_token.every((v) => typeof v === "string")
    )
  ) {
    throw new Oid4vpError(
      "oid4vp.invalid_value_type",
      "vp_token must be a string or an array of strings",
    );
  }
}

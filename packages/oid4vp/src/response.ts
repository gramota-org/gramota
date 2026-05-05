import { Oid4vpError, type AuthorizationResponse } from "./types.js";

/**
 * Serialise an Authorization Response to a URL-encoded form body, suitable
 * for `direct_post` (POST application/x-www-form-urlencoded). Per OID4VP §6:
 *
 *  - `vp_token` is the raw presentation string, a JSON-encoded array if
 *    multiple credentials are presented (PEX), or a JSON-encoded object
 *    keyed by DCQL credential id (DCQL response form).
 *  - `presentation_submission` is JSON-encoded — only included for PEX
 *    responses; DCQL responses omit it.
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
  } else if (
    response.vp_token !== null &&
    typeof response.vp_token === "object"
  ) {
    // DCQL response — JSON object keyed by credential id.
    body.set("vp_token", JSON.stringify(response.vp_token));
  } else {
    throw new Oid4vpError(
      "oid4vp.invalid_value_type",
      "vp_token must be a string, array of strings, or DCQL credential map",
    );
  }
  if (response.presentation_submission !== undefined) {
    body.set(
      "presentation_submission",
      JSON.stringify(response.presentation_submission),
    );
  }
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

  // vp_token may be:
  //   - a single SD-JWT-VC string (PEX, single credential)
  //   - a JSON-encoded string[] (PEX, multiple credentials)
  //   - a JSON-encoded object keyed by DCQL credential id (DCQL response,
  //     OID4VP Final 1.0 — what production EU wallets send)
  let vp_token: AuthorizationResponse["vp_token"] = vpRaw;
  const trimmed = vpRaw.trim();
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(vpRaw);
      if (Array.isArray(parsed) && parsed.every((p) => typeof p === "string")) {
        vp_token = parsed;
      } else if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed)
      ) {
        // DCQL response form — keys are credential ids, values are
        // (single-credential) strings or arrays.
        const obj = parsed as Record<string, unknown>;
        const flat: Record<string, string> = {};
        for (const [id, val] of Object.entries(obj)) {
          if (typeof val === "string") {
            flat[id] = val;
          } else if (
            Array.isArray(val) &&
            val.length === 1 &&
            typeof val[0] === "string"
          ) {
            // Some wallets wrap each credential in a single-element array
            // (anticipating multi-instance presentations). Flatten for our
            // SD-JWT-VC verifier which expects a single string per id.
            flat[id] = val[0]!;
          } else {
            throw new Oid4vpError(
              "oid4vp.invalid_value_type",
              `vp_token[${id}] must be a string or single-element array of strings`,
            );
          }
        }
        vp_token = flat;
      }
    } catch (err) {
      if (err instanceof Oid4vpError) throw err;
      // Not a JSON array/object — treat as a literal string.
    }
  }

  // presentation_submission is required for PEX responses (string or
  // string[] vp_token), optional for DCQL responses (object vp_token).
  const isDcqlResponse =
    typeof vp_token === "object" && !Array.isArray(vp_token);
  let submission: Record<string, unknown> | undefined;
  if (submissionRaw !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(submissionRaw);
    } catch (err) {
      throw new Oid4vpError(
        "oid4vp.invalid_json",
        `presentation_submission is not valid JSON: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Oid4vpError(
        "oid4vp.malformed_submission",
        "presentation_submission must be a JSON object (DIF Presentation Exchange v2)",
      );
    }
    submission = parsed as Record<string, unknown>;
  } else if (!isDcqlResponse) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "Authorization Response is missing required parameter: presentation_submission",
    );
  }

  const result: AuthorizationResponse = { vp_token };
  if (submission !== undefined) result.presentation_submission = submission;
  const state = get("state");
  if (state !== undefined) result.state = state;
  const iss = get("iss");
  if (iss !== undefined) result.iss = iss;

  validateResponse(result);
  return result;
}

function validateResponse(resp: Partial<AuthorizationResponse>): void {
  if (resp.vp_token === undefined) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "Authorization Response is missing required parameter: vp_token",
    );
  }
  const isString = typeof resp.vp_token === "string";
  const isStringArray =
    Array.isArray(resp.vp_token) &&
    resp.vp_token.every((v) => typeof v === "string");
  const isDcqlMap =
    !Array.isArray(resp.vp_token) &&
    resp.vp_token !== null &&
    typeof resp.vp_token === "object" &&
    Object.values(resp.vp_token as Record<string, unknown>).every(
      (v) => typeof v === "string",
    );
  if (!isString && !isStringArray && !isDcqlMap) {
    throw new Oid4vpError(
      "oid4vp.invalid_value_type",
      "vp_token must be a string, array of strings, or DCQL credential map",
    );
  }
  // PEX path requires presentation_submission; DCQL path doesn't.
  if (
    (isString || isStringArray) &&
    resp.presentation_submission === undefined
  ) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "Authorization Response is missing required parameter: presentation_submission",
    );
  }
}

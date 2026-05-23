/**
 * `direct_post.jwt` response mode — OID4VP Final 1.0 §8.3.1, HAIP §5.1.
 *
 * Where `direct_post` sends the Authorization Response as plaintext
 * `application/x-www-form-urlencoded`, `direct_post.jwt` wraps the
 * exact same fields (`vp_token`, optional `presentation_submission`,
 * `state`, `iss`) into a JSON object, then encrypts that object into
 * a compact-serialised JWE keyed by the verifier's published
 * encryption JWK. The JWE rides on a single form field named
 * `response`.
 *
 *   wallet ─ JSON encode vp_token + state + iss ──►
 *          ─ JWE-wrap with verifier.client_metadata.jwks[*].use="enc" ──►
 *          ─ form-encode as response=<JWE> ──►
 *                                                verifier
 *
 *   verifier ─ extract `response` form param ──►
 *            ─ decrypt JWE with private encryption key ──►
 *            ─ JSON parse the cleartext payload ──►
 *            ─ feed into parseAuthorizationResponseBody equivalent ──►
 *
 * Why HAIP mandates this: with plaintext `direct_post` the PID claims
 * (disclosed names, birthdates, addresses) travel as form fields the
 * verifier's TLS terminator, reverse proxy, and downstream log
 * pipelines can capture. Encrypting end-to-end (wallet → application)
 * shrinks the trust boundary to the application that holds the
 * private key.
 *
 * The crypto primitives used by default:
 *   - `alg = ECDH-ES`  — direct ECDH-derived CEK, no extra key wrap.
 *     P-256 is the curve every HAIP wallet implements.
 *   - `enc = A256GCM`  — authenticated encryption of the payload.
 *
 * Callers can opt into different `alg`/`enc` values via the options.
 */

import { CompactEncrypt, compactDecrypt, exportJWK, generateKeyPair, importJWK } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Oid4vpError, type AuthorizationResponse } from "./types.js";

/** Default JWE key-agreement algorithm — ECDH-ES, the option the EU
 * reference wallet and HAIP §5.1 baseline implement. */
export const DEFAULT_RESPONSE_JWE_ALG = "ECDH-ES";
/** Default JWE content-encryption algorithm — A256GCM (authenticated). */
export const DEFAULT_RESPONSE_JWE_ENC = "A256GCM";

/**
 * Generate a fresh JWE encryption keypair for the verifier.
 *
 * The public JWK goes into `client_metadata.jwks.keys[]` on the
 * Authorization Request; the private JWK stays on the verifier and
 * decrypts inbound `direct_post.jwt` responses.
 *
 * Returns both JWKs annotated with:
 *   - `use: "enc"` (RFC 7517 §4.2) so wallets can pick the right key
 *     when both signing and encryption keys are published
 *   - `alg`: the key-agreement algorithm (default ECDH-ES)
 *   - `kid` (optional, caller-supplied)
 *
 * Production deployments may want HSM-backed keys instead — the
 * encryption keypair is a long-lived secret per verifier, not a
 * per-request ephemeral. This generator is the development /
 * pinned-trust path; the surface contract (JsonWebKey in and out) is
 * the same regardless of where the bits come from.
 */
export interface GenerateResponseEncryptionKeyOptions {
  /** Key-agreement algorithm. Default `"ECDH-ES"`. */
  readonly alg?: string;
  /** Optional key id — written to both JWKs as `kid`. */
  readonly kid?: string;
}

export async function generateResponseEncryptionKey(
  options: GenerateResponseEncryptionKeyOptions = {},
): Promise<{ publicJwk: JsonWebKey; privateJwk: JsonWebKey }> {
  const alg = options.alg ?? DEFAULT_RESPONSE_JWE_ALG;
  let keys;
  try {
    keys = await generateKeyPair(alg, { extractable: true });
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      `generateResponseEncryptionKey: alg ${JSON.stringify(alg)} not supported: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const publicJwk = (await exportJWK(keys.publicKey)) as JsonWebKey;
  const privateJwk = (await exportJWK(keys.privateKey)) as JsonWebKey;
  publicJwk.use = "enc";
  privateJwk.use = "enc";
  publicJwk.alg = alg;
  privateJwk.alg = alg;
  if (options.kid !== undefined) {
    publicJwk.kid = options.kid;
    privateJwk.kid = options.kid;
  }
  return { publicJwk, privateJwk };
}

// ---------------------------------------------------------------------------
// Wallet side — wrap an AuthorizationResponse into a JWE.
// ---------------------------------------------------------------------------

export interface EncryptAuthorizationResponseOptions {
  /** The Authorization Response to wrap. The same object you'd hand to
   * `buildAuthorizationResponseBody` for `direct_post`. */
  readonly response: AuthorizationResponse;
  /** Verifier's encryption JWK — picked from `client_metadata.jwks`. */
  readonly encryptionKey: JsonWebKey;
  /** Optional override of the JWE `alg` header. Default
   * {@link DEFAULT_RESPONSE_JWE_ALG} or `encryptionKey.alg` when set. */
  readonly alg?: string;
  /** Optional override of the JWE `enc` header. Default
   * {@link DEFAULT_RESPONSE_JWE_ENC}. */
  readonly enc?: string;
  /** Optional override of the JWE `kid` header. Default
   * `encryptionKey.kid`. */
  readonly kid?: string;
}

/**
 * Encrypt an Authorization Response per OID4VP §8.3.1.
 *
 * The cleartext is the JSON object the spec describes — same shape as
 * the form-encoded `direct_post` body would carry, but as JSON rather
 * than URL-encoded form. The output is a compact-serialised JWE
 * suitable for the `response` form parameter of the wallet's POST to
 * the verifier's `response_uri`.
 *
 * @throws {@link Oid4vpError} `oid4vp.response_encryption_failed`.
 */
export async function encryptAuthorizationResponse(
  options: EncryptAuthorizationResponseOptions,
): Promise<string> {
  if (
    options.encryptionKey === null ||
    typeof options.encryptionKey !== "object"
  ) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      "encryptAuthorizationResponse: encryptionKey is required",
    );
  }
  const alg =
    options.alg ??
    (typeof options.encryptionKey.alg === "string"
      ? options.encryptionKey.alg
      : DEFAULT_RESPONSE_JWE_ALG);
  const enc = options.enc ?? DEFAULT_RESPONSE_JWE_ENC;

  const payload = buildJwtResponsePayload(options.response);

  let publicKey;
  try {
    publicKey = await importJWK(
      options.encryptionKey as Parameters<typeof importJWK>[0],
      alg,
    );
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      `encryptAuthorizationResponse: failed to import encryption JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  const protectedHeader: Record<string, unknown> = { alg, enc };
  const kid =
    options.kid ??
    (typeof options.encryptionKey.kid === "string"
      ? options.encryptionKey.kid
      : undefined);
  if (kid !== undefined) protectedHeader["kid"] = kid;

  try {
    const cleartext = new TextEncoder().encode(JSON.stringify(payload));
    return await new CompactEncrypt(cleartext)
      .setProtectedHeader(
        protectedHeader as Parameters<
          InstanceType<typeof CompactEncrypt>["setProtectedHeader"]
        >[0],
      )
      .encrypt(publicKey);
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      `encryptAuthorizationResponse: JWE encryption failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/** Convert an AuthorizationResponse to the JSON object that
 * `direct_post.jwt` ships as the JWE cleartext.
 *
 * The JWE cleartext is conceptually the same as the `direct_post`
 * form body, except parameters are JSON-typed (no URL encoding /
 * string coercion), and complex values (vp_token map, submission
 * map) are nested as objects rather than embedded as JSON-string
 * fields. This mirrors what production EU wallets send.
 */
function buildJwtResponsePayload(
  response: AuthorizationResponse,
): Record<string, unknown> {
  const out: Record<string, unknown> = { vp_token: response.vp_token };
  if (response.presentation_submission !== undefined) {
    out["presentation_submission"] = response.presentation_submission;
  }
  if (response.state !== undefined) out["state"] = response.state;
  if (response.iss !== undefined) out["iss"] = response.iss;
  return out;
}

// ---------------------------------------------------------------------------
// Verifier side — decrypt + parse the JWE into an AuthorizationResponse.
// ---------------------------------------------------------------------------

export interface DecryptAuthorizationResponseOptions {
  /** The compact-serialised JWE pulled from the `response` form field. */
  readonly jwe: string;
  /** The verifier's private encryption JWK — counterpart to the public
   * key published in `client_metadata.jwks`. */
  readonly privateKey: JsonWebKey;
  /** Optional allowlist of acceptable `enc` values. Default
   * `["A256GCM"]` — narrow / widen for interop. */
  readonly enc?: readonly string[];
  /** Optional allowlist of acceptable `alg` values. Default
   * `["ECDH-ES"]`. */
  readonly alg?: readonly string[];
}

export interface DecryptedAuthorizationResponse {
  /** The wallet's Authorization Response, ready to feed to the
   * verifier's existing validation pipeline. */
  readonly response: AuthorizationResponse;
  /** The verified JWE protected header — `alg`, `enc`, `kid`. */
  readonly header: Readonly<Record<string, unknown>>;
}

/**
 * Decrypt a `direct_post.jwt` Authorization Response.
 *
 * Reverses {@link encryptAuthorizationResponse}: imports the private
 * JWK, runs JWE compact-decrypt, JSON-parses the cleartext, validates
 * shape (vp_token present, PEX path carries presentation_submission),
 * and returns the {@link AuthorizationResponse}.
 *
 * The function enforces:
 *   - The JWE protected header `alg` is in the caller's allowlist
 *     (default `["ECDH-ES"]`).
 *   - The JWE protected header `enc` is in the caller's allowlist
 *     (default `["A256GCM"]`).
 *   - The cleartext is a JSON object (not an array, not bare string).
 *   - `vp_token` is present and is one of: string, string[], DCQL
 *     credential map.
 *   - PEX responses (string / string[]) carry `presentation_submission`;
 *     DCQL responses (object) need not.
 *
 * @throws {@link Oid4vpError} with codes
 *   `oid4vp.response_encryption_failed` (decryption / header rejection),
 *   `oid4vp.required_field_missing`, `oid4vp.invalid_value_type`,
 *   `oid4vp.malformed_body`, or `oid4vp.invalid_json`.
 */
export async function decryptAuthorizationResponse(
  options: DecryptAuthorizationResponseOptions,
): Promise<DecryptedAuthorizationResponse> {
  if (typeof options.jwe !== "string" || options.jwe.length === 0) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "decryptAuthorizationResponse: jwe is required",
    );
  }
  if (
    options.privateKey === null ||
    typeof options.privateKey !== "object"
  ) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      "decryptAuthorizationResponse: privateKey is required",
    );
  }

  const allowedAlgs = options.alg ?? [DEFAULT_RESPONSE_JWE_ALG];
  const allowedEncs = options.enc ?? [DEFAULT_RESPONSE_JWE_ENC];

  // Pre-flight header inspection — the JWE library will also reject
  // out-of-allowlist algs once we pass keyManagementAlgorithms /
  // contentEncryptionAlgorithms, but we want spec-quality errors with
  // our stable codes, so we look at the header explicitly first.
  const segments = options.jwe.split(".");
  if (segments.length !== 5) {
    throw new Oid4vpError(
      "oid4vp.malformed_body",
      "decryptAuthorizationResponse: malformed JWE (compact serialisation has 5 segments)",
    );
  }
  let header: Record<string, unknown>;
  try {
    const json = Buffer.from(segments[0]!, "base64url").toString("utf-8");
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("JWE header is not a JSON object");
    }
    header = parsed as Record<string, unknown>;
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.malformed_body",
      `decryptAuthorizationResponse: malformed JWE header: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const headerAlg = header["alg"];
  const headerEnc = header["enc"];
  if (
    typeof headerAlg !== "string" ||
    !(allowedAlgs as readonly string[]).includes(headerAlg)
  ) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      `decryptAuthorizationResponse: JWE alg ${JSON.stringify(
        headerAlg,
      )} is not in allowlist (${allowedAlgs.join(", ")})`,
    );
  }
  if (
    typeof headerEnc !== "string" ||
    !(allowedEncs as readonly string[]).includes(headerEnc)
  ) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      `decryptAuthorizationResponse: JWE enc ${JSON.stringify(
        headerEnc,
      )} is not in allowlist (${allowedEncs.join(", ")})`,
    );
  }

  let privateKey;
  try {
    privateKey = await importJWK(
      options.privateKey as Parameters<typeof importJWK>[0],
      headerAlg,
    );
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      `decryptAuthorizationResponse: failed to import private JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  let plaintextBytes: Uint8Array;
  try {
    const decrypted = await compactDecrypt(options.jwe, privateKey, {
      keyManagementAlgorithms: [...allowedAlgs],
      contentEncryptionAlgorithms: [...allowedEncs],
    });
    plaintextBytes = decrypted.plaintext;
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.response_encryption_failed",
      `decryptAuthorizationResponse: JWE decryption failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  let body: Record<string, unknown>;
  try {
    const json = new TextDecoder().decode(plaintextBytes);
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("response payload is not a JSON object");
    }
    body = parsed as Record<string, unknown>;
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.invalid_json",
      `decryptAuthorizationResponse: cleartext is not a JSON object: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  const response = parseJwtResponsePayload(body);
  return { response, header };
}

/** Convert the JWE cleartext (already parsed as a JSON object) into an
 * AuthorizationResponse. The shape constraints mirror those enforced
 * by `parseAuthorizationResponseFromParams` for the form-encoded path.
 */
function parseJwtResponsePayload(
  body: Record<string, unknown>,
): AuthorizationResponse {
  const vpTokenRaw = body["vp_token"];
  if (vpTokenRaw === undefined) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "Authorization Response is missing required parameter: vp_token",
    );
  }

  let vp_token: AuthorizationResponse["vp_token"];
  if (typeof vpTokenRaw === "string") {
    vp_token = vpTokenRaw;
  } else if (
    Array.isArray(vpTokenRaw) &&
    vpTokenRaw.every((v) => typeof v === "string")
  ) {
    vp_token = vpTokenRaw as readonly string[];
  } else if (
    vpTokenRaw !== null &&
    typeof vpTokenRaw === "object" &&
    !Array.isArray(vpTokenRaw)
  ) {
    // DCQL credential map — keys are credential ids. Some wallets wrap
    // each value in a single-element array (mirroring multi-instance
    // presentation futures); flatten to match the form-encoded path.
    const obj = vpTokenRaw as Record<string, unknown>;
    const flat: Record<string, string> = {};
    for (const [id, val] of Object.entries(obj)) {
      if (typeof val === "string") {
        flat[id] = val;
      } else if (
        Array.isArray(val) &&
        val.length === 1 &&
        typeof val[0] === "string"
      ) {
        flat[id] = val[0]!;
      } else {
        throw new Oid4vpError(
          "oid4vp.invalid_value_type",
          `vp_token[${id}] must be a string or single-element array of strings`,
        );
      }
    }
    vp_token = flat;
  } else {
    throw new Oid4vpError(
      "oid4vp.invalid_value_type",
      "vp_token must be a string, array of strings, or DCQL credential map",
    );
  }

  const isDcqlResponse =
    typeof vp_token === "object" && !Array.isArray(vp_token);

  let submission: Record<string, unknown> | undefined;
  const submissionRaw = body["presentation_submission"];
  if (submissionRaw !== undefined) {
    if (
      submissionRaw === null ||
      typeof submissionRaw !== "object" ||
      Array.isArray(submissionRaw)
    ) {
      throw new Oid4vpError(
        "oid4vp.malformed_submission",
        "presentation_submission must be a JSON object (DIF Presentation Exchange v2)",
      );
    }
    submission = submissionRaw as Record<string, unknown>;
  } else if (!isDcqlResponse) {
    throw new Oid4vpError(
      "oid4vp.required_field_missing",
      "Authorization Response is missing required parameter: presentation_submission",
    );
  }

  const result: AuthorizationResponse = { vp_token };
  if (submission !== undefined) result.presentation_submission = submission;
  const state = body["state"];
  if (typeof state === "string") result.state = state;
  const iss = body["iss"];
  if (typeof iss === "string") result.iss = iss;
  return result;
}

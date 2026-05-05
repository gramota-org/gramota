import { compactVerify, importJWK } from "jose";
import type { CompactVerifyResult } from "jose";
import {
  JoseError,
  type JsonWebKey,
  type SupportedAlg,
  type VerifiedJws,
  type VerifyJwsOptions,
} from "./types.js";

const ALL_ALGS: readonly SupportedAlg[] = [
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
];

/**
 * Verify a compact-serialised JWS against a public JWK.
 *
 * Hard rules (enforced before any crypto runs, so attackers can't smuggle
 * past via a body the crypto library accepts despite a malformed header):
 *  - `alg=none` is rejected unconditionally, regardless of the caller's
 *    allowlist.
 *  - The header `alg` MUST appear in `options.algorithms` (defaults to
 *    every IETF JOSE asymmetric algorithm).
 *  - The payload MUST decode to a JSON object — bare strings / arrays
 *    are rejected.
 *
 * @example
 * ```ts
 * const { header, payload, alg } = await verifyJws(jws, issuerJwk, {
 *   algorithms: ["ES256"], // narrow the allowlist
 * });
 * console.log(payload.iss);
 * ```
 *
 * @throws {@link JoseError} with stable codes:
 *   - `jose.invalid_input` — empty / non-string JWS
 *   - `jose.malformed_jws`, `jose.malformed_header` — pre-flight parse failures
 *   - `jose.alg_missing`, `jose.alg_none_disallowed`, `jose.alg_not_allowed`
 *   - `jose.key_import_failed` — JWK couldn't be imported for this alg
 *   - `jose.signature_invalid` — cryptographic verification failed
 *   - `jose.malformed_payload` — payload isn't a JSON object
 */
export async function verifyJws(
  jws: string,
  publicKey: JsonWebKey,
  options: VerifyJwsOptions = {},
): Promise<VerifiedJws> {
  if (typeof jws !== "string" || jws.length === 0) {
    throw new JoseError(
      "jose.invalid_input",
      "jws must be a non-empty string",
    );
  }

  const allowedAlgs = options.algorithms ?? ALL_ALGS;

  const alg = enforceHeaderRules(jws, allowedAlgs);

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(publicKey as Parameters<typeof importJWK>[0], alg);
  } catch (err) {
    throw new JoseError(
      "jose.key_import_failed",
      `failed to import public JWK: ${describe(err)}`,
    );
  }

  let result: CompactVerifyResult;
  try {
    result = await compactVerify(jws, key, {
      algorithms: [...allowedAlgs],
    });
  } catch (err) {
    throw new JoseError(
      "jose.signature_invalid",
      `signature verification failed: ${describe(err)}`,
    );
  }

  let payload: Record<string, unknown>;
  try {
    const json = new TextDecoder().decode(result.payload);
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("payload is not a JSON object");
    }
    payload = parsed as Record<string, unknown>;
  } catch (err) {
    throw new JoseError(
      "jose.malformed_payload",
      `invalid payload: ${describe(err)}`,
    );
  }

  return {
    header: result.protectedHeader as { alg: string; [key: string]: unknown },
    payload,
    alg: alg as SupportedAlg,
  };
}

function enforceHeaderRules(
  jws: string,
  allowedAlgs: readonly SupportedAlg[],
): string {
  const headerB64 = jws.split(".")[0];
  if (headerB64 === undefined || headerB64.length === 0) {
    throw new JoseError(
      "jose.malformed_jws",
      "malformed JWS: missing header segment",
    );
  }

  let header: unknown;
  try {
    const json = Buffer.from(headerB64, "base64url").toString("utf-8");
    header = JSON.parse(json);
  } catch {
    throw new JoseError(
      "jose.malformed_header",
      "malformed JWS header (not base64url JSON)",
    );
  }
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new JoseError(
      "jose.malformed_header",
      "JWS header must be a JSON object",
    );
  }

  const alg = (header as Record<string, unknown>)["alg"];
  if (typeof alg !== "string" || alg.length === 0) {
    throw new JoseError(
      "jose.alg_missing",
      "JWS header is missing alg",
    );
  }
  if (alg.toLowerCase() === "none") {
    throw new JoseError(
      "jose.alg_none_disallowed",
      "alg=none is never permitted, regardless of allowlist",
    );
  }
  if (!(allowedAlgs as readonly string[]).includes(alg)) {
    throw new JoseError(
      "jose.alg_not_allowed",
      `alg ${alg} is not in the allowlist (${allowedAlgs.join(", ")})`,
    );
  }
  return alg;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

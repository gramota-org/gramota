import { CompactSign, importJWK } from "jose";
import {
  JoseVerificationError,
  type JsonWebKey,
  type SupportedAlg,
} from "./types.js";

export interface SignJwsOptions {
  /** Algorithm to use. Must be in the supported set. */
  alg: SupportedAlg;
  /** Optional `typ` JOSE header (e.g. "kb+jwt", "vc+sd-jwt"). */
  typ?: string;
  /** Optional `kid` JOSE header. */
  kid?: string;
  /** Additional protected header parameters. Cannot override `alg`/`typ`/`kid`. */
  extraHeader?: Record<string, unknown>;
}

/**
 * Sign a payload as a compact-serialised JWS.
 *
 * Hard rules:
 *  - `alg=none` is impossible to request via this API: SupportedAlg never
 *    contains "none".
 *  - The provided `alg` is set in the protected header — `jose` will refuse
 *    to sign if the JWK can't perform that algorithm, so a typo is loud.
 */
export async function signJws(
  payload: Record<string, unknown>,
  privateKey: JsonWebKey,
  options: SignJwsOptions,
): Promise<string> {
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new JoseVerificationError(
      "jose.invalid_input",
      "payload must be a JSON object",
    );
  }
  if (
    typeof options.alg !== "string" ||
    options.alg.length === 0 ||
    options.alg.toLowerCase() === "none"
  ) {
    throw new JoseVerificationError(
      "jose.alg_none_disallowed",
      "alg is required and cannot be 'none'",
    );
  }

  const header: Record<string, unknown> = {
    ...options.extraHeader,
    alg: options.alg,
  };
  if (options.typ !== undefined) header["typ"] = options.typ;
  if (options.kid !== undefined) header["kid"] = options.kid;

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(
      privateKey as Parameters<typeof importJWK>[0],
      options.alg,
    );
  } catch (err) {
    throw new JoseVerificationError(
      "jose.key_import_failed",
      `failed to import private JWK: ${describe(err)}`,
    );
  }

  try {
    const encoded = new TextEncoder().encode(JSON.stringify(payload));
    return await new CompactSign(encoded)
      .setProtectedHeader(header as Parameters<CompactSign["setProtectedHeader"]>[0])
      .sign(key);
  } catch (err) {
    throw new JoseVerificationError(
      "jose.signing_failed",
      `signing failed: ${describe(err)}`,
    );
  }
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

import { compactVerify, importJWK } from "jose";
import type { CompactVerifyResult } from "jose";
import {
  JoseVerificationError,
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
 * Hard rules:
 *  - `alg=none` is rejected unconditionally — even if the caller's allowlist
 *    were to contain it.
 *  - The header `alg` must appear in the allowlist (default: every IETF JOSE
 *    asymmetric algorithm).
 *  - We pre-flight-parse the header to enforce these rules *before* importing
 *    the key or invoking crypto, so an attacker can't sneak past us by
 *    crafting a malformed body that the crypto library happens to accept.
 */
export async function verifyJws(
  jws: string,
  publicKey: JsonWebKey,
  options: VerifyJwsOptions = {},
): Promise<VerifiedJws> {
  if (typeof jws !== "string" || jws.length === 0) {
    throw new JoseVerificationError("jws must be a non-empty string");
  }

  const allowedAlgs = options.algorithms ?? ALL_ALGS;

  const alg = enforceHeaderRules(jws, allowedAlgs);

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(publicKey as Parameters<typeof importJWK>[0], alg);
  } catch (err) {
    throw new JoseVerificationError(
      `failed to import public JWK: ${describe(err)}`,
    );
  }

  let result: CompactVerifyResult;
  try {
    result = await compactVerify(jws, key, {
      algorithms: [...allowedAlgs],
    });
  } catch (err) {
    throw new JoseVerificationError(
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
    throw new JoseVerificationError(`invalid payload: ${describe(err)}`);
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
    throw new JoseVerificationError("malformed JWS: missing header segment");
  }

  let header: unknown;
  try {
    const json = Buffer.from(headerB64, "base64url").toString("utf-8");
    header = JSON.parse(json);
  } catch {
    throw new JoseVerificationError("malformed JWS header (not base64url JSON)");
  }
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new JoseVerificationError("JWS header must be a JSON object");
  }

  const alg = (header as Record<string, unknown>)["alg"];
  if (typeof alg !== "string" || alg.length === 0) {
    throw new JoseVerificationError("JWS header is missing alg");
  }
  if (alg.toLowerCase() === "none") {
    throw new JoseVerificationError(
      "alg=none is never permitted, regardless of allowlist",
    );
  }
  if (!(allowedAlgs as readonly string[]).includes(alg)) {
    throw new JoseVerificationError(
      `alg ${alg} is not in the allowlist (${allowedAlgs.join(", ")})`,
    );
  }
  return alg;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

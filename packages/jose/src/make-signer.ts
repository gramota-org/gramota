import { CompactSign, importJWK } from "jose";
import {
  JoseVerificationError,
  type JsonWebKey,
  type SupportedAlg,
} from "./types.js";

/**
 * Build a signer compatible with `@gateway/sd-jwt`'s `issueSdJwt` `signer`
 * field — takes `header.payload` and returns just the base64url signature.
 *
 * This is the bridge between @gateway/jose (which signs full JWS strings)
 * and @gateway/sd-jwt (which composes its own header/payload and only needs
 * the signature back).
 */
export async function makeSigner(
  privateKey: JsonWebKey,
  alg: SupportedAlg,
): Promise<(signedPayload: string) => Promise<string>> {
  if (
    typeof alg !== "string" ||
    alg.length === 0 ||
    alg.toLowerCase() === "none"
  ) {
    throw new JoseVerificationError("makeSigner: alg is required and cannot be 'none'");
  }
  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    key = await importJWK(privateKey as Parameters<typeof importJWK>[0], alg);
  } catch (err) {
    throw new JoseVerificationError(
      `makeSigner: failed to import private JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  return async (signedPayload: string): Promise<string> => {
    const parts = signedPayload.split(".");
    if (parts.length !== 2) {
      throw new JoseVerificationError(
        "makeSigner: signedPayload must be 'header.payload' (two segments)",
      );
    }
    const [headerB64, payloadB64] = parts as [string, string];
    let header: unknown;
    try {
      header = JSON.parse(
        Buffer.from(headerB64, "base64url").toString("utf-8"),
      );
    } catch {
      throw new JoseVerificationError(
        "makeSigner: header is not valid base64url JSON",
      );
    }
    const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");

    const fullJws = await new CompactSign(
      new TextEncoder().encode(payloadJson),
    )
      .setProtectedHeader(
        header as Parameters<CompactSign["setProtectedHeader"]>[0],
      )
      .sign(key);

    const sigParts = fullJws.split(".");
    if (sigParts.length !== 3) {
      throw new JoseVerificationError(
        "makeSigner: jose returned a malformed compact JWS",
      );
    }
    return sigParts[2]!;
  };
}

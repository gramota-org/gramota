import { randomUUID } from "node:crypto";
import {
  parseSdJwt,
  verifyHashBinding,
  type ParsedSdJwt,
} from "@gramota/sd-jwt";
import {
  verifyJws,
  JoseError,
  type Signer,
} from "@gramota/jose";
import { publicJwksEqual } from "./jwk-equal.js";
import {
  HolderError,
  type CredentialStore,
  type ReceiveOptions,
  type StoredCredential,
} from "./types.js";

/**
 * Receive and validate an issued credential per IETF SD-JWT §5.1.
 *
 * Holder-side validation steps:
 *   1. Parse the compact serialisation.
 *   2. Verify the issuer JWS against at least one trusted issuer key.
 *   3. Verify hash binding — every disclosure must match an `_sd` digest.
 *   4. Verify cnf.jwk equals the holder's own public key (not someone else's).
 *
 * Only after all four pass do we persist.
 */
export async function receiveCredential(
  token: string,
  signer: Signer,
  store: CredentialStore,
  options: ReceiveOptions,
): Promise<StoredCredential> {
  // 1. Parse
  let parsed: ParsedSdJwt;
  try {
    parsed = parseSdJwt(token);
  } catch (err) {
    throw new HolderError(
      "holder.malformed_token",
      `cannot receive credential — token is malformed: ${describe(err)}`,
    );
  }

  // 2. Verify issuer JWS against the trusted set
  if (
    !Array.isArray(options.trustedIssuers) ||
    options.trustedIssuers.length === 0
  ) {
    throw new HolderError("holder.no_trusted_issuers", "at least one trustedIssuer is required");
  }
  let verifiedAgainstAny = false;
  let lastError: unknown;
  for (const issuerKey of options.trustedIssuers) {
    try {
      await verifyJws(
        `${parsed.signedPayload}.${parsed.signature}`,
        issuerKey,
      );
      verifiedAgainstAny = true;
      break;
    } catch (err) {
      lastError = err;
    }
  }
  if (!verifiedAgainstAny) {
    const detail = lastError instanceof JoseError ? lastError.message : "no match";
    throw new HolderError(
      "holder.issuer_signature_invalid",
      `issuer signature did not verify against any trusted key: ${detail}`,
    );
  }

  // 3. Hash binding — disclosures must match _sd digests
  const verified = verifyHashBinding(parsed);
  if (verified.unmatchedDisclosures.length > 0) {
    const names = verified.unmatchedDisclosures
      .map((d) => d.name ?? "<array element>")
      .join(", ");
    throw new HolderError(
      "holder.disclosure_forged",
      `credential contains forged disclosures: ${names}`,
    );
  }

  // 4. cnf.jwk must equal the holder's public key
  const cnf = parsed.payload["cnf"];
  if (cnf === null || typeof cnf !== "object" || Array.isArray(cnf)) {
    throw new HolderError(
      "holder.cnf_missing",
      "credential has no cnf claim — cannot bind to this holder",
    );
  }
  const cnfJwk = (cnf as Record<string, unknown>)["jwk"];
  if (!publicJwksEqual(cnfJwk, signer.publicKey)) {
    throw new HolderError(
      "holder.cnf_mismatch",
      "credential cnf.jwk does not match this holder's public key — credential was issued to a different holder",
    );
  }

  // 5. Persist
  const stored: StoredCredential = {
    id: randomUUID(),
    token,
    parsed,
    issuer:
      typeof parsed.payload["iss"] === "string"
        ? parsed.payload["iss"]
        : "<unknown>",
    receivedAt: Math.floor(Date.now() / 1000),
  };
  await store.add(stored);
  return stored;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

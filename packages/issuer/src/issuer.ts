import { randomUUID } from "node:crypto";
import { issueSdJwt, type HashAlg } from "@gateway/sd-jwt";
import { makeSigner } from "@gateway/jose";
import {
  IssuerError,
  type IssueOptions,
  type IssueResult,
  type IssuerConfig,
} from "./types.js";

const DEFAULT_TYP = "vc+sd-jwt";
const DEFAULT_HASH_ALG: HashAlg = "sha-256";

/**
 * The issuer role per IETF SD-JWT-VC §3.
 *
 * Wraps `issueSdJwt` (the low-level primitive in `@gateway/sd-jwt`) with:
 *   - stateful config (key, alg, issuer id, optional kid),
 *   - holder-binding (cnf.jwk),
 *   - sensible expiry handling (`expiresIn` or `expiresAt`),
 *   - validation: every claim listed in `selectivelyDisclosable` must
 *     appear in `subject`,
 *   - JOSE signing via `@gateway/jose.makeSigner` (no direct `jose` dep
 *     here — Dependency Inversion against the jose library).
 */
export class Issuer {
  private readonly config: Required<
    Pick<IssuerConfig, "privateKey" | "publicKey" | "alg" | "issuerId">
  > &
    Pick<IssuerConfig, "kid" | "typ" | "hashAlg">;

  constructor(config: IssuerConfig) {
    if (config.privateKey === null || typeof config.privateKey !== "object") {
      throw new TypeError("Issuer: privateKey is required (a JsonWebKey)");
    }
    if (config.publicKey === null || typeof config.publicKey !== "object") {
      throw new TypeError("Issuer: publicKey is required (a JsonWebKey)");
    }
    if (typeof config.alg !== "string" || config.alg.length === 0) {
      throw new TypeError("Issuer: alg is required");
    }
    if (typeof config.issuerId !== "string" || config.issuerId.length === 0) {
      throw new TypeError("Issuer: issuerId is required (a stable URL)");
    }
    this.config = {
      privateKey: config.privateKey,
      publicKey: config.publicKey,
      alg: config.alg,
      issuerId: config.issuerId,
    };
    if (config.kid !== undefined) this.config.kid = config.kid;
    if (config.typ !== undefined) this.config.typ = config.typ;
    if (config.hashAlg !== undefined) this.config.hashAlg = config.hashAlg;
  }

  /** Issue a single SD-JWT-VC credential bound to a holder. */
  async issue(options: IssueOptions): Promise<IssueResult> {
    validate(options);

    const issuedAt = options.issuedAt ?? Math.floor(Date.now() / 1000);
    const expiresAt = computeExpiry(options, issuedAt);
    const credentialId = options.credentialId ?? randomUUID();

    // Split subject claims: SD ones become `sdClaims`, the rest are inlined
    // directly in the JWT payload.
    const sdNames = new Set(options.selectivelyDisclosable ?? []);
    const sdClaims: Record<string, unknown> = {};
    const directClaims: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(options.subject)) {
      if (sdNames.has(k)) sdClaims[k] = v;
      else directClaims[k] = v;
    }

    const payload: Record<string, unknown> = {
      iss: this.config.issuerId,
      iat: issuedAt,
      vct: options.vct,
      cnf: { jwk: options.holderKey },
      ...directClaims,
    };
    if (expiresAt !== undefined) payload["exp"] = expiresAt;
    if (options.notBefore !== undefined) payload["nbf"] = options.notBefore;
    if (options.status !== undefined) payload["status"] = options.status;

    const signer = await makeSigner(this.config.privateKey, this.config.alg);

    const issueOpts: Parameters<typeof issueSdJwt>[0] = {
      payload,
      sdClaims,
      alg: this.config.alg,
      typ: this.config.typ ?? DEFAULT_TYP,
      signer,
      hashAlg: this.config.hashAlg ?? DEFAULT_HASH_ALG,
    };
    if (this.config.kid !== undefined) {
      issueOpts.extraHeader = { kid: this.config.kid };
    }

    const result = await issueSdJwt(issueOpts);

    return {
      token: result.token,
      credentialId,
      disclosures: result.disclosures,
      expiresAt,
    };
  }

  /** The issuer's public JWK — useful to publish at /.well-known/jwks.json. */
  get publicKey(): IssuerConfig["publicKey"] {
    return this.config.publicKey;
  }

  /** The issuer's identifier — useful for downstream URLs. */
  get issuerId(): string {
    return this.config.issuerId;
  }
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

function validate(options: IssueOptions): void {
  if (
    options.subject === null ||
    typeof options.subject !== "object" ||
    Array.isArray(options.subject)
  ) {
    throw new IssuerError("issuer.subject_invalid", "issue: subject must be a non-null object");
  }
  if (options.holderKey === null || typeof options.holderKey !== "object") {
    throw new IssuerError("issuer.holder_key_required", "issue: holderKey is required (a JsonWebKey)");
  }
  if (typeof options.vct !== "string" || options.vct.length === 0) {
    throw new IssuerError(
      "issuer.vct_required",
      "issue: vct is required per IETF SD-JWT-VC §3.2.2.1",
    );
  }
  if (options.expiresIn !== undefined && options.expiresAt !== undefined) {
    throw new IssuerError(
      "issuer.expiry_conflict",
      "issue: expiresIn and expiresAt are mutually exclusive",
    );
  }
  if (options.selectivelyDisclosable !== undefined) {
    for (const name of options.selectivelyDisclosable) {
      if (!Object.prototype.hasOwnProperty.call(options.subject, name)) {
        throw new IssuerError(
          "issuer.disclosable_missing",
          `issue: selectively disclosable claim '${name}' is not present in subject`,
        );
      }
    }
  }
  // Reserved payload claims must NOT come from the subject.
  for (const reserved of ["iss", "iat", "exp", "nbf", "cnf", "vct", "status"]) {
    if (Object.prototype.hasOwnProperty.call(options.subject, reserved)) {
      throw new IssuerError(
        "issuer.reserved_claim_in_subject",
        `issue: subject must not contain reserved JWT claim '${reserved}' — pass via options instead`,
      );
    }
  }
}

function computeExpiry(
  options: IssueOptions,
  issuedAt: number,
): number | undefined {
  if (options.expiresAt !== undefined) {
    if (options.expiresAt <= issuedAt) {
      throw new IssuerError(
        "issuer.expiry_invalid",
        `issue: expiresAt (${options.expiresAt}) must be > issuedAt (${issuedAt})`,
      );
    }
    return options.expiresAt;
  }
  if (options.expiresIn !== undefined) {
    if (options.expiresIn <= 0) {
      throw new IssuerError("issuer.expiry_invalid", "issue: expiresIn must be > 0 seconds");
    }
    return issuedAt + options.expiresIn;
  }
  return undefined;
}

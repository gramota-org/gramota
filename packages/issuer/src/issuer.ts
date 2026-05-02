import { randomUUID } from "node:crypto";
import { issueSdJwt, type HashAlg } from "@gramota/sd-jwt";
import { asSigner, type JsonWebKey, type Signer } from "@gramota/jose";
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
 * Wraps `issueSdJwt` (the low-level primitive in `@gramota/sd-jwt`) with:
 *   - stateful config (signer, issuer id, optional kid/typ/hashAlg),
 *   - holder-binding (cnf.jwk),
 *   - sensible expiry handling (`expiresIn` or `expiresAt`),
 *   - validation: every claim listed in `selectivelyDisclosable` must
 *     appear in `subject`,
 *   - {@link Signer} Strategy for signing — accepts raw JWKs (shorthand)
 *     or production-grade Signers (HSM, KMS, custom backends).
 */
export class Issuer {
  /** The issuer's signer. Either supplied directly via `config.signer`
   * (production: HSM/KMS) or built from raw JWKs via {@link asSigner}. */
  private readonly signer: Signer;
  /** Stable issuer id (`iss` claim). */
  private readonly issuerIdValue: string;
  private readonly kid: string | undefined;
  private readonly typ: string | undefined;
  private readonly hashAlg: HashAlg | undefined;

  constructor(config: IssuerConfig) {
    if (typeof config.issuerId !== "string" || config.issuerId.length === 0) {
      throw new TypeError("Issuer: issuerId is required (a stable URL)");
    }
    this.signer = normalizeIssuerSigner(config);
    this.issuerIdValue = config.issuerId;
    this.kid = config.kid;
    this.typ = config.typ;
    this.hashAlg = config.hashAlg;
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
      iss: this.issuerIdValue,
      iat: issuedAt,
      vct: options.vct,
      cnf: { jwk: options.holderKey },
      ...directClaims,
    };
    if (expiresAt !== undefined) payload["exp"] = expiresAt;
    if (options.notBefore !== undefined) payload["nbf"] = options.notBefore;
    if (options.status !== undefined) payload["status"] = options.status;

    // Adapt the Signer to issueSdJwt's `signer: (s) => Promise<sig>` shape.
    const signFn = (signedPayload: string): Promise<string> =>
      this.signer.sign(signedPayload);

    const issueOpts: Parameters<typeof issueSdJwt>[0] = {
      payload,
      sdClaims,
      alg: this.signer.alg,
      typ: this.typ ?? DEFAULT_TYP,
      signer: signFn,
      hashAlg: this.hashAlg ?? DEFAULT_HASH_ALG,
    };
    if (this.kid !== undefined) {
      issueOpts.extraHeader = { kid: this.kid };
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
  get publicKey(): JsonWebKey {
    return this.signer.publicKey;
  }

  /** The issuer's identifier — useful for downstream URLs. */
  get issuerId(): string {
    return this.issuerIdValue;
  }
}

/**
 * Normalize the Issuer config into a Signer (raw JWKs OR Signer).
 */
function normalizeIssuerSigner(config: IssuerConfig): Signer {
  if (
    "signer" in config &&
    config.signer !== undefined &&
    typeof (config.signer as Signer).sign === "function"
  ) {
    return config.signer;
  }
  if (
    "privateKey" in config &&
    "publicKey" in config &&
    "alg" in config &&
    config.privateKey !== null &&
    typeof config.privateKey === "object" &&
    config.publicKey !== null &&
    typeof config.publicKey === "object" &&
    typeof config.alg === "string" &&
    config.alg.length > 0
  ) {
    return asSigner({
      publicKey: config.publicKey,
      privateKey: config.privateKey,
      alg: config.alg,
    });
  }
  throw new TypeError(
    "Issuer: pass either { privateKey, publicKey, alg } (raw shorthand) or { signer } (production)",
  );
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

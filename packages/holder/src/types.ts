import type { JsonWebKey, SupportedAlg } from "@gateway/jose";
import type { ParsedSdJwt } from "@gateway/sd-jwt";

/** Identifier of a stored credential. UUID v4, generated at receive time. */
export type CredentialId = string;

/** A credential the holder has received and validated. */
export interface StoredCredential {
  id: CredentialId;
  /** The original compact-serialised SD-JWT-VC issuance token. */
  token: string;
  /** Pre-parsed view; pre-computed for faster queries. */
  parsed: ParsedSdJwt;
  /** Issuer identifier, copied out of `iss` for indexed access. */
  issuer: string;
  /** Unix seconds of when the holder accepted this credential. */
  receivedAt: number;
}

/** Optional filter when listing stored credentials. */
export interface CredentialQuery {
  issuer?: string;
  /** Match credentials that contain a given selectively-disclosable claim. */
  withClaim?: string;
}

/**
 * Persistence boundary (Strategy + Repository pattern).
 *
 * Implementations are interchangeable — `Holder` depends only on this
 * interface (Dependency Inversion). Default: `InMemoryCredentialStore`.
 *
 * Future implementations: `FileCredentialStore`, `EncryptedCredentialStore`,
 * `IndexedDBCredentialStore` (browser).
 */
export interface CredentialStore {
  add(credential: StoredCredential): Promise<void>;
  get(id: CredentialId): Promise<StoredCredential | undefined>;
  list(query?: CredentialQuery): Promise<readonly StoredCredential[]>;
  remove(id: CredentialId): Promise<boolean>;
}

/** Configuration for a Holder instance. */
export interface HolderConfig {
  /** Holder's PRIVATE JWK. Used to sign Key Binding JWTs. Public part must
   * match `cnf.jwk` of received credentials. */
  privateKey: JsonWebKey;
  /** Holder's PUBLIC JWK. Used to validate `cnf.jwk` matches at receive time
   * and to inform issuers (out of band) what to bind credentials to. */
  publicKey: JsonWebKey;
  /** JWS algorithm. Must be compatible with the key. */
  alg: SupportedAlg;
  /** Storage backend. Default: in-memory (lost on process exit). */
  store?: CredentialStore;
}

export interface ReceiveOptions {
  /** Public JWKs of issuers the holder trusts. The credential's signature
   * must verify against at least one. */
  trustedIssuers: readonly JsonWebKey[];
}

export interface PresentOptions {
  credentialId: CredentialId;
  /** Names of object claims to selectively disclose. All must be available
   * in the credential. To disclose nothing, pass `[]`. */
  disclose: readonly string[];
  /** Verifier identifier — bound into the KB-JWT's `aud` claim. */
  audience: string;
  /** Verifier challenge — bound into the KB-JWT's `nonce` claim. */
  nonce: string;
  /** Override "now" — for tests. */
  now?: () => number;
}

export class HolderError extends Error {
  override readonly name = "HolderError";
}

import { receiveCredential } from "./receive.js";
import { buildPresentation } from "./present.js";
import { InMemoryCredentialStore } from "./store/memory.js";
import {
  HolderError,
  type CredentialId,
  type CredentialQuery,
  type CredentialStore,
  type HolderConfig,
  type PresentOptions,
  type ReceiveOptions,
  type StoredCredential,
} from "./types.js";

/**
 * The holder/wallet role in IETF SD-JWT-VC §6.
 *
 * Composes a key (holder's binding key) with a credential store (Strategy
 * pattern). The class is a thin orchestrator; the heavy lifting lives in
 * pure functions (receive, buildPresentation) that don't need an instance —
 * easier to test, easier to reuse without classes.
 */
export class Holder {
  private readonly config: HolderConfig;
  private readonly store: CredentialStore;

  constructor(config: HolderConfig) {
    if (config.privateKey === null || typeof config.privateKey !== "object") {
      throw new TypeError("Holder: privateKey is required");
    }
    if (config.publicKey === null || typeof config.publicKey !== "object") {
      throw new TypeError("Holder: publicKey is required");
    }
    if (typeof config.alg !== "string" || config.alg.length === 0) {
      throw new TypeError("Holder: alg is required");
    }
    this.config = config;
    this.store = config.store ?? new InMemoryCredentialStore();
  }

  /** Validate and store an issued SD-JWT-VC. Returns the stored credential. */
  receive(
    token: string,
    options: ReceiveOptions,
  ): Promise<StoredCredential> {
    return receiveCredential(token, this.config, this.store, options);
  }

  /** Build a selective-disclosure presentation against a stored credential. */
  present(options: PresentOptions): Promise<string> {
    return buildPresentation(this.config, this.store, options);
  }

  /** Get a single stored credential by id. */
  get(id: CredentialId): Promise<StoredCredential | undefined> {
    return this.store.get(id);
  }

  /** List stored credentials, optionally filtered. */
  list(query?: CredentialQuery): Promise<readonly StoredCredential[]> {
    return this.store.list(query);
  }

  /** Remove a stored credential. Returns true if it existed. */
  remove(id: CredentialId): Promise<boolean> {
    return this.store.remove(id);
  }

  /** Public key — useful to share with issuers so they can bind credentials. */
  get publicKey(): HolderConfig["publicKey"] {
    return this.config.publicKey;
  }
}

export { HolderError };

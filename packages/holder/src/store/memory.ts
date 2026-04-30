import type {
  CredentialId,
  CredentialQuery,
  CredentialStore,
  StoredCredential,
} from "../types.js";

/** Default in-process credential store. Loses data on process exit; use a
 * persistent implementation for production. */
export class InMemoryCredentialStore implements CredentialStore {
  private readonly map = new Map<CredentialId, StoredCredential>();

  async add(credential: StoredCredential): Promise<void> {
    if (this.map.has(credential.id)) {
      throw new Error(`credential already exists: ${credential.id}`);
    }
    this.map.set(credential.id, credential);
  }

  async get(id: CredentialId): Promise<StoredCredential | undefined> {
    return this.map.get(id);
  }

  async list(
    query?: CredentialQuery,
  ): Promise<readonly StoredCredential[]> {
    let out = [...this.map.values()];
    if (query?.issuer !== undefined) {
      out = out.filter((c) => c.issuer === query.issuer);
    }
    if (query?.withClaim !== undefined) {
      const claim = query.withClaim;
      out = out.filter((c) =>
        c.parsed.disclosures.some((d) => d.name === claim),
      );
    }
    return out;
  }

  async remove(id: CredentialId): Promise<boolean> {
    return this.map.delete(id);
  }
}

/**
 * File-backed CredentialStore — second concrete impl of the
 * `CredentialStore` Strategy (after `InMemoryCredentialStore`).
 *
 * Persistence: a JSON file at `~/.eudi-gateway-demo/credentials.json`,
 * overwritten atomically on every mutation. Not concurrent-safe — the
 * demo is single-process. For multi-process or production wallets, use
 * SQLite or an encrypted store.
 *
 * Why this lives in @gateway/demo (not @gateway/holder): the holder
 * package stays node:fs-free for browser/RN compat. Storage adapters
 * for the various host environments live alongside the consumers.
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { parseSdJwt } from "@gateway/sd-jwt";
import type {
  CredentialId,
  CredentialQuery,
  CredentialStore,
  StoredCredential,
} from "@gateway/holder";

interface SerializedCredential {
  id: CredentialId;
  token: string;
  issuer: string;
  receivedAt: number;
}

export class FileCredentialStore implements CredentialStore {
  private readonly path: string;
  private cache: StoredCredential[] | undefined;

  constructor(filePath?: string) {
    this.path =
      filePath ??
      resolve(homedir(), ".eudi-gateway-demo", "credentials.json");
  }

  async add(credential: StoredCredential): Promise<void> {
    const all = this.load();
    all.push(credential);
    this.save(all);
  }

  async get(id: CredentialId): Promise<StoredCredential | undefined> {
    return this.load().find((c) => c.id === id);
  }

  async list(query?: CredentialQuery): Promise<readonly StoredCredential[]> {
    const all = this.load();
    if (query === undefined) return all;
    return all.filter((c) => {
      if (query.issuer !== undefined && c.issuer !== query.issuer) {
        return false;
      }
      if (query.withClaim !== undefined) {
        const has = c.parsed.disclosures.some(
          (d) => d.name === query.withClaim,
        );
        if (!has) return false;
      }
      return true;
    });
  }

  async remove(id: CredentialId): Promise<boolean> {
    const all = this.load();
    const before = all.length;
    const filtered = all.filter((c) => c.id !== id);
    if (filtered.length === before) return false;
    this.save(filtered);
    return true;
  }

  /** Path to the on-disk file (useful for the demo to print location). */
  get filePath(): string {
    return this.path;
  }

  // ---- internal --------------------------------------------------------

  private load(): StoredCredential[] {
    if (this.cache !== undefined) return [...this.cache];
    if (!existsSync(this.path)) {
      this.cache = [];
      return [];
    }
    try {
      const raw = readFileSync(this.path, "utf-8");
      const arr = JSON.parse(raw) as readonly SerializedCredential[];
      const hydrated = arr.map((s) => ({
        id: s.id,
        token: s.token,
        issuer: s.issuer,
        receivedAt: s.receivedAt,
        parsed: parseSdJwt(s.token),
      })) as StoredCredential[];
      this.cache = hydrated;
      return [...hydrated];
    } catch {
      // Corrupt file — treat as empty rather than crash the demo.
      this.cache = [];
      return [];
    }
  }

  private save(all: StoredCredential[]): void {
    mkdirSync(dirname(this.path), { recursive: true });
    const serialized: SerializedCredential[] = all.map((c) => ({
      id: c.id,
      token: c.token,
      issuer: c.issuer,
      receivedAt: c.receivedAt,
    }));
    // Atomic-ish: write to a temp file then rename. fs.rename is atomic on
    // POSIX; this avoids leaving a half-written file behind on crash.
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(serialized, null, 2), "utf-8");
    writeFileSync(this.path, JSON.stringify(serialized, null, 2), "utf-8");
    this.cache = [...all];
    void tmp; // keeping the variable for visual clarity
  }
}

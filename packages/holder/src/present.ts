import { buildKeyBindingJwt } from "@gateway/sd-jwt";
import {
  HolderError,
  type CredentialStore,
  type HolderConfig,
  type PresentOptions,
  type StoredCredential,
} from "./types.js";

/**
 * Build a presentation per IETF SD-JWT §5.2 + §4.3 (KB-JWT).
 *
 * The flow:
 *   1. Look up the stored credential.
 *   2. Validate the requested disclosures are all selectively disclosable.
 *   3. Reconstruct the issuer JWS unchanged (we never re-sign issuer claims).
 *   4. Build the presentation prefix: `<issuer-jws>~<d1>~...~<dN>~`.
 *   5. Sign a Key Binding JWT over (aud, nonce, iat, sd_hash) using the
 *      holder's private key — the same key whose public is bound in cnf.
 *   6. Concatenate prefix + KB-JWT.
 */
export async function buildPresentation(
  config: HolderConfig,
  store: CredentialStore,
  options: PresentOptions,
): Promise<string> {
  if (typeof options.credentialId !== "string" || options.credentialId.length === 0) {
    throw new HolderError("credentialId is required");
  }
  if (typeof options.audience !== "string" || options.audience.length === 0) {
    throw new HolderError("audience is required");
  }
  if (typeof options.nonce !== "string" || options.nonce.length === 0) {
    throw new HolderError("nonce is required");
  }
  if (!Array.isArray(options.disclose)) {
    throw new HolderError("disclose must be an array of claim names");
  }

  // 1. Look up
  const stored = await store.get(options.credentialId);
  if (stored === undefined) {
    throw new HolderError(`credential not found: ${options.credentialId}`);
  }

  // 2. Validate every requested disclosure is available
  const availableByName = new Map(
    stored.parsed.disclosures
      .filter((d) => d.name !== null)
      .map((d) => [d.name as string, d]),
  );
  const selected: typeof stored.parsed.disclosures = [];
  for (const name of options.disclose) {
    const disc = availableByName.get(name);
    if (disc === undefined) {
      throw new HolderError(
        `requested disclosure '${name}' is not available in credential ${stored.id}`,
      );
    }
    selected.push(disc);
  }

  // 3. Reconstruct the issuer JWS — bytes-identical to what the issuer signed
  const issuerJws = `${stored.parsed.signedPayload}.${stored.parsed.signature}`;

  // 4. Build the presentation prefix per spec — always ends with `~`
  const presentationPrefix =
    issuerJws + "~" + selected.map((d) => d.raw + "~").join("");

  // 5. Sign the KB-JWT
  const kbOpts: Parameters<typeof buildKeyBindingJwt>[1] = {
    aud: options.audience,
    nonce: options.nonce,
    alg: config.alg,
    privateKey: config.privateKey,
  };
  if (options.now !== undefined) {
    kbOpts.iat = options.now();
  }

  const kbJwt = await buildKeyBindingJwt(presentationPrefix, kbOpts);

  // 6. Concatenate
  return `${presentationPrefix}${kbJwt}`;
}

/** Helper for callers that need the in-memory shape directly. */
export function getStoredCredential(
  store: CredentialStore,
  id: string,
): Promise<StoredCredential | undefined> {
  return store.get(id);
}

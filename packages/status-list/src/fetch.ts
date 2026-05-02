import { verifyJws, type JsonWebKey } from "@gramota/jose";
import { parseStatusListToken } from "./parse.js";
import { StatusListError, type StatusList } from "./types.js";

export type Fetcher = (
  url: string,
  init?: RequestInit,
) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
}>;

export interface FetchStatusListOptions {
  /** Override fetch — for tests. */
  fetcher?: Fetcher;
  /** Trusted issuer JWKs the list's signature must verify against. If
   * omitted, the list is parsed but its signature is NOT checked. */
  trustedIssuers?: readonly JsonWebKey[];
  /** Override "now" — for expiry checks. Defaults to system time. */
  now?: () => number;
}

/**
 * Fetch a status list from `url`, optionally verify its JWS signature
 * against `trustedIssuers`, and return the parsed list.
 *
 * Per the IETF spec, the list's `sub` claim MUST equal the URL it was
 * fetched from — we enforce this so a stolen list can't be presented
 * for a different URL.
 */
export async function fetchStatusList(
  url: string,
  options: FetchStatusListOptions = {},
): Promise<StatusList> {
  if (typeof url !== "string" || url.length === 0) {
    throw new StatusListError(
      "status_list.invalid_input",
      "fetchStatusList: url is required",
    );
  }

  const fetcher = options.fetcher ?? defaultFetcher;
  let response: Awaited<ReturnType<Fetcher>>;
  try {
    response = await fetcher(url, {
      headers: {
        Accept: "application/statuslist+jwt, application/jwt",
      },
    });
  } catch (err) {
    throw new StatusListError(
      "status_list.fetch_failed",
      `failed to fetch ${url}: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!response.ok) {
    throw new StatusListError(
      "status_list.fetch_failed",
      `${url} returned HTTP ${response.status}`,
    );
  }

  const token = (await response.text()).trim();
  const list = parseStatusListToken(token);

  // Optional signature verification (skipped if no trustedIssuers passed —
  // useful for diagnostic / inspection paths but the production verifier
  // path always passes them).
  if (
    Array.isArray(options.trustedIssuers) &&
    options.trustedIssuers.length > 0
  ) {
    let verified = false;
    let lastError: unknown;
    for (const key of options.trustedIssuers) {
      try {
        await verifyJws(token, key);
        verified = true;
        break;
      } catch (err) {
        lastError = err;
      }
    }
    if (!verified) {
      throw new StatusListError(
        "status_list.signature_invalid",
        `status list signature did not verify against any trusted key: ${
          lastError instanceof Error ? lastError.message : "no match"
        }`,
      );
    }
  }

  // The `sub` claim binds the list to its URL — without this check, an
  // attacker could substitute a benign list at a malicious URL.
  if (list.subject !== url) {
    throw new StatusListError(
      "status_list.subject_mismatch",
      `status list 'sub' (${list.subject}) does not match fetched URL (${url})`,
    );
  }

  // Expiry check — if the list says it's expired, refuse to use it.
  if (list.expiresAt !== undefined) {
    const now = (options.now ?? defaultNow)();
    if (now > list.expiresAt) {
      throw new StatusListError(
        "status_list.expired",
        `status list expired at ${list.expiresAt} (now=${now})`,
      );
    }
  }

  return list;
}

const defaultFetcher: Fetcher = (url, init) =>
  fetch(url, init).then((r) => ({
    ok: r.ok,
    status: r.status,
    text: () => r.text(),
  }));

function defaultNow(): number {
  return Math.floor(Date.now() / 1000);
}

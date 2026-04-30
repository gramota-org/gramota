import {
  DcqlError,
  type DcqlCredentialQuery,
  type DcqlQuery,
} from "./types.js";
import { validateDcqlPath } from "./path.js";
import {
  DcqlSdJwtVcMatcher,
  type DcqlMatchResult,
} from "./sd-jwt-vc-matcher.js";

export interface DcqlMatcher<TCredential> {
  formats: readonly string[];
  match(
    credential: TCredential,
    query: DcqlCredentialQuery,
  ): DcqlMatchResult | null;
}

export interface DcqlSelectInput<TCredential> {
  query: DcqlQuery;
  credentials: readonly TCredential[];
  /** Strategy: zero or more matchers, dispatched by format. Default: SD-JWT-VC. */
  matchers?: readonly DcqlMatcher<TCredential>[];
  /** Picker when multiple credentials satisfy a query. Default: first match. */
  pickCredential?: (
    candidates: readonly {
      credential: TCredential;
      result: DcqlMatchResult;
    }[],
  ) => { credential: TCredential; result: DcqlMatchResult };
}

export interface DcqlSelectionMatch<TCredential> {
  query: DcqlCredentialQuery;
  credential: TCredential;
  disclose: readonly string[];
  result: DcqlMatchResult;
}

export interface DcqlSelectionFailure {
  query: DcqlCredentialQuery;
  reason: string;
}

export interface DcqlSelection<TCredential> {
  matches: readonly DcqlSelectionMatch<TCredential>[];
  unmatched: readonly DcqlSelectionFailure[];
  /** Whether every required credential_set is satisfied (or, when no sets
   * are present, every credentials[] entry is matched). */
  fullySatisfied: boolean;
}

/** Run a DCQL query against the holder's credentials. */
export function selectForDcql<TCredential>(
  input: DcqlSelectInput<TCredential>,
): DcqlSelection<TCredential> {
  validateQuery(input.query);

  const matchers =
    input.matchers ??
    ([new DcqlSdJwtVcMatcher()] as unknown as readonly DcqlMatcher<
      TCredential
    >[]);
  const pick = input.pickCredential ?? ((cands) => cands[0]!);

  const matches: DcqlSelectionMatch<TCredential>[] = [];
  const unmatched: DcqlSelectionFailure[] = [];
  const matchedIds = new Set<string>();

  for (const credentialQuery of input.query.credentials) {
    const matcher = matchers.find((m) =>
      m.formats.includes(credentialQuery.format),
    );
    if (matcher === undefined) {
      unmatched.push({
        query: credentialQuery,
        reason: `no matcher registered for format '${credentialQuery.format}'`,
      });
      continue;
    }

    const candidates: {
      credential: TCredential;
      result: DcqlMatchResult;
    }[] = [];
    for (const credential of input.credentials) {
      const result = matcher.match(credential, credentialQuery);
      if (result !== null) {
        candidates.push({ credential, result });
      }
    }
    if (candidates.length === 0) {
      unmatched.push({
        query: credentialQuery,
        reason: `no credential satisfies '${credentialQuery.id}'`,
      });
      continue;
    }
    const chosen = pick(candidates);
    matches.push({
      query: credentialQuery,
      credential: chosen.credential,
      disclose: chosen.result.disclose,
      result: chosen.result,
    });
    matchedIds.add(credentialQuery.id);
  }

  const fullySatisfied = evaluateCredentialSets(input.query, matchedIds);

  return { matches, unmatched, fullySatisfied };
}

function evaluateCredentialSets(
  query: DcqlQuery,
  matchedIds: ReadonlySet<string>,
): boolean {
  if (query.credential_sets === undefined || query.credential_sets.length === 0) {
    return query.credentials.every((c) => matchedIds.has(c.id));
  }
  for (const set of query.credential_sets) {
    if (set.required === false) continue;
    const optionSatisfied = set.options.some((option) =>
      option.every((id) => matchedIds.has(id)),
    );
    if (!optionSatisfied) return false;
  }
  return true;
}

function validateQuery(query: DcqlQuery): void {
  if (query === null || typeof query !== "object" || Array.isArray(query)) {
    throw new DcqlError(
      "dcql.invalid_query",
      "DCQL query must be a non-null object",
    );
  }
  if (!Array.isArray(query.credentials) || query.credentials.length === 0) {
    throw new DcqlError(
      "dcql.invalid_query",
      "DCQL query.credentials must be a non-empty array",
    );
  }
  const ids = new Set<string>();
  for (const c of query.credentials) {
    if (typeof c.id !== "string" || c.id.length === 0) {
      throw new DcqlError(
        "dcql.invalid_query",
        "DCQL credential entry must have a non-empty string id",
      );
    }
    if (ids.has(c.id)) {
      throw new DcqlError(
        "dcql.invalid_query",
        `DCQL credential ids must be unique; duplicate '${c.id}'`,
      );
    }
    ids.add(c.id);
    if (typeof c.format !== "string" || c.format.length === 0) {
      throw new DcqlError(
        "dcql.invalid_query",
        `DCQL credential '${c.id}' missing format`,
      );
    }
    for (const claim of c.claims ?? []) {
      validateDcqlPath(claim.path);
    }
  }
}

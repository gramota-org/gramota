import { SdJwtVcMatcher } from "./sd-jwt-vc-matcher.js";
import type {
  CredentialMatcher,
  MatchResult,
} from "./matcher.js";
import type {
  PresentationDefinition,
  InputDescriptor,
  PresentationSubmission,
} from "./types.js";
import { PresentationExchangeError } from "./types.js";

export interface SelectInput<TCredential> {
  definition: PresentationDefinition;
  credentials: readonly TCredential[];
  /** Custom matchers — Strategy pattern; default is SD-JWT-VC. */
  matchers?: readonly CredentialMatcher<TCredential>[];
  /** When multiple credentials satisfy a descriptor, which to pick.
   * Default: the first one. */
  pickCredential?: (
    candidates: readonly { credential: TCredential; result: MatchResult }[],
  ) => { credential: TCredential; result: MatchResult };
}

export interface SelectionMatch<TCredential> {
  descriptor: InputDescriptor;
  credential: TCredential;
  /** Names of selectively-disclosable claims to disclose. */
  disclose: readonly string[];
  /** Audit detail. */
  result: MatchResult;
}

export interface SelectionFailure {
  descriptor: InputDescriptor;
  reason: string;
}

export interface Selection<TCredential> {
  matches: readonly SelectionMatch<TCredential>[];
  unmatched: readonly SelectionFailure[];
  fullySatisfied: boolean;
}

/**
 * Pick credentials + disclosures that satisfy a Presentation Definition.
 *
 * Pure function: given a definition and a credential set, return what to
 * present. Caller (the holder) executes the actual presentation building
 * with `@gateway/holder`.
 */
export function selectForDefinition<TCredential>(
  input: SelectInput<TCredential>,
): Selection<TCredential> {
  const matchers =
    input.matchers ??
    ([new SdJwtVcMatcher()] as unknown as readonly CredentialMatcher<TCredential>[]);
  const pick = input.pickCredential ?? ((cands) => cands[0]!);

  const matches: SelectionMatch<TCredential>[] = [];
  const unmatched: SelectionFailure[] = [];

  for (const descriptor of input.definition.input_descriptors) {
    const matcher = matchers.find((m) => m.appliesTo(descriptor));
    if (matcher === undefined) {
      unmatched.push({
        descriptor,
        reason: `no matcher for descriptor format(s) ${JSON.stringify(
          descriptor.format ?? input.definition.format,
        )}`,
      });
      continue;
    }

    const candidates: { credential: TCredential; result: MatchResult }[] = [];
    for (const credential of input.credentials) {
      const result = matcher.match(credential, descriptor);
      if (result !== null) {
        candidates.push({ credential, result });
      }
    }
    if (candidates.length === 0) {
      unmatched.push({
        descriptor,
        reason: `no credential satisfies all required fields of '${descriptor.id}'`,
      });
      continue;
    }
    const chosen = pick(candidates);
    matches.push({
      descriptor,
      credential: chosen.credential,
      disclose: chosen.result.disclose,
      result: chosen.result,
    });
  }

  return {
    matches,
    unmatched,
    fullySatisfied: unmatched.length === 0,
  };
}

/** Build a Presentation Submission from a Selection. The vp_token paths
 * follow the convention: `$` for a single credential, `$[0]`, `$[1]`, ...
 * for arrays. */
export function buildPresentationSubmission<TCredential>(
  definition: PresentationDefinition,
  selection: Selection<TCredential>,
  options?: { id?: string },
): PresentationSubmission {
  if (!selection.fullySatisfied) {
    throw new PresentationExchangeError(
      `cannot build submission — ${selection.unmatched.length} descriptor(s) unmatched`,
    );
  }

  const multi = selection.matches.length > 1;
  return {
    id: options?.id ?? `sub-${definition.id}`,
    definition_id: definition.id,
    descriptor_map: selection.matches.map((m, i) => ({
      id: m.descriptor.id,
      format: "vc+sd-jwt",
      path: multi ? `$[${i}]` : "$",
    })),
  };
}

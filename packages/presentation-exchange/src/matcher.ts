import type { InputDescriptor } from "./types.js";

/** A credential matcher per credential format. New formats (W3C VC, mdoc)
 * can plug in new implementations of this interface — Strategy pattern. */
export interface CredentialMatcher<TCredential> {
  /** Stable format identifier (e.g. "vc+sd-jwt"). */
  readonly format: string;

  /** Decide whether the descriptor's format/alg constraints apply to this
   * credential type. */
  appliesTo(descriptor: InputDescriptor): boolean;

  /** Evaluate the credential against the descriptor. Returns the disclosure
   * names this descriptor would require, or `null` if no match. */
  match(
    credential: TCredential,
    descriptor: InputDescriptor,
  ): MatchResult | null;
}

export interface MatchResult {
  /** Names of selectively-disclosable claims required to satisfy the
   * descriptor. Pass these to `holder.present({ disclose: [...] })`. */
  disclose: readonly string[];
  /** Field-by-field detail, useful for audit logs and debug UIs. */
  satisfiedFields: readonly { fieldId: string | undefined; path: string }[];
}

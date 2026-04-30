/**
 * DCQL — Digital Credentials Query Language (OID4VP 2.0).
 * Spec: OID4VP 2.0 §6 (DCQL).
 *
 * The OID4VP 2.0 replacement for DIF Presentation Exchange v2 (which lives
 * in `@gateway/presentation-exchange`). Both query languages exist; pick
 * whichever your verifier or wallet ecosystem speaks.
 */

export interface DcqlQuery {
  /** Credential queries the wallet must satisfy. */
  credentials: readonly DcqlCredentialQuery[];
  /** Optional sets describing which combinations of credentials are
   * acceptable (OR/AND logic across credentials). */
  credential_sets?: readonly DcqlCredentialSet[];
}

export interface DcqlCredentialQuery {
  id: string;
  /** Credential format: "vc+sd-jwt", "dc+sd-jwt", "mso_mdoc", "ldp_vc", … */
  format: string;
  /** Format-specific filters. For SD-JWT-VC: `{ vct_values: string[] }`.
   * For mDoc: `{ doctype_value: string }`. */
  meta?: Readonly<Record<string, unknown>>;
  /** Claims the wallet must reveal. */
  claims?: readonly DcqlClaimQuery[];
  /** Named groups of claims, when the verifier accepts alternate sets. */
  claim_sets?: readonly (readonly string[])[];
}

export interface DcqlClaimQuery {
  /** Optional identifier for use in `claim_sets`. */
  id?: string;
  /** Path segments to the claim. Strings = property keys; numbers = array
   * indices; null = "any element of an array". E.g.
   *   ["family_name"]                            → top-level family_name
   *   ["address", "country"]                     → nested address.country
   *   ["eu.europa.ec.eudi.pid.1", "family_name"] → mDoc namespaced */
  path: readonly (string | number | null)[];
  /** Optional value constraint — claim must equal one of these. */
  values?: readonly unknown[];
}

export interface DcqlCredentialSet {
  /** Each option is a list of credential ids. The wallet picks one option
   * whose credentials it can all supply. */
  options: readonly (readonly string[])[];
  /** When `false`, the verifier accepts the request without this set. */
  required?: boolean;
  purpose?: string;
}

/** Stable codes for `DcqlError`. */
export type DcqlErrorCode =
  | "dcql.invalid_query"
  | "dcql.invalid_path"
  | "dcql.unsatisfiable"
  | "dcql.format_unsupported";

export class DcqlError extends Error {
  override readonly name = "DcqlError";
  readonly code: DcqlErrorCode;
  constructor(
    code: DcqlErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.code = code;
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

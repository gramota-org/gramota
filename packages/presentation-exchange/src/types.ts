/**
 * DIF Presentation Exchange v2 types — what the verifier asks for, and how
 * the holder responds.
 *
 * Spec: https://identity.foundation/presentation-exchange/spec/v2.1.1/
 *
 * Scope of this package: input_descriptors, fields, format, limit_disclosure.
 * Deferred to v2: submission_requirements, predicate, full filter (JSON
 * Schema), frame.
 */

export interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  /** Acceptable credential formats and their algorithms, applied at the PD
   * level (overridable per input_descriptor). */
  format?: FormatMap;
  input_descriptors: readonly InputDescriptor[];
}

/** Maps a credential format identifier (e.g. "vc+sd-jwt") to algorithm
 * constraints. Per DIF PE §5.5. */
export type FormatMap = Readonly<Record<string, { alg?: readonly string[] }>>;

export interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  /** Per-descriptor format override. */
  format?: FormatMap;
  constraints: Constraints;
}

export interface Constraints {
  fields?: readonly Field[];
  /** When "required", the holder MUST limit disclosure to only the requested
   * fields (selective disclosure mandatory). When "preferred", it's a hint. */
  limit_disclosure?: "required" | "preferred";
}

export interface Field {
  /** JSONPath expressions; the verifier's query into the credential. The
   * field is satisfied if ANY of the paths match. */
  path: readonly string[];
  /** Optional friendly id for audit logs. */
  id?: string;
  /** When true, missing field doesn't fail the descriptor. */
  optional?: boolean;
  /** JSON Schema fragment to validate the matched value. v1 supports
   * `{ type: "..." }` only. */
  filter?: { type?: "string" | "number" | "integer" | "boolean" };
  purpose?: string;
}

/** A holder-built mapping of which credentials satisfy which descriptors,
 * per DIF PE §6 — the wallet's response to a Presentation Definition. */
export interface PresentationSubmission {
  id: string;
  definition_id: string;
  descriptor_map: readonly DescriptorMap[];
}

export interface DescriptorMap {
  id: string;
  /** e.g. "vc+sd-jwt", "jwt_vp", "ldp_vp", "mso_mdoc". */
  format: string;
  /** JSONPath into the vp_token (`$` for single-credential responses). */
  path: string;
  path_nested?: DescriptorMap;
}

/** Stable codes for `PresentationExchangeError`. */
export type PresentationExchangeErrorCode =
  | "pe.jsonpath_invalid"
  | "pe.unsatisfiable"
  | "pe.format_unsupported"
  | "pe.invalid_input"
  | "dcql.invalid_query"
  | "dcql.invalid_path";

// ---------------------------------------------------------------------------
// DCQL — Digital Credentials Query Language (OID4VP 2.0)
// ---------------------------------------------------------------------------

/** A DCQL query — what a verifier asks the wallet for under OID4VP 2.0.
 * Spec: OID4VP 2.0 §6 (Digital Credentials Query Language). */
export interface DcqlQuery {
  /** Credential queries the wallet must satisfy. */
  credentials: readonly DcqlCredentialQuery[];
  /** Optional sets describing which combinations of credentials are
   * acceptable (think of it as OR/AND logic across credentials). */
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
   *   ["family_name"]                 → top-level family_name
   *   ["address", "country"]          → nested address.country
   *   ["eu.europa.ec.eudi.pid.1", "family_name"]  → mDoc namespaced */
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

export class PresentationExchangeError extends Error {
  override readonly name = "PresentationExchangeError";
  readonly code: PresentationExchangeErrorCode;
  constructor(
    code: PresentationExchangeErrorCode,
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

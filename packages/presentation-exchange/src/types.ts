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

export class PresentationExchangeError extends Error {
  override readonly name = "PresentationExchangeError";
}

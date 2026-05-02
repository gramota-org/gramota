/**
 * Credential-format handler types.
 *
 * The base `CredentialFormatHandler` interface is intentionally minimal —
 * just enough to identify supported formats. Capability-specific
 * sub-interfaces (issuance, parsing, verification, presentation, etc.)
 * extend the base and add their own methods. Consumers depend on the
 * narrowest capability they need:
 *
 *   const h: IssuanceCapableHandler = registry.requireIssuance(format);
 *   h.validateIssuanceToken(token);
 *
 * This is **Interface Segregation in action**: a Verifier doesn't depend
 * on issuance methods; an Issuer doesn't depend on presentation methods.
 *
 * Capability flags (`canReceiveIssuance: true`, etc.) are TypeScript-only
 * brand bits used by `Registry.requireXxx()` for runtime narrowing — no
 * code paths key on them.
 */

/**
 * Base — every format handler advertises which format strings it claims.
 *
 * Implementations live close to the format-specific logic they wrap (e.g.
 * `SdJwtVcFormatHandler` lives in `@gramota/credential-format-sd-jwt-vc`,
 * future `MDocFormatHandler` in `@gramota/credential-format-mdoc`).
 */
export interface CredentialFormatHandler {
  /** Format identifiers this handler claims, e.g. ["vc+sd-jwt", "dc+sd-jwt"]. */
  readonly formats: readonly string[];

  /** True iff `format` is in {@link formats}. Strict equality. */
  supports(format: string): boolean;
}

// ---------------------------------------------------------------------------
// Capability sub-interfaces
// ---------------------------------------------------------------------------

/**
 * Issuance capability — the handler can validate a token returned by an
 * OID4VCI credential endpoint of this format.
 *
 * Implemented by `SdJwtVcFormatHandler` (validates compact-serialized
 * SD-JWT-VC). Future `MDocFormatHandler` would validate a base64url-
 * encoded CBOR `IssuerSigned` structure.
 */
export interface IssuanceCapableHandler extends CredentialFormatHandler {
  /** Brand bit — see file header. */
  readonly canReceiveIssuance: true;
  /**
   * Validate a credential token returned by an OID4VCI credential
   * endpoint. Throws if the token is malformed for this format.
   *
   * Pre-condition: caller has already confirmed the token's format
   * matches `this.formats` via the registry.
   */
  validateIssuanceToken(token: string): void;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type CredentialFormatErrorCode =
  | "credential_format.unknown_format"
  | "credential_format.duplicate_format"
  | "credential_format.capability_missing"
  | "credential_format.invalid_token";

export class CredentialFormatError extends Error {
  override readonly name = "CredentialFormatError";
  readonly code: CredentialFormatErrorCode;
  constructor(
    code: CredentialFormatErrorCode,
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

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

export function hasIssuanceCapability(
  handler: CredentialFormatHandler,
): handler is IssuanceCapableHandler {
  return (
    (handler as IssuanceCapableHandler).canReceiveIssuance === true &&
    typeof (handler as IssuanceCapableHandler).validateIssuanceToken === "function"
  );
}

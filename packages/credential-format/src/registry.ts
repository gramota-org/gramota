import {
  CredentialFormatError,
  hasIssuanceCapability,
  type CredentialFormatHandler,
  type IssuanceCapableHandler,
} from "./types.js";

/**
 * Registry of credential-format handlers (GoF Registry + Strategy).
 *
 * Use cases:
 *
 *   1. The OID4VCI client asks "do you have an issuance handler for
 *      'vc+sd-jwt'?" — `requireIssuance(format)` returns the narrow
 *      capability or throws.
 *
 *   2. A wallet author writes their own format (e.g. an internal proof-
 *      of-concept), registers it, and the rest of the SDK accepts
 *      credentials in that format without modification.
 *
 *     const registry = new CredentialFormatRegistry()
 *       .register(new SdJwtVcFormatHandler())
 *       .register(new MDocFormatHandler())     // future
 *       .register(new MyCustomHandler());      // your own
 *
 * The registry is mutable in the builder phase but its `find/require`
 * methods are pure — many lookups can run concurrently against one
 * registry instance.
 */
export class CredentialFormatRegistry {
  private readonly byFormat = new Map<string, CredentialFormatHandler>();

  /** Register a handler. Each format the handler claims becomes a key.
   * Throws if any of those keys is already taken — duplicate registration
   * is a programmer error, not a silent override. */
  register(handler: CredentialFormatHandler): this {
    if (
      handler === null ||
      typeof handler !== "object" ||
      typeof handler.supports !== "function" ||
      !Array.isArray(handler.formats)
    ) {
      throw new CredentialFormatError(
        "credential_format.unknown_format",
        "register: handler must implement CredentialFormatHandler",
      );
    }
    if (handler.formats.length === 0) {
      throw new CredentialFormatError(
        "credential_format.unknown_format",
        "register: handler.formats must be a non-empty array",
      );
    }
    for (const fmt of handler.formats) {
      if (typeof fmt !== "string" || fmt.length === 0) {
        throw new CredentialFormatError(
          "credential_format.unknown_format",
          "register: each entry of handler.formats must be a non-empty string",
        );
      }
      if (this.byFormat.has(fmt)) {
        throw new CredentialFormatError(
          "credential_format.duplicate_format",
          `register: a handler is already registered for format '${fmt}'`,
        );
      }
      this.byFormat.set(fmt, handler);
    }
    return this;
  }

  /** Lookup a handler by format string. Returns undefined if none claims it. */
  find(format: string): CredentialFormatHandler | undefined {
    return this.byFormat.get(format);
  }

  /** True iff some registered handler claims `format`. */
  has(format: string): boolean {
    return this.byFormat.has(format);
  }

  /** All format identifiers any registered handler claims. */
  knownFormats(): readonly string[] {
    return Array.from(this.byFormat.keys());
  }

  /** Lookup with capability narrowing — issuance flow.
   *
   * Throws `credential_format.unknown_format` when no handler claims
   * `format`, or `credential_format.capability_missing` when the handler
   * exists but doesn't support issuance. */
  requireIssuance(format: string): IssuanceCapableHandler {
    const h = this.byFormat.get(format);
    if (h === undefined) {
      throw new CredentialFormatError(
        "credential_format.unknown_format",
        `no handler registered for credential format '${format}' — known formats: [${this.knownFormats().join(", ") || "<none>"}]`,
      );
    }
    if (!hasIssuanceCapability(h)) {
      throw new CredentialFormatError(
        "credential_format.capability_missing",
        `handler for '${format}' does not implement IssuanceCapableHandler`,
      );
    }
    return h;
  }
}

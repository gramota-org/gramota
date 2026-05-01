import { CredentialFormatRegistry } from "./registry.js";
import { SdJwtVcFormatHandler } from "./sd-jwt-vc.js";

/**
 * Build a registry pre-populated with the SD-JWT-VC handler.
 *
 *   const registry = createDefaultCredentialFormatRegistry()
 *     .register(new MyCustomHandler());
 *
 * Returns a new instance every call — never share state across consumers.
 */
export function createDefaultCredentialFormatRegistry(): CredentialFormatRegistry {
  return new CredentialFormatRegistry().register(new SdJwtVcFormatHandler());
}

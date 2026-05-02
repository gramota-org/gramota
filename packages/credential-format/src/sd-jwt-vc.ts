import {
  CredentialFormatError,
  type IssuanceCapableHandler,
} from "./types.js";

const SD_JWT_VC_FORMAT = "vc+sd-jwt";
const DC_SD_JWT_VC_FORMAT = "dc+sd-jwt";

/**
 * Default handler for SD-JWT-VC and dc+sd-jwt credentials.
 *
 * Bundled with `@gramota/credential-format` because SD-JWT-VC is the
 * dominant EUDIW format. mDoc gets its own package when it lands.
 *
 * The validation here is intentionally minimal — full structural
 * verification (parsing, hash binding, KB-JWT, etc.) lives in
 * `@gramota/sd-jwt` / `@gramota/verifier`. This handler only confirms
 * the token "looks like" an SD-JWT-VC issuance: at minimum a JWS with
 * `~`-separated disclosure segments. That's enough to gate the OID4VCI
 * credential-endpoint response without pulling in the full sd-jwt
 * dependency tree.
 */
export class SdJwtVcFormatHandler implements IssuanceCapableHandler {
  readonly formats: readonly string[] = [
    SD_JWT_VC_FORMAT,
    DC_SD_JWT_VC_FORMAT,
  ];
  readonly canReceiveIssuance = true as const;

  supports(format: string): boolean {
    return this.formats.includes(format);
  }

  validateIssuanceToken(token: string): void {
    if (typeof token !== "string" || token.length === 0) {
      throw new CredentialFormatError(
        "credential_format.invalid_token",
        "SD-JWT-VC token must be a non-empty string",
      );
    }
    // Issuance form per IETF SD-JWT §4.2: <signedPayload>.<signature>~<disclosure>~...~[kbJwt]
    // For ISSUANCE specifically, the token should end with `~` (no KB-JWT yet).
    if (!token.includes("~")) {
      throw new CredentialFormatError(
        "credential_format.invalid_token",
        "SD-JWT-VC issuance token must contain at least one `~` separator (issuance form)",
      );
    }
    const parts = token.split("~");
    const jwsPart = parts[0];
    if (jwsPart === undefined || jwsPart.split(".").length !== 3) {
      throw new CredentialFormatError(
        "credential_format.invalid_token",
        "SD-JWT-VC token must start with a compact-serialized JWS (3 dot-separated segments)",
      );
    }
  }
}

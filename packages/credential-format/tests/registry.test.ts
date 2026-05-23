/**
 * @gramota/credential-format — registry behavior + extensibility.
 *
 * Three layers of coverage:
 *
 *   1. SdJwtVcFormatHandler — basic validate() correctness
 *   2. CredentialFormatRegistry — lookup, capability narrowing, errors
 *   3. Extensibility — a custom IssuanceCapableHandler plugs in
 */

import { describe, it, expect } from "vitest";
import {
  CredentialFormatError,
  CredentialFormatRegistry,
  SdJwtVcFormatHandler,
  createDefaultCredentialFormatRegistry,
  hasIssuanceCapability,
  type IssuanceCapableHandler,
} from "../src/index.js";

describe("SdJwtVcFormatHandler — issuance-token validation", () => {
  const handler = new SdJwtVcFormatHandler();

  it("claims dc+sd-jwt (preferred per SD-JWT-VC §3.2.1) and the legacy vc+sd-jwt", () => {
    // Modern `dc+sd-jwt` is listed first — it's the spec-mandated typ since
    // SD-JWT-VC draft-08 (Nov 2024). `vc+sd-jwt` remains accepted for
    // back-compat with already-minted credentials.
    expect(handler.formats).toEqual(["dc+sd-jwt", "vc+sd-jwt"]);
    expect(handler.supports("vc+sd-jwt")).toBe(true);
    expect(handler.supports("dc+sd-jwt")).toBe(true);
    expect(handler.supports("mso_mdoc")).toBe(false);
  });

  it("accepts a well-formed SD-JWT-VC issuance token (3-part JWS + ~)", () => {
    expect(() =>
      handler.validateIssuanceToken("h.p.s~"),
    ).not.toThrow();
    expect(() =>
      handler.validateIssuanceToken("h.p.s~d1~d2~"),
    ).not.toThrow();
  });

  it("rejects an empty / non-string token", () => {
    expect(() => handler.validateIssuanceToken("")).toThrowError(
      CredentialFormatError,
    );
    // @ts-expect-error: testing runtime guard
    expect(() => handler.validateIssuanceToken(null)).toThrowError(
      CredentialFormatError,
    );
  });

  it("rejects a token without `~` (presentation-form not allowed at issuance)", () => {
    try {
      handler.validateIssuanceToken("h.p.s");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as CredentialFormatError).code).toBe(
        "credential_format.invalid_token",
      );
    }
  });

  it("rejects a token whose JWS part is malformed (not 3 dot-segments)", () => {
    expect(() => handler.validateIssuanceToken("hp~")).toThrowError(
      /3 dot-separated segments/,
    );
    expect(() => handler.validateIssuanceToken("h.p.s.x~")).toThrowError(
      /3 dot-separated segments/,
    );
  });

  it("hasIssuanceCapability identifies it as issuance-capable", () => {
    expect(hasIssuanceCapability(handler)).toBe(true);
  });
});

describe("CredentialFormatRegistry — lookup & errors", () => {
  it("registers a handler for each declared format", () => {
    const r = new CredentialFormatRegistry().register(
      new SdJwtVcFormatHandler(),
    );
    expect(r.has("vc+sd-jwt")).toBe(true);
    expect(r.has("dc+sd-jwt")).toBe(true);
    expect(r.has("mso_mdoc")).toBe(false);
    expect(r.knownFormats()).toEqual(["dc+sd-jwt", "vc+sd-jwt"]);
  });

  it("rejects duplicate registration of the same format", () => {
    const r = new CredentialFormatRegistry().register(
      new SdJwtVcFormatHandler(),
    );
    try {
      r.register(new SdJwtVcFormatHandler());
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as CredentialFormatError).code).toBe(
        "credential_format.duplicate_format",
      );
    }
  });

  it("rejects handlers with no format strings", () => {
    const empty: IssuanceCapableHandler = {
      formats: [],
      canReceiveIssuance: true,
      supports: () => false,
      validateIssuanceToken: () => undefined,
    };
    expect(() => new CredentialFormatRegistry().register(empty)).toThrowError(
      CredentialFormatError,
    );
  });

  it("requireIssuance returns the handler for a known issuance-capable format", () => {
    const r = createDefaultCredentialFormatRegistry();
    const h = r.requireIssuance("vc+sd-jwt");
    expect(h.canReceiveIssuance).toBe(true);
    expect(h.supports("vc+sd-jwt")).toBe(true);
  });

  it("requireIssuance throws unknown_format for unregistered formats", () => {
    const r = createDefaultCredentialFormatRegistry();
    try {
      r.requireIssuance("mso_mdoc");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as CredentialFormatError).code).toBe(
        "credential_format.unknown_format",
      );
      expect((err as CredentialFormatError).message).toMatch(/mso_mdoc/);
      // Error message should hint at known formats for diagnostics.
      expect((err as CredentialFormatError).message).toMatch(/vc\+sd-jwt/);
    }
  });

  it("requireIssuance throws capability_missing for handlers without issuance capability", () => {
    // Handler that claims a format but doesn't implement issuance.
    const minimalHandler = {
      formats: ["fake_format"],
      supports(format: string) {
        return format === "fake_format";
      },
    };
    const r = new CredentialFormatRegistry().register(minimalHandler);
    try {
      r.requireIssuance("fake_format");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as CredentialFormatError).code).toBe(
        "credential_format.capability_missing",
      );
    }
  });

  it("find() returns the handler or undefined", () => {
    const r = createDefaultCredentialFormatRegistry();
    expect(r.find("vc+sd-jwt")).toBeDefined();
    expect(r.find("nonexistent")).toBeUndefined();
  });
});

describe("CredentialFormatRegistry — extensibility", () => {
  it("a user-defined IssuanceCapableHandler plugs in via register()", () => {
    // Stand-in for a future MDocFormatHandler: a handler for an
    // entirely different format that the registry treats as a peer.
    class CborCapsuleFormatHandler implements IssuanceCapableHandler {
      readonly formats: readonly string[] = ["application/cbor-capsule"];
      readonly canReceiveIssuance = true as const;
      supports(format: string): boolean {
        return this.formats.includes(format);
      }
      validateIssuanceToken(token: string): void {
        // CBOR tokens base64url-encode to a known prefix — we don't
        // actually parse CBOR here, just demonstrate format-specific
        // validation is decoupled from the registry.
        if (!token.startsWith("cbor:")) {
          throw new CredentialFormatError(
            "credential_format.invalid_token",
            "CBOR capsule must start with 'cbor:'",
          );
        }
      }
    }

    const r = createDefaultCredentialFormatRegistry().register(
      new CborCapsuleFormatHandler(),
    );

    // Existing default handler still works
    expect(r.requireIssuance("vc+sd-jwt").supports("vc+sd-jwt")).toBe(true);
    // The custom handler also works — same registry, same surface
    const cbor = r.requireIssuance("application/cbor-capsule");
    expect(() => cbor.validateIssuanceToken("cbor:abcd")).not.toThrow();
    expect(() =>
      cbor.validateIssuanceToken("notcbor"),
    ).toThrowError(/cbor:/);
  });

  it("a custom handler can override default behavior by registering FIRST", () => {
    // Use case: a wallet author wants to enforce stricter SD-JWT-VC validation
    // (e.g., reject tokens with too few disclosures). They register their
    // strict handler in a fresh registry.
    class StrictSdJwtVcHandler implements IssuanceCapableHandler {
      readonly formats: readonly string[] = ["vc+sd-jwt"];
      readonly canReceiveIssuance = true as const;
      supports(format: string): boolean {
        return format === "vc+sd-jwt";
      }
      validateIssuanceToken(token: string): void {
        const parts = token.split("~").filter((s) => s.length > 0);
        if (parts.length < 4) {
          throw new CredentialFormatError(
            "credential_format.invalid_token",
            "strict policy: at least 3 disclosures required",
          );
        }
      }
    }

    // Build a fresh registry — default handler is NOT installed.
    const r = new CredentialFormatRegistry().register(new StrictSdJwtVcHandler());
    const h = r.requireIssuance("vc+sd-jwt");
    expect(() => h.validateIssuanceToken("h.p.s~d1~")).toThrowError(
      /at least 3 disclosures/,
    );
    expect(() =>
      h.validateIssuanceToken("h.p.s~d1~d2~d3~"),
    ).not.toThrow();
  });
});

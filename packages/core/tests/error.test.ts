import { describe, expect, it } from "vitest";
import { GramotaError, isGramotaError } from "../src/index.js";

describe("GramotaError", () => {
  it("extends Error, carries code + message + name", () => {
    const e = new GramotaError("boom", "verify.signature");
    expect(e).toBeInstanceOf(Error);
    expect(e).toBeInstanceOf(GramotaError);
    expect(e.message).toBe("boom");
    expect(e.code).toBe("verify.signature");
    expect(e.name).toBe("GramotaError");
    expect(e.cause).toBeUndefined();
  });

  it("survives 'instanceof Error' across realms (no need for Error.captureStackTrace)", () => {
    function rejects(): never {
      throw new GramotaError("x", "code.x");
    }
    try {
      rejects();
    } catch (err) {
      expect(err instanceof Error).toBe(true);
      expect(err instanceof GramotaError).toBe(true);
    }
  });

  it("threads cause through the standard Error options bag", () => {
    const inner = new TypeError("invalid argument");
    const e = new GramotaError("wrapped failure", "wrap", { cause: inner });
    expect(e.cause).toBe(inner);
  });

  it("subclasses can narrow the code type while keeping runtime compat", () => {
    type IssuerCode = "issue.no_metadata" | "issue.invalid_proof";

    class IssuerError extends GramotaError {
      override readonly code: IssuerCode;
      constructor(message: string, code: IssuerCode, options?: { cause?: unknown }) {
        super(message, code, options);
        this.name = "IssuerError";
        this.code = code;
      }
    }

    const e = new IssuerError("no metadata", "issue.no_metadata");
    expect(e).toBeInstanceOf(GramotaError);
    expect(e).toBeInstanceOf(IssuerError);
    expect(e.code).toBe("issue.no_metadata");
    expect(e.name).toBe("IssuerError");
  });
});

describe("isGramotaError", () => {
  it("narrows positively for GramotaError instances", () => {
    const err: unknown = new GramotaError("boom", "x");
    expect(isGramotaError(err)).toBe(true);
    if (isGramotaError(err)) {
      // type narrowed — code is accessible without cast
      expect(err.code).toBe("x");
    }
  });

  it("returns false for plain Error", () => {
    expect(isGramotaError(new Error("plain"))).toBe(false);
  });

  it("returns false for non-error values", () => {
    expect(isGramotaError(undefined)).toBe(false);
    expect(isGramotaError(null)).toBe(false);
    expect(isGramotaError("string")).toBe(false);
    expect(isGramotaError({ code: "fake" })).toBe(false);
  });
});

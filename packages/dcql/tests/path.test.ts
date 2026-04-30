import { describe, it, expect } from "vitest";
import {
  DcqlError,
  evaluateDcqlPath,
  leafPropertyName,
  validateDcqlPath,
} from "../src/index.js";

describe("evaluateDcqlPath", () => {
  const obj = {
    family_name: "Smith",
    address: { country: "BG", city: "Sofia" },
    items: ["a", "b", "c"],
    nested: { deep: { value: 42 } },
    namespaced: {
      "eu.europa.ec.eudi.pid.1": { family_name: "Petrov" },
    },
  };

  it("returns top-level property", () => {
    expect(evaluateDcqlPath(["family_name"], obj)).toBe("Smith");
  });

  it("traverses nested objects", () => {
    expect(evaluateDcqlPath(["address", "country"], obj)).toBe("BG");
    expect(evaluateDcqlPath(["nested", "deep", "value"], obj)).toBe(42);
  });

  it("indexes into arrays with numbers", () => {
    expect(evaluateDcqlPath(["items", 0], obj)).toBe("a");
    expect(evaluateDcqlPath(["items", 2], obj)).toBe("c");
  });

  it("treats null as wildcard (single-value: takes first element)", () => {
    expect(evaluateDcqlPath(["items", null], obj)).toBe("a");
  });

  it("returns undefined when traversing through missing keys", () => {
    expect(evaluateDcqlPath(["nope"], obj)).toBeUndefined();
    expect(evaluateDcqlPath(["address", "zip"], obj)).toBeUndefined();
    expect(evaluateDcqlPath(["items", 99], obj)).toBeUndefined();
  });

  it("returns undefined when traversing through null/undefined", () => {
    expect(evaluateDcqlPath(["x", "y"], { x: null })).toBeUndefined();
  });

  it("handles namespaced paths (mDoc-style: namespace + claim)", () => {
    expect(
      evaluateDcqlPath(
        ["namespaced", "eu.europa.ec.eudi.pid.1", "family_name"],
        obj,
      ),
    ).toBe("Petrov");
  });
});

describe("validateDcqlPath", () => {
  it("accepts a single-segment path", () => {
    expect(() => validateDcqlPath(["foo"])).not.toThrow();
  });

  it("accepts mixed path segments (string + number + null)", () => {
    expect(() =>
      validateDcqlPath(["foo", 0, null, "bar"]),
    ).not.toThrow();
  });

  it("rejects an empty path", () => {
    try {
      validateDcqlPath([]);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(DcqlError);
      expect((err as DcqlError).code).toBe("dcql.invalid_path");
    }
  });

  it("rejects non-array input", () => {
    try {
      validateDcqlPath("not-array");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as DcqlError).code).toBe("dcql.invalid_path");
    }
  });

  it("rejects unsupported segment types", () => {
    try {
      // @ts-expect-error: testing runtime guard
      validateDcqlPath(["x", true]);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as DcqlError).code).toBe("dcql.invalid_path");
    }
  });
});

describe("leafPropertyName", () => {
  it("returns the property name for single-string paths", () => {
    expect(leafPropertyName(["foo"])).toBe("foo");
  });

  it("returns null for nested paths", () => {
    expect(leafPropertyName(["foo", "bar"])).toBeNull();
  });

  it("returns null for paths starting with index/null", () => {
    expect(leafPropertyName([0])).toBeNull();
    expect(leafPropertyName([null])).toBeNull();
  });
});

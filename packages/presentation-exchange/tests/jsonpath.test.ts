import { describe, it, expect } from "vitest";
import {
  evaluateJsonPath,
  leafClaimName,
  parseJsonPath,
  PresentationExchangeError,
} from "../src/index.js";

describe("parseJsonPath", () => {
  it("parses '$' as the root (no segments)", () => {
    expect(parseJsonPath("$")).toEqual([]);
  });

  it("parses '$.given_name' as a single property segment", () => {
    expect(parseJsonPath("$.given_name")).toEqual([
      { kind: "property", name: "given_name" },
    ]);
  });

  it("parses nested property path '$.address.country'", () => {
    expect(parseJsonPath("$.address.country")).toEqual([
      { kind: "property", name: "address" },
      { kind: "property", name: "country" },
    ]);
  });

  it("parses bracket notation $['foo']", () => {
    expect(parseJsonPath("$['foo']")).toEqual([
      { kind: "property", name: "foo" },
    ]);
  });

  it("parses chained bracket notation $['a']['b']", () => {
    expect(parseJsonPath("$['a']['b']")).toEqual([
      { kind: "property", name: "a" },
      { kind: "property", name: "b" },
    ]);
  });

  it("parses array index $.items[0]", () => {
    expect(parseJsonPath("$.items[0]")).toEqual([
      { kind: "property", name: "items" },
      { kind: "index", index: 0 },
    ]);
  });

  it("rejects empty expressions", () => {
    expect(() => parseJsonPath("")).toThrow(PresentationExchangeError);
  });

  it("rejects expressions not starting with $", () => {
    expect(() => parseJsonPath("foo.bar")).toThrow(/start with '\$'/);
  });

  it("rejects empty property name '$.'", () => {
    expect(() => parseJsonPath("$.")).toThrow(/empty property/);
  });

  it("rejects unterminated bracket", () => {
    expect(() => parseJsonPath("$.foo[")).toThrow(/unterminated/);
  });

  it("rejects negative or non-integer array indices", () => {
    expect(() => parseJsonPath("$.foo[-1]")).toThrow(/invalid array index/);
    expect(() => parseJsonPath("$.foo[a]")).toThrow(/invalid array index/);
  });
});

describe("evaluateJsonPath", () => {
  const obj = {
    given_name: "Alice",
    address: { country: "BG", city: "Sofia" },
    items: ["a", "b", "c"],
    nested: { deep: { value: 42 } },
  };

  it("returns the root for '$'", () => {
    expect(evaluateJsonPath("$", obj)).toBe(obj);
  });

  it("returns top-level property", () => {
    expect(evaluateJsonPath("$.given_name", obj)).toBe("Alice");
  });

  it("traverses nested objects", () => {
    expect(evaluateJsonPath("$.address.country", obj)).toBe("BG");
    expect(evaluateJsonPath("$.nested.deep.value", obj)).toBe(42);
  });

  it("indexes into arrays", () => {
    expect(evaluateJsonPath("$.items[0]", obj)).toBe("a");
    expect(evaluateJsonPath("$.items[2]", obj)).toBe("c");
  });

  it("returns undefined for missing paths", () => {
    expect(evaluateJsonPath("$.nope", obj)).toBeUndefined();
    expect(evaluateJsonPath("$.address.zip", obj)).toBeUndefined();
    expect(evaluateJsonPath("$.items[10]", obj)).toBeUndefined();
  });

  it("returns undefined when traversing through null/undefined", () => {
    expect(evaluateJsonPath("$.x.y", { x: null })).toBeUndefined();
  });
});

describe("leafClaimName", () => {
  it("returns the property name for $.foo", () => {
    expect(leafClaimName("$.foo")).toBe("foo");
  });

  it("returns the property name for $['foo']", () => {
    expect(leafClaimName("$['foo']")).toBe("foo");
  });

  it("returns null for nested paths $.foo.bar", () => {
    expect(leafClaimName("$.foo.bar")).toBeNull();
  });

  it("returns null for the root $", () => {
    expect(leafClaimName("$")).toBeNull();
  });

  it("returns null for array index paths", () => {
    expect(leafClaimName("$.foo[0]")).toBeNull();
  });
});

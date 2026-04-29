import { describe, it, expect } from "vitest";
import { parseSdJwt } from "../src/parse.js";

const b64u = (s: string): string =>
  Buffer.from(s, "utf-8").toString("base64url");

describe("parseSdJwt", () => {
  const header = b64u('{"typ":"vc+sd-jwt","alg":"ES256"}');
  const payload = b64u(
    '{"iss":"https://issuer.example.com","iat":1700000000,"_sd_alg":"sha-256"}',
  );
  const signature = "AAAA";

  const disclosure1Json = '["salt1","given_name","Alice"]';
  const disclosure2Json = '["salt2","family_name","Smith"]';
  const disclosure1 = b64u(disclosure1Json);
  const disclosure2 = b64u(disclosure2Json);

  const baseToken = `${header}.${payload}.${signature}`;

  it("parses header, payload, and signature from a JWT-only token", () => {
    const result = parseSdJwt(`${baseToken}~`);

    expect(result.header.typ).toBe("vc+sd-jwt");
    expect(result.header.alg).toBe("ES256");
    expect(result.payload.iss).toBe("https://issuer.example.com");
    expect(result.payload.iat).toBe(1700000000);
    expect(result.payload._sd_alg).toBe("sha-256");
    expect(result.signature).toBe(signature);
    expect(result.signedPayload).toBe(`${header}.${payload}`);
  });

  it("parses disclosures into salt, name, and value", () => {
    const token = `${baseToken}~${disclosure1}~${disclosure2}~`;

    const result = parseSdJwt(token);

    expect(result.disclosures).toHaveLength(2);
    expect(result.disclosures[0]).toEqual({
      raw: disclosure1,
      salt: "salt1",
      name: "given_name",
      value: "Alice",
    });
    expect(result.disclosures[1]).toEqual({
      raw: disclosure2,
      salt: "salt2",
      name: "family_name",
      value: "Smith",
    });
  });

  it("captures a key-binding JWT when present at the end", () => {
    const kbHeader = b64u('{"typ":"kb+jwt","alg":"ES256"}');
    const kbPayload = b64u(
      '{"aud":"https://verifier.example.com","iat":1700000010,"nonce":"n-0S6_WzA2Mj"}',
    );
    const kbJwt = `${kbHeader}.${kbPayload}.BBBB`;
    const token = `${baseToken}~${disclosure1}~${kbJwt}`;

    const result = parseSdJwt(token);

    expect(result.disclosures).toHaveLength(1);
    expect(result.keyBindingJwt).toBe(kbJwt);
  });

  it("rejects a token without the SD-JWT separator", () => {
    expect(() => parseSdJwt(baseToken)).toThrow();
  });

  it("rejects a malformed JWT segment", () => {
    expect(() => parseSdJwt("not.a.token~")).toThrow();
  });

  it("rejects a malformed disclosure", () => {
    const malformed = b64u('"not-an-array"');
    expect(() => parseSdJwt(`${baseToken}~${malformed}~`)).toThrow();
  });
});

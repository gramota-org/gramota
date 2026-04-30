// Conformance: verify the canonical EU Commission SD-JWT example token's
// RS256 signature against the published issuer JWK.
//
// Fixtures:
//   - tests/fixtures/eu-issuer-key.public.json
//     (public part of refs/eudi-lib-jvm-sdjwt-kt/.../examplesIssuerKey.json)
//   - tests/fixtures/eu-issuance-sdjwt.txt (mirrored from the sd-jwt package)
//
// Source license: Apache-2.0 (European Commission).

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyJws } from "../../src/verify.js";
import {
  JoseVerificationError,
  type JsonWebKey,
} from "../../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "..", "fixtures");

const issuerKey = JSON.parse(
  readFileSync(join(fixturesDir, "eu-issuer-key.public.json"), "utf-8"),
) as JsonWebKey;

// The EU example SD-JWT begins with the JWS that the issuer signed.
// We extract the JWS portion (everything before the first `~`) for jose tests.
const sdJwtPath = join(
  here,
  "..",
  "..",
  "..",
  "sd-jwt",
  "tests",
  "fixtures",
  "eu-sdjwt-kt",
  "exampleIssuanceSdJwt.txt",
);
const fullToken = readFileSync(sdJwtPath, "utf-8").trim();
const issuerJws = fullToken.split("~")[0]!;

describe("EU issuer RS256 conformance", () => {
  it("verifies the EU example SD-JWT issuer signature", async () => {
    const verified = await verifyJws(issuerJws, issuerKey);

    expect(verified.alg).toBe("RS256");
    expect(verified.header.alg).toBe("RS256");
    expect(verified.payload["iss"]).toBe("https://example.com/issuer");
    expect(verified.payload["sub"]).toBe(
      "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    );
    expect(verified.payload["_sd_alg"]).toBe("sha-256");
  });

  it("rejects a token whose payload has been tampered with", async () => {
    // Flip a single character in the payload segment.
    const [headerB64, payloadB64, signature] = issuerJws.split(".") as [
      string,
      string,
      string,
    ];
    const tamperedPayload = payloadB64.slice(0, -2) + "AB";
    const tamperedJws = `${headerB64}.${tamperedPayload}.${signature}`;

    await expect(verifyJws(tamperedJws, issuerKey)).rejects.toBeInstanceOf(
      JoseVerificationError,
    );
  });

  it("rejects a token whose signature has been tampered with", async () => {
    const [headerB64, payloadB64, signature] = issuerJws.split(".") as [
      string,
      string,
      string,
    ];
    const tamperedSig = signature.slice(0, -4) + "AAAA";
    const tamperedJws = `${headerB64}.${payloadB64}.${tamperedSig}`;

    await expect(verifyJws(tamperedJws, issuerKey)).rejects.toBeInstanceOf(
      JoseVerificationError,
    );
  });

  it("rejects when the wrong public key is supplied", async () => {
    const wrongKey: JsonWebKey = {
      ...issuerKey,
      // Modify the modulus by swapping a couple of characters near the end.
      n: (issuerKey.n as string).slice(0, -4) + "AAAA",
    };

    await expect(verifyJws(issuerJws, wrongKey)).rejects.toBeInstanceOf(
      JoseVerificationError,
    );
  });

  it("rejects when the verifier's algorithm allowlist excludes RS256", async () => {
    await expect(
      verifyJws(issuerJws, issuerKey, { algorithms: ["ES256"] }),
    ).rejects.toBeInstanceOf(JoseVerificationError);
  });

  it("never permits alg=none, even if the allowlist contains everything else", async () => {
    const fakeNone = `${Buffer.from('{"alg":"none"}', "utf-8").toString(
      "base64url",
    )}.${issuerJws.split(".")[1]}.`;

    await expect(verifyJws(fakeNone, issuerKey)).rejects.toBeInstanceOf(
      JoseVerificationError,
    );
  });
});

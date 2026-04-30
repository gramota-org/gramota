// Conformance: round-trip verification using the canonical RFC 7515 §A.3
// ES256 key pair and payload. ECDSA signatures are non-deterministic, so we
// sign with the RFC's private key (using the `jose` library) and verify
// through our own wrapper. The keypair is the IETF spec ground truth.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { importJWK, SignJWT } from "jose";
import { verifyJws } from "../../src/verify.js";
import { JoseVerificationError, type JsonWebKey } from "../../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const vector = JSON.parse(
  readFileSync(
    join(here, "..", "fixtures", "rfc7515-a3-es256.json"),
    "utf-8",
  ),
) as {
  header: { alg: string };
  payload: Record<string, unknown>;
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
};

async function signWithRfcKey(): Promise<string> {
  const privateKey = await importJWK(
    vector.privateKey as Parameters<typeof importJWK>[0],
    "ES256",
  );
  return await new SignJWT(vector.payload as Record<string, unknown>)
    .setProtectedHeader({ alg: "ES256" })
    .sign(privateKey);
}

describe("RFC 7515 §A.3 ES256 conformance", () => {
  it("verifies a JWS signed with the RFC's canonical P-256 key", async () => {
    const jws = await signWithRfcKey();
    const verified = await verifyJws(jws, vector.publicKey);

    expect(verified.alg).toBe("ES256");
    expect(verified.payload["iss"]).toBe("joe");
    expect(verified.payload["exp"]).toBe(1300819380);
    expect(verified.payload["http://example.com/is_root"]).toBe(true);
  });

  it("rejects ES256 when the allowlist excludes it", async () => {
    const jws = await signWithRfcKey();
    await expect(
      verifyJws(jws, vector.publicKey, { algorithms: ["RS256"] }),
    ).rejects.toBeInstanceOf(JoseVerificationError);
  });

  it("accepts ES256 when allowlist explicitly includes it", async () => {
    const jws = await signWithRfcKey();
    const verified = await verifyJws(jws, vector.publicKey, {
      algorithms: ["ES256"],
    });
    expect(verified.alg).toBe("ES256");
  });
});

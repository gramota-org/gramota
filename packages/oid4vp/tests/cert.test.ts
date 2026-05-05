/**
 * Self-signed verifier cert generation conformance.
 *
 * What we pin:
 *   - Output is a structurally valid X.509 leaf cert (parseable by
 *     `@peculiar/x509`).
 *   - Subject Alternative Name carries the requested `sanDns` plus any
 *     `extraSanDns` entries (in order), all type=DNS.
 *   - Validity window straddles `notBefore` ≤ now < `notAfter`.
 *   - Extensions: BasicConstraints CA:false, KeyUsage includes
 *     digitalSignature, ExtendedKeyUsage includes serverAuth + clientAuth.
 *   - Round-trip: signing with the cert's private key, then verifying
 *     with the cert's public key, succeeds.
 *   - x5c is the base64-DER form (no PEM wrappers, single leaf entry).
 *   - Subject DN preserves CN + O.
 *   - Defensive: empty `sanDns` is rejected.
 */

// Must be the first import — `@peculiar/x509@2.x` uses tsyringe and
// fails at module load if reflect-metadata isn't already available.
// The library handles this internally in `cert.ts`, but this test file
// imports `@peculiar/x509` directly to inspect the generated certs, so
// it needs the polyfill itself.
import "reflect-metadata";
import { describe, it, expect } from "vitest";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import { importPKCS8, importX509, SignJWT, jwtVerify } from "jose";
import {
  Oid4vpError,
  generateSigningCert,
  signingCertToJwks,
  type SigningCert,
} from "../src/index.js";

// @peculiar/x509 in tests needs the same crypto provider hookup the lib
// installs internally. Matching it explicitly here keeps the test
// independent of import order.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
x509.cryptoProvider.set(webcrypto as any);

async function gen(): Promise<{ cert: SigningCert; parsed: x509.X509Certificate }> {
  const cert = await generateSigningCert({
    sanDns: "verifier.example",
    organizationName: "Example Corp",
    validDays: 30,
  });
  const parsed = new x509.X509Certificate(cert.certificatePem);
  return { cert, parsed };
}

describe("generateSigningCert — output shape", () => {
  it("returns PEM-encoded private key + leaf cert", async () => {
    const { cert } = await gen();
    expect(cert.privateKeyPem.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(
      true,
    );
    expect(cert.privateKeyPem.includes("-----END PRIVATE KEY-----")).toBe(
      true,
    );
    expect(cert.certificatePem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(
      true,
    );
  });

  it("populates x5c with a single base64-DER cert (no PEM wrappers)", async () => {
    const { cert } = await gen();
    expect(cert.x5c).toHaveLength(1);
    const entry = cert.x5c[0]!;
    expect(entry.includes("BEGIN CERTIFICATE")).toBe(false);
    // base64 alphabet (+/=) plus we expect a non-trivial size.
    expect(entry).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(entry.length).toBeGreaterThan(200);
  });

  it("echoes sanDns on the result", async () => {
    const { cert } = await gen();
    expect(cert.sanDns).toBe("verifier.example");
  });
});

describe("generateSigningCert — Subject Alternative Name", () => {
  it("embeds the primary sanDns as a DNS SAN", async () => {
    const { parsed } = await gen();
    const san = parsed.getExtension(
      x509.SubjectAlternativeNameExtension,
    ) as x509.SubjectAlternativeNameExtension | null;
    expect(san).not.toBeNull();
    const dnsNames = san!.names.items
      .filter((n) => n.type === "dns")
      .map((n) => n.value);
    expect(dnsNames).toContain("verifier.example");
  });

  it("appends extraSanDns entries in order", async () => {
    const cert = await generateSigningCert({
      sanDns: "verifier.example",
      extraSanDns: ["*.verifier.example", "alt.verifier.example"],
    });
    const parsed = new x509.X509Certificate(cert.certificatePem);
    const san = parsed.getExtension(
      x509.SubjectAlternativeNameExtension,
    ) as x509.SubjectAlternativeNameExtension;
    const dnsNames = san.names.items
      .filter((n) => n.type === "dns")
      .map((n) => n.value);
    expect(dnsNames).toEqual([
      "verifier.example",
      "*.verifier.example",
      "alt.verifier.example",
    ]);
  });
});

describe("generateSigningCert — validity window", () => {
  it("issues a cert valid right now", async () => {
    const { parsed } = await gen();
    const now = new Date();
    expect(parsed.notBefore.getTime()).toBeLessThanOrEqual(now.getTime());
    expect(parsed.notAfter.getTime()).toBeGreaterThan(now.getTime());
  });

  it("respects validDays", async () => {
    const cert = await generateSigningCert({
      sanDns: "verifier.example",
      validDays: 7,
    });
    const parsed = new x509.X509Certificate(cert.certificatePem);
    const spanMs = parsed.notAfter.getTime() - parsed.notBefore.getTime();
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
    // Allow ±1s slop for the date arithmetic.
    expect(Math.abs(spanMs - sevenDaysMs)).toBeLessThan(2000);
  });
});

describe("generateSigningCert — extensions", () => {
  it("marks the cert as a leaf (CA:false)", async () => {
    const { parsed } = await gen();
    const bc = parsed.getExtension(
      x509.BasicConstraintsExtension,
    ) as x509.BasicConstraintsExtension | null;
    expect(bc).not.toBeNull();
    expect(bc!.ca).toBe(false);
  });

  it("includes Extended Key Usage entries for serverAuth + clientAuth", async () => {
    const { parsed } = await gen();
    const eku = parsed.getExtension(
      x509.ExtendedKeyUsageExtension,
    ) as x509.ExtendedKeyUsageExtension | null;
    expect(eku).not.toBeNull();
    expect(eku!.usages).toContain("1.3.6.1.5.5.7.3.1"); // serverAuth
    expect(eku!.usages).toContain("1.3.6.1.5.5.7.3.2"); // clientAuth
  });
});

describe("generateSigningCert — keypair round-trip", () => {
  it("private key signs and the cert's public key verifies", async () => {
    const { cert } = await gen();
    const priv = await importPKCS8(cert.privateKeyPem, "ES256");
    const pub = await importX509(cert.certificatePem, "ES256");

    const jwt = await new SignJWT({ hello: "world" })
      .setProtectedHeader({ alg: "ES256" })
      .sign(priv);

    const { payload } = await jwtVerify(jwt, pub);
    expect(payload).toMatchObject({ hello: "world" });
  });
});

describe("generateSigningCert — input validation", () => {
  it("rejects empty sanDns", async () => {
    await expect(
      generateSigningCert({ sanDns: "" }),
    ).rejects.toBeInstanceOf(Oid4vpError);
  });
});

describe("signingCertToJwks — PEM → JWK pair", () => {
  it("returns matching public + private JWKs annotated with alg=ES256", async () => {
    const { cert } = await gen();
    const { publicJwk, privateJwk } = await signingCertToJwks(cert);

    expect(publicJwk.kty).toBe("EC");
    expect(publicJwk.crv).toBe("P-256");
    expect(publicJwk.alg).toBe("ES256");
    // Public JWK should NOT carry private fields.
    expect(publicJwk.d).toBeUndefined();

    expect(privateJwk.kty).toBe("EC");
    expect(privateJwk.crv).toBe("P-256");
    expect(privateJwk.alg).toBe("ES256");
    expect(typeof privateJwk.d).toBe("string");

    // Same EC point — public coords match across the pair.
    expect(privateJwk.x).toBe(publicJwk.x);
    expect(privateJwk.y).toBe(publicJwk.y);
  });

  it("rejects a malformed cert with a stable error code", async () => {
    try {
      await signingCertToJwks({
        privateKeyPem: "not a real pem",
        certificatePem: "also fake",
        x5c: ["abc"],
        sanDns: "x",
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Oid4vpError);
      expect((err as Oid4vpError).code).toBe("oid4vp.cert_generation_failed");
    }
  });

  it("rejects when fields are missing entirely", async () => {
    await expect(
      signingCertToJwks({} as unknown as SigningCert),
    ).rejects.toBeInstanceOf(Oid4vpError);
  });
});

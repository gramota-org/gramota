/**
 * X.509 self-signed cert generation for OID4VP verifiers.
 *
 * The EU reference wallet's `X509SanDns` client_id_prefix accepts
 * Authorization Requests signed by a cert whose Subject Alternative Name
 * matches the verifier's hostname. For local dev, mock environments, and
 * pinned-trust deployments we generate a fresh ES256 keypair + a leaf
 * cert with the right SAN. Production deployments swap this for an
 * externally issued cert (ACME / corporate CA) — the {@link SigningCert}
 * shape is the same, only the origin differs.
 *
 * The cert+key pair is consumed by:
 *   1. `signAuthorizationRequest` — signs the JAR JWS, embedding the
 *      cert in the `x5c` header.
 *   2. The wallet's TLS / trust-anchor store — it must trust this cert
 *      out-of-band (in production: via a CA the wallet already trusts;
 *      for emulators: via patching the wallet's trust list).
 */

// `@peculiar/x509@2.x` uses tsyringe for dependency injection, which in
// turn requires the Reflect.metadata polyfill at module load time. We
// import it here so consumers don't have to. The package.json marks
// `dist/cert.js` as a side-effecting module so bundlers don't drop it.
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import { exportJWK, importPKCS8, importX509 } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import { Oid4vpError, type SigningCert } from "./types.js";

// @peculiar/x509 needs a Web Crypto provider — Node's webcrypto suffices.
// Safe to call multiple times; no-op after first.
let cryptoProviderSet = false;
function ensureCryptoProvider(): void {
  if (cryptoProviderSet) return;
  // @peculiar/x509's CryptoProvider type wants a DOM `Crypto`. Node's
  // webcrypto is API-compatible — the cast is just to satisfy TS.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  x509.cryptoProvider.set(webcrypto as any);
  cryptoProviderSet = true;
}

export interface GenerateSigningCertOptions {
  /** Primary DNS name for the cert's Subject Alternative Name. Must match
   * the verifier's hostname (the part the wallet sees in the OID4VP
   * `client_id` after the `x509_san_dns:` prefix). */
  readonly sanDns: string;
  /** Additional SAN-DNS entries — used for wildcards (e.g. `*.localtest.me`)
   * so a single cert covers per-tenant subdomains, or for serving multiple
   * verifier hostnames behind one identity. */
  readonly extraSanDns?: readonly string[];
  /** Cert subject CN — purely cosmetic, shown in cert viewers. Defaults
   * to `sanDns`. */
  readonly commonName?: string;
  /** Org name for the cert subject. Defaults to `"Gramota Verifier"`. */
  readonly organizationName?: string;
  /** Validity in days. Default 365. */
  readonly validDays?: number;
}

/**
 * Generate an ES256 keypair + self-signed X.509 cert with the given
 * SAN-DNS entries.
 *
 * The cert carries the standard verifier-identity extensions: serverAuth
 * + clientAuth EKUs (so wallets that look for a TLS-style cert accept
 * it), digitalSignature + keyEncipherment KU flags, and CA:false.
 *
 * Returns a {@link SigningCert} ready to feed into
 * {@link signAuthorizationRequest}.
 *
 * @throws {@link Oid4vpError} with `oid4vp.cert_generation_failed` if
 *   the underlying crypto / X.509 generation fails.
 */
export async function generateSigningCert(
  input: GenerateSigningCertOptions,
): Promise<SigningCert> {
  if (typeof input.sanDns !== "string" || input.sanDns.length === 0) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      "generateSigningCert: sanDns is required",
    );
  }

  ensureCryptoProvider();

  const validDays = input.validDays ?? 365;
  const notBefore = new Date();
  const notAfter = new Date(
    notBefore.getTime() + validDays * 24 * 60 * 60 * 1000,
  );

  // ES256 — the algorithm the EU wallet uses for KB-JWT and what most
  // OID4VP implementations default to.
  const algorithm = { name: "ECDSA", namedCurve: "P-256" } as const;
  const keys = await webcrypto.subtle.generateKey(algorithm, true, [
    "sign",
    "verify",
  ]);

  const subjectName = buildSubjectDn({
    commonName: input.commonName ?? input.sanDns,
    organizationName: input.organizationName ?? "Gramota Verifier",
  });

  let cert: x509.X509Certificate;
  try {
    cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: randomSerial(),
      name: subjectName,
      notBefore,
      notAfter,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      keys,
      extensions: [
        // Subject Alternative Name — what the wallet validates against
        // `client_id` (OID4VP `x509_san_dns:<host>`) and what TLS clients
        // match the host header against.
        new x509.SubjectAlternativeNameExtension([
          { type: "dns", value: input.sanDns },
          ...(input.extraSanDns ?? []).map((value) => ({
            type: "dns" as const,
            value,
          })),
        ]),
        // Standard verifier-identity usage flags.
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        ),
        new x509.ExtendedKeyUsageExtension([
          // serverAuth — wallets that expect a TLS-style cert accept this
          "1.3.6.1.5.5.7.3.1",
          // clientAuth — used by some wallets to bind the verifier identity
          "1.3.6.1.5.5.7.3.2",
        ]),
        // Leaf cert, not a CA.
        new x509.BasicConstraintsExtension(false),
      ],
    });
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      `generateSigningCert: X.509 generation failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  // Export private key as PKCS#8 PEM
  const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  const privateKeyPem = derToPem(new Uint8Array(pkcs8), "PRIVATE KEY");

  // Cert PEM
  const certificatePem = cert.toString("pem");

  // x5c header value: array of base64-encoded DER certs (no PEM wrappers).
  const certDer = new Uint8Array(cert.rawData);
  const x5c = [bytesToBase64(certDer)];

  return {
    privateKeyPem,
    certificatePem,
    x5c,
    sanDns: input.sanDns,
  };
}

/**
 * Convert a {@link SigningCert} (PEM bundle) into the JWK pair that
 * `@gramota/issuer` and other JOSE consumers expect.
 *
 * Unlike `generateSigningCert` this is a pure conversion — it doesn't
 * touch crypto state or generate anything new. It just bridges the two
 * representations of the same key material:
 *
 *   - Input shape: PKCS#8 PEM (private) + X.509 PEM (public-via-cert)
 *   - Output shape: two RFC 7517 JWKs with `alg: "ES256"` set
 *
 * Throws {@link Oid4vpError} with `oid4vp.cert_generation_failed` on a
 * malformed PEM or an unrecognised key type.
 */
export async function signingCertToJwks(
  cert: SigningCert,
): Promise<{ publicJwk: JsonWebKey; privateJwk: JsonWebKey }> {
  if (
    cert === null ||
    typeof cert !== "object" ||
    typeof cert.privateKeyPem !== "string" ||
    typeof cert.certificatePem !== "string"
  ) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      "signingCertToJwks: cert must include privateKeyPem and certificatePem",
    );
  }

  let privateJwk;
  let publicJwk;
  try {
    const priv = await importPKCS8(cert.privateKeyPem, "ES256");
    const pub = await importX509(cert.certificatePem, "ES256");
    privateJwk = (await exportJWK(priv)) as JsonWebKey;
    publicJwk = (await exportJWK(pub)) as JsonWebKey;
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      `signingCertToJwks: failed to import key material: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  // Annotate with `alg` so downstream consumers (e.g. @gramota/issuer)
  // can pick a JWS algorithm without re-deriving it.
  privateJwk.alg = "ES256";
  publicJwk.alg = "ES256";

  return { publicJwk, privateJwk };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function buildSubjectDn(parts: {
  commonName: string;
  organizationName: string;
}): string {
  return `CN=${escapeDn(parts.commonName)}, O=${escapeDn(parts.organizationName)}`;
}

function escapeDn(value: string): string {
  // Minimal RFC 4514 escaping — commas, equals, plus.
  return value.replace(/([,=+])/g, "\\$1");
}

function randomSerial(): string {
  // 20-byte hex string — RFC 5280 §4.1.2.2 says serials must be positive
  // integers up to 20 octets.
  const bytes = new Uint8Array(20);
  webcrypto.getRandomValues(bytes);
  // Ensure leading byte isn't zero so it's a positive integer.
  if (bytes[0] === 0) bytes[0] = 1;
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function derToPem(der: Uint8Array, label: string): string {
  const b64 = bytesToBase64(der);
  // 64-char wrap per RFC 7468.
  const wrapped = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

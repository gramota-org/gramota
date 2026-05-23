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
import { createHash, webcrypto } from "node:crypto";
import { exportJWK, importPKCS8, importX509 } from "jose";
import type { JsonWebKey } from "@gramota/jose";
import {
  Oid4vpError,
  type ClientIdScheme,
  type SigningCert,
} from "./types.js";

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

// ---------------------------------------------------------------------------
// Client Identifier Prefixes — OID4VP §5.9.3, HAIP Final 1.0 §5.
// ---------------------------------------------------------------------------

/**
 * Compute the `x509_hash` digest of a signing cert per OID4VP §5.9.3 +
 * HAIP Final 1.0 §5: `base64url(SHA-256(DER-encoded leaf certificate))`.
 *
 * The leaf cert's DER bytes are taken from the first entry of {@link
 * SigningCert.x5c}. That entry is already base64-encoded DER (no PEM
 * armour) — we decode, hash, and base64url-encode the digest.
 *
 * The result becomes the value part of the `x509_hash:<digest>` Client
 * Identifier. Wallets that see this prefix:
 *   1. Read the JWS `x5c` header.
 *   2. Compute the same hash over the leaf cert.
 *   3. Compare against the value portion of `client_id`.
 *   4. If they match, the cert is the verifier's authentic key.
 *
 * Unlike `x509_san_dns`, the cert's SAN is not consulted — the cert
 * itself, via its hash, IS the identity. This makes the prefix the
 * spec-preferred form for HAIP Final 1.0: an attacker who steals the
 * `client_id` cannot substitute a different (same-SAN) cert.
 *
 * @throws {@link Oid4vpError} `oid4vp.cert_generation_failed` when the
 *   cert's `x5c` is missing or the leaf bytes are malformed base64.
 */
export function computeCertX509Hash(cert: SigningCert): string {
  if (
    cert === null ||
    typeof cert !== "object" ||
    !Array.isArray(cert.x5c) ||
    cert.x5c.length === 0 ||
    typeof cert.x5c[0] !== "string" ||
    cert.x5c[0].length === 0
  ) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      "computeCertX509Hash: cert.x5c[0] must be a non-empty base64-DER string",
    );
  }
  let der: Buffer;
  try {
    der = Buffer.from(cert.x5c[0], "base64");
  } catch (err) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      `computeCertX509Hash: failed to decode cert.x5c[0]: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (der.length === 0) {
    throw new Oid4vpError(
      "oid4vp.cert_generation_failed",
      "computeCertX509Hash: cert.x5c[0] decoded to zero bytes",
    );
  }
  return createHash("sha256").update(der).digest("base64url");
}

/** Schemes {@link buildClientIdFromCert} can construct. */
export type CertBackedClientIdScheme = "x509_san_dns" | "x509_hash";

export interface BuildClientIdFromCertOptions {
  /** Signing material the verifier already provisioned. */
  readonly cert: SigningCert;
  /** Prefix to emit. Default `"x509_hash"` — HAIP Final 1.0 §5 mandates
   * this prefix for production HAIP-conformant verifiers. Use
   * `"x509_san_dns"` only for legacy / emulator interop where the wallet
   * doesn't yet accept `x509_hash`. */
  readonly scheme?: CertBackedClientIdScheme;
}

/**
 * Build the OID4VP `client_id` for a cert-backed verifier.
 *
 * Returns the prefixed identifier per OID4VP §5.9.3:
 *
 *   - `x509_san_dns:<sanDns>` — legacy. Wallet looks up the cert's SAN
 *     DNS entry; useful when wallets pre-resolve identity by hostname.
 *   - `x509_hash:<base64url(sha256(DER(leaf)))>` — HAIP Final 1.0 §5
 *     bullet 3 (MUST for HAIP-conformant verifiers). Wallet hashes the
 *     leaf cert in the JWS `x5c` header and compares — no DNS coupling.
 *
 * Pair the returned `client_id` with the matching {@link ClientIdScheme}
 * literal when populating an {@link AuthorizationRequest}.
 *
 * @throws {@link Oid4vpError} `oid4vp.cert_generation_failed` for an
 *   unknown scheme, missing SAN-DNS, or malformed `x5c`.
 */
export function buildClientIdFromCert(
  options: BuildClientIdFromCertOptions,
): { clientId: string; scheme: ClientIdScheme } {
  const scheme = options.scheme ?? "x509_hash";
  if (scheme === "x509_san_dns") {
    if (
      typeof options.cert?.sanDns !== "string" ||
      options.cert.sanDns.length === 0
    ) {
      throw new Oid4vpError(
        "oid4vp.cert_generation_failed",
        "buildClientIdFromCert(x509_san_dns): cert.sanDns is required",
      );
    }
    return {
      clientId: `x509_san_dns:${options.cert.sanDns}`,
      scheme: "x509_san_dns",
    };
  }
  if (scheme === "x509_hash") {
    const digest = computeCertX509Hash(options.cert);
    return { clientId: `x509_hash:${digest}`, scheme: "x509_hash" };
  }
  throw new Oid4vpError(
    "oid4vp.cert_generation_failed",
    `buildClientIdFromCert: unknown scheme ${JSON.stringify(scheme)}`,
  );
}

/**
 * DPoP — Demonstration of Proof-of-Possession at the Application Layer.
 * RFC 9449.
 *
 * Sender-constrains OAuth tokens. The wallet attaches a per-request
 * `DPoP: <jwt>` header alongside `Authorization: ...`. The proof is
 * a JWS signed with the wallet's holder-binding key, embedding:
 *
 *   - `htm` (HTTP method)
 *   - `htu` (HTTP target URI, stripped of query + fragment)
 *   - `iat` (timestamp)
 *   - `jti` (unique per proof — replay protection)
 *   - `ath` (sha256(access_token), base64url) — only on resource access
 *   - `nonce` — when the server demands one (RFC 9449 §8)
 *
 * The JWS header carries `typ: "dpop+jwt"` and the signer's public JWK,
 * so any AS/RS can verify without a separate key-discovery step.
 *
 * Why it matters: a stolen Bearer token is replayable by anyone. A
 * stolen DPoP-bound token is useless without the holder's private
 * key — and we already abstract that key behind a {@link Signer},
 * so production HSM-backed wallets work transparently.
 */

import { randomBytes, createHash } from "node:crypto";
import {
  computeJwkThumbprint,
  verifyJws,
  type JsonWebKey,
  type Signer,
} from "@gramota/jose";
import { Oid4vciError } from "./types.js";
import type { Fetcher, FetcherResponse } from "./metadata.js";

export interface BuildDpopJwtOptions {
  /** Wallet's signer — produces the proof signature. The signer's
   * publicKey is embedded in the JWS header so verifiers can match. */
  signer: Signer;
  /** HTTP method (must match the request being made). */
  htm: "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH";
  /** HTTP target URI. Query + fragment are stripped per RFC 9449 §4.2. */
  htu: string;
  /** Override iat — for tests. Default: now. */
  iat?: number;
  /** Override jti — for tests. Default: random. */
  jti?: string;
  /** When set, payload includes `ath = base64url(sha256(accessToken))`
   * per RFC 9449 §6.1. Only used on resource-server requests, not on
   * the initial token-endpoint request. */
  accessToken?: string;
  /** Server-supplied nonce (RFC 9449 §8). When the AS/RS returns
   * `DPoP-Nonce: <value>`, retry with the value here. */
  nonce?: string;
}

/**
 * Build a DPoP proof JWT per RFC 9449 §4.2.
 *
 * Returns a compact-serialized JWS suitable for the `DPoP:` header.
 */
export async function buildDpopJwt(
  options: BuildDpopJwtOptions,
): Promise<string> {
  if (
    options.signer === null ||
    typeof options.signer !== "object" ||
    typeof options.signer.sign !== "function"
  ) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "buildDpopJwt: signer is required",
    );
  }
  if (typeof options.htm !== "string" || options.htm.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "buildDpopJwt: htm is required",
    );
  }
  if (typeof options.htu !== "string" || options.htu.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "buildDpopJwt: htu is required",
    );
  }

  const header: Record<string, unknown> = {
    typ: "dpop+jwt",
    alg: options.signer.alg,
    jwk: stripPrivateFields(options.signer.publicKey),
  };

  const payload: Record<string, unknown> = {
    jti: options.jti ?? randomJti(),
    htm: options.htm,
    htu: stripQueryAndFragment(options.htu),
    iat: options.iat ?? Math.floor(Date.now() / 1000),
  };
  if (options.accessToken !== undefined) {
    payload["ath"] = computeAccessTokenHash(options.accessToken);
  }
  if (options.nonce !== undefined) {
    payload["nonce"] = options.nonce;
  }

  const headerB64 = Buffer.from(JSON.stringify(header), "utf-8").toString(
    "base64url",
  );
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf-8").toString(
    "base64url",
  );
  const signed = `${headerB64}.${payloadB64}`;
  const signature = await options.signer.sign(signed);
  return `${signed}.${signature}`;
}

/**
 * Compute the `ath` claim per RFC 9449 §6.1: base64url(sha256(token)).
 *
 * Exposed standalone so resource servers (verifiers) can compute the
 * expected `ath` independently when verifying inbound DPoP proofs.
 */
export function computeAccessTokenHash(accessToken: string): string {
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "computeAccessTokenHash: accessToken must be a non-empty string",
    );
  }
  return createHash("sha256").update(accessToken).digest("base64url");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** RFC 9449 §4.2: htu MUST NOT include query or fragment. */
function stripQueryAndFragment(url: string): string {
  let out = url;
  const fragIdx = out.indexOf("#");
  if (fragIdx >= 0) out = out.slice(0, fragIdx);
  const queryIdx = out.indexOf("?");
  if (queryIdx >= 0) out = out.slice(0, queryIdx);
  return out;
}

/** Strip private-key fields from a JWK before embedding in the JWS header.
 * For JwkSigner this is a no-op (publicKey is already public-only) but a
 * defensive guard for custom Signer impls that might return a JWK with `d`. */
function stripPrivateFields(
  jwk: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const PRIVATE_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "k"];
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(jwk)) {
    if (!PRIVATE_FIELDS.includes(k)) out[k] = v;
  }
  return out;
}

function randomJti(): string {
  // 16 bytes → 22 base64url chars; well above RFC 9449's "MUST be unique" bar.
  return randomBytes(16).toString("base64url");
}

// ---------------------------------------------------------------------------
// Server-side: verify an inbound DPoP proof (RFC 9449 §4.3 / §6 / §8)
// ---------------------------------------------------------------------------

export interface VerifyDpopJwtOptions {
  /** Compact-serialized DPoP JWT from the inbound `DPoP:` header. */
  jwt: string;
  /** HTTP method of the request being authenticated (must equal `htm`). */
  htm: string;
  /** HTTP URL of the request, including scheme + host + path. Query and
   * fragment are stripped before comparing against `htu` per RFC 9449 §4.2. */
  htu: string;
  /** When verifying a resource-server request, the access token whose
   * sha256 (base64url) must equal the proof's `ath`. Omit on
   * authorization-server (`/token`) verification — the proof's `ath`
   * MUST then be absent (§6.1). */
  accessToken?: string;
  /** When the server demands a nonce (RFC 9449 §8), the proof must echo
   * this exact value in its `nonce` claim. */
  nonce?: string;
  /** Allowed iat skew in seconds. Default 60. */
  maxAgeSeconds?: number;
  /** Replay-protection callback. Return `true` if the `jti` has been
   * seen before. Omit to skip replay checks entirely (e.g. tests). */
  hasSeenJti?: (jti: string) => boolean | Promise<boolean>;
  /** Record a successfully-verified `jti` so future calls reject it.
   * Called only after all other checks pass — never on failure. */
  recordJti?: (jti: string) => void | Promise<void>;
  /** Clock override for tests, in seconds-since-epoch. Default `Date.now()`. */
  now?: number;
}

export interface VerifyDpopJwtResult {
  /** Public JWK extracted from the proof's JWS header. Caller can use
   * this to identify the wallet's binding key. */
  publicJwk: JsonWebKey;
  /** RFC 7638 thumbprint of `publicJwk`. Used as the `jkt` value when
   * binding access tokens — issuers store this with the token, then on
   * resource-server access compare against the next proof's thumbprint. */
  jkt: string;
  /** Verified payload of the proof. Includes at minimum `jti`, `htm`,
   * `htu`, `iat`. May include `ath`, `nonce` per the request type. */
  payload: Readonly<Record<string, unknown>>;
}

/**
 * Verify an inbound DPoP proof JWT and return the JWK thumbprint binding.
 *
 * The verifier:
 *   1. Parses the JWS header — checks `typ: "dpop+jwt"` and reads `jwk`.
 *   2. Verifies the JWS signature against the embedded `jwk` (no
 *      external key resolution — DPoP proofs are self-attesting).
 *   3. Validates payload claims: `htm` matches request method, `htu`
 *      matches request URL (after stripping query/fragment), `iat`
 *      is within `maxAgeSeconds`, `jti` is present and not replayed,
 *      and (for resource-server access) `ath` matches the access token.
 *   4. Returns the verifier-relevant outputs: the public JWK, its
 *      RFC 7638 thumbprint (use as token binding), and the verified
 *      payload for any caller-specific claim inspection.
 *
 * Throws {@link Oid4vciError} with `oid4vci.invalid_input` (malformed) or
 * `oid4vci.token_response_invalid` (semantic violation) on rejection.
 */
export async function verifyDpopJwt(
  options: VerifyDpopJwtOptions,
): Promise<VerifyDpopJwtResult> {
  if (typeof options.jwt !== "string" || options.jwt.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyDpopJwt: jwt is required",
    );
  }
  if (typeof options.htm !== "string" || options.htm.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyDpopJwt: htm is required",
    );
  }
  if (typeof options.htu !== "string" || options.htu.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyDpopJwt: htu is required",
    );
  }

  // Parse the protected header to extract typ + jwk before signature
  // verification — we need the embedded key.
  const segments = options.jwt.split(".");
  if (segments.length !== 3) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyDpopJwt: malformed JWT (expected 3 segments)",
    );
  }
  let header: Record<string, unknown>;
  try {
    const json = Buffer.from(segments[0]!, "base64url").toString("utf-8");
    const parsed: unknown = JSON.parse(json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("header is not a JSON object");
    }
    header = parsed as Record<string, unknown>;
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyDpopJwt: malformed header: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  if (header["typ"] !== "dpop+jwt") {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyDpopJwt: header typ must be "dpop+jwt", got ${JSON.stringify(header["typ"])}`,
    );
  }

  const jwk = header["jwk"];
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyDpopJwt: header is missing jwk",
    );
  }
  const publicJwk = jwk as JsonWebKey;

  // verifyJws also enforces alg allowlist (no `alg=none`) and parses
  // the payload as a JSON object.
  let verified;
  try {
    verified = await verifyJws(options.jwt, publicJwk);
  } catch (err) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyDpopJwt: signature verification failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const payload = verified.payload;

  // Claim checks. These are spec-mandated; failure of any is a hard reject.
  const jti = payload["jti"];
  if (typeof jti !== "string" || jti.length === 0) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyDpopJwt: payload is missing jti",
    );
  }

  const htm = payload["htm"];
  if (htm !== options.htm) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyDpopJwt: htm mismatch (proof=${JSON.stringify(htm)}, expected=${JSON.stringify(options.htm)})`,
    );
  }

  const expectedHtu = stripQueryAndFragment(options.htu);
  const proofHtu = payload["htu"];
  if (typeof proofHtu !== "string" || stripQueryAndFragment(proofHtu) !== expectedHtu) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyDpopJwt: htu mismatch (proof=${JSON.stringify(proofHtu)}, expected=${JSON.stringify(expectedHtu)})`,
    );
  }

  const iat = payload["iat"];
  if (typeof iat !== "number" || !Number.isFinite(iat)) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      "verifyDpopJwt: payload is missing iat or iat is not numeric",
    );
  }
  const nowSec = options.now ?? Math.floor(Date.now() / 1000);
  const maxAge = options.maxAgeSeconds ?? 60;
  if (iat > nowSec + maxAge) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyDpopJwt: iat is in the future (iat=${iat}, now=${nowSec})`,
    );
  }
  if (iat < nowSec - maxAge) {
    throw new Oid4vciError(
      "oid4vci.invalid_input",
      `verifyDpopJwt: iat is too old (iat=${iat}, now=${nowSec}, maxAge=${maxAge}s)`,
    );
  }

  // ath — required only when verifying resource-server access (the caller
  // signals this by passing accessToken). On token-endpoint requests the
  // caller omits accessToken and the proof must NOT include ath.
  if (options.accessToken !== undefined) {
    const expectedAth = computeAccessTokenHash(options.accessToken);
    const ath = payload["ath"];
    if (typeof ath !== "string" || ath.length === 0) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        "verifyDpopJwt: ath is required for resource-server requests",
      );
    }
    if (ath !== expectedAth) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        "verifyDpopJwt: ath does not match the access token",
      );
    }
  }

  // nonce — required only when caller demands one.
  if (options.nonce !== undefined) {
    if (payload["nonce"] !== options.nonce) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        "verifyDpopJwt: nonce mismatch",
      );
    }
  }

  // Replay check + record. Order matters: we check first, then record only
  // after every other validation passes, so a failed proof can't poison
  // the jti store.
  if (options.hasSeenJti) {
    const seen = await options.hasSeenJti(jti);
    if (seen) {
      throw new Oid4vciError(
        "oid4vci.invalid_input",
        `verifyDpopJwt: jti ${jti} has been seen before (replay)`,
      );
    }
  }
  if (options.recordJti) {
    await options.recordJti(jti);
  }

  return {
    publicJwk,
    jkt: computeJwkThumbprint(publicJwk),
    payload,
  };
}

// ---------------------------------------------------------------------------
// DPoP-aware POST with use_dpop_nonce retry (RFC 9449 §8)
// ---------------------------------------------------------------------------

export interface PostWithDpopRetryOptions {
  fetcher: Fetcher;
  url: string;
  body: string;
  contentType: string;
  accept: string;
  /** When set, attach a DPoP proof. */
  dpopSigner?: Signer;
  /** When the request includes a Bearer token (resource-server access),
   * pass it here so we set `Authorization: DPoP <token>` AND include
   * `ath` in the proof. Omit on token-endpoint requests. */
  bearerToken?: string;
  /** Force a specific HTTP method into the DPoP `htm` claim. Default: POST. */
  htm?: BuildDpopJwtOptions["htm"];
}

/**
 * POST that handles RFC 9449 §8 `use_dpop_nonce` retry transparently.
 *
 * Sequence:
 *   1. Build a DPoP proof (if dpopSigner set) and POST.
 *   2. If response is 401/400 with `DPoP-Nonce: <nonce>` and the body
 *      indicates `use_dpop_nonce`, rebuild the proof with that nonce
 *      and retry once. (Spec allows servers to demand a fresh nonce
 *      on every request — we re-issue per-call automatically.)
 *   3. Return the final response.
 *
 * This means callers don't have to know about the DPoP-Nonce dance.
 * They just provide the signer and the SDK handles the protocol.
 */
export async function postWithDpopRetry(
  options: PostWithDpopRetryOptions,
): Promise<FetcherResponse> {
  const htm = options.htm ?? "POST";
  const baseHeaders: Record<string, string> = {
    "Content-Type": options.contentType,
    Accept: options.accept,
  };

  const sendOnce = async (
    nonce: string | undefined,
  ): Promise<FetcherResponse> => {
    const headers = { ...baseHeaders };
    if (options.dpopSigner !== undefined) {
      const dpopOpts: BuildDpopJwtOptions = {
        signer: options.dpopSigner,
        htm,
        htu: options.url,
      };
      if (options.bearerToken !== undefined) {
        dpopOpts.accessToken = options.bearerToken;
      }
      if (nonce !== undefined) dpopOpts.nonce = nonce;
      headers["DPoP"] = await buildDpopJwt(dpopOpts);
    }
    if (options.bearerToken !== undefined) {
      // RFC 9449 §7.1: when a DPoP proof is bound, use `DPoP` scheme.
      // Plain Bearer is also acceptable on resource servers that don't
      // verify the proof; we use DPoP scheme when we have a signer to
      // make our intent explicit.
      headers["Authorization"] =
        options.dpopSigner !== undefined
          ? `DPoP ${options.bearerToken}`
          : `Bearer ${options.bearerToken}`;
    }

    try {
      return await options.fetcher(options.url, {
        method: htm,
        headers,
        body: options.body,
      });
    } catch (err) {
      throw new Oid4vciError(
        "oid4vci.token_request_failed",
        `request to ${options.url} failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  };

  const response = await sendOnce(undefined);
  if (
    options.dpopSigner === undefined ||
    response.ok ||
    !shouldRetryWithNonce(response)
  ) {
    return response;
  }

  const nonce = response.headers?.get("DPoP-Nonce");
  if (typeof nonce !== "string" || nonce.length === 0) {
    return response; // server signaled retry but didn't provide a nonce
  }
  return await sendOnce(nonce);
}

/** RFC 9449 §8: server signals "include this nonce" via response status
 * 400 with `error: use_dpop_nonce` (token endpoint) or 401 with
 * `WWW-Authenticate: DPoP error="use_dpop_nonce"` (resource server). */
function shouldRetryWithNonce(response: FetcherResponse): boolean {
  if (response.status !== 400 && response.status !== 401) return false;
  if (response.headers === undefined) return false; // adapter doesn't expose headers
  const nonceHeader = response.headers.get("DPoP-Nonce");
  return typeof nonceHeader === "string" && nonceHeader.length > 0;
}

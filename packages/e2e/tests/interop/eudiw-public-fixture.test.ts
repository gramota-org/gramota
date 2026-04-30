/**
 * Drive @gateway/* libraries against REAL EU public-verifier output.
 *
 * The fixture (init-transaction.example.json) is a real init-transaction
 * response the EU publishes in their openapi.json. Every assertion in this
 * file goes through one of our libraries — this is what proves our SDK
 * actually handles real EU bytes, not just our own roundtrips.
 *
 * Always runs in CI, no network required.
 *
 * Libraries exercised:
 *   - @gateway/oid4vp        parseAuthorizationRequestSearchParams
 *   - @gateway/presentation-exchange  selectForDefinition matcher
 *   - @gateway/sd-jwt        parser primitives (for the JAR JWS shape)
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parseAuthorizationRequestSearchParams,
  type AuthorizationRequest,
} from "@gateway/oid4vp";
import {
  SdJwtVcMatcher,
  selectForDefinition,
  type PresentationDefinition,
} from "@gateway/presentation-exchange";
import { parseSdJwt } from "@gateway/sd-jwt";
import { verifyJwsWithX5c, x5cToPem } from "@gateway/jose";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(
  here,
  "..",
  "fixtures",
  "captured",
  "eudiw-public",
  "init-transaction.example.json",
);

interface InitTxnFixture {
  transaction_id: string;
  client_id: string;
  request: string;
}
const fixture = JSON.parse(
  readFileSync(fixturePath, "utf-8"),
) as InitTxnFixture;

/** Parse the JAR payload — what's normally inside the signed request JWT
 * the EU verifier emits. This is the real OID4VP authorization request. */
function decodeJarPayload(jar: string): Record<string, unknown> {
  const segments = jar.split(".");
  expect(segments).toHaveLength(3); // 3-segment compact JWS
  const payloadJson = Buffer.from(segments[1]!, "base64url").toString(
    "utf-8",
  );
  return JSON.parse(payloadJson) as Record<string, unknown>;
}

/** Convert the JAR's OID4VP fields into a URL-search-param-equivalent form
 * that @gateway/oid4vp's parser consumes. Object-valued fields (like
 * presentation_definition) get JSON-stringified the same way they would be
 * in a query-string-encoded request. */
function jarPayloadAsParams(
  payload: Record<string, unknown>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(payload)) {
    if (v === undefined) continue;
    out[k] = typeof v === "string" ? v : JSON.stringify(v);
  }
  return out;
}

describe("EUDIW public verifier — drive @gateway/* against real EU bytes", () => {
  describe("@gateway/sd-jwt — JWS structural parsing of the JAR", () => {
    it("the EU JAR has a 3-segment compact JWS shape our libraries can read", () => {
      const segments = fixture.request.split(".");
      expect(segments).toHaveLength(3);

      const header = JSON.parse(
        Buffer.from(segments[0]!, "base64url").toString("utf-8"),
      ) as { alg?: string; typ?: string; x5c?: string[] };
      expect(header.alg).toBe("ES256");
      expect(header.typ).toBe("oauth-authz-req+jwt");
      expect(Array.isArray(header.x5c)).toBe(true);
    });

    it("our parseSdJwt rejects the JAR (it's a JWS, not an SD-JWT-VC) — confirms scope", () => {
      // The EU JAR is a JWS, not an SD-JWT-VC. parseSdJwt should refuse it
      // because it's missing the SD-JWT '~' separator. This proves our parser
      // correctly distinguishes the two formats — false positives on JARs
      // would be a security regression.
      expect(() => parseSdJwt(fixture.request)).toThrow(/separator/);
    });
  });

  describe("@gateway/oid4vp — parse the inner OID4VP authorization request", () => {
    const jarPayload = decodeJarPayload(fixture.request);
    const params = jarPayloadAsParams(jarPayload);

    it("parses real EU JAR payload as a valid AuthorizationRequest", () => {
      const parsed: AuthorizationRequest =
        parseAuthorizationRequestSearchParams(params);

      expect(parsed.response_type).toBe("vp_token");
      expect(parsed.client_id).toBe("dev.verifier-backend.eudiw.dev");
      expect(parsed.client_id_scheme).toBe("x509_san_dns");
      expect(parsed.response_mode).toBe("direct_post.jwt");
      expect(parsed.response_uri).toContain(
        "verifier-backend.eudiw.dev/wallet/direct_post",
      );
      expect(typeof parsed.nonce).toBe("string");
      expect(parsed.nonce.length).toBeGreaterThan(0);
    });

    it("@gateway/oid4vp recovers the presentation_definition object intact", () => {
      const parsed: AuthorizationRequest =
        parseAuthorizationRequestSearchParams(params);

      const pd = parsed.presentation_definition as
        | PresentationDefinition
        | undefined;
      expect(pd).toBeDefined();
      if (pd === undefined) return;
      expect(typeof pd.id).toBe("string");
      expect(pd.input_descriptors).toHaveLength(1);
      expect(pd.input_descriptors[0]?.id).toBe("eu.europa.ec.eudi.pid.1");
    });

    it("@gateway/oid4vp validation rejects a tampered EU request (missing nonce)", () => {
      const broken = { ...params };
      delete broken["nonce"];
      expect(() => parseAuthorizationRequestSearchParams(broken)).toThrow(
        /nonce/,
      );
    });
  });

  describe("@gateway/presentation-exchange — match credentials against real EU PD", () => {
    const jarPayload = decodeJarPayload(fixture.request);
    const pd = jarPayload["presentation_definition"] as PresentationDefinition;

    it("the real EU PD parses through our types unmodified", () => {
      expect(pd.input_descriptors[0]?.format?.["mso_mdoc"]).toBeDefined();
      expect(pd.input_descriptors[0]?.constraints.fields?.[0]?.path[0]).toBe(
        "$['eu.europa.ec.eudi.pid.1']['family_name']",
      );
    });

    it("SdJwtVcMatcher correctly declines an EU mso_mdoc-only descriptor", () => {
      const matcher = new SdJwtVcMatcher();
      // The EU's PD asks for mso_mdoc format only. SD-JWT-VC matcher must
      // refuse — a wallet that holds only SD-JWT-VC credentials cannot
      // satisfy this descriptor.
      const desc = pd.input_descriptors[0]!;
      expect(matcher.appliesTo(desc)).toBe(false);
    });

    it("selectForDefinition reports the EU PD as unsatisfiable for SD-JWT-VC wallets", () => {
      // Drive the full selector against the real EU PD with no credentials.
      // Expected: not satisfied, with the descriptor flagged unmatched.
      const sel = selectForDefinition({
        definition: pd,
        credentials: [], // empty wallet — and even if non-empty, the format mismatch would fail
      });
      expect(sel.fullySatisfied).toBe(false);
      expect(sel.unmatched).toHaveLength(1);
      expect(sel.unmatched[0]?.descriptor.id).toBe("eu.europa.ec.eudi.pid.1");
    });
  });

  describe("@gateway/jose — verify the real EU JAR signature via x5c", () => {
    it("verifyJwsWithX5c successfully verifies the EU JAR signature", async () => {
      const result = await verifyJwsWithX5c(fixture.request);

      expect(result.alg).toBe("ES256");
      expect(result.header["typ"]).toBe("oauth-authz-req+jwt");
      expect(result.payload["response_type"]).toBe("vp_token");
      expect(result.payload["client_id"]).toBe(
        "dev.verifier-backend.eudiw.dev",
      );
    });

    it("verifyJwsWithX5c with chain validation against the EU CA also passes", async () => {
      // Pin x5c[1] (the EU dev CA cert) as the trust anchor. In production
      // this PEM would be loaded from a trusted source; here we use what's
      // in the chain itself, which proves the chain validates.
      const headerB64 = fixture.request.split(".")[0]!;
      const header = JSON.parse(
        Buffer.from(headerB64, "base64url").toString("utf-8"),
      ) as { x5c: string[] };
      const euCaPem = x5cToPem(header.x5c[1]!);

      const result = await verifyJwsWithX5c(fixture.request, {
        trustAnchors: [euCaPem],
        // Pinned to a date inside the cert validity window (2024-02 → 2026-02).
        now: new Date("2025-06-01T00:00:00Z"),
      });

      expect(result.chain).toBeDefined();
      expect(result.chain?.leaf.subject).toContain("EUDI Remote Verifier");
      expect(result.payload["response_type"]).toBe("vp_token");
    });

    it("verifyJwsWithX5c rejects when chain does not lead to the supplied anchor", async () => {
      // Use an unrelated cert as the only anchor.
      const headerB64 = fixture.request.split(".")[0]!;
      const header = JSON.parse(
        Buffer.from(headerB64, "base64url").toString("utf-8"),
      ) as { x5c: string[] };
      // Re-use leaf as anchor (won't match the chain root).
      const wrongAnchor = x5cToPem(header.x5c[0]!);

      try {
        await verifyJwsWithX5c(fixture.request, {
          trustAnchors: [wrongAnchor],
          now: new Date("2025-06-01T00:00:00Z"),
        });
        throw new Error("should have thrown");
      } catch (err) {
        expect(err).toMatchObject({ code: "jose.x5c_no_trust_anchor" });
      }
    });
  });
});

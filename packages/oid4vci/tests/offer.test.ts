import { describe, it, expect } from "vitest";
import {
  Oid4vciError,
  parseCredentialOffer,
  parseOfferJson,
  buildCredentialOfferUrl,
  extractPreAuthorizedCode,
  extractTxCodeRequirement,
  type CredentialOffer,
} from "../src/index.js";

const validOffer: CredentialOffer = {
  credential_issuer: "https://issuer.example.com",
  credential_configuration_ids: ["pid-sd-jwt"],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "AbC123Xyz",
    },
  },
};

const offerUrl = (offer: object): string =>
  `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;

describe("parseCredentialOffer", () => {
  it("parses an offer-by-value URL", () => {
    const parsed = parseCredentialOffer(offerUrl(validOffer));
    expect(parsed.credential_issuer).toBe("https://issuer.example.com");
    expect(parsed.credential_configuration_ids).toEqual(["pid-sd-jwt"]);
  });

  it("works with custom URL schemes (openid-credential-offer, haip, etc.)", () => {
    const httpsForm = `https://wallet.example.com/credential_offer?credential_offer=${encodeURIComponent(JSON.stringify(validOffer))}`;
    const parsed = parseCredentialOffer(httpsForm);
    expect(parsed.credential_issuer).toBe("https://issuer.example.com");
  });

  it("rejects invalid URLs", () => {
    try {
      parseCredentialOffer("not a url");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Oid4vciError);
      expect((err as Oid4vciError).code).toBe("oid4vci.invalid_url");
    }
  });

  it("rejects URLs with no offer parameter", () => {
    try {
      parseCredentialOffer("openid-credential-offer://?other=foo");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.invalid_offer");
    }
  });

  it("rejects URLs that mix credential_offer with credential_offer_uri", () => {
    const mixed =
      "openid-credential-offer://?credential_offer=%7B%7D&credential_offer_uri=https%3A%2F%2Fx.com";
    try {
      parseCredentialOffer(mixed);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).message).toMatch(/mutually exclusive/);
    }
  });

  it("rejects offer-by-reference (credential_offer_uri) — must be fetched separately", () => {
    const byRef =
      "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Foffer";
    try {
      parseCredentialOffer(byRef);
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).message).toMatch(/separate fetch/);
    }
  });
});

describe("parseOfferJson", () => {
  it("rejects malformed JSON", () => {
    try {
      parseOfferJson("not-json");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).code).toBe("oid4vci.invalid_offer");
    }
  });

  it("rejects offers missing credential_issuer", () => {
    try {
      parseOfferJson(JSON.stringify({ credential_configuration_ids: ["x"] }));
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).message).toMatch(/credential_issuer/);
    }
  });

  it("rejects offers with empty credential_configuration_ids", () => {
    try {
      parseOfferJson(
        JSON.stringify({
          credential_issuer: "https://x.com",
          credential_configuration_ids: [],
        }),
      );
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Oid4vciError).message).toMatch(
        /credential_configuration_ids/,
      );
    }
  });
});

describe("extractPreAuthorizedCode", () => {
  it("returns the pre-authorized_code when present", () => {
    expect(extractPreAuthorizedCode(validOffer)).toBe("AbC123Xyz");
  });

  it("returns null when only authorization_code grant is present", () => {
    const offer: CredentialOffer = {
      credential_issuer: "https://x.com",
      credential_configuration_ids: ["x"],
      grants: { authorization_code: { issuer_state: "abc" } },
    };
    expect(extractPreAuthorizedCode(offer)).toBeNull();
  });

  it("returns null when no grants are specified", () => {
    const offer: CredentialOffer = {
      credential_issuer: "https://x.com",
      credential_configuration_ids: ["x"],
    };
    expect(extractPreAuthorizedCode(offer)).toBeNull();
  });
});

describe("extractTxCodeRequirement", () => {
  it("returns the tx_code requirement when the issuer demands one", () => {
    const offer: CredentialOffer = {
      credential_issuer: "https://x.com",
      credential_configuration_ids: ["x"],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": "abc",
          tx_code: { input_mode: "numeric", length: 6, description: "Pin" },
        },
      },
    };
    const req = extractTxCodeRequirement(offer);
    expect(req).toEqual({
      input_mode: "numeric",
      length: 6,
      description: "Pin",
    });
  });

  it("returns null when no tx_code is required", () => {
    expect(extractTxCodeRequirement(validOffer)).toBeNull();
  });
});

describe("buildCredentialOfferUrl", () => {
  it("round-trips through parseCredentialOffer (build → parse → equal)", () => {
    const url = buildCredentialOfferUrl(validOffer);
    expect(url.startsWith("openid-credential-offer://?credential_offer=")).toBe(true);
    const roundTripped = parseCredentialOffer(url);
    expect(roundTripped).toEqual(validOffer);
  });

  it("honours custom schemes", () => {
    const url = buildCredentialOfferUrl(validOffer, { scheme: "haip://" });
    expect(url.startsWith("haip://?credential_offer=")).toBe(true);
  });

  it("rejects offer missing credential_issuer", () => {
    expect(() =>
      // @ts-expect-error: missing required field
      buildCredentialOfferUrl({ credential_configuration_ids: ["pid"] }),
    ).toThrow(Oid4vciError);
  });

  it("rejects offer with empty credential_configuration_ids", () => {
    expect(() =>
      buildCredentialOfferUrl({
        credential_issuer: "https://x.example",
        credential_configuration_ids: [],
        grants: {},
      }),
    ).toThrow(Oid4vciError);
  });

  it("rejects malformed scheme", () => {
    expect(() =>
      buildCredentialOfferUrl(validOffer, { scheme: "not a scheme" }),
    ).toThrow(/scheme/i);
  });
});

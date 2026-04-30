import type { JsonWebKey } from "@gateway/jose";
import {
  buildAuthorizationResponseBody,
  parseAuthorizationRequestUrl,
  type AuthorizationRequest,
} from "@gateway/oid4vp";
import {
  Oid4vciClient,
  type AcceptOfferOptions,
  type CredentialOffer,
} from "@gateway/oid4vci";
import {
  buildPresentationSubmission,
  selectForDefinition,
  type PresentationDefinition,
  type SdJwtVcCredentialView,
} from "@gateway/presentation-exchange";
import { receiveCredential } from "./receive.js";
import { buildPresentation } from "./present.js";
import { InMemoryCredentialStore } from "./store/memory.js";
import {
  HolderError,
  type CredentialId,
  type CredentialQuery,
  type CredentialStore,
  type HolderConfig,
  type PresentOptions,
  type ReceiveOptions,
  type StoredCredential,
} from "./types.js";

/** Stripe-style sub-API for OID4VCI credential offers. `holder.offers.X(...)`. */
export interface OffersApi {
  /** Parse a credential offer URL with no network I/O — preview an offer
   * before deciding to accept it. */
  parse(url: string): CredentialOffer;
  /** Accept a credential offer end-to-end: parse → fetch metadata → token →
   * proof JWT → credential request → validate → store. Returns the
   * StoredCredential, same shape as `holder.credentials.receive`. */
  accept(url: string, options: AcceptOptions): Promise<StoredCredential>;
}

/** Options for `holder.offers.accept()`. Extends OID4VCI's accept options
 * with trustedIssuers (same semantics as credentials.receive). */
export interface AcceptOptions extends AcceptOfferOptions {
  /** Trusted issuer JWKs the received credential's signature must verify
   * against. The credential is rejected if it does not. */
  trustedIssuers: readonly JsonWebKey[];
}

/** Options for `holder.respondTo()`. */
export interface RespondOptions {
  /** Override "now" — for tests. */
  now?: () => number;
  /** When the verifier supplies multiple compatible credentials and you want
   * to control which one is presented, pass a picker. Default: first match. */
  pickCredential?: (
    candidates: readonly {
      credential: StoredCredential;
      disclose: readonly string[];
    }[],
  ) => { credential: StoredCredential; disclose: readonly string[] };
}

/** Result of `holder.respondTo()`. */
export interface RespondResult {
  /** Form-encoded body to POST to the verifier's `response_uri`. */
  body: string;
  /** The matched credential (id + token + parsed). */
  credential: StoredCredential;
  /** What was disclosed. */
  disclosed: readonly string[];
  /** The original parsed request, for caller logging. */
  request: AuthorizationRequest;
}

/** Stripe-style sub-API for credential CRUD. `holder.credentials.X(...)`. */
export interface CredentialsApi {
  /** Validate and store an issued SD-JWT-VC. */
  receive(token: string, options: ReceiveOptions): Promise<StoredCredential>;
  /** Get one stored credential by id. */
  get(id: CredentialId): Promise<StoredCredential | undefined>;
  /** List stored credentials, optionally filtered. */
  list(query?: CredentialQuery): Promise<readonly StoredCredential[]>;
  /** Remove a credential. Returns true if it existed. */
  remove(id: CredentialId): Promise<boolean>;
}

/**
 * The holder/wallet role in IETF SD-JWT-VC §6.
 *
 * Composes a key (holder's binding key) with a credential store (Strategy
 * pattern). The class is a thin orchestrator; the heavy lifting lives in
 * pure functions (receive, buildPresentation) that don't need an instance —
 * easier to test, easier to reuse without classes.
 */
export class Holder {
  private readonly config: HolderConfig;
  private readonly store: CredentialStore;

  /** Credential CRUD. `holder.credentials.{receive, list, get, remove}(...)`. */
  readonly credentials: CredentialsApi;

  /** OID4VCI offers. `holder.offers.{parse, accept}(...)`. */
  readonly offers: OffersApi;

  constructor(config: HolderConfig) {
    if (config.privateKey === null || typeof config.privateKey !== "object") {
      throw new TypeError("Holder: privateKey is required");
    }
    if (config.publicKey === null || typeof config.publicKey !== "object") {
      throw new TypeError("Holder: publicKey is required");
    }
    if (typeof config.alg !== "string" || config.alg.length === 0) {
      throw new TypeError("Holder: alg is required");
    }
    this.config = config;
    this.store = config.store ?? new InMemoryCredentialStore();

    this.credentials = {
      receive: (token, options) =>
        receiveCredential(token, this.config, this.store, options),
      get: (id) => this.store.get(id),
      list: (query) => this.store.list(query),
      remove: (id) => this.store.remove(id),
    };

    // OID4VCI client — built lazily so tests that don't use it incur no cost.
    let oid4vciClient: Oid4vciClient | undefined;
    const ensureClient = (): Oid4vciClient => {
      if (oid4vciClient === undefined) {
        oid4vciClient = new Oid4vciClient({
          holderPublicKey: this.config.publicKey,
          holderPrivateKey: this.config.privateKey,
          alg: this.config.alg,
        });
      }
      return oid4vciClient;
    };

    this.offers = {
      parse: (url) => ensureClient().parseOffer(url),
      accept: async (url, options) => {
        const client = ensureClient();
        const acceptOpts: AcceptOfferOptions = {};
        if (options.txCode !== undefined) acceptOpts.txCode = options.txCode;
        if (options.credentialConfigurationId !== undefined) {
          acceptOpts.credentialConfigurationId = options.credentialConfigurationId;
        }
        if (options.proofIat !== undefined) acceptOpts.proofIat = options.proofIat;
        if (options.fetcher !== undefined) acceptOpts.fetcher = options.fetcher;

        const result = await client.acceptOffer(url, acceptOpts);
        // Validate + store using the same path as credentials.receive.
        return await receiveCredential(
          result.credential,
          this.config,
          this.store,
          { trustedIssuers: options.trustedIssuers },
        );
      },
    };
  }

  /** Build a selective-disclosure presentation against a stored credential. */
  present(options: PresentOptions): Promise<string> {
    return buildPresentation(this.config, this.store, options);
  }

  /** Public key — useful to share with issuers so they can bind credentials. */
  get publicKey(): HolderConfig["publicKey"] {
    return this.config.publicKey;
  }

  /**
   * Respond to an OID4VP Authorization Request URL.
   *
   * The holder:
   *   1. Parses the URL.
   *   2. Runs DIF Presentation Exchange against stored credentials.
   *   3. Builds the presentation with selective disclosure.
   *   4. Builds the OID4VP authorization response form body.
   *
   * Returns the body string ready to POST to `response_uri`, plus metadata.
   */
  async respond(
    requestUrl: string,
    options: RespondOptions = {},
  ): Promise<RespondResult> {
    if (typeof requestUrl !== "string" || requestUrl.length === 0) {
      throw new HolderError("holder.invalid_input", "holder.respond: requestUrl is required");
    }

    const request = parseAuthorizationRequestUrl(requestUrl);

    // PD must be inline for v1 (presentation_definition_uri = future work).
    const pd = request.presentation_definition as
      | PresentationDefinition
      | undefined;
    if (pd === undefined) {
      throw new HolderError(
        "holder.pd_required",
        "holder.respond: only inline presentation_definition is supported in v1",
      );
    }

    const credentials = await this.credentials.list();
    const credentialViews: readonly (StoredCredential & SdJwtVcCredentialView)[] =
      credentials as readonly (StoredCredential & SdJwtVcCredentialView)[];

    const selectInput: Parameters<typeof selectForDefinition>[0] = {
      definition: pd,
      credentials: credentialViews,
    };
    if (options.pickCredential !== undefined) {
      const userPick = options.pickCredential;
      selectInput.pickCredential = (cands) => {
        const adapted = cands.map((c) => ({
          credential: c.credential as StoredCredential,
          disclose: c.result.disclose,
        }));
        const chosen = userPick(adapted);
        return cands.find(
          (c) =>
            (c.credential as StoredCredential).id === chosen.credential.id,
        )!;
      };
    }
    const selection = selectForDefinition(selectInput);

    if (!selection.fullySatisfied) {
      const ids = selection.unmatched.map((u) => u.descriptor.id).join(", ");
      throw new HolderError(
        "holder.pd_unsatisfiable",
        `holder.respond: cannot satisfy presentation_definition — unmatched descriptors: ${ids}`,
      );
    }
    if (selection.matches.length > 1) {
      throw new HolderError(
        "holder.multi_credential_unsupported",
        "holder.respond: multi-credential responses are not yet supported in v1",
      );
    }

    const match = selection.matches[0]!;
    const presentOpts: PresentOptions = {
      credentialId: (match.credential as StoredCredential).id,
      disclose: match.disclose,
      audience: request.client_id,
      nonce: request.nonce,
    };
    if (options.now !== undefined) presentOpts.now = options.now;
    const presentation = await this.present(presentOpts);

    const submission = buildPresentationSubmission(pd, selection);

    const responseBody = buildAuthorizationResponseBody({
      vp_token: presentation,
      presentation_submission: submission as unknown as Readonly<
        Record<string, unknown>
      >,
      ...(request.state !== undefined ? { state: request.state } : {}),
    });

    return {
      body: responseBody,
      credential: match.credential as StoredCredential,
      disclosed: match.disclose,
      request,
    };
  }
}

export { HolderError };

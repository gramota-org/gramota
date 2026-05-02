import { asSigner, type JsonWebKey, type Signer } from "@gramota/jose";
import {
  buildAuthorizationResponseBody,
  parseAuthorizationRequestUrl,
  type AuthorizationRequest,
} from "@gramota/oid4vp";
import {
  Oid4vciClient,
  type AcceptOfferOptions,
  type AuthorizationServerMetadata,
  type AuthorizeOfferOptions,
  type AuthorizeOfferResult,
  type CredentialOffer,
  type Fetcher,
  type IssuerMetadata,
} from "@gramota/oid4vci";
import {
  buildPresentationSubmission,
  selectForDefinition,
  type PresentationDefinition,
  type SdJwtVcCredentialView,
} from "@gramota/presentation-exchange";
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
  /** Accept a credential offer end-to-end via the pre-authorized code flow:
   * parse → fetch metadata → token → proof JWT → credential request →
   * validate → store. Returns the StoredCredential, same shape as
   * `holder.credentials.receive`. Throws if the offer doesn't include a
   * pre-authorized_code grant — use `authorize` + `claim` for auth-code. */
  accept(url: string, options: AcceptOptions): Promise<StoredCredential>;
  /**
   * Step 1 of the OID4VCI auth-code flow. Returns the URL the wallet must
   * navigate the user to, plus PKCE+state secrets to keep until step 2.
   * The Holder caches flow context (metadata, offer, redirect_uri,
   * client_id) keyed by `state`, so step 2 only needs the callback +
   * verifier + state.
   */
  authorize(
    url: string,
    options: AuthorizeOptions,
  ): Promise<AuthorizeResult>;
  /** Step 2: exchange the issuer's redirect-callback for a credential,
   * validate it against `trustedIssuers`, and store it. Looks up the
   * pending flow by `state` (same value passed to/from `authorize`). */
  claim(options: ClaimOptions): Promise<StoredCredential>;
}

/** Options for `holder.offers.accept()`. Extends OID4VCI's accept options
 * with trustedIssuers (same semantics as credentials.receive). */
export interface AcceptOptions extends AcceptOfferOptions {
  /** Trusted issuer JWKs the received credential's signature must verify
   * against. The credential is rejected if it does not. */
  trustedIssuers: readonly JsonWebKey[];
}

/** Options for `holder.offers.authorize()`. */
export interface AuthorizeOptions {
  /** Where the issuer should redirect the user after consent. Must match
   * a redirect URI registered with / accepted by the issuer. */
  redirectUri: string;
  /** OAuth `client_id`. Defaults to `redirectUri` (a common public-client
   * pattern when the wallet has no separate registered identifier). */
  clientId?: string;
  /** Override which credential to request. Default: first id from the offer. */
  credentialConfigurationId?: string;
  /** Optional OAuth scope. */
  scope?: string;
  /** Optional pre-existing PKCE verifier — for tests. Default: random. */
  codeVerifier?: string;
  /** Optional pre-existing CSRF state — for tests. Default: random. */
  state?: string;
  /** Optional fetcher override. */
  fetcher?: Fetcher;
}

/** Result of `holder.offers.authorize()`. */
export interface AuthorizeResult {
  /** Open this URL in the user's browser. */
  authorizationUrl: string;
  /** Persist with the user's session — passed to `claim`. */
  codeVerifier: string;
  /** Persist and verify against `?state=` on the callback. Doubles as
   * the lookup key for the pending flow inside the Holder. */
  state: string;
}

/** Options for `holder.offers.claim()`. */
export interface ClaimOptions {
  /** The full callback URL the issuer redirected to (with ?code=&state=). */
  callbackUrl: string;
  /** From `authorize`'s result. */
  codeVerifier: string;
  /** From `authorize`'s result. Used as lookup key for the pending flow. */
  state: string;
  /** Trusted issuer JWKs the received credential must verify against. */
  trustedIssuers: readonly JsonWebKey[];
  /** Optional fetcher override. */
  fetcher?: Fetcher;
  /** Override iat in the proof JWT — for tests. */
  proofIat?: number;
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
/** Internal state held between `authorize()` and `claim()`. */
interface PendingAuthCodeFlow {
  metadata: IssuerMetadata;
  authorizationServerMetadata: AuthorizationServerMetadata;
  offer: CredentialOffer;
  credentialConfigurationId: string;
  redirectUri: string;
  clientId: string;
}

export class Holder {
  /** The Holder's signer. Either supplied directly via `config.signer`
   * (production wallets backed by HSM/WebAuthn/Secure Enclave) or built
   * from raw JWKs via {@link asSigner}. Used to sign KB-JWTs and OID4VCI
   * proof JWTs — never exposes the private key downstream. */
  private readonly signer: Signer;
  private readonly store: CredentialStore;
  /** In-flight auth-code flows, keyed by `state`. Removed on `claim()`. */
  private readonly pendingFlows = new Map<string, PendingAuthCodeFlow>();

  /** Credential CRUD. `holder.credentials.{receive, list, get, remove}(...)`. */
  readonly credentials: CredentialsApi;

  /** OID4VCI offers. `holder.offers.{parse, accept, authorize, claim}(...)`. */
  readonly offers: OffersApi;

  constructor(config: HolderConfig) {
    this.signer = normalizeHolderSigner(config);
    this.store = config.store ?? new InMemoryCredentialStore();

    this.credentials = {
      receive: (token, options) =>
        receiveCredential(token, this.signer, this.store, options),
      get: (id) => this.store.get(id),
      list: (query) => this.store.list(query),
      remove: (id) => this.store.remove(id),
    };

    // OID4VCI client — built lazily so tests that don't use it incur no cost.
    // Pass the SAME Signer to keep cnf.jwk consistent end-to-end.
    let oid4vciClient: Oid4vciClient | undefined;
    const ensureClient = (): Oid4vciClient => {
      if (oid4vciClient === undefined) {
        oid4vciClient = new Oid4vciClient({ signer: this.signer });
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
          this.signer,
          this.store,
          { trustedIssuers: options.trustedIssuers },
        );
      },
      authorize: async (url, options) => {
        if (
          typeof options.redirectUri !== "string" ||
          options.redirectUri.length === 0
        ) {
          throw new HolderError(
            "holder.invalid_input",
            "offers.authorize: redirectUri is required",
          );
        }
        const client = ensureClient();
        const clientId = options.clientId ?? options.redirectUri;

        const authOpts: AuthorizeOfferOptions = {
          clientId,
          redirectUri: options.redirectUri,
        };
        if (options.credentialConfigurationId !== undefined) {
          authOpts.credentialConfigurationId = options.credentialConfigurationId;
        }
        if (options.codeVerifier !== undefined) {
          authOpts.codeVerifier = options.codeVerifier;
        }
        if (options.state !== undefined) authOpts.state = options.state;
        if (options.scope !== undefined) authOpts.scope = options.scope;
        if (options.fetcher !== undefined) authOpts.fetcher = options.fetcher;

        const started: AuthorizeOfferResult = await client.authorize(
          url,
          authOpts,
        );

        // Remember the per-flow context — so `claim` can look it up by state.
        this.pendingFlows.set(started.state, {
          metadata: started.metadata,
          authorizationServerMetadata: started.authorizationServerMetadata,
          offer: started.offer,
          credentialConfigurationId: started.credentialConfigurationId,
          redirectUri: options.redirectUri,
          clientId,
        });

        return {
          authorizationUrl: started.authorizationUrl,
          codeVerifier: started.codeVerifier,
          state: started.state,
        };
      },
      claim: async (options) => {
        if (
          typeof options.state !== "string" ||
          options.state.length === 0
        ) {
          throw new HolderError(
            "holder.invalid_input",
            "offers.claim: state is required",
          );
        }
        const pending = this.pendingFlows.get(options.state);
        if (pending === undefined) {
          throw new HolderError(
            "holder.unknown_flow",
            "offers.claim: no pending auth-code flow for this state — call authorize() first",
          );
        }

        const client = ensureClient();
        const claimOpts: Parameters<Oid4vciClient["claim"]>[0] = {
          callbackUrl: options.callbackUrl,
          codeVerifier: options.codeVerifier,
          state: options.state,
          metadata: pending.metadata,
          authorizationServerMetadata: pending.authorizationServerMetadata,
          offer: pending.offer,
          credentialConfigurationId: pending.credentialConfigurationId,
          redirectUri: pending.redirectUri,
          clientId: pending.clientId,
        };
        if (options.fetcher !== undefined) claimOpts.fetcher = options.fetcher;
        if (options.proofIat !== undefined) claimOpts.proofIat = options.proofIat;

        let result;
        try {
          result = await client.claim(claimOpts);
        } catch (err) {
          // If the issuer rejects (bad code, expired, etc.) the pending state
          // is now useless — drop it so it can't be retried.
          this.pendingFlows.delete(options.state);
          throw err;
        }

        // Always free the pending state once we've used it (success or stored).
        this.pendingFlows.delete(options.state);

        return await receiveCredential(
          result.credential,
          this.signer,
          this.store,
          { trustedIssuers: options.trustedIssuers },
        );
      },
    };
  }

  /** Build a selective-disclosure presentation against a stored credential. */
  present(options: PresentOptions): Promise<string> {
    return buildPresentation(this.signer, this.store, options);
  }

  /** Public key — useful to share with issuers so they can bind credentials. */
  get publicKey(): JsonWebKey {
    return this.signer.publicKey;
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

/**
 * Normalize the Holder's signer-input config (raw JWKs OR Signer)
 * into a Signer instance. Throws TypeError if neither shape is met.
 */
function normalizeHolderSigner(config: HolderConfig): Signer {
  if (
    "signer" in config &&
    config.signer !== undefined &&
    typeof (config.signer as Signer).sign === "function"
  ) {
    return config.signer;
  }
  if (
    "privateKey" in config &&
    "publicKey" in config &&
    "alg" in config &&
    config.privateKey !== null &&
    typeof config.privateKey === "object" &&
    config.publicKey !== null &&
    typeof config.publicKey === "object" &&
    typeof config.alg === "string" &&
    config.alg.length > 0
  ) {
    return asSigner({
      publicKey: config.publicKey,
      privateKey: config.privateKey,
      alg: config.alg,
    });
  }
  throw new TypeError(
    "Holder: pass either { privateKey, publicKey, alg } (raw shorthand) or { signer } (production)",
  );
}

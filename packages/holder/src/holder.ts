import {
  buildAuthorizationResponseBody,
  parseAuthorizationRequestUrl,
  type AuthorizationRequest,
} from "@gateway/oid4vp";
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

/** Options for `holder.respondTo()`. */
export interface RespondToOptions {
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
export interface RespondToResult {
  /** Form-encoded body to POST to the verifier's `response_uri`. */
  body: string;
  /** The matched credential (id + token + parsed). */
  credential: StoredCredential;
  /** What was disclosed. */
  disclosed: readonly string[];
  /** The original parsed request, for caller logging. */
  request: AuthorizationRequest;
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
  }

  /** Validate and store an issued SD-JWT-VC. Returns the stored credential. */
  receive(
    token: string,
    options: ReceiveOptions,
  ): Promise<StoredCredential> {
    return receiveCredential(token, this.config, this.store, options);
  }

  /** Build a selective-disclosure presentation against a stored credential. */
  present(options: PresentOptions): Promise<string> {
    return buildPresentation(this.config, this.store, options);
  }

  /** Get a single stored credential by id. */
  get(id: CredentialId): Promise<StoredCredential | undefined> {
    return this.store.get(id);
  }

  /** List stored credentials, optionally filtered. */
  list(query?: CredentialQuery): Promise<readonly StoredCredential[]> {
    return this.store.list(query);
  }

  /** Remove a stored credential. Returns true if it existed. */
  remove(id: CredentialId): Promise<boolean> {
    return this.store.remove(id);
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
  async respondTo(
    requestUrl: string,
    options: RespondToOptions = {},
  ): Promise<RespondToResult> {
    if (typeof requestUrl !== "string" || requestUrl.length === 0) {
      throw new HolderError("respondTo: requestUrl is required");
    }

    const request = parseAuthorizationRequestUrl(requestUrl);

    // PD must be inline for v1 (presentation_definition_uri = future work).
    const pd = request.presentation_definition as
      | PresentationDefinition
      | undefined;
    if (pd === undefined) {
      throw new HolderError(
        "respondTo: only inline presentation_definition is supported in v1",
      );
    }

    const credentials = await this.list();
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
        `respondTo: cannot satisfy presentation_definition — unmatched descriptors: ${ids}`,
      );
    }
    if (selection.matches.length > 1) {
      throw new HolderError(
        "respondTo: multi-credential responses are not yet supported in v1",
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

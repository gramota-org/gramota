/**
 * Authorization-transport strategies (GoF Strategy pattern).
 *
 * The high-level `Oid4vciClient.authorize()` doesn't care HOW the
 * authorization parameters reach the AS — only that the user ends up at
 * an URL the AS will honor. Different ecosystems wrap that delivery in
 * different envelopes:
 *
 *   - PAR (RFC 9126) — POST params, get back `request_uri`, redirect with
 *     `client_id + request_uri`. Required by EUDIW Keycloak realms; the
 *     security-recommended default for OAuth-based credential issuance.
 *   - Direct URL (RFC 6749 §4.1.1) — encode every param directly on the
 *     authorization-endpoint URL. The "classic" OAuth path, still used by
 *     simpler issuers.
 *   - JAR (RFC 9101) — params signed as a JWT, sent via `request=` or
 *     `request_uri=`. Supported by some EU dev infra; not implemented here
 *     yet but the abstraction makes it a drop-in addition.
 *
 * Adding a new transport requires implementing one method:
 *
 *     class MyTransport implements AuthorizationTransport {
 *       async deliver(input: DeliverInput): Promise<string> { ... }
 *     }
 *
 * and passing an instance via `Oid4vciClientConfig.authorizationTransport`.
 * No changes to `Oid4vciClient` itself — Open/Closed Principle.
 */

import { Oid4vciError } from "./types.js";
import {
  buildPostParAuthorizationUrl,
  pushAuthorizationRequest,
} from "./auth-code.js";
import type {
  AuthorizationServerMetadata,
  Fetcher,
} from "./metadata.js";

/** Inputs every transport needs to deliver an authorization request. */
export interface DeliverInput {
  /** AS metadata, already resolved (handles §11.2.2 delegation). */
  authorizationServerMetadata: AuthorizationServerMetadata;
  /** Canonical authorization parameters — same shape regardless of
   * transport. The strategy decides how to ship them to the AS. */
  params: Readonly<Record<string, string>>;
  /** Caller's client_id. Some transports (PAR) need it for the post-PAR
   * URL even though it's already in `params`. */
  clientId: string;
  /** Optional fetcher override. */
  fetcher?: Fetcher;
}

/**
 * Strategy interface for delivering authorization requests to the AS.
 *
 * Implementations decide HOW the params reach the AS; the orchestrator
 * just calls `deliver()` and gets back the URL to redirect the user to.
 *
 * Pure: a strategy holds no per-flow state. Multiple flows can share one
 * instance. Stateless implementations are trivially thread-safe.
 */
export interface AuthorizationTransport {
  /** Deliver the authorization request to the AS, return the URL the
   * wallet should navigate the user to. */
  deliver(input: DeliverInput): Promise<string>;
}

// ---------------------------------------------------------------------------
// Concrete strategies
// ---------------------------------------------------------------------------

/**
 * Pushed Authorization Requests per RFC 9126.
 *
 * Default for `Oid4vciClient`. Required by the EU dev issuer's
 * `wallet-dev` client. Refuses if the AS doesn't advertise a
 * `pushed_authorization_request_endpoint` — fail loudly, don't silently
 * leak parameters to a less-secure transport.
 */
export class ParAuthorizationTransport implements AuthorizationTransport {
  async deliver(input: DeliverInput): Promise<string> {
    const parEndpoint =
      input.authorizationServerMetadata.pushed_authorization_request_endpoint;
    if (typeof parEndpoint !== "string" || parEndpoint.length === 0) {
      throw new Oid4vciError(
        "oid4vci.par_endpoint_missing",
        `authorization server '${input.authorizationServerMetadata.issuer}' does not advertise a pushed_authorization_request_endpoint — RFC 9126 PAR is required by the configured ParAuthorizationTransport`,
      );
    }
    const parOpts: Parameters<typeof pushAuthorizationRequest>[0] = {
      parEndpoint,
      params: input.params,
    };
    if (input.fetcher !== undefined) parOpts.fetcher = input.fetcher;
    const par = await pushAuthorizationRequest(parOpts);
    return buildPostParAuthorizationUrl(
      input.authorizationServerMetadata.authorization_endpoint,
      input.clientId,
      par.requestUri,
    );
  }
}

/**
 * Direct authorization-URL transport per RFC 6749 §4.1.1.
 *
 * The classic OAuth path: every param is encoded on the authorization-
 * endpoint URL. Used by simpler issuers that don't support PAR.
 *
 * NOT the default. Pass an instance via `Oid4vciClientConfig.authorizationTransport`
 * to opt in:
 *
 *     new Oid4vciClient({
 *       ...,
 *       authorizationTransport: new DirectAuthorizationTransport(),
 *     });
 *
 * Trade-off: parameters are visible in browser history, server logs, and
 * referer headers. Prefer PAR when the AS supports it.
 */
export class DirectAuthorizationTransport implements AuthorizationTransport {
  async deliver(input: DeliverInput): Promise<string> {
    const url = new URL(
      input.authorizationServerMetadata.authorization_endpoint,
    );
    for (const [k, v] of Object.entries(input.params)) {
      url.searchParams.set(k, v);
    }
    return url.toString();
  }
}

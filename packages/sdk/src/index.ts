/**
 * `@gramota/sdk` — top-level facade for the Gramota EU Digital Identity
 * Wallet SDK.
 *
 * Use this package when you want one import + one config object instead
 * of wiring `@gramota/verifier`, `@gramota/issuer`, `@gramota/holder`,
 * and `@gramota/qr` separately.
 *
 *   ```ts
 *   import { Gramota } from "@gramota/sdk";
 *
 *   const gramota = new Gramota({
 *     verifier: { audience: "https://my-bank.com", trust },
 *   });
 *
 *   const result = await gramota.verifier.presentations.verify(token, { nonce });
 *   const code = gramota.qr.fromAuthorizationRequest(req);
 *   ```
 *
 * Re-exports the foundational types from `@gramota/core` (`GramotaError`,
 * `Fetcher`) so app code rarely has to import from `@gramota/core`
 * directly.
 */
export { Gramota, type GramotaOptions } from "./gramota.js";

// Foundational types — re-exported for convenience.
export {
  GramotaError,
  isGramotaError,
  type Fetcher,
  type FetcherResponse,
  mockFetcherResponse,
} from "@gramota/core";

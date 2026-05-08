/**
 * `@gramota/core` — shared primitives for the Gramota SDK.
 *
 * Imported by every other `@gramota/*` package; depends on nothing.
 *
 * Exports:
 *   - `Fetcher`, `FetcherResponse` — HTTP transport interface used by
 *     every package that makes outbound calls.
 *   - `mockFetcherResponse` — test helper for building fake responses.
 *   - `GramotaError` — base class every package's error type extends.
 *   - `isGramotaError` — type guard for catch sites.
 */
export {
  type Fetcher,
  type FetcherResponse,
  mockFetcherResponse,
} from "./fetcher.js";

export { GramotaError, isGramotaError } from "./error.js";

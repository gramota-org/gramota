import { parseSdJwt, type ParsedSdJwt } from "@gramota/sd-jwt";

/**
 * Parse an SD-JWT-VC presentation token without verifying anything.
 * Useful for debug UIs, CLI tools, and admin dashboards. Never use the
 * output to make trust decisions — that's `verifier.verify()`'s job.
 */
export function inspect(presentationToken: string): ParsedSdJwt {
  return parseSdJwt(presentationToken);
}

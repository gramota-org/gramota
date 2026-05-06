/**
 * Public types and the {@link QrError} class for `@gramota/qr`.
 *
 * These are intentionally narrow — the package's surface area is small
 * (one Strategy interface, one result type, one error class). New
 * variations (other output formats, decorated renderers) are added by
 * implementing {@link QrRenderer} and passing it via
 * {@link QrFactoryOptions.renderer}, NOT by widening these types.
 */

/** Output formats a {@link QrRenderer} may be asked to produce. */
export type QrFormat = "dataUrl" | "svg" | "png";

/**
 * Stable error codes for {@link QrError}. Pinned strings (not
 * descriptions) so callers can branch on them in switch statements.
 */
export type QrErrorCode =
  /** Input wasn't a non-empty string / well-formed URL. */
  | "qr.invalid_url"
  /** The configured {@link QrRenderer} couldn't produce the requested format. */
  | "qr.render_failed"
  /** The format requested isn't supported by this renderer. */
  | "qr.unsupported_format";

/**
 * Errors thrown anywhere in `@gramota/qr` carry one of these codes
 * plus a free-form message. Caught upstream, the code is stable
 * across releases — log it in audit trails, branch on it in handlers.
 */
export class QrError extends Error {
  override readonly name = "QrError";
  readonly code: QrErrorCode;
  constructor(code: QrErrorCode, message: string, options?: { cause?: unknown }) {
    super(message);
    this.code = code;
    if (options?.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/**
 * Layout options forwarded to the renderer. Specific renderers may
 * accept additional knobs (logo embedding, custom corner shapes, …)
 * via their own constructor options — these four are the universal
 * subset every renderer is expected to honour.
 */
export interface QrOptions {
  /** Pixel width of the rendered QR. PNG uses this directly; SVG
   * scales to fit. Default: 300. */
  readonly width?: number;
  /** Quiet-zone modules around the matrix. Default: 1. */
  readonly margin?: number;
  /** Foreground / background colours. CSS colour strings (e.g.
   * `"#0b1220"`). Default: black on white. */
  readonly colors?: {
    readonly dark?: string;
    readonly light?: string;
  };
  /** Reed-Solomon error-correction level. Higher = more redundant
   * data, larger matrix, more tolerant of dirt / partial occlusion.
   * Default: `"M"` (15% recovery — the QR-spec recommendation for
   * general use). */
  readonly errorCorrection?: "L" | "M" | "Q" | "H";
}

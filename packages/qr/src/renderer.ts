/**
 * The {@link QrRenderer} Strategy + the default Adapter implementation.
 *
 * Strategy (GoF): consumers swap renderers without touching the
 * orchestrator. Default = {@link DefaultQrRenderer}, which Adapts the
 * `qrcode` npm package to our shape. Want logo embedding, custom corner
 * shapes, or a browser-native renderer using `canvas`? Implement
 * {@link QrRenderer} and pass it via `qr.fromUrl(url, { renderer })`.
 *
 * Dependency-inversion: the rest of the package depends on this
 * abstraction — never on `qrcode` directly. The concrete `qrcode`
 * import is fully isolated to {@link DefaultQrRenderer}.
 */
import qrcode from "qrcode";
import { QrError, type QrFormat, type QrOptions } from "./types.js";

/** Strategy interface. Implementations decide HOW to render; the
 * orchestrator decides WHEN. */
export interface QrRenderer {
  /**
   * Render the given URL as a QR code in `format`.
   *
   * Return type depends on `format`:
   *   - `"dataUrl"` → `string` (a `data:image/png;base64,...` URL)
   *   - `"svg"` → `string` (the raw `<svg>...</svg>` markup)
   *   - `"png"` → `Uint8Array` (raw PNG bytes — `Buffer` in Node, but
   *     typed as `Uint8Array` so this is portable).
   *
   * Throw {@link QrError} with `qr.unsupported_format` if the
   * renderer can't produce the requested format, or
   * `qr.render_failed` for any other failure.
   */
  render(
    url: string,
    format: QrFormat,
    options: QrOptions,
  ): Promise<string | Uint8Array>;
}

/**
 * Default renderer — Adapter (GoF) over the `qrcode` npm package.
 *
 * Maps our {@link QrOptions} shape onto `qrcode`'s, dispatches based
 * on `format`, and surfaces failures as {@link QrError}. Swappable
 * via {@link QrRenderer}: anyone with stricter requirements
 * (Trust-on-first-use logo embedding, brand-coloured QR with a styled
 * data-pattern, etc.) writes their own implementation.
 */
export class DefaultQrRenderer implements QrRenderer {
  async render(
    url: string,
    format: QrFormat,
    options: QrOptions,
  ): Promise<string | Uint8Array> {
    const opts = {
      width: options.width ?? 300,
      margin: options.margin ?? 1,
      errorCorrectionLevel: options.errorCorrection ?? "M",
      color: {
        dark: options.colors?.dark ?? "#000000",
        light: options.colors?.light ?? "#ffffff",
      },
    } as const;

    try {
      switch (format) {
        case "dataUrl":
          return await qrcode.toDataURL(url, opts);
        case "svg":
          return await qrcode.toString(url, { ...opts, type: "svg" });
        case "png": {
          // toBuffer is Node-only; throws in pure-browser bundles.
          const buf = await qrcode.toBuffer(url, opts);
          // Return Uint8Array (the portable shape) — Buffer extends it.
          return new Uint8Array(buf);
        }
        default: {
          // Exhaustive-check assertion. If a new QrFormat is added to
          // the type union without a matching `case` here, TypeScript
          // fails at compile time on this line.
          const _exhaustive: never = format;
          throw new QrError(
            "qr.unsupported_format",
            `format ${String(_exhaustive)} is not supported by DefaultQrRenderer`,
          );
        }
      }
    } catch (err) {
      // Don't double-wrap our own errors.
      if (err instanceof QrError) throw err;
      throw new QrError(
        "qr.render_failed",
        `qrcode failed to render ${format}: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
  }
}

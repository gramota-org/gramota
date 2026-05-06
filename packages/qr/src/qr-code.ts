/**
 * The {@link QrCode} result type — what every `qr.from*` factory returns.
 *
 * Holds the source URL plus a memoised cache for each output format.
 * Consumers ask for whichever shape they need (`toDataUrl`, `toSvg`,
 * `toPng`) — the renderer is invoked on first call only; subsequent
 * calls return the cached buffer/string.
 *
 * Lazy + memoised because rendering isn't free (the PNG path costs a
 * Reed-Solomon encode per call) and most consumers want exactly one
 * output format. Pay once, reuse.
 */
import type { QrOptions } from "./types.js";
import type { QrRenderer } from "./renderer.js";

export class QrCode {
  /** The URL encoded in the QR matrix — exactly what scanners will read. */
  readonly url: string;

  private readonly renderer: QrRenderer;
  private readonly options: QrOptions;

  // Lazy / memoised caches. Promise-typed so concurrent first-callers
  // share the same in-flight render.
  private dataUrlCache?: Promise<string>;
  private svgCache?: Promise<string>;
  private pngCache?: Promise<Uint8Array>;

  /** @internal — construct via the {@link qr} factories, not directly. */
  constructor(url: string, renderer: QrRenderer, options: QrOptions = {}) {
    this.url = url;
    this.renderer = renderer;
    this.options = options;
  }

  /**
   * PNG as a `data:image/png;base64,…` URL — drop directly into an
   * `<img src>` attribute. Best for fast inline rendering in HTML
   * emails and dashboards.
   */
  toDataUrl(): Promise<string> {
    return (this.dataUrlCache ??= this.renderer
      .render(this.url, "dataUrl", this.options)
      .then((v) => v as string));
  }

  /**
   * Raw SVG markup — drop into `innerHTML` (or Angular `[innerHTML]`).
   * Scales without quality loss, good for print and high-DPI screens.
   */
  toSvg(): Promise<string> {
    return (this.svgCache ??= this.renderer
      .render(this.url, "svg", this.options)
      .then((v) => v as string));
  }

  /**
   * Raw PNG bytes — `Uint8Array` for portability (Node `Buffer`
   * extends it). Use for `fs.writeFile`, multipart uploads, and
   * binary-channel transports.
   */
  toPng(): Promise<Uint8Array> {
    return (this.pngCache ??= this.renderer
      .render(this.url, "png", this.options)
      .then((v) => v as Uint8Array));
  }
}

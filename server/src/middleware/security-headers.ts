import type { RequestHandler } from "express";

/**
 * Baseline browser-hardening headers for every response.
 *
 * These are deliberately limited to values that do not change how the UI,
 * the API, or plugin UIs behave:
 *
 * - `X-Content-Type-Options: nosniff` stops browsers from upgrading a
 *   mis-typed response into script or HTML. Every served asset already
 *   carries an explicit content type.
 * - `X-Frame-Options: SAMEORIGIN` blocks cross-site framing of the board UI
 *   (clickjacking). Plugin UIs and artifact previews are framed from the
 *   same origin or via `srcdoc`, which this header does not affect.
 * - `Referrer-Policy: strict-origin-when-cross-origin` keeps instance paths
 *   (company prefixes, issue ids) out of third-party request logs when
 *   agent-authored markdown embeds remote images or links.
 *
 * Routes that need a stricter value (for example `no-referrer` on OAuth
 * callbacks, or a `Content-Security-Policy` sandbox on served attachments)
 * set it afterwards and override these defaults.
 */
export function baselineSecurityHeaders(): RequestHandler {
  return (_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    next();
  };
}

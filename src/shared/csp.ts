// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The Content-Security-Policy, in one place.
 *
 * `webRequest.onHeadersReceived` **does not fire for `file://`**, and production
 * loads the renderer with `loadFile` — so a header-only policy does not apply in
 * a packaged build. The meta tag in `index.html` is therefore generated from
 * this function at build time and the header repeats it. Both must stay in
 * agreement: two policies both apply and CSP intersects them, so a divergence
 * silently produces the intersection rather than either policy.
 */
export function contentSecurityPolicy(dev: boolean): string {
  // `dev` is the Vite dev server: HMR needs eval and a socket home. Nothing else does.
  const scriptSrc = dev ? `'self' 'unsafe-inline' 'unsafe-eval'` : `'self'`
  const connectSrc = dev ? `'self' ws://localhost:* ws://127.0.0.1:*` : `'self'`

  return [
    `default-src 'self'`,
    `script-src ${scriptSrc}`,
    // Inline styles are unavoidable: xterm.js writes them on the fly.
    `style-src 'self' 'unsafe-inline'`,
    // data: covers the inline favicon and xterm's generated glyph atlas.
    `img-src 'self' data:`,
    `font-src 'self' data:`,
    `connect-src ${connectSrc}`,
    `object-src 'none'`,
    `frame-src 'none'`,
    `base-uri 'none'`,
    `form-action 'none'`
  ].join('; ')
}

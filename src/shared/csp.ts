// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The Content-Security-Policy, in one place.
 *
 * There used to be two: a strict one built in `applyCsp()` and a permissive one
 * hardcoded in `index.html`. The strict one was installed through
 * `webRequest.onHeadersReceived`, which **does not fire for `file://`** — and
 * production loads the renderer with `loadFile`. So the policy that actually
 * shipped was the meta tag's, which carried the development relaxations.
 *
 * That was measured, not inferred: in a packaged build `eval('1+1')` returned
 * 2 and `new WebSocket('wss://example.invalid/')` was permitted. A bare `wss:`
 * scheme-source matches any host, in an application that holds private keys.
 *
 * Now the meta tag is written at build time from this function and the header
 * repeats it. Two policies both apply and CSP intersects them, so agreement is
 * required — a divergence would silently produce the intersection rather than
 * either policy, which is exactly the failure that hid the original bug.
 */

/**
 * @param dev  true for the dev server, which needs inline/eval for HMR and a
 *             websocket back to Vite. Production gets neither.
 */
export function contentSecurityPolicy(dev: boolean): string {
  // HMR needs eval and a socket home. Nothing else ever does.
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

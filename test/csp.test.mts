// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The Content-Security-Policy.
 *
 * This function exists because the shipped policy once came from a meta tag
 * carrying the development relaxations, while the strict one built in
 * `applyCsp()` was installed through `webRequest.onHeadersReceived` — which
 * does not fire for `file://`, and production loads the renderer with
 * `loadFile`. In a packaged build `eval('1+1')` returned 2 and a `wss://` socket
 * to any host was permitted, in an application that holds private keys.
 *
 * So the tests below are not about string formatting. Each one pins a
 * relaxation that must never reach a production build, in a function whose
 * whole purpose is that both copies of the policy agree.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { contentSecurityPolicy } from '../src/shared/csp.ts'

/** The policy as a directive -> value map, which is how it is actually read. */
function directives(dev: boolean): Map<string, string> {
  const map = new Map<string, string>()
  for (const part of contentSecurityPolicy(dev).split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const space = trimmed.indexOf(' ')
    if (space < 0) {
      map.set(trimmed, '')
      continue
    }
    assert.equal(map.has(trimmed.slice(0, space)), false, `${trimmed} is declared twice`)
    map.set(trimmed.slice(0, space), trimmed.slice(space + 1))
  }
  return map
}

describe('contentSecurityPolicy', () => {
  test('production allows no eval and no inline script', () => {
    // The exact pair that shipped by accident. `unsafe-eval` in a renderer that
    // displays untrusted terminal output is the whole game.
    const script = directives(false).get('script-src')
    assert.equal(script, `'self'`, `production script-src is ${script}`)
  })

  test('production allows no outbound connection anywhere', () => {
    // A bare `wss:` scheme-source matches ANY host. This is the exfiltration
    // channel the original bug left open.
    const connect = directives(false).get('connect-src')
    assert.equal(connect, `'self'`, `production connect-src is ${connect}`)
    assert.ok(!connect.includes('ws'), 'a websocket scheme survived into production')
    assert.ok(!connect.includes('*'), 'a wildcard survived into production')
  })

  test('production carries no wildcard and no remote scheme at all', () => {
    const policy = contentSecurityPolicy(false)
    for (const forbidden of ['unsafe-eval', 'unsafe-inline ', 'http:', 'https:', 'ws:', 'wss:']) {
      // `style-src` legitimately needs 'unsafe-inline', so that one is checked
      // on its own below rather than banned outright here.
      if (forbidden === 'unsafe-inline ') continue
      assert.ok(!policy.includes(forbidden), `production policy contains ${forbidden}`)
    }
    assert.ok(!/\*/.test(policy), 'production policy contains a wildcard')
  })

  test('inline styles are allowed, because xterm writes them at runtime', () => {
    // Documented as unavoidable. Pinned so that "tighten the CSP" does not
    // silently break the terminal for everyone.
    assert.match(directives(false).get('style-src'), /'unsafe-inline'/)
  })

  test('the dangerous sinks are shut in both builds', () => {
    for (const dev of [true, false]) {
      const d = directives(dev)
      assert.equal(d.get('object-src'), `'none'`, `object-src open in dev=${dev}`)
      assert.equal(d.get('frame-src'), `'none'`, `frame-src open in dev=${dev}`)
      assert.equal(d.get('base-uri'), `'none'`, `base-uri open in dev=${dev}`)
      assert.equal(d.get('form-action'), `'none'`, `form-action open in dev=${dev}`)
      assert.equal(d.get('default-src'), `'self'`, `default-src open in dev=${dev}`)
    }
  })

  test('dev relaxes exactly two directives and nothing else', () => {
    // The bug was a dev relaxation reaching production. The mirror risk is a
    // relaxation being added for dev and quietly applying to both, so the
    // difference between the two policies is pinned rather than assumed.
    const dev = directives(true)
    const prod = directives(false)
    const differing = [...prod.keys()].filter((k) => dev.get(k) !== prod.get(k))
    assert.deepEqual(
      differing.sort(),
      ['connect-src', 'script-src'],
      `dev and production differ in ${differing.join(', ')}`
    )
  })

  test('dev and production declare the same directives', () => {
    // A directive present in one and absent in the other means the two policies
    // do not intersect to either of them.
    assert.deepEqual([...directives(true).keys()].sort(), [...directives(false).keys()].sort())
  })

  test('every directive is declared exactly once', () => {
    // A repeated directive is silently ignored after the first, which is a
    // policy that looks stricter than it is. `directives()` asserts this while
    // parsing; this test is what makes the assertion run for both builds.
    directives(true)
    directives(false)
  })
})

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The Content-Security-Policy. One function exists so that both copies of the
 * policy agree: when they did not, the packaged build served the meta tag's
 * development relaxations, because `webRequest.onHeadersReceived` does not fire
 * for the `file://` load production uses. Each test pins a relaxation that must
 * never reach a production build.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { contentSecurityPolicy } from '../src/shared/csp.ts'

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
    // `unsafe-eval` in a renderer that displays untrusted terminal output is
    // the whole game.
    const script = directives(false).get('script-src')
    assert.equal(script, `'self'`, `production script-src is ${script}`)
  })

  test('production allows no outbound connection anywhere', () => {
    // A bare `wss:` scheme-source matches ANY host: an exfiltration channel.
    const connect = directives(false).get('connect-src')
    assert.equal(connect, `'self'`, `production connect-src is ${connect}`)
    assert.ok(!connect.includes('ws'), 'a websocket scheme survived into production')
    assert.ok(!connect.includes('*'), 'a wildcard survived into production')
  })

  test('production carries no wildcard and no remote scheme at all', () => {
    const policy = contentSecurityPolicy(false)
    for (const forbidden of ['unsafe-eval', 'unsafe-inline ', 'http:', 'https:', 'ws:', 'wss:']) {
      // `style-src` legitimately needs 'unsafe-inline'; checked on its own below.
      if (forbidden === 'unsafe-inline ') continue
      assert.ok(!policy.includes(forbidden), `production policy contains ${forbidden}`)
    }
    assert.ok(!/\*/.test(policy), 'production policy contains a wildcard')
  })

  test('inline styles are allowed, because xterm writes them at runtime', () => {
    // Unavoidable, and pinned so that "tighten the CSP" does not silently break
    // the terminal for everyone.
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
    // The mirror of the original bug: a relaxation added for dev that quietly
    // applies to both. The difference is pinned rather than assumed.
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
    // A repeated directive is ignored after the first, so the policy looks
    // stricter than it is. `directives()` asserts this while parsing; this test
    // makes that assertion run for both builds.
    directives(true)
    directives(false)
  })
})

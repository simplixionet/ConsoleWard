// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The HTTP layer in front of the MCP tools.
 *
 * These are the checks that run before a single byte of body is read: the
 * Host/Origin gate, the bearer token, and the two exported helpers the request
 * handler is built out of. `hostAllowed`, `modelErrorFor` and `onceClosed` are
 * pure, so they need no server at all — which is why they were extracted rather
 * than left inline in the handler.
 *
 * `mcp.ts` reaches Electron transitively (mcp.ts -> vault.ts -> electron), so
 * electron and the two side modules are stubbed before the import.
 */

import { describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'

mock.module('electron', { exports: { app: { getPath: () => '' } } })
mock.module('../src/main/vault.ts', {
  exports: { vault: { isUnlocked: () => true, read: () => ({ settings: {} }) } }
})
mock.module('../src/main/ssh.ts', {
  exports: { ssh: { isReady: () => true, title: () => 'web01', listForModel: () => [] } }
})

const { hostAllowed, modelErrorFor, onceClosed } = await import('../src/main/mcp.ts')

const PORT = 7345
const HOSTS = [`127.0.0.1:${PORT}`, `localhost:${PORT}`]
const ORIGINS = [`http://127.0.0.1:${PORT}`, `http://localhost:${PORT}`]

const allowed = (headers: Record<string, string>): boolean =>
  hostAllowed(headers, HOSTS, ORIGINS)

/* ------------------------------------------------------- the Host/Origin gate */

describe('hostAllowed', () => {
  test('accepts the two names the server actually listens under', () => {
    assert.equal(allowed({ host: `127.0.0.1:${PORT}` }), true)
    assert.equal(allowed({ host: `localhost:${PORT}` }), true)
  })

  test('refuses every name a rebinding attack can produce', () => {
    // A browser puts the NAME it was given in Host, never the address it
    // resolved to — which is the only reason this defence works at all. Each of
    // these is simply not in the allow list; none needs a rule of its own.
    for (const host of [
      `localhost.evil.com:${PORT}`,
      `127.0.0.2:${PORT}`,
      `[::1]:${PORT}`,
      `evil.com:${PORT}`,
      '127.0.0.1',
      `LOCALHOST:${PORT}`,
      `127.0.0.1:${PORT + 1}`,
      `127.0.0.1:${PORT} `
    ]) {
      assert.equal(allowed({ host }), false, `Host: ${host} was accepted`)
    }
  })

  test('refuses a request with no Host at all', () => {
    assert.equal(allowed({}), false)
  })

  test('accepts a missing Origin but refuses a wrong one', () => {
    // An ordinary MCP client sends no Origin; a browser always does. So absent
    // is fine and present-and-wrong is not.
    assert.equal(allowed({ host: HOSTS[0] }), true, 'a client with no Origin was refused')
    assert.equal(allowed({ host: HOSTS[0], origin: ORIGINS[0] }), true)
    assert.equal(
      allowed({ host: HOSTS[0], origin: 'http://evil.com' }),
      false,
      'a page on another origin was let through on a correct Host'
    )
    assert.equal(
      allowed({ host: HOSTS[0], origin: `https://localhost:${PORT}` }),
      false,
      'the scheme is part of the origin and must match'
    )
  })
})

/* ------------------------------------------------- what the model is told went wrong */

describe('modelErrorFor', () => {
  test('maps a translated AppError to fixed English', () => {
    // The message on an AppError has already been through t(). Passing it on
    // ships Czech diagnostics to an English-speaking tool, and the text changes
    // whenever the human changes language. The key does not.
    assert.equal(
      modelErrorFor({ key: 'error.sessionNotFound', message: 'Relace neexistuje.' }),
      'The session does not exist or is not ready.'
    )
    assert.equal(
      modelErrorFor({ key: 'error.requestTooLarge', message: 'Požadavek je příliš velký.' }),
      'The request body is too large.'
    )
  })

  test('never passes an unmapped message through', () => {
    // An unmapped error is a path nobody traced, so its message may carry a
    // path from this machine, the human's language, or a server's own words.
    const leaky = new Error('ENOENT: no such file, open C:\\Users\\stan\\vault.enc')
    const text = modelErrorFor(leaky)
    assert.ok(!text.includes('C:\\'), `the fallback leaked a local path: ${text}`)
    assert.ok(!text.includes('ENOENT'), `the fallback leaked the raw error: ${text}`)
  })

  test('survives the things that are not AppErrors at all', () => {
    // readJsonBody can throw a SyntaxError from JSON.parse, which has no `key`.
    for (const thrown of [null, undefined, 'a string', 42, new SyntaxError('Unexpected token')]) {
      assert.equal(typeof modelErrorFor(thrown), 'string', `threw on ${String(thrown)}`)
    }
    assert.equal(
      modelErrorFor({ key: { toString: () => 'error.sessionNotFound' } }),
      'ConsoleWard could not carry out the request.',
      'a non-string key was coerced and matched'
    )
  })
})

/* ------------------------------------------------------------- cleanup on abort */

describe('onceClosed', () => {
  class FakeRes extends EventEmitter {
    closed = false
  }

  test('defers the cleanup while the response is still open', () => {
    const res = new FakeRes()
    let ran = 0
    onceClosed(res as never, () => ran++)
    assert.equal(ran, 0, 'the cleanup ran before the response was finished with')
    res.emit('close')
    assert.equal(ran, 1, 'the cleanup never ran')
  })

  test('runs the cleanup at once when the response is already closed', () => {
    // This is the whole finding: a client that gives up mid-request closes the
    // socket while the handler is still waiting on a human, so by the time the
    // handler returns `res` has already emitted close. `res.on('close', …)` on
    // a closed stream is never called and both objects leak for good.
    const res = new FakeRes()
    res.closed = true
    let ran = 0
    onceClosed(res as never, () => ran++)
    assert.equal(ran, 1, 'an aborted request left the transport and server open')
  })

  test('runs the cleanup exactly once', () => {
    const res = new FakeRes()
    let ran = 0
    onceClosed(res as never, () => ran++)
    res.emit('close')
    res.emit('close')
    assert.equal(ran, 1, 'the cleanup ran twice')
  })
})

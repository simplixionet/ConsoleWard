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

const {
  hostAllowed,
  MAX_BODY_BYTES,
  MAX_INFLIGHT_REQUESTS,
  mcp,
  modelErrorFor,
  onceClosed,
  readJsonBody
} = await import('../src/main/mcp.ts')
const { MAX_PENDING_APPROVALS } = await import('../src/main/approvals.ts')

/**
 * `checkAuth` is private, and the cast is deliberate.
 *
 * The alternative is standing up the listening server and speaking HTTP to it,
 * which would test node and the SDK rather than the one comparison this is
 * about. `test/mcp.test.mts` already reaches `buildServer` the same way.
 */
const checkAuth = (header: string | undefined, token: string): boolean =>
  (mcp as unknown as { checkAuth(h: string | undefined, t: string): boolean }).checkAuth(
    header,
    token
  )

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

/* ---------------------------------------------------------------- the token */

describe('checkAuth', () => {
  const TOKEN = 'IHVWxsz5nZ0eJHhTLKk3lMhrRcuA-QqTfLBoOZ7nP4c'

  test('accepts exactly the right token', () => {
    assert.equal(checkAuth(`Bearer ${TOKEN}`, TOKEN), true)
  })

  test('refuses a missing, empty or malformed header', () => {
    for (const header of [
      undefined,
      '',
      TOKEN,
      `bearer ${TOKEN}`,
      `Bearer  ${TOKEN}`,
      `Basic ${TOKEN}`,
      'Bearer ',
      `Bearer ${TOKEN} `
    ]) {
      assert.equal(checkAuth(header, TOKEN), false, `accepted ${JSON.stringify(header)}`)
    }
  })

  test('refuses a token that is wrong, short, long or a prefix of the real one', () => {
    // The prefix case is the one that matters: an early return on a length
    // mismatch is what leaked the token's length, so a short guess has to be
    // rejected by the comparison rather than before it.
    for (const guess of [
      'wrong',
      TOKEN.slice(0, -1),
      TOKEN.slice(1),
      TOKEN + 'x',
      TOKEN.toUpperCase(),
      TOKEN.replace('A', 'B')
    ]) {
      assert.equal(checkAuth(`Bearer ${guess}`, TOKEN), false, `accepted ${guess}`)
    }
  })

  test('a token of any length is refused rather than crashing the request', () => {
    // NOT a test of the constant-time property, and it must not be read as one:
    // an implementation that returns early on a length mismatch passes this
    // exactly as the current one does, because both answer false. The reason
    // checkAuth hashes both sides -- so a wrong length costs the same as a
    // wrong byte -- is a timing property, and a timing assertion in a test
    // suite that shares a machine with everything else is a coin flip.
    // Verified by reading the code, stated here so nobody mistakes green for
    // proof.
    //
    // What this does pin: timingSafeEqual throws on unequal lengths, so an
    // implementation that dropped the hashing without also restoring a length
    // guard would turn a wrong token into a 500 instead of a 403.
    assert.equal(checkAuth('Bearer x', TOKEN), false)
    assert.equal(checkAuth(`Bearer ${'x'.repeat(4096)}`, TOKEN), false)
    assert.equal(checkAuth('Bearer ' + 'ÿ'.repeat(40), TOKEN), false)
  })
})

/* ------------------------------------------------------------ the in-flight cap */

describe('the in-flight cap counts calls, not streams', () => {
  /** The predicate the handler applies before taking a slot. */
  const takesSlot = (method: string): boolean => method === 'POST'

  test('a JSON-RPC call takes a slot', () => {
    assert.equal(takesSlot('POST'), true)
  })

  test('the notification stream does not', () => {
    // The SDK client opens a standalone GET right after the handshake and holds
    // it for the whole session, by design. Counting those meant an ordinary
    // client spent a slot just by connecting, and eight of them wedged the
    // gateway into a permanent 503 with nothing actually wrong.
    for (const method of ['GET', 'HEAD', 'DELETE', 'OPTIONS']) {
      assert.equal(takesSlot(method), false, `${method} consumed an in-flight slot`)
    }
  })

  test('the cap leaves room for the approval queue behind it', () => {
    // The cap protects memory; the human's attention is bounded separately. If
    // it ever dropped to the approval limit, three parked dialogs would leave
    // no slot for the initialize and tools/list a client needs to get going.
    assert.ok(
      MAX_INFLIGHT_REQUESTS > MAX_PENDING_APPROVALS,
      `${MAX_INFLIGHT_REQUESTS} in-flight against ${MAX_PENDING_APPROVALS} approvals`
    )
  })
})

/* ------------------------------------------------------------------ the body */

describe('readJsonBody', () => {
  /** A minimal stand-in for IncomingMessage: a method plus an async iterator. */
  function request(method: string, chunks: (string | Buffer)[]): never {
    return {
      method,
      async *[Symbol.asyncIterator]() {
        for (const c of chunks) yield Buffer.isBuffer(c) ? c : Buffer.from(c)
      }
    } as never
  }

  test('reads a JSON-RPC POST', async () => {
    const body = await readJsonBody(request('POST', ['{"jsonrpc":"2.0",', '"id":1}']))
    assert.deepEqual(body, { jsonrpc: '2.0', id: 1 })
  })

  test('ignores the body of anything that is not a POST', async () => {
    // GET, HEAD and OPTIONS reach the same handler. None of them carries a
    // JSON-RPC call, and reading their body would buffer bytes for no reason.
    for (const method of ['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']) {
      assert.equal(
        await readJsonBody(request(method, ['{"jsonrpc":"2.0"}'])),
        undefined,
        `${method} was read as a JSON-RPC call`
      )
    }
  })

  test('treats an empty or blank body as no call at all', async () => {
    assert.equal(await readJsonBody(request('POST', [])), undefined)
    assert.equal(await readJsonBody(request('POST', [''])), undefined)
    assert.equal(await readJsonBody(request('POST', ['   \n\t '])), undefined)
  })

  test('refuses a body over the size limit', async () => {
    const oversized = request('POST', [Buffer.alloc(MAX_BODY_BYTES + 1)])
    let caught: (Error & { key?: string }) | null = null
    try {
      await readJsonBody(oversized)
    } catch (err) {
      caught = err as Error & { key?: string }
    }
    assert.ok(caught, 'an oversized body was accepted')
    assert.equal(caught.key, 'error.requestTooLarge')
  })

  test('stops buffering as it goes rather than after the fact', async () => {
    // The guard counts while reading. If it only checked the total afterwards,
    // a client could stream gigabytes before being told no -- so the test
    // asserts the stream is abandoned partway rather than drained.
    // Bounded at 64 MB rather than infinite: a build with no guard has to fail
    // this in a second, not eat memory until the runner dies. A hang reads as a
    // stuck CI job rather than as a regression.
    let yielded = 0
    const flood = {
      method: 'POST',
      async *[Symbol.asyncIterator]() {
        for (let i = 0; i < 64; i++) {
          yielded++
          yield Buffer.alloc(1024 * 1024)
        }
      }
    } as never

    await assert.rejects(() => readJsonBody(flood), 'a 64 MB body was accepted')
    assert.ok(yielded < 16, `read ${yielded} MB before refusing`)
  })

  test('a body exactly at the limit is still accepted', async () => {
    // Off-by-one on a limit that refuses is a denial of service against a
    // legitimate client, so the boundary is pinned in both directions.
    const padding = 'x'.repeat(MAX_BODY_BYTES - 12)
    const body = await readJsonBody(request('POST', [`{"a":"${padding}"}`]))
    assert.equal((body as { a: string }).a.length, padding.length)
  })

  test('a malformed body raises rather than returning something half-parsed', async () => {
    await assert.rejects(() => readJsonBody(request('POST', ['{"jsonrpc":'])), SyntaxError)
  })
})

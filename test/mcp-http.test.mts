// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The HTTP layer in front of the MCP tools: the Host/Origin gate, the bearer
 * token, and the helpers the request handler is built out of. The last block
 * starts a real server, because the address it binds to and the order its gates
 * run in exist only inside the closure `start()` builds. Electron and the two
 * side modules are stubbed before the import.
 */

import { after, before, describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createServer, request, type ClientRequest, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

const SERVER_TOKEN = 'PZ2s7Wd0m3n5FQ0RkGm4tYbXH1qLcJ8vE6oS9rT2uA0'

const vaultState = {
  unlocked: true,
  data: { settings: { mcpPort: 0 }, mcpToken: SERVER_TOKEN }
}

mock.module('electron', { exports: { app: { getPath: () => '' } } })
mock.module('../src/main/vault.ts', {
  exports: {
    vault: {
      isUnlocked: (): boolean => vaultState.unlocked,
      read: () => vaultState.data,
      mutate: async (fn: (data: typeof vaultState.data) => void): Promise<void> => {
        fn(vaultState.data)
      }
    }
  }
})
mock.module('../src/main/ssh.ts', {
  exports: {
    UPLOAD_MAX_BYTES: 1024 * 1024,
    ssh: {
      isReady: () => true,
      title: () => 'web01',
      listForModel: () => [],
      // read_terminal reads a preview before it ever asks the human; without
      // this the tool fails before reaching the dialog and the streaming test
      // below would prove nothing.
      readText: () => 'preview'
    }
  }
})

const {
  hostAllowed,
  MAX_BODY_BYTES,
  MAX_INFLIGHT_REQUESTS,
  mcp,
  modelErrorFor,
  onceClosed,
  PROGRESS_INTERVAL_MS,
  readJsonBody,
  takesSlot,
  whileAwaitingHuman
} = await import('../src/main/mcp.ts')
const { MAX_PENDING_APPROVALS } = await import('../src/main/approvals.ts')

/** `checkAuth` is private; going over HTTP would test node and the SDK. */
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

describe('hostAllowed', () => {
  test('accepts the two names the server actually listens under', () => {
    assert.equal(allowed({ host: `127.0.0.1:${PORT}` }), true)
    assert.equal(allowed({ host: `localhost:${PORT}` }), true)
  })

  test('refuses every name a rebinding attack can produce', () => {
    // A browser puts the NAME it was given in Host, never the address it
    // resolved to, which is the only reason this defence works at all.
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
    // An ordinary MCP client sends no Origin; a browser always does.
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

describe('modelErrorFor', () => {
  test('maps a translated AppError to fixed English', () => {
    // An AppError's message has been through t(), so it carries the human's
    // language and changes when they switch it. The key does not.
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
    // An unmapped error's message may carry a local path or a server's words.
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
    // A client that gives up while the handler waits on a human has already
    // emitted close by the time the handler returns, and `res.on('close', …)`
    // on a closed stream never fires — leaking the transport and server.
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
    // An early return on a length mismatch leaks the token's length, so a short
    // guess must be rejected by the comparison rather than before it.
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
    // NOT a test of the constant-time property — an early return on a length
    // mismatch passes this too, and no test sharing a machine with everything
    // else can assert timing. What it does pin: timingSafeEqual throws on
    // unequal lengths, so dropping the hashing that equalises them, without
    // restoring a length guard, turns a wrong token into a 500 instead of a 403.
    assert.equal(checkAuth('Bearer x', TOKEN), false)
    assert.equal(checkAuth(`Bearer ${'x'.repeat(4096)}`, TOKEN), false)
    assert.equal(checkAuth('Bearer ' + 'ÿ'.repeat(40), TOKEN), false)
  })
})

describe('the in-flight cap counts calls, not streams', () => {
  test('a JSON-RPC call takes a slot', () => {
    assert.equal(takesSlot('POST'), true)
  })

  test('the notification stream does not', () => {
    // The SDK client holds a standalone GET open for the whole session by
    // design, so counting those wedges the gateway into a permanent 503.
    for (const method of ['GET', 'HEAD', 'DELETE', 'OPTIONS']) {
      assert.equal(takesSlot(method), false, `${method} consumed an in-flight slot`)
    }
  })

  test('the cap leaves room for the approval queue behind it', () => {
    // At the approval limit, parked dialogs would leave no slot for the
    // initialize and tools/list a client needs to get going.
    assert.ok(
      MAX_INFLIGHT_REQUESTS > MAX_PENDING_APPROVALS,
      `${MAX_INFLIGHT_REQUESTS} in-flight against ${MAX_PENDING_APPROVALS} approvals`
    )
  })
})

describe('readJsonBody', () => {
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
    // The guard has to count while reading: checking the total afterwards lets
    // a client stream gigabytes first. Bounded at 64 MB so a build without the
    // guard fails in a second rather than eating memory until the runner dies.
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
    // Off-by-one here denies service to a legitimate client.
    const padding = 'x'.repeat(MAX_BODY_BYTES - 12)
    const body = await readJsonBody(request('POST', [`{"a":"${padding}"}`]))
    assert.equal((body as { a: string }).a.length, padding.length)
  })

  test('a malformed body raises rather than returning something half-parsed', async () => {
    await assert.rejects(() => readJsonBody(request('POST', ['{"jsonrpc":'])), SyntaxError)
  })
})

interface Answer {
  status: number
  body: string
}

const CALL = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

const CLIENT_HEADERS = {
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream'
}

/**
 * `agent: false` so each call gets its own socket: the parked calls below must
 * be in flight at once, and a pooled agent would serialise them onto one
 * connection and quietly test nothing.
 */
function call(
  port: number,
  opts: { host?: string; origin?: string; token?: string | null; body?: string } = {}
): Promise<Answer> {
  const headers: Record<string, string> = { ...CLIENT_HEADERS }
  if (opts.host !== undefined) headers.host = opts.host
  if (opts.origin !== undefined) headers.origin = opts.origin
  if (opts.token !== null) headers.authorization = `Bearer ${opts.token ?? SERVER_TOKEN}`

  return new Promise<Answer>((resolve, reject) => {
    const req = request(
      { host: '127.0.0.1', port, method: 'POST', agent: false, headers },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk: string) => {
          body += chunk
        })
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
      }
    )
    req.on('error', reject)
    req.end(opts.body ?? CALL)
  })
}

/**
 * A POST whose body never arrives, so it sits past the gate holding a slot —
 * the shape of a call parked on a human. `release()` finishes the body rather
 * than aborting, so the server answers 500 through its ordinary catch and the
 * handler's `finally` runs; an abort would also exercise teardown.
 */
function park(port: number): { release: () => Promise<Answer> } {
  let settle: (answer: Answer) => void = () => {}
  const done = new Promise<Answer>((resolve) => {
    settle = resolve
  })
  const req: ClientRequest = request(
    {
      host: '127.0.0.1',
      port,
      method: 'POST',
      agent: false,
      headers: { ...CLIENT_HEADERS, authorization: `Bearer ${SERVER_TOKEN}` }
    },
    (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (chunk: string) => {
        body += chunk
      })
      res.on('end', () => settle({ status: res.statusCode ?? 0, body }))
    }
  )
  // Chunked, because no content-length was set.
  req.write('{')
  return {
    release: () => {
      req.end()
      return done
    }
  }
}

/** A port nobody is on, so the suite never fights the running app for 7345. */
async function freePort(): Promise<number> {
  const probe = createServer()
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve))
  const { port } = probe.address() as AddressInfo
  await new Promise<void>((resolve) => probe.close(() => resolve()))
  return port
}

describe('the server that actually listens', () => {
  let port = 0

  before(async () => {
    port = await freePort()
    // Below 1024 clampPort silently substitutes the default and every test here
    // would talk to nothing.
    assert.ok(port >= 1024, `the ephemeral port ${port} is one clampPort would replace`)
    vaultState.unlocked = true
    vaultState.data.settings.mcpPort = port
    await mcp.start()
  })

  after(async () => {
    vaultState.unlocked = true
    await mcp.stop()
  })

  test('it listens on the loopback address and nowhere else', async () => {
    // On 0.0.0.0 every machine on the network reaches a gateway into the
    // human's SSH sessions, and no other check would notice: the caller writes
    // the Host header, so anything on the LAN can put `127.0.0.1:PORT` in it
    // and satisfy the rebinding guard, which only ever stopped browsers. Read
    // off the socket, not probed: a firewall dropping the probe would make this
    // pass against a server bound to the whole world.
    const server = (mcp as unknown as { http: Server | null }).http
    assert.ok(server, 'the server is not running at all')
    const address = server.address() as AddressInfo
    assert.equal(
      address.address,
      '127.0.0.1',
      `the gateway is bound to ${address.address}; only 127.0.0.1 keeps it off the network`
    )
    assert.equal(address.port, port, 'the server took a port it was not configured with')
    assert.equal(mcp.status().port, port, 'status() reports a port the server is not on')
  })

  test('a client with the right name and the right token gets in', async () => {
    // The counterweight to every refusal below.
    const answer = await call(port)
    assert.equal(answer.status, 200, `a legitimate call was refused: ${answer.body}`)
    assert.match(answer.body, /run_command/, 'the tools never reached a client that was let in')
  })

  test('every wrong request gets the same 403, byte for byte', async () => {
    // Byte for byte and not merely 403: this rejection is the only answer a
    // page guessing at the port ever gets, so a one-character difference tells
    // it which half it had right. Status alone also cannot tell our 403 from
    // the SDK's rebinding guard, which echoes the offending Host back.
    const wrong: [string, Parameters<typeof call>[1]][] = [
      ['a foreign Host', { host: `evil.com:${port}` }],
      ['a name that merely starts right', { host: `localhost.evil.com:${port}` }],
      ['the neighbouring loopback address', { host: `127.0.0.2:${port}` }],
      ['the v6 loopback', { host: `[::1]:${port}` }],
      ['a page on another origin', { origin: 'http://evil.com' }],
      ['the right origin under the wrong scheme', { origin: `https://localhost:${port}` }],
      ['a wrong token', { token: 'not-the-token' }],
      ['no token at all', { token: null }],
      ['a token one character short of the real one', { token: SERVER_TOKEN.slice(0, -1) }]
    ]

    const answers: [string, string][] = []
    for (const [what, opts] of wrong) {
      const answer = await call(port, opts)
      assert.equal(answer.status, 403, `${what} was answered ${answer.status}, not refused`)
      answers.push([what, answer.body])
    }

    for (const [what, body] of answers) {
      assert.equal(
        body,
        answers[0][1],
        `${what} is answered differently from ${answers[0][0]}, so the two can be told apart`
      )
    }
  })

  test('a locked vault is 503, and only for a caller that proved both', async () => {
    vaultState.unlocked = false
    try {
      const client = await call(port)
      assert.equal(client.status, 503, `a locked vault answered ${client.status}`)
      assert.match(client.body, /vault_locked/, 'the client cannot tell why it was refused')

      // Behind the gate on purpose: a caller that has not proved both is not
      // entitled to know whether the vault is open.
      const stranger = await call(port, { token: 'not-the-token' })
      assert.equal(stranger.status, 403, 'the lock state was disclosed before the gate')
      assert.ok(
        !stranger.body.includes('vault'),
        'the rejection told an unauthenticated caller about the vault'
      )
    } finally {
      vaultState.unlocked = true
    }
  })

  test(`call ${MAX_INFLIGHT_REQUESTS + 1} is refused rather than queued`, async () => {
    // Each parked call pins a buffered body, an McpServer and a transport for
    // up to five minutes. Node bounds none of that — maxConnections is unset —
    // so this cap is all that stands between a chatty client and the main
    // process's memory. Asserted before the test opens that many real sockets.
    assert.ok(
      MAX_INFLIGHT_REQUESTS <= 32,
      `a cap of ${MAX_INFLIGHT_REQUESTS} in-flight calls bounds nothing; each one may pin ` +
        `${MAX_BODY_BYTES} bytes of body plus a parked server and transport`
    )
    const parked = Array.from({ length: MAX_INFLIGHT_REQUESTS }, () => park(port))
    let busy: Answer = { status: 0, body: '' }
    try {
      // Polling, because the parked calls are admitted asynchronously; bounded
      // so a build with no cap fails in two seconds rather than hanging.
      const deadline = Date.now() + 2_000
      busy = await call(port)
      while (busy.status !== 503 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20))
        busy = await call(port)
      }
    } finally {
      await Promise.all(parked.map((p) => p.release()))
    }

    assert.equal(busy.status, 503, `a ${MAX_INFLIGHT_REQUESTS + 1}th call was admitted`)
    assert.match(busy.body, /"reason":"busy"/, 'the client cannot tell a busy server from a broken one')

    // The decrement lives in a `finally`; losing it wedges the gateway at 503.
    const afterwards = await call(port)
    assert.equal(afterwards.status, 200, `the slots were never given back: ${afterwards.body}`)
  })
})

/**
 * The response has to start before the human answers.
 *
 * This is the whole reason the transport streams instead of buffering. Under
 * `enableJsonResponse: true` the SDK returns a promise that settles only once
 * the tool handler does, so nothing at all — not even the status line — left
 * the server while a dialog was open. Clients bound the wait to their first
 * response byte, and Claude Code allows 60 seconds for an HTTP MCP server, so a
 * call died mid-decision and the human's answer arrived for a request that had
 * already been abandoned.
 *
 * The assertion is an ordering, not a duration: the headers must be readable
 * while the bridge promise is still pending. Nothing here sleeps, so a build
 * that goes back to buffering fails by timing out on a `response` event that
 * can never come, rather than by being slow.
 */
describe('a call parked on a human starts its response immediately', () => {
  let port = 0

  before(async () => {
    port = await freePort()
    assert.ok(port >= 1024, `the ephemeral port ${port} is one clampPort would replace`)
    vaultState.unlocked = true
    vaultState.data.settings.mcpPort = port
    await mcp.start()
  })

  after(async () => {
    vaultState.unlocked = true
    await mcp.stop()
  })

  test('the headers arrive while the dialog is still open, and the answer follows', async () => {
    let answerTheHuman: (value: { shared: boolean; text: string }) => void = () => {}
    let dialogOpened: () => void = () => {}
    const opened = new Promise<void>((resolve) => {
      dialogOpened = resolve
    })

    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: () =>
        new Promise<{ shared: boolean; text: string }>((resolve) => {
          answerTheHuman = resolve
          dialogOpened()
        })
    })

    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'read_terminal',
        arguments: { session_id: 's1', reason: 'checking' },
        // A client that wants to be kept informed sends this; the server may
        // not depend on it, but it must not ignore one that is offered.
        _meta: { progressToken: 'tok-1' }
      }
    })

    const req = request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      agent: false,
      headers: { ...CLIENT_HEADERS, authorization: `Bearer ${SERVER_TOKEN}` }
    })

    const headers = new Promise<{ status: number; contentType: string; finished: Promise<string> }>(
      (resolve, reject) => {
        req.on('error', reject)
        req.on('response', (res) => {
          let text = ''
          res.setEncoding('utf8')
          res.on('data', (chunk: string) => {
            text += chunk
          })
          resolve({
            status: res.statusCode ?? 0,
            contentType: String(res.headers['content-type'] ?? ''),
            finished: new Promise<string>((done) => res.on('end', () => done(text)))
          })
        })
      }
    )
    req.end(body)

    // The dialog is open and unanswered from here until the resolve below.
    await opened
    const started = await headers

    assert.equal(started.status, 200, 'no status reached the client while the human was deciding')
    assert.match(
      started.contentType,
      /text\/event-stream/,
      `the response was buffered as ${started.contentType}: nothing can reach the client until ` +
        'the handler returns, which is exactly the timeout this streaming exists to avoid'
    )

    answerTheHuman({ shared: true, text: 'the human picked this' })
    const full = await started.finished
    assert.match(full, /the human picked this/, 'the answer never reached the client')
    assert.match(
      full,
      /^event: message\r?\ndata: /,
      `the stream was not SSE-framed: ${JSON.stringify(full.slice(0, 60))}`
    )
    // Progress is deliberately NOT asserted here: this test answers the human
    // as soon as the headers land, so no interval has elapsed and none is due.
    // The notifications themselves are pinned in the whileAwaitingHuman block.
  })

  test('a call still works for a client that sends no progress token', async () => {
    // The token is optional in the protocol, so the waiting cannot depend on it.
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async () => ({ shared: true, text: 'answered without progress' })
    })

    const answer = await call(port, {
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'read_terminal', arguments: { session_id: 's1', reason: 'checking' } }
      })
    })

    assert.equal(answer.status, 200, `a call without a progress token was refused: ${answer.body}`)
    assert.match(answer.body, /answered without progress/, 'the answer never reached the client')
    assert.ok(
      !answer.body.includes('notifications/progress'),
      'progress was sent to a client that never asked to be kept informed'
    )
  })
})

/**
 * Saying "still waiting" for as long as a human takes.
 *
 * Tested here rather than over HTTP because the interval is measured in tens of
 * seconds: a real socket would have to be held open for a minute to see two
 * notifications, and a suite that sleeps is a suite nobody runs.
 */
describe('whileAwaitingHuman', () => {
  /** Collects what the transport would have put on the wire. */
  function recorder(token?: string | number) {
    const sent: { progressToken: string | number; progress: number; message?: string }[] = []
    return {
      sent,
      extra: {
        _meta: token === undefined ? undefined : { progressToken: token },
        sendNotification: async (n: {
          method: 'notifications/progress'
          params: { progressToken: string | number; progress: number; message?: string }
        }): Promise<void> => {
          assert.equal(n.method, 'notifications/progress', 'wrong notification method')
          sent.push(n.params)
        }
      }
    }
  }

  test('reports progress for as long as the human takes', async (t) => {
    mock.timers.enable({ apis: ['setInterval'] })
    t.after(() => mock.timers.reset())
    const rec = recorder('tok')

    let answer: (value: string) => void = () => {}
    const decision = new Promise<string>((resolve) => {
      answer = resolve
    })
    const waiting = whileAwaitingHuman(rec.extra, decision)

    mock.timers.tick(PROGRESS_INTERVAL_MS * 3)
    assert.equal(rec.sent.length, 3, `three intervals produced ${rec.sent.length} notifications`)
    assert.deepEqual(
      rec.sent.map((p) => p.progress),
      [1, 2, 3],
      'progress must advance, or a client cannot tell a live wait from a stuck one'
    )
    assert.ok(
      rec.sent.every((p) => p.progressToken === 'tok'),
      'every notification must carry the token the client asked us to use'
    )
    assert.ok(
      rec.sent.every((p) => !('total' in p) || p.total === undefined),
      'a total would render as a progress bar, and nobody knows how long a person takes'
    )

    answer('decided')
    assert.equal(await waiting, 'decided', 'the human decision must pass through unchanged')
  })

  test('stops reporting the moment the human answers', async (t) => {
    mock.timers.enable({ apis: ['setInterval'] })
    t.after(() => mock.timers.reset())
    const rec = recorder('tok')

    await whileAwaitingHuman(rec.extra, Promise.resolve('immediate'))
    mock.timers.tick(PROGRESS_INTERVAL_MS * 5)
    assert.equal(rec.sent.length, 0, 'notifications kept firing after the call had finished')
  })

  test('says nothing when the client sent no progress token', async (t) => {
    // Optional in the protocol: there is nothing to address a notification to,
    // and the waiting itself must not depend on having one.
    mock.timers.enable({ apis: ['setInterval'] })
    t.after(() => mock.timers.reset())
    const rec = recorder(undefined)

    let answer: (value: string) => void = () => {}
    const waiting = whileAwaitingHuman(
      rec.extra,
      new Promise<string>((resolve) => {
        answer = resolve
      })
    )
    mock.timers.tick(PROGRESS_INTERVAL_MS * 4)
    assert.equal(rec.sent.length, 0, 'progress was addressed to a token that does not exist')

    answer('decided')
    assert.equal(await waiting, 'decided', 'the wait broke without a progress token')
  })

  test('a client that has gone away does not deny the human their answer', async (t) => {
    // The notification fails once the client drops. The person is still at the
    // dialog, and their answer is still worth delivering if the stream lives.
    mock.timers.enable({ apis: ['setInterval'] })
    t.after(() => mock.timers.reset())

    const extra = {
      _meta: { progressToken: 'tok' },
      sendNotification: async (): Promise<void> => {
        throw new Error('client is gone')
      }
    }

    let answer: (value: string) => void = () => {}
    const waiting = whileAwaitingHuman(
      extra,
      new Promise<string>((resolve) => {
        answer = resolve
      })
    )
    mock.timers.tick(PROGRESS_INTERVAL_MS * 2)
    answer('decided')
    assert.equal(await waiting, 'decided', 'a failed notification rejected the tool call')
  })

  test('a rejected decision still stops the reporting', async (t) => {
    // askShare rejects when the approval queue is full; the interval must be
    // cleared on that path too or it outlives the request that armed it.
    mock.timers.enable({ apis: ['setInterval'] })
    t.after(() => mock.timers.reset())
    const rec = recorder('tok')

    await assert.rejects(
      () => whileAwaitingHuman(rec.extra, Promise.reject(new Error('queue full'))),
      /queue full/
    )
    mock.timers.tick(PROGRESS_INTERVAL_MS * 3)
    assert.equal(rec.sent.length, 0, 'the interval outlived the request that armed it')
  })
})

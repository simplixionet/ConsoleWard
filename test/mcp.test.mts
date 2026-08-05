// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The MCP gate: what can reach the model without a human looking at it.
 *
 * `mcp.ts` reaches Electron transitively (mcp.ts → vault.ts → electron), so
 * `electron` is stubbed before the import. `./ssh` is replaced outright — these
 * tests are about the gate, not about SSH, and a stub is the only way to decide
 * what the captured output says.
 *
 * The tool bodies are reached through `buildServer()` and `_registeredTools`.
 * That is deliberate: the alternative — standing up the HTTP transport and
 * speaking JSON-RPC — would test the SDK rather than the gate. The shape is
 * asserted rather than assumed, because the SDK has already renamed this field
 * once (`callback` → `handler`) and a silent `undefined` would turn every test
 * below green for the wrong reason.
 *
 * The window raise is NOT asserted here. It left `McpBridge` with B3 and now
 * belongs to the approval queue, which is where its tests live.
 */

import { describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'

mock.module('electron', { exports: { app: { getPath: () => '' } } })

interface RunResult {
  output: string
  exitCode: number | null
  signal: string | null
  timedOut: boolean
  truncated: boolean
}

/** What the stubbed `runOnce` hands back; each test sets it. */
let run: RunResult = {
  output: '',
  exitCode: 0,
  signal: null,
  timedOut: false,
  truncated: false
}

mock.module('../src/main/ssh.ts', {
  exports: {
    ssh: {
      isReady: (): boolean => true,
      title: (): string => 'web01',
      list: () => [],
      readText: (): string => 'last twenty lines',
      runOnce: async () => run
    }
  }
})

const { mcp, outputNeedsReview } = await import('../src/main/mcp.ts')

/* ------------------------------------------------------------------ nářadí */

const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.' +
  'dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk'

const LS_LA = [
  'total 48',
  'drwxr-xr-x  6 stan stan  4096 Aug  4 21:13 .',
  '-rw-r--r--  1 stan stan  1071 Jul 30 11:44 LICENSE',
  'stan@web01:~$ '
].join('\n')

interface ToolResult {
  isError?: true
  content: { type: 'text'; text: string }[]
}

type ShareSeen = { origin: string; text: string; autoShareOverridden?: boolean }
type Handler = (args: Record<string, string>, extra: unknown) => Promise<ToolResult>

/** A RunResult carrying `output`, everything else at its ordinary value. */
function ran(output: string, over: Partial<RunResult> = {}): RunResult {
  return { output, exitCode: 0, signal: null, timedOut: false, truncated: false, ...over }
}

/** The callback the SDK would invoke for `name`, with the shape checked. */
function toolHandler(name: string): Handler {
  const server = (mcp as unknown as { buildServer(): unknown }).buildServer()
  const registry = (server as { _registeredTools?: Record<string, { handler?: unknown }> })
    ._registeredTools
  assert.ok(registry, 'the MCP SDK no longer exposes _registeredTools — fix this helper')
  const tool = registry[name]
  assert.ok(tool, `no tool named ${name}; the server has ${Object.keys(registry).join(', ')}`)
  assert.equal(typeof tool.handler, 'function', `${name}.handler is not callable — SDK shape moved`)
  return tool.handler as Handler
}

/** Approves a command, lets it "run", and records everything the bridge saw. */
async function approveAndRun(opts: {
  result: RunResult
  autoShare: boolean
  command?: string
  shareAnswer?: { shared: boolean; text: string }
}): Promise<{ result: ToolResult; shares: ShareSeen[] }> {
  run = opts.result
  const shares: ShareSeen[] = []
  mcp.bind({
    askCommand: async () => ({ approved: true, autoShare: opts.autoShare }),
    askShare: async (req) => {
      shares.push(req as unknown as ShareSeen)
      return opts.shareAnswer ?? { shared: true, text: req.text }
    }
  })
  const result = await toolHandler('run_command')(
    { session_id: 's1', command: opts.command ?? 'cat /srv/app/.env', reason: 'checking config' },
    {}
  )
  return { result, shares }
}

/* --------------------------------------- run_command: the auto-share tick */

describe('run_command: the auto-share tick cannot outrun the detector', () => {
  test('a planted JWT reaches the share dialog even with auto-share ticked', async () => {
    const r = await approveAndRun({ result: ran(`API_TOKEN=${JWT}\n`), autoShare: true })
    assert.equal(
      r.shares.length,
      1,
      'output carrying a JWT went straight to the model: the tick was given while reading the ' +
        'COMMAND, before a single byte of output existed'
    )
    assert.equal(r.shares[0].origin, 'command_output')
    assert.equal(r.shares[0].text, `API_TOKEN=${JWT}\n`, 'the dialog was handed the wrong text')
    assert.equal(
      r.shares[0].autoShareOverridden,
      true,
      'the dialog was not told the tick had been overridden, so it cannot explain itself and ' +
        'the override reads as a bug'
    )
    assert.ok(!r.result.isError, 'the forced dialog turned an approved command into an error')
  })

  test('ordinary ls output with auto-share ticked skips the dialog', async () => {
    const r = await approveAndRun({ result: ran(LS_LA), autoShare: true, command: 'ls -la' })
    assert.equal(
      r.shares.length,
      0,
      'the detector fired on an ordinary directory listing; a checkbox that never applies is ' +
        'worse than no checkbox — it teaches the human to click through'
    )
    assert.match(r.result.content[0].text, /LICENSE/, 'the output never reached the model')
  })

  test('without the tick the dialog opens as before and claims no override', async () => {
    const r = await approveAndRun({ result: ran(LS_LA), autoShare: false, command: 'ls -la' })
    assert.equal(r.shares.length, 1, 'the ordinary path stopped asking')
    assert.ok(
      !r.shares[0].autoShareOverridden,
      'a dialog nobody overrode must not claim it was overridden'
    )
  })

  test('a refusal at the forced dialog keeps the secret off the wire', async () => {
    const r = await approveAndRun({
      result: ran(`API_TOKEN=${JWT}`),
      autoShare: true,
      shareAnswer: { shared: false, text: '' }
    })
    assert.ok(
      !r.result.content[0].text.includes(JWT),
      'the JWT reached the model even though the human refused at the forced dialog'
    )
  })

  test('the tool result says nothing about what the detector found', async () => {
    const r = await approveAndRun({
      result: ran(`API_TOKEN=${JWT}`),
      autoShare: true,
      shareAnswer: { shared: false, text: '' }
    })
    const text = r.result.content[0].text
    for (const leak of ['secret.', 'JWT', 'severity', 'detected', 'credential']) {
      assert.ok(
        !text.includes(leak),
        `the refusal mentions ${leak}; counts and labels describe exactly the text the human ` +
          'withheld, which turns a refusal into an oracle'
      )
    }
  })
})

/* ------------------------------------------------------------ read_terminal */

describe('read_terminal is unaffected', () => {
  test('read_terminal still asks, and never claims an override', async () => {
    const shares: ShareSeen[] = []
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => {
        shares.push(req as unknown as ShareSeen)
        return { shared: true, text: req.text }
      }
    })
    await toolHandler('read_terminal')({ session_id: 's1', reason: 'why' }, {})
    assert.equal(shares.length, 1, 'read_terminal stopped asking')
    assert.equal(shares[0].origin, 'read_terminal')
    assert.ok(!shares[0].autoShareOverridden, 'read_terminal has no tick to override')
  })
})

/* ------------------------------------------------------- the severity policy */

describe('outputNeedsReview: what revokes the tick', () => {
  test('high severity revokes it', () => {
    assert.equal(outputNeedsReview(ran(`API_TOKEN=${JWT}`)), true, 'a JWT in an assignment')
    assert.equal(outputNeedsReview(ran(JWT)), true, 'a bare JWT')
    assert.equal(
      outputNeedsReview(ran('-----BEGIN OPENSSH PRIVATE KEY-----')),
      true,
      'a private key'
    )
    assert.equal(
      outputNeedsReview(ran('psql postgres://app:s3cr3t@db1/app')),
      true,
      'creds in a URL'
    )
  })

  test('a secret on stderr counts too', () => {
    // runExec appends stderr under a label, so the detector sees both streams.
    // `sudo` failures and Authorization errors land there, not on stdout.
    assert.equal(
      outputNeedsReview(ran(`ok\n--- stderr ---\ncurl: Authorization: Bearer ${JWT}\n`)),
      true,
      'the detector was pointed at stdout only'
    )
  })

  test('medium severity does not, because it fires on ordinary output', () => {
    assert.equal(outputNeedsReview(ran('inet 10.0.0.7/24 brd 10.0.0.255')), false, 'ip a')
    assert.equal(
      outputNeedsReview(ran('commit 4f2a1b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6')),
      false,
      'a git SHA is a 40-character random-looking run; forcing here neuters the checkbox'
    )
    assert.equal(outputNeedsReview(ran(LS_LA)), false, 'ls -la')
    assert.equal(outputNeedsReview(ran('')), false, 'empty output')
  })

  test('output that hit the byte cap is never auto-shared', () => {
    // Not a second length limit: runExec already refused to collect more, and
    // an output that ran into the ceiling is exactly the one the human cannot
    // have known the shape of when they ticked the box.
    assert.equal(outputNeedsReview(ran(LS_LA, { truncated: true })), true, 'truncated output')
    assert.equal(outputNeedsReview(ran(LS_LA, { truncated: false })), false, 'complete output')
  })
})

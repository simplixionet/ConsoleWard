// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The MCP gate: what can reach the model without a human looking at it.
 * `electron` and `./ssh` are stubbed before the import, so the tests can decide
 * what the captured output says.
 *
 * Tool bodies are reached through `buildServer()` and `_registeredTools` rather
 * than over JSON-RPC. `toolHandler` asserts that shape, because the SDK has
 * renamed the field once already (`callback` → `handler`) and a silent
 * `undefined` would turn every test below green for the wrong reason.
 */

import { describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { MAX_SCAN_CHARS } from '../src/shared/secretPatterns.ts'

mock.module('electron', { exports: { app: { getPath: () => '' } } })

interface RunResult {
  output: string
  exitCode: number | null
  signal: string | null
  timedOut: boolean
  truncated: boolean
}

let run: RunResult = {
  output: '',
  exitCode: 0,
  signal: null,
  timedOut: false,
  truncated: false
}

const MODEL_SESSIONS = [
  { id: 's1', name: 'web01', status: 'ready' },
  { id: 's2', name: 'Session 1', status: 'ready' }
]

/**
 * The human's view, carrying what the tool promises to withhold: reading this
 * instead of `listForModel` must fail a test, not quietly ship an address.
 */
const HUMAN_SESSIONS = [
  { id: 's1', connectionId: 'c1', title: 'web01', status: 'ready' },
  { id: 's2', connectionId: 'c2', title: 'root@10.0.0.5', status: 'ready' }
]

const PREVIEW = 'last twenty lines'

/**
 * Every command that actually reached the server. A refusal must leave this
 * empty: asserting only on what came back would pass against a build that ran
 * the command and declined to report it, and the running is what matters.
 */
let executed: string[] = []

mock.module('../src/main/ssh.ts', {
  exports: {
    ssh: {
      isReady: (): boolean => true,
      title: (): string => 'web01',
      list: () => HUMAN_SESSIONS,
      listForModel: () => MODEL_SESSIONS,
      readText: (): string => PREVIEW,
      runOnce: async (_id: string, command: string) => {
        executed.push(command)
        return run
      }
    }
  }
})

const { mcp, outputNeedsReview } = await import('../src/main/mcp.ts')

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

function ran(output: string, over: Partial<RunResult> = {}): RunResult {
  return { output, exitCode: 0, signal: null, timedOut: false, truncated: false, ...over }
}

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

describe('run_command: "no" stops the command, not just the answer', () => {
  test('a denied command never runs and nothing comes back from it', async () => {
    executed = []
    run = ran('root:$6$Xy9/aB.rootHashGoesHere:19700:0:99999:7:::')
    const shares: ShareSeen[] = []
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => {
        shares.push(req as unknown as ShareSeen)
        return { shared: true, text: req.text }
      }
    })

    const result = await toolHandler('run_command')(
      { session_id: 's1', command: 'cat /etc/shadow', reason: 'auditing accounts' },
      {}
    )

    assert.deepEqual(
      executed,
      [],
      'the command the human refused was sent to the server anyway; nothing the tool returns can ' +
        'undo that, the file was already read'
    )
    assert.equal(shares.length, 0, 'a refused command still opened a dialog over its output')
    assert.equal(result.isError, true, 'the refusal was reported to the model as an ordinary result')
    assert.ok(
      !result.content[0].text.includes('rootHashGoesHere'),
      'output of a command the human refused reached the model'
    )
  })

  test('an approved command does run, so the test above is not green by accident', async () => {
    executed = []
    await approveAndRun({ result: ran(LS_LA), autoShare: true, command: 'ls -la' })
    assert.deepEqual(executed, ['ls -la'], 'the approved path never reaches runOnce at all')
  })
})

describe('list_sessions withholds what its description promises to withhold', () => {
  test('it publishes exactly id, name and status', async () => {
    const result = await toolHandler('list_sessions')({}, {})
    const { sessions } = JSON.parse(result.content[0].text) as {
      sessions: Record<string, unknown>[]
    }
    assert.equal(sessions.length, 2, 'the fixture did not reach the tool')
    for (const s of sessions) {
      assert.deepEqual(
        Object.keys(s).sort(),
        ['id', 'name', 'status'],
        `list_sessions published ${Object.keys(s).join(', ')}`
      )
    }
  })

  test('an unnamed connection does not leak its username or address', async () => {
    const result = await toolHandler('list_sessions')({}, {})
    const text = result.content[0].text
    assert.ok(!text.includes('@'), 'the model was handed a username@host session name')
    assert.ok(!text.includes('10.0.0.5'), 'the model was handed the server address')
    assert.match(text, /Session 1/, 'the neutral placeholder never reached the model')
  })
})

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

  test('a declined preview never reaches the model', async () => {
    const shares: ShareSeen[] = []
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => {
        shares.push(req as unknown as ShareSeen)
        return { shared: false, text: '' }
      }
    })

    const result = await toolHandler('read_terminal')({ session_id: 's1', reason: 'why' }, {})

    assert.equal(shares[0]?.text, PREVIEW, 'precondition: the dialog really was offered the buffer')
    assert.equal(
      result.isError,
      true,
      'a refusal came back as a successful read, so the model concludes the terminal is empty ' +
        'rather than that it was told no'
    )
    assert.ok(
      !result.content[0].text.includes(PREVIEW),
      'the human declined and the buffer was sent regardless'
    )
  })

  test('text handed back alongside a refusal is still not sent', async () => {
    // `answerShare` blanks the text on a refusal today, but the tool must not
    // lean on that: the refusal decides, not whether the buffer was cleared.
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: false, text: req.text })
    })

    const result = await toolHandler('read_terminal')({ session_id: 's1', reason: 'why' }, {})

    assert.equal(result.isError, true, 'a refusal carrying text was treated as a share')
    assert.ok(
      !result.content[0].text.includes(PREVIEW),
      'the buffer went out on a refusal because only the accompanying text was read'
    )
  })
})

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
    // `sudo` failures and Authorization errors land on stderr, which runExec
    // appends under a label, so the detector has to see both streams.
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

  test('output too long to scan is never auto-shared', () => {
    // Unscanned text is not clean text. `ran()` leaves truncated false, so this
    // is scanSecrets' clip path, not runExec's byte cap.
    const long = 'ls -la\n'.repeat(50_000)
    assert.ok(long.length > MAX_SCAN_CHARS, 'the fixture really does exceed the scan limit')
    assert.equal(outputNeedsReview(ran(long)), true, 'text nobody scanned was auto-shared')
  })

  test('a medium pattern hitting its hit cap does not revoke the tick', () => {
    // `ip -4 route` on a router caps secret.ipAddress at 2000 in ~18 KB, so
    // forcing on `incomplete` would fire on routing tables and little else.
    const routes = Array.from(
      { length: 3000 },
      (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250} dev eth0`
    ).join('\n')
    assert.ok(routes.length < MAX_SCAN_CHARS, 'precondition: this is the hit cap, not the clip')
    assert.equal(outputNeedsReview(ran(routes)), false, 'a routing table revoked the tick')
  })

  test('a key after the hit cap is still found, because the cap is per pattern', () => {
    const routes = Array.from(
      { length: 3000 },
      (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250} dev eth0`
    ).join('\n')
    assert.equal(
      outputNeedsReview(ran(routes + '\n-----BEGIN OPENSSH PRIVATE KEY-----')),
      true,
      'secret.ipAddress capping must not stop secret.privateKeyStart from scanning'
    )
  })

  test('output that hit the byte cap is never auto-shared', () => {
    // Output that hit runExec's byte ceiling is the output whose shape the
    // human cannot have known when they ticked the box.
    assert.equal(outputNeedsReview(ran(LS_LA, { truncated: true })), true, 'truncated output')
    assert.equal(outputNeedsReview(ran(LS_LA, { truncated: false })), false, 'complete output')
  })
})

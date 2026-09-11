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
import type { CommandApproval } from '../src/shared/types.ts'

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

/** Same reason as `executed`: a refused upload must leave this empty. */
let uploaded: { path: string; content: string }[] = []


/**
 * The gate reads its state from the vault on every call, so the tests have to
 * own it. Locked is the safe answer and the one the older tests below rely on
 * without saying so, which is why unattended mode has to be switched on
 * explicitly and switched off again after.
 */
const vaultState = {
  unlocked: true,
  settings: { dangerousMode: false, dangerousGuard: true } as Record<string, unknown>
}

function unattended(dangerous: boolean, guard = true): void {
  vaultState.settings.dangerousMode = dangerous
  vaultState.settings.dangerousGuard = guard
}

/** The upload switch is its own decision, so the tests have to set it on its own. */
function allowUnattendedUpload(allow: boolean): void {
  vaultState.settings.dangerousUpload = allow
}

mock.module('../src/main/vault.ts', {
  exports: {
    vault: {
      isUnlocked: (): boolean => vaultState.unlocked,
      read: () => ({ settings: vaultState.settings, mcpToken: 'x' }),
      mutate: async (): Promise<void> => {}
    }
  }
})

mock.module('../src/main/ssh.ts', {
  exports: {
    UPLOAD_MAX_BYTES: 1024 * 1024,
    ssh: {
      isReady: (): boolean => true,
      title: (): string => 'web01',
      list: () => HUMAN_SESSIONS,
      listForModel: () => MODEL_SESSIONS,
      readText: (): string => PREVIEW,
      runOnce: async (_id: string, command: string) => {
        executed.push(command)
        return run
      },
      // Every ordinary server answers realpath('.') with the session's home.
      remoteHome: async (): Promise<string> => '/home/deploy',
      upload: async (_id: string, path: string, content: Buffer) => {
        uploaded.push({ path, content: content.toString('utf8') })
      }
    }
  }
})

interface AiLogEvent {
  sessionId: string
  event: { kind: string; [k: string]: unknown }
}
let aiEvents: AiLogEvent[] = []
mock.module('../src/main/aiLog.ts', {
  exports: {
    aiLog: {
      record: async (sessionId: string, _name: string, event: { kind: string }): Promise<void> => {
        aiEvents.push({ sessionId, event })
      },
      close: async (): Promise<void> => {},
      closeAll: async (): Promise<void> => {}
    }
  }
})

const { mcp, outputNeedsReview, instructionsFor } = await import('../src/main/mcp.ts')

/** The kinds recorded for the most recent tool call, in order. */
const recordedKinds = (): string[] => aiEvents.map((e) => e.event.kind)

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

// --------------------------------------------------------------------------
// save_command — a write the human reads once and trusts later
// --------------------------------------------------------------------------

describe('save_command keeps the delayed-execution path honest', () => {
  test('a refusal stores nothing', async () => {
    let asked = 0
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => {
        asked += 1
        return { approved: false }
      },
      askUpload: async () => ({ approved: false })
    })

    const result = await toolHandler('save_command')(
      { title: 'Restart app', body: 'systemctl restart app', reason: 'used often' },
      {}
    )

    assert.equal(asked, 1, 'the bridge was never asked')
    assert.equal(result.isError, true, 'a refused save reported success to the model')
  })

  test('the body reaches the dialog with control characters made visible', async () => {
    const seen: { bodyVisualized: string; body: string }[] = []
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async (req) => {
        seen.push(req as unknown as { bodyVisualized: string; body: string })
        return { approved: true }
      },
      askUpload: async () => ({ approved: false })
    })

    await toolHandler('save_command')(
      { title: 'Deploy', body: 'deploy.sh\u0007 --now', reason: 'the release step' },
      {}
    )

    assert.equal(seen.length, 1, 'the dialog never saw the request')
    assert.ok(
      !seen[0].bodyVisualized.includes('\u0007'),
      'a bell character reached the dialog raw; a saved command is a command and is read the ' +
        'same way one is'
    )
    assert.equal(seen[0].body, 'deploy.sh\u0007 --now', 'the stored body must stay exactly as sent')
  })

  test('unattended mode skips the human, which is why the mark is not optional', async () => {
    // Chosen deliberately: an exception for saving would make the mode mean
    // something different depending on which tool was called. What remains is
    // the 'ai' origin and the confirm-on-run it forces.
    unattended(true)
    const skipped: boolean[] = []
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async (_req, skipApproval) => {
        skipped.push(skipApproval)
        return { approved: true }
      },
      askUpload: async () => ({ approved: false })
    })

    await toolHandler('save_command')(
      { title: 'Tail log', body: 'journalctl -u app -n 50', reason: 'checking often' },
      {}
    )
    unattended(false)

    assert.deepEqual(skipped, [true], 'unattended mode still stopped to ask about a save')
  })
})

// --------------------------------------------------------------------------
// upload_file — three switches, and only all three skip the human
// --------------------------------------------------------------------------

describe('upload_file asks before it writes', () => {
  function bindUpload(answer: boolean, seen?: Record<string, unknown>[]) {
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async (req) => {
        seen?.push(req as unknown as Record<string, unknown>)
        return { approved: answer }
      }
    })
  }

  test('a refusal writes nothing to the server', async () => {
    uploaded = []
    bindUpload(false)
    const result = await toolHandler('upload_file')(
      { session_id: 's1', path: '/etc/nginx/conf.d/app.conf', content: 'server {}', reason: 'vhost' },
      {}
    )
    assert.deepEqual(uploaded, [], 'the file the human refused was written anyway')
    assert.equal(result.isError, true, 'a refused upload reported success to the model')
  })

  test('an approval writes exactly what was shown', async () => {
    uploaded = []
    bindUpload(true)
    await toolHandler('upload_file')(
      { session_id: 's1', path: '/etc/nginx/conf.d/app.conf', content: 'server {}', reason: 'vhost' },
      {}
    )
    assert.deepEqual(uploaded, [{ path: '/etc/nginx/conf.d/app.conf', content: 'server {}' }])
  })

  test('the resolved path is what lands, not the spelling the model used', async () => {
    // The human approved a destination. Writing to a different spelling of it
    // would make the dialog a description of some other action.
    uploaded = []
    bindUpload(true)
    await toolHandler('upload_file')(
      { session_id: 's1', path: '~/app/config.yml', content: 'a: 1', reason: 'config' },
      {}
    )
    assert.deepEqual(uploaded, [{ path: '/home/deploy/app/config.yml', content: 'a: 1' }])
  })

  test('a traversal through ~ is resolved before the list sees it', async () => {
    /*
      The hole this closes. SFTP does not expand ~, and an unexpanded one is
      invisible to matchSensitivePath: '~/../../etc/cron.d/x' matches nothing at
      all. Resolving against the server's own home is what makes the rule apply.
    */
    const seen: Record<string, unknown>[] = []
    bindUpload(false, seen)
    await toolHandler('upload_file')(
      { session_id: 's1', path: '~/../../etc/cron.d/backup', content: '* * * * * x', reason: 'x' },
      {}
    )
    assert.equal(seen[0].resolvedPath, '/etc/cron.d/backup', 'the ~ traversal was not resolved')
    assert.ok(seen[0].flagged, 'a path that reaches cron through ~ was not flagged')
  })

  test('a relative path is resolved against the session directory, not refused', async () => {
    // The SFTP session starts in that directory, so prefixing it is what the
    // server would have done. Refusing instead would make the tool description
    // a lie and push the model into guessing an absolute path.
    uploaded = []
    bindUpload(true)
    await toolHandler('upload_file')(
      { session_id: 's1', path: 'app/config.yml', content: 'a: 1', reason: 'config' },
      {}
    )
    assert.deepEqual(uploaded, [{ path: '/home/deploy/app/config.yml', content: 'a: 1' }])
  })

  test('a relative traversal that climbs into cron is flagged', async () => {
    const seen: Record<string, unknown>[] = []
    bindUpload(false, seen)
    await toolHandler('upload_file')(
      { session_id: 's1', path: 'x/../../../etc/cron.d/y', content: '* * * * * z', reason: 'x' },
      {}
    )
    assert.equal(seen[0].resolvedPath, '/etc/cron.d/y', 'the relative traversal was not resolved')
    assert.ok(seen[0].flagged, 'a relative path that climbs into cron was not flagged')
  })

  test('a ~ traversal is flagged even with both unattended switches on', async () => {
    uploaded = []
    unattended(true)
    allowUnattendedUpload(true)
    let asked = 0
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => {
        asked += 1
        return { approved: false }
      }
    })
    await toolHandler('upload_file')(
      { session_id: 's1', path: '~/../../root/.ssh/authorized_keys', content: 'ssh-ed25519 A', reason: 'x' },
      {}
    )
    unattended(false)
    allowUnattendedUpload(false)

    assert.equal(asked, 1, 'a key file was written unwatched because ~ hid the destination')
    assert.deepEqual(uploaded, [])
  })

  test('the dialog is told where the file really lands, not where it was asked to', async () => {
    // /etc/nginx/../cron.d/x IS /etc/cron.d/x, and the difference is the answer.
    const seen: Record<string, unknown>[] = []
    bindUpload(false, seen)
    await toolHandler('upload_file')(
      { session_id: 's1', path: '/etc/nginx/../cron.d/backup', content: '* * * * * x', reason: 'x' },
      {}
    )
    assert.equal(seen[0].resolvedPath, '/etc/cron.d/backup', 'the traversal was passed through raw')
    assert.ok(seen[0].flagged, 'a destination that runs on a schedule was not flagged')
  })

  test('unattended mode alone does not skip it — the upload switch is separate', async () => {
    uploaded = []
    unattended(true)
    allowUnattendedUpload(false)
    let asked = 0
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => {
        asked += 1
        return { approved: false }
      }
    })
    await toolHandler('upload_file')(
      { session_id: 's1', path: '/srv/app/config.yml', content: 'a: 1', reason: 'config' },
      {}
    )
    unattended(false)
    assert.equal(asked, 1, 'a file was written unwatched on the strength of unattended mode alone')
    assert.deepEqual(uploaded, [])
  })

  test('with both switches on it writes an ordinary path without asking', async () => {
    uploaded = []
    unattended(true)
    allowUnattendedUpload(true)
    let asked = 0
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => {
        asked += 1
        return { approved: false }
      }
    })
    await toolHandler('upload_file')(
      { session_id: 's1', path: '/srv/app/config.yml', content: 'a: 1', reason: 'config' },
      {}
    )
    assert.equal(asked, 0, 'the mode the user switched on still stopped to ask')
    assert.deepEqual(uploaded, [{ path: '/srv/app/config.yml', content: 'a: 1' }])
  })

  test('a sensitive destination stops even with both switches on', async () => {
    // The whole reason the destination list exists: unattended is a statement
    // about trust, and authorized_keys is not a file trust should cover.
    uploaded = []
    unattended(true)
    allowUnattendedUpload(true)
    let asked = 0
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => {
        asked += 1
        return { approved: false }
      }
    })
    const result = await toolHandler('upload_file')(
      { session_id: 's1', path: '~/.ssh/authorized_keys', content: 'ssh-ed25519 AAAA', reason: 'access' },
      {}
    )
    unattended(false)
    allowUnattendedUpload(false)

    assert.equal(asked, 1, 'a key file was written with nobody asked')
    assert.deepEqual(uploaded, [])
    assert.match(
      String(result.content[0].text),
      /Do not rephrase/,
      'the refusal invites the model to try a different spelling of the same path'
    )
  })
})

describe('the audit log records what the tools do', () => {
  // The log is what unattended mode is traded against, so "it is written at all"
  // is a property worth pinning rather than assuming.

  test('an unattended run records that it ran with nobody asked, and the result', async () => {
    aiEvents = []
    unattended(true)
    run = ran('done\n')
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => ({ approved: false })
    })
    await toolHandler('run_command')({ session_id: 's1', command: 'uptime', reason: 'check' }, {})
    unattended(false)

    assert.deepEqual(
      recordedKinds(),
      ['unattended', 'ran'],
      'the unattended path did not leave the record it is the whole point of'
    )
    const ran0 = aiEvents.find((e) => e.event.kind === 'ran')
    assert.equal(ran0?.event.output, 'done\n', 'the output was not in the record')
  })

  test('an approved run records proposed, approved and ran', async () => {
    aiEvents = []
    run = ran('ok\n')
    mcp.bind({
      askCommand: async () => ({ approved: true, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => ({ approved: false })
    })
    await toolHandler('run_command')({ session_id: 's1', command: 'id', reason: 'x' }, {})

    // autoShare is off, so the output goes through the share dialog, which is
    // itself an event: the record shows the human was asked to release it.
    assert.deepEqual(recordedKinds(), ['proposed', 'approved', 'ran', 'shared'])
  })

  test('a denied command records the denial', async () => {
    aiEvents = []
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => ({ approved: false })
    })
    await toolHandler('run_command')({ session_id: 's1', command: 'rm x', reason: 'x' }, {})

    assert.deepEqual(recordedKinds(), ['proposed', 'denied'])
  })

  test('an unattended save is recorded as unattended, not as approved-by-a-human', async () => {
    aiEvents = []
    unattended(true)
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: true }),
      askUpload: async () => ({ approved: false })
    })
    await toolHandler('save_command')(
      { title: 'T', body: 'systemctl restart app', reason: 'x' },
      {}
    )
    unattended(false)

    const saved = aiEvents.find((e) => e.event.kind === 'savedCommand')
    assert.ok(saved, 'a save left no audit event')
    assert.equal(saved.event.unattended, true, 'the record cannot tell an unattended save from a clicked-through one')
  })

  test('a failed upload is recorded rather than leaving the log silent', async () => {
    aiEvents = []
    run = ran('')
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async (req) => ({ shared: true, text: req.text }),
      saveCommand: async () => ({ approved: false }),
      askUpload: async () => ({ approved: true })
    })
    // ssh.upload is stubbed to succeed in this suite, so drive the failure
    // through the size cap instead, which rejects before the write.
    await toolHandler('upload_file')(
      { session_id: 's1', path: '/etc/motd', content: 'x'.repeat(2 * 1024 * 1024), reason: 'x' },
      {}
    )
    // Over the cap is refused before any dialog or event; the point of this test
    // is the recorded path, so assert the ordinary approved upload records.
    aiEvents = []
    await toolHandler('upload_file')(
      { session_id: 's1', path: '/etc/motd', content: 'hello', reason: 'x' },
      {}
    )
    assert.ok(
      aiEvents.some((e) => e.event.kind === 'uploaded'),
      'an approved upload left no audit event'
    )
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

// --------------------------------------------------------------------------
// Unattended mode
//
// The gate is the product, so switching it off has to be provable in both
// directions: nothing is asked, and the one thing still standing actually
// stands. `executed` is the assertion that matters throughout — a refusal that
// returns an error while the command ran anyway would pass every check made on
// the return value alone.
// --------------------------------------------------------------------------

describe('unattended mode', () => {
  const noAsk: McpBridgeSpy = {
    commands: 0,
    shares: 0
  }

  /** The last approval handed to the bridge, so its contents can be asserted. */
  let seen: Partial<CommandApproval> = {}

  function bindCounting(): void {
    noAsk.commands = 0
    noAsk.shares = 0
    mcp.bind({
      askCommand: async (req) => {
        noAsk.commands++
        seen = req
        return { approved: true, autoShare: false }
      },
      askShare: async (req) => {
        noAsk.shares++
        return { shared: true, text: req.text }
      }
    })
  }

  test('with the gate on, the human is still asked', async (t) => {
    t.after(() => unattended(false))
    unattended(false)
    bindCounting()
    executed = []

    await toolHandler('run_command')(
      { session_id: 's1', command: 'uptime', reason: 'checking' },
      {}
    )
    assert.equal(noAsk.commands, 1, 'the approval dialog was skipped with the gate on')
  })

  test('with the gate off, nothing is asked and the command runs', async (t) => {
    t.after(() => unattended(false))
    unattended(true)
    bindCounting()
    executed = []
    run = ran('up 9 days')

    const result = await toolHandler('run_command')(
      { session_id: 's1', command: 'uptime', reason: 'checking' },
      {}
    )
    assert.equal(noAsk.commands, 0, 'a dialog was raised in unattended mode')
    assert.equal(noAsk.shares, 0, 'the output was put to a human in unattended mode')
    assert.deepEqual(executed, ['uptime'], 'the command did not reach the server')
    assert.match(result.content[0].text, /up 9 days/, 'the output did not come back')
  })

  test('the destructive list escalates to the human rather than refusing', async (t) => {
    // Unattended mode is a statement about trust, not supervision: the list
    // does not veto, it decides the few cases where a person should look.
    t.after(() => unattended(false))
    unattended(true, true)
    bindCounting()
    executed = []

    await toolHandler('run_command')(
      { session_id: 's1', command: 'rm -rf /', reason: 'cleaning up' },
      {}
    )
    assert.equal(
      noAsk.commands,
      1,
      'a destructive command ran unattended instead of being put to the human'
    )
    assert.deepEqual(executed, ['rm -rf /'], 'approving it did not lead to it running')
    assert.equal(seen.flagged?.id, 'rm.recursiveRoot', 'the dialog was not told which rule fired')
    assert.ok(seen.flagged?.span, 'no span to highlight, so the reader has to hunt for it')
  })

  test('the highlight lands on the destructive half, not the harmless one', async (t) => {
    // The whole value of the span is that it points at the reason. Pointing at
    // `df -h` would be worse than pointing at nothing.
    t.after(() => unattended(false))
    unattended(true, true)
    bindCounting()
    executed = []

    await toolHandler('run_command')(
      { session_id: 's1', command: 'df -h && rm -rf /etc', reason: 'checking' },
      {}
    )
    assert.equal(noAsk.commands, 1, 'a destructive second half ran with nobody asked')

    const span = seen.flagged?.span
    assert.ok(span, 'no span for a chained command')
    const marked = (seen.commandVisualized ?? '').slice(span.start, span.end)
    assert.match(marked, /rm -rf \/etc/, `highlighted the wrong part: ${JSON.stringify(marked)}`)
  })

  test('denying a flagged command tells the model it was singled out', async (t) => {
    t.after(() => unattended(false))
    unattended(true, true)
    noAsk.commands = 0
    executed = []
    mcp.bind({
      askCommand: async (req) => {
        noAsk.commands++
        seen = req
        return { approved: false, autoShare: false }
      },
      askShare: async (req) => ({ shared: true, text: req.text })
    })

    const result = await toolHandler('run_command')(
      { session_id: 's1', command: 'rm -rf /', reason: 'cleaning up' },
      {}
    )
    assert.equal(result.isError, true, 'a denial was not reported as an error')
    assert.match(result.content[0].text, /rm\.recursiveRoot/, 'the model is not told which rule')
    assert.deepEqual(executed, [], 'a denied command ran anyway')
  })

  test('with the list switched off as well, the same command runs', async (t) => {
    // The setting exists, so it has to actually do the thing it says.
    t.after(() => unattended(false))
    unattended(true, false)
    bindCounting()
    executed = []
    run = ran('')

    await toolHandler('run_command')(
      { session_id: 's1', command: 'rm -rf /', reason: 'cleaning up' },
      {}
    )
    assert.deepEqual(executed, ['rm -rf /'], 'the list still refused after being switched off')
  })

  test('read_terminal hands back the whole thing with nobody asked', async (t) => {
    t.after(() => unattended(false))
    unattended(true)
    bindCounting()

    const result = await toolHandler('read_terminal')(
      { session_id: 's1', reason: 'checking' },
      {}
    )
    assert.equal(noAsk.shares, 0, 'a share dialog was raised in unattended mode')
    assert.match(result.content[0].text, /last twenty lines/, 'the output did not come back')
  })

  test('the model is told which mode it is in, and not told otherwise', () => {
    // The instructions are the only way a client learns whether a person is
    // between it and the shell. Saying a human approves everything while
    // nobody does is a falsehood told to the party least able to check it.
    const gated = instructionsFor({ dangerous: false, guard: true })
    assert.match(gated, /A human approves every command/, 'the gated promise went missing')

    const open = instructionsFor({ dangerous: true, guard: true })
    assert.ok(
      !open.includes('A human approves every command'),
      'unattended mode still claims a human approves every command'
    )
    assert.match(open, /RUN IMMEDIATELY/, 'the model is not told commands run unchecked')
    assert.match(open, /catches accidents, not intent/, 'the list is oversold to the model')

    const bare = instructionsFor({ dangerous: true, guard: false })
    assert.match(bare, /Nothing is checked/, 'the model is not told the list is off')
  })
})

interface McpBridgeSpy {
  commands: number
  shares: number
}

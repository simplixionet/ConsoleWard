// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The MCP exec channel.
 *
 * Unlike `ssh.test.mts`, which tests pure helpers, this file stands up the
 * manager: `ssh2` and the vault are replaced with fakes, so `connect()` reaches
 * `ready` without a socket. That is the only way to assert the property this
 * whole change exists for — that bytes arriving on the human's shell stream
 * cannot reach the model — because it is a statement about which stream the
 * manager reads, not about any single function's return value.
 *
 * `mock.module` is keyed on the resolved URL, so mocking '../src/main/vault.ts'
 * also intercepts ssh.ts's own `import { vault } from './vault'`.
 */

import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'

mock.module('electron', { exports: { app: { getPath: () => '' } } })

/** One end of a channel: readable via emit('data'), with a separate stderr. */
class FakeChannel extends EventEmitter {
  stderr = new EventEmitter()
  written: string[] = []
  ended = false
  closed = false
  write(data: Buffer | string): void {
    this.written.push(Buffer.from(data as Buffer).toString('utf8'))
  }
  end(): void {
    this.ended = true
  }
  close(): void {
    this.closed = true
  }
  setWindow(): void {}
}

/** The most recently constructed client, so a test can drive the connection. */
let lastClient: FakeClient | null = null

class FakeClient extends EventEmitter {
  /** The interactive shell — the stream the human types into. */
  shellChannel = new FakeChannel()
  execCalls: { cmd: string; opts: Record<string, unknown>; channel: FakeChannel }[] = []
  /** Set to an Error to make the server refuse the second channel. */
  static denyExec: Error | null = null

  constructor() {
    super()
    lastClient = this
  }
  connect(): this {
    setImmediate(() => this.emit('ready'))
    return this
  }
  shell(_opts: unknown, cb: (err: Error | undefined, ch: FakeChannel) => void): this {
    setImmediate(() => cb(undefined, this.shellChannel))
    return this
  }
  exec(
    cmd: string,
    opts: Record<string, unknown>,
    cb: (err: Error | undefined, ch: FakeChannel) => void
  ): this {
    if (FakeClient.denyExec) {
      const err = FakeClient.denyExec
      setImmediate(() => cb(err, null as unknown as FakeChannel))
      return this
    }
    const channel = new FakeChannel()
    this.execCalls.push({ cmd, opts, channel })
    setImmediate(() => cb(undefined, channel))
    return this
  }
  end(): void {}
  destroy(): void {}
}

mock.module('ssh2', { exports: { Client: FakeClient } })
mock.module('../src/main/vault.ts', {
  exports: {
    vault: {
      isUnlocked: () => true,
      read: () => ({
        connections: [
          {
            id: 'c1',
            name: 'prod',
            host: 'h',
            port: 22,
            username: 'u',
            authKind: 'password',
            password: 'p'
          }
        ],
        knownHosts: [],
        settings: {}
      }),
      mutate: async () => {}
    }
  }
})

const { ssh, runExec } = await import('../src/main/ssh.ts')

const tick = (): Promise<void> => new Promise((r) => setImmediate(r))
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20))

/** A connected, ready session backed by a fresh FakeClient. */
async function readySession(): Promise<{ id: string; client: FakeClient }> {
  const id = await ssh.connect('c1')
  await settle()
  assert.equal(ssh.isReady(id), true, 'fixture: the session never became ready')
  return { id, client: lastClient! }
}

// ---------------------------------------------------------------------------
// The property the exec channel exists for
// ---------------------------------------------------------------------------

describe('runOnce isolation', () => {
  it('never returns bytes the human typed into the interactive session', async () => {
    const { id, client } = await readySession()
    const promise = ssh.runOnce(id, 'id')
    await tick()
    const { channel } = client.execCalls[0]

    // A PTY echoes every keystroke back on the shell stream. Under the old
    // capture this exact sequence came back as the command's output.
    client.shellChannel.emit('data', Buffer.from('sudo -i\r\n'))
    channel.emit('data', Buffer.from('uid=0(root)\n'))
    client.shellChannel.emit('data', Buffer.from('hunter2\r\n'))
    channel.emit('exit', 0)
    channel.emit('close')

    const result = await promise
    assert.equal(result.output, 'uid=0(root)\n')
    assert.ok(!result.output.includes('hunter2'), 'the typed password reached the model')
    assert.ok(!result.output.includes('sudo -i'), 'the typed command reached the model')
  })

  it('writes nothing into the interactive shell', async () => {
    const { id, client } = await readySession()
    const promise = ssh.runOnce(id, 'whoami')
    await tick()
    const { channel, cmd } = client.execCalls[0]
    channel.emit('exit', 0)
    channel.emit('close')
    await promise
    assert.deepEqual(client.shellChannel.written, [], 'the command was typed into the shell')
    assert.equal(cmd, 'whoami', 'the approved text must reach exec verbatim')
  })

  it('sends the approved text byte for byte, without rewriting line endings', async () => {
    const { id, client } = await readySession()
    const promise = ssh.runOnce(id, 'echo a\rb')
    await tick()
    const { cmd, channel } = client.execCalls[0]
    channel.emit('exit', 0)
    channel.emit('close')
    await promise
    assert.equal(cmd, 'echo a\rb')
  })

  it('lets the human keep typing while an AI command runs', async () => {
    const { id, client } = await readySession()
    const promise = ssh.runOnce(id, 'sleep 1')
    await tick()
    assert.doesNotThrow(() => ssh.write(id, 'ls\n'))
    assert.deepEqual(client.shellChannel.written, ['ls\n'])
    const { channel } = client.execCalls[0]
    channel.emit('exit', 0)
    channel.emit('close')
    await promise
  })

  it('refuses a second AI command in the same session', async () => {
    const { id, client } = await readySession()
    const promise = ssh.runOnce(id, 'sleep 1')
    await tick()
    await assert.rejects(
      () => ssh.runOnce(id, 'other'),
      (e: Error & { key?: string }) => e.key === 'error.commandRunning'
    )
    const { channel } = client.execCalls[0]
    channel.emit('exit', 0)
    channel.emit('close')
    await promise
  })

  it('reports a refused channel and does not fall back to the shell', async () => {
    const { id, client } = await readySession()
    FakeClient.denyExec = new Error('(SSH) Channel open failure: open failed')
    try {
      await assert.rejects(
        () => ssh.runOnce(id, 'id'),
        (e: Error & { key?: string }) => e.key === 'error.execFailed'
      )
    } finally {
      FakeClient.denyExec = null
    }
    assert.deepEqual(client.shellChannel.written, [])
  })
})

// ---------------------------------------------------------------------------
// runExec: ending, exit status, limits
// ---------------------------------------------------------------------------

/** A client with only the one method runExec is allowed to touch. */
function execOnly(): {
  calls: { cmd: string; opts: Record<string, unknown>; channel: FakeChannel }[]
  exec: FakeClient['exec']
} {
  const calls: { cmd: string; opts: Record<string, unknown>; channel: FakeChannel }[] = []
  return {
    calls,
    exec(cmd, opts, cb) {
      const channel = new FakeChannel()
      calls.push({ cmd, opts, channel })
      setImmediate(() => cb(undefined, channel))
      return this as never
    }
  }
}

describe('runExec', () => {
  it('reports the real exit status instead of guessing from silence', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'false')
    await tick()
    const { channel } = client.calls[0]
    channel.emit('data', Buffer.from('a'))
    // A pause far longer than the old 900 ms idle window. Nothing may end here.
    await new Promise((r) => setTimeout(r, 1200))
    channel.emit('data', Buffer.from('b'))
    channel.emit('exit', 3)
    channel.emit('close')
    const r = await promise
    assert.equal(r.exitCode, 3)
    assert.equal(r.signal, null)
    assert.equal(r.timedOut, false)
    assert.equal(r.output, 'ab', 'a pause mid-command must not truncate the output')
  })

  it('reports a signal death as a null exit status plus the signal name', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'sleep 99')
    await tick()
    const { channel } = client.calls[0]
    channel.emit('exit', null, 'SIGKILL', false, '')
    channel.emit('close')
    const r = await promise
    assert.equal(r.exitCode, null)
    assert.equal(r.signal, 'SIGKILL')
  })

  it('labels stderr rather than interleaving it with stdout', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'ls /nope')
    await tick()
    const { channel } = client.calls[0]
    channel.stderr.emit('data', Buffer.from('ls: cannot access /nope\n'))
    channel.emit('data', Buffer.from('still stdout\n'))
    channel.emit('exit', 2)
    channel.emit('close')
    const r = await promise
    assert.equal(r.output, 'still stdout\n--- stderr ---\nls: cannot access /nope\n')
  })

  it('leaves the label out when the command wrote nothing to stderr', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'true')
    await tick()
    const { channel } = client.calls[0]
    channel.emit('data', Buffer.from('ok\n'))
    channel.emit('exit', 0)
    channel.emit('close')
    assert.equal((await promise).output, 'ok\n')
  })

  it('caps the output and keeps its head, not its tail', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'yes', { maxBytes: 10 })
    await tick()
    const { channel } = client.calls[0]
    channel.emit('data', Buffer.from('0123456789ABCDEF'))
    channel.emit('data', Buffer.from('MORE'))
    channel.emit('exit', 0)
    channel.emit('close')
    const r = await promise
    assert.equal(r.output, '0123456789')
    assert.equal(r.truncated, true)
    assert.equal(r.exitCode, 0, 'the cap must not cost us the exit status')
  })

  it('does not claim truncation when the output exactly fills the cap', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'echo', { maxBytes: 4 })
    await tick()
    const { channel } = client.calls[0]
    channel.emit('data', Buffer.from('abcd'))
    channel.emit('exit', 0)
    channel.emit('close')
    const r = await promise
    assert.equal(r.output, 'abcd')
    assert.equal(r.truncated, false)
  })

  it('times out, closes the channel and does not pretend the command finished', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'sleep 600', { timeoutMs: 40 })
    await tick()
    const { channel } = client.calls[0]
    channel.emit('data', Buffer.from('partial'))
    const r = await promise
    assert.equal(r.timedOut, true)
    assert.equal(r.exitCode, null)
    assert.equal(r.output, 'partial')
    assert.equal(channel.closed, true, 'a timed-out channel must be closed')
  })

  it('ignores an exit that arrives after the timeout already resolved', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'sleep 600', { timeoutMs: 30 })
    await tick()
    const { channel } = client.calls[0]
    const r = await promise
    channel.emit('exit', 0)
    channel.emit('close')
    await tick()
    assert.equal(r.timedOut, true)
    assert.equal(r.exitCode, null)
  })

  it('never asks for a terminal and closes stdin at once', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'sudo id')
    await tick()
    const { opts, channel } = client.calls[0]
    assert.equal(opts.pty, false, 'a pty would fold stderr into stdout and let sudo hang')
    assert.notEqual(opts.allowHalfOpen, false, 'allowHalfOpen:false makes end() kill the command')
    assert.equal(channel.ended, true, 'stdin must be closed so readers get EOF, not a wait')
    channel.emit('exit', 1)
    channel.emit('close')
    await promise
  })

  it('survives a channel error instead of taking the main process down', async () => {
    const client = execOnly()
    const promise = runExec(client as never, 'id')
    await tick()
    const { channel } = client.calls[0]
    channel.emit('data', Buffer.from('half'))
    channel.emit('error', new Error('broken pipe'))
    const r = await promise
    assert.equal(r.output, 'half')
    assert.equal(r.exitCode, null)
  })

  it('rejects with error.execFailed when exec throws synchronously', async () => {
    const client = {
      exec(): never {
        throw new Error('Not connected')
      }
    }
    await assert.rejects(
      () => runExec(client as never, 'id'),
      (e: Error & { key?: string }) => e.key === 'error.execFailed'
    )
  })
})

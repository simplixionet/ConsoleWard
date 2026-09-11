// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The session transcript, end to end, with one property under test: a password
 * the user types at a hidden prompt never reaches the log.
 *
 * The transcript is on by default and exports to plaintext, so a keystroke feed
 * into it would put every sudo and ssh password on disk. A transcript records
 * what the terminal SHOWED — the server's output — and the server does not echo
 * a password, which is the whole reason the write path must not log keystrokes.
 * This was a real regression: the first draft logged both directions.
 *
 * `ssh2` is faked to reach `ready` without a socket; the log is real and is
 * decrypted back with the format module to see what actually landed.
 */

import { after, before, beforeEach, describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

const LOG_KEY = randomBytes(32).toString('base64')

class FakeChannel extends EventEmitter {
  stderr = new EventEmitter()
  write(): void {}
  end(): void {}
  close(): void {}
  setWindow(): void {}
}

let lastClient: FakeClient | null = null

class FakeClient extends EventEmitter {
  shellChannel = new FakeChannel()
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
  exec(): this {
    return this
  }
  end(): void {}
  destroy(): void {}
}

mock.module('electron', { exports: { app: { getPath: () => '' } } })
mock.module('ssh2', { exports: { Client: FakeClient } })
mock.module('../src/main/vault.ts', {
  exports: {
    vault: {
      isUnlocked: () => true,
      read: () => ({
        connections: [
          { id: 'c1', name: 'prod', host: 'h', port: 22, username: 'u', authKind: 'password', password: 'p' }
        ],
        knownHosts: [],
        settings: { sessionLogs: true },
        logKey: LOG_KEY
      }),
      mutate: async () => {}
    }
  }
})

const { ssh } = await import('../src/main/ssh.ts')
const { logs } = await import('../src/main/logs.ts')
const { readLogFile } = await import('../src/main/logFormat.ts')

let dir = ''
before(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'cwtx-'))
  logs.setDirectory(dir)
})
after(() => rmSync(dir, { recursive: true, force: true }))

// One transcript per test: the file id is a fresh UUID, not the session id, so
// there is no way to pick a test's own file out of several by name.
beforeEach(() => {
  for (const name of readdirSync(dir)) rmSync(path.join(dir, name), { force: true })
})

/** Opening a log runs a blocking scrypt (~200 ms), so poll rather than fix a wait. */
async function waitFor(cond: () => boolean, ms = 3000): Promise<void> {
  const started = Date.now()
  while (!cond()) {
    if (Date.now() - started > ms) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 15))
  }
}

/** A ready session whose transcript file exists on disk. */
async function readySession(): Promise<{ id: string; shell: FakeChannel }> {
  const id = await ssh.connect('c1')
  await waitFor(() => ssh.isReady(id))
  await waitFor(() => readdirSync(dir).some((n) => n.startsWith('transcript-')))
  return { id, shell: lastClient!.shellChannel }
}

/**
 * The transcript, once `marker` has been flushed to it. `disconnect` flushes on
 * a voided promise, so poll rather than assume it landed — and read through the
 * decryptor, which tolerates a partial trailing frame if one is mid-write.
 */
async function transcriptContaining(marker: string): Promise<string> {
  let text = ''
  await waitFor(() => {
    const files = readdirSync(dir)
      .filter((n) => n.startsWith('transcript-'))
      .sort()
    if (files.length === 0) return false
    try {
      const bytes = readFileSync(path.join(dir, files[files.length - 1]))
      text = readLogFile(bytes, Buffer.from(LOG_KEY, 'base64'))
        .frames.map((f) => f.toString('utf8'))
        .join('')
    } catch {
      return false
    }
    return text.includes(marker)
  })
  return text
}

describe('the transcript is what the terminal showed, not what was typed', () => {
  test('a password typed at a hidden prompt never reaches the log', async () => {
    const { id, shell } = await readySession()

    // The server prints a prompt and does not echo what follows — a sudo or ssh
    // password prompt. The user types the password; only ssh.write carries it.
    shell.emit('data', Buffer.from('[sudo] password for u: '))
    ssh.write(id, 'hunter2\r')
    shell.emit('data', Buffer.from('\r\nuid=0(root) gid=0(root)\r\n'))
    await ssh.disconnect(id)

    const text = await transcriptContaining('uid=0(root)')
    assert.ok(!text.includes('hunter2'), 'the typed password landed in the transcript')
    assert.ok(text.includes('password for u:'), 'the prompt the server showed is missing')
  })

  test('a command the server echoes appears once, from the server stream', async () => {
    const { id, shell } = await readySession()

    // A PTY echoes what the user types, so the command appears through the
    // server stream. The user's own keystrokes must not add a second copy.
    ssh.write(id, 'whoami\r')
    shell.emit('data', Buffer.from('whoami\r\nroot\r\n'))
    await ssh.disconnect(id)

    const text = await transcriptContaining('root')
    const hits = text.match(/whoami/g)?.length ?? 0
    assert.equal(hits, 1, `"whoami" appears ${hits} times, not once`)
  })
})

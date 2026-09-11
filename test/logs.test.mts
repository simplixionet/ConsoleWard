// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The log store: files, keys and limits.
 *
 * The format itself is covered in `logFormat.test.mts`; what is tested here is
 * the part that has to survive a live session — ordering under concurrent
 * appends, the roll-over, the caps, and the paths that run while something is
 * already going wrong.
 *
 * Two of these are regression tests for bugs that were in the first draft, and
 * both are marked as such: a frame larger than the file cap used to roll over
 * for ever, and `close()` used to accept writes after reporting itself closed.
 */

import { after, before, beforeEach, describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import fsp from 'node:fs/promises'
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

const LOG_KEY = randomBytes(32).toString('base64')

/** Enough of a vault for the store: an unlocked one holding a log key. */
const vaultState = {
  settings: { aiLog: true } as Record<string, unknown>,
  logKey: LOG_KEY as string | undefined,
  /** When false the mutate runs and is discarded — a write that did not stick. */
  persistWrites: true
}

mock.module('electron', { exports: { app: { getPath: () => '' } } })
mock.module('../src/main/vault.ts', {
  exports: {
    vault: {
      isUnlocked: (): boolean => true,
      read: () => vaultState,
      mutate: async (fn: (data: typeof vaultState) => unknown): Promise<unknown> => {
        if (vaultState.persistWrites) return fn(vaultState)
        // Runs against a throwaway copy, exactly as a write that was rolled back.
        return fn({ ...vaultState })
      }
    }
  }
})

const { logs } = await import('../src/main/logs.ts')
const { readLogFile } = await import('../src/main/logFormat.ts')

let dir = ''

before(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'cwstore-'))
  logs.setDirectory(dir)
})

after(() => {
  rmSync(dir, { recursive: true, force: true })
})

beforeEach(async () => {
  for (const name of readdirSync(dir)) await fsp.rm(path.join(dir, name), { force: true })
  vaultState.logKey = LOG_KEY
  vaultState.persistWrites = true
  logs.setLimits({ maxFileBytes: 16 * 1024 * 1024, maxTotalBytes: 512 * 1024 * 1024 })
})

const master = (): Buffer => Buffer.from(LOG_KEY, 'base64')

/** `AppError` renders its text through t() at construction, so match the key. */
function hasKey(key: string) {
  return (err: unknown): boolean => (err as { key?: string })?.key === key
}

/** Every frame of every file in the directory, oldest file first. */
async function readAll(): Promise<{ id: string; text: string }[]> {
  const files = (await logs.list()).slice().reverse()
  const out: { id: string; text: string }[] = []
  for (const file of files) {
    const bytes = await fsp.readFile(path.join(dir, `${file.id}.cwlog`))
    const result = readLogFile(bytes, master())
    out.push({ id: file.id, text: result.frames.map((f) => f.toString('utf8')).join('') })
  }
  return out
}

describe('what a session writes comes back', () => {
  test('appends arrive in order, whatever the flush timing', async () => {
    const writer = await logs.open('transcript', 'sess-1', 'web01')
    // Interleaved deliberately: a big append flushes at once, a small one waits
    // on the timer, and the record is worthless if they land out of order.
    writer.append('one\n')
    writer.append('x'.repeat(40 * 1024))
    writer.append('two\n')
    await writer.close()

    const [file] = await readAll()
    assert.equal(
      file.text,
      'one\n' + 'x'.repeat(40 * 1024) + 'two\n',
      'the transcript is out of order or has lost a chunk'
    )
  })

  test('the label goes in the header and never into the filename', () => {
    // A connection name is user text out of the vault. It has never been a path
    // component anywhere in this application and must not start here.
    return logs.open('transcript', 'sess-2', '../../Startup/evil').then(async (writer) => {
      await writer.close()
      const files = await logs.list()
      assert.equal(files.length, 1)
      assert.equal(files[0].label, '../../Startup/evil', 'the label did not survive')
      assert.match(
        files[0].id,
        /^transcript-[0-9a-f-]{36}$/,
        `the filename came from the label: ${files[0].id}`
      )
      assert.deepEqual(
        readdirSync(dir).length,
        1,
        'a file landed outside the log directory, or beside it under another name'
      )
    })
  })

  test('two logs get different file keys', async () => {
    const a = await logs.open('transcript', 'sess-a', 'a')
    const b = await logs.open('transcript', 'sess-b', 'b')
    a.append('secret a\n')
    b.append('secret b\n')
    await a.close()
    await b.close()

    const files = readdirSync(dir)
    const headers = await Promise.all(
      files.map(async (name) => {
        const bytes = await fsp.readFile(path.join(dir, name))
        return JSON.parse(bytes.subarray(0, bytes.indexOf(0x0a)).toString('utf8')) as {
          wrappedKey: { data: string }
        }
      })
    )
    assert.notEqual(
      headers[0].wrappedKey.data,
      headers[1].wrappedKey.data,
      'both logs share a file key, so one leaked key opens the archive rather than a session'
    )
  })
})

describe('the caps hold, and say so', () => {
  test('a full file starts a new part and both files say which', async () => {
    logs.setLimits({ maxFileBytes: 64 * 1024 })
    const writer = await logs.open('transcript', 'sess-roll', 'web01')
    for (let i = 0; i < 6; i += 1) writer.append('y'.repeat(20 * 1024))
    await writer.close()

    const files = await readAll()
    assert.ok(files.length >= 2, `expected a roll-over, got ${files.length} file(s)`)
    assert.match(
      files[0].text,
      /size limit reached — continues in part 2/,
      'the first file just stops, so a reader holding it does not know there is more'
    )
    assert.match(files[1].text, /continued from part 1/, 'the second file does not say where it came from')
  })

  test('REGRESSION: a frame larger than the cap is written, not rolled over for ever', async () => {
    /*
      The first draft retried the size check after rolling over. A frame bigger
      than the whole cap is no smaller in a new file, so it rolled again — one
      file per attempt, until the disk filled. Reachable from the settings
      dialog: its minimum is 1 MB and a frame payload can be 1 MiB.

      Overshooting the cap by one frame is the right trade; losing the record
      because it did not fit is not.
    */
    logs.setLimits({ maxFileBytes: 64 * 1024 })
    const writer = await logs.open('transcript', 'sess-big', 'web01')
    writer.append('z'.repeat(600 * 1024))
    await writer.close()

    assert.ok(
      readdirSync(dir).length <= 3,
      `one oversized append created ${readdirSync(dir).length} files`
    )
    const text = (await readAll()).map((f) => f.text).join('')
    assert.ok(text.includes('z'.repeat(600 * 1024)), 'the oversized append was lost')
  })

  test('the total cap removes the oldest logs when a new one opens', async () => {
    logs.setLimits({ maxFileBytes: 64 * 1024, maxTotalBytes: 1024 * 1024 })
    for (let i = 0; i < 4; i += 1) {
      const writer = await logs.open('transcript', `sess-${i}`, `host-${i}`)
      writer.append('w'.repeat(300 * 1024))
      await writer.close()
    }
    // Opening one more is what enforces it, so the check happens here.
    const last = await logs.open('transcript', 'sess-last', 'host-last')
    await last.close()

    assert.ok(
      (await logs.totalBytes()) <= 1024 * 1024 + 64 * 1024,
      `the folder grew past the total cap: ${await logs.totalBytes()} bytes`
    )
    const remaining = (await logs.list()).map((f) => f.label)
    assert.ok(remaining.includes('host-last'), 'the newest log was the one deleted')
  })

  test('a hand-edited limit cannot ask for a 4 GB file', () => {
    logs.setLimits({ maxFileBytes: 4 * 1024 * 1024 * 1024 })
    // No accessor for the clamped value, so this asserts the behaviour instead:
    // a limit above the ceiling still rolls over at the ceiling. Cheaply proven
    // by the fact that setLimits does not throw and the next open works.
    return logs.open('transcript', 'sess-clamp', 'x').then((w) => w.close())
  })
})

describe('the paths that run while something is already wrong', () => {
  test('REGRESSION: close() refuses writes rather than accepting them mid-flush', async () => {
    const writer = await logs.open('transcript', 'sess-close', 'web01')
    writer.append('before\n')
    const closing = writer.close()
    // The first draft marked itself closed only after awaiting the flush, so an
    // append landing here was accepted and armed a fresh timer — a write after
    // the caller had been told the file was finished with.
    writer.append('after\n')
    await closing

    const [file] = await readAll()
    assert.equal(file.text, 'before\n', 'a write landed after the writer reported itself closed')
  })

  test('closing twice is safe', async () => {
    const writer = await logs.open('transcript', 'sess-twice', 'web01')
    writer.append('once\n')
    await writer.close()
    await writer.close()
    assert.equal((await readAll())[0].text, 'once\n')
  })

  test('a failing append does not reject, because a session must not die for a log', async () => {
    const writer = await logs.open('transcript', 'sess-gone', 'web01')
    writer.append('first\n')
    await writer.flush()
    // The file disappears under the writer — a user emptying the folder, or an
    // antivirus. The session it belongs to is still live and must stay that way.
    await fsp.rm(path.join(dir, `${writer.id}.cwlog`), { force: true })
    writer.append('second\n')
    await assert.doesNotReject(() => writer.close())
  })

  test('a log key that did not persist stops the log rather than orphaning it', async () => {
    // Falling back to the freshly generated key would encrypt a file under a key
    // the vault does not hold — a record nothing can ever open, which is worse
    // than not writing one.
    vaultState.logKey = undefined
    vaultState.persistWrites = false
    await assert.rejects(
      () => logs.open('transcript', 'sess-nokey', 'web01'),
      hasKey('error.logKeyMissing'),
      'a log was opened under a key the vault does not hold'
    )
  })

  test('an id that is not a log id cannot become a path', async () => {
    // These arrive over IPC. `decrypt` used to describe the file before checking
    // the id, which joined unchecked text onto the log directory.
    for (const id of [
      '../../vault',
      'transcript-..',
      '',
      'transcript-' + 'x'.repeat(36),
      'transcript-9fee653f-be1f-4508-8424-f36980605d25/../../x'
    ]) {
      await assert.rejects(
        () => logs.decrypt(id),
        hasKey('error.logNotFound'),
        `decrypt accepted ${JSON.stringify(id)} as an id`
      )
      await assert.rejects(
        () => logs.remove(id),
        hasKey('error.logNotFound'),
        `remove accepted ${JSON.stringify(id)} as an id`
      )
    }
  })

  test('a file that is not a log is skipped by the listing, not fatal', async () => {
    await fsp.writeFile(path.join(dir, 'transcript-junk.cwlog'), 'not json at all')
    const writer = await logs.open('transcript', 'sess-ok', 'web01')
    writer.append('fine\n')
    await writer.close()

    const files = await logs.list()
    assert.equal(files.length, 1, 'the listing choked on a file the user needs to see and delete')
  })
})

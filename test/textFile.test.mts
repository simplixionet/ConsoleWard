// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Reading a file the human picked in the open dialog.
 *
 * The interesting case is the one `fsp.stat` cannot see: on Windows a named
 * pipe reports `size: 0` AND `isFile() === true`, so the obvious `stat.isFile()`
 * guard lets it through and the read that follows never returns. The pipe test
 * below is therefore the point of this file, not a corner case.
 *
 * Every assertion is raced against a timer. A regression here does not produce
 * a wrong value, it produces a promise that never settles — and a hanging test
 * reads as a stuck CI runner rather than as a failure.
 */

import { describe, test, mock, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'

mock.module('electron', { exports: { app: { getPath: () => '' } } })

const { readSmallTextFile, TEXT_FILE_MAX_BYTES } = await import('../src/main/textFile.ts')

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-textfile-'))
const servers: net.Server[] = []

after(() => {
  for (const s of servers) s.close()
  fs.rmSync(dir, { recursive: true, force: true })
})

const at = (name: string): string => path.join(dir, name)

function write(name: string, content: string): string {
  const p = at(name)
  fs.writeFileSync(p, content)
  return p
}

const HUNG = Symbol('the call never settled')

/** Resolves to HUNG rather than hanging, so a regression is red and not stuck. */
function within<T>(promise: Promise<T>, ms = 2000): Promise<T | typeof HUNG | Error> {
  return Promise.race([
    promise.catch((err: Error) => err),
    new Promise<typeof HUNG>((r) => setTimeout(() => r(HUNG), ms))
  ])
}

const keyOf = (result: unknown): string | undefined =>
  (result as { key?: string } | undefined)?.key

describe('readSmallTextFile', () => {
  test('reads an ordinary file whole', async () => {
    const body = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n'
    const result = await within(readSmallTextFile(write('id_ed25519', body)))
    assert.deepEqual(result, { name: 'id_ed25519', content: body })
  })

  test('reads an empty file without complaining', async () => {
    const result = await within(readSmallTextFile(write('empty.key', '')))
    assert.deepEqual(result, { name: 'empty.key', content: '' })
  })

  test('refuses a file over the size limit', async () => {
    const result = await within(readSmallTextFile(write('big.key', 'x'.repeat(64)), 32))
    assert.equal(keyOf(result), 'error.fileTooLarge')
  })

  test('accepts a file exactly at the limit', async () => {
    const result = await within(readSmallTextFile(write('exact.key', 'x'.repeat(32)), 32))
    assert.deepEqual(result, { name: 'exact.key', content: 'x'.repeat(32) })
  })

  test('refuses a directory instead of trying to read it', async () => {
    fs.mkdirSync(at('adir'), { recursive: true })
    const result = await within(readSmallTextFile(at('adir')))
    assert.ok(result instanceof Error, 'a directory was read as a file')
  })

  test('reports a missing file rather than hanging', async () => {
    const result = await within(readSmallTextFile(at('nope.key')))
    assert.ok(result instanceof Error, 'a missing file did not raise')
    assert.notEqual(result, HUNG)
  })

  test('refuses a pipe that stat calls a regular file', async (t) => {
    // THE finding. On win32 a named pipe answers `size: 0, isFile() === true`
    // to a path stat, so the release plan's proposed `stat.isFile()` fix leaves
    // this wide open — and fsp.readFile on it never returns, pinning one of the
    // four libuv threadpool threads for good.
    if (process.platform !== 'win32') {
      // POSIX: a real FIFO. mkfifo is not available through node, so skip
      // rather than pretend — the win32 path is the one that ships.
      t.skip('named pipes are exercised on win32; POSIX FIFOs need mkfifo')
      return
    }
    const pipePath = `\\\\.\\pipe\\cw-test-${process.pid}-${servers.length}`
    const server = net.createServer(() => {})
    servers.push(server)
    await new Promise<void>((resolve) => server.listen(pipePath, resolve))

    const result = await within(readSmallTextFile(pipePath))
    assert.notEqual(result, HUNG, 'reading a named pipe wedged the process')
    assert.equal(
      keyOf(result),
      'error.notRegularFile',
      'a named pipe was accepted as an ordinary file'
    )
  })

  test('the default limit is a megabyte', () => {
    assert.equal(TEXT_FILE_MAX_BYTES, 1024 * 1024)
  })
})

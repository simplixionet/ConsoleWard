// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The standalone decryptor against the writer.
 *
 * The format is a public promise, and `scripts/decrypt-log.mjs` is a second
 * implementation of it, written from the documentation rather than from
 * `logFormat.ts`. These tests are what stops the two drifting apart — a change
 * to the writer that nobody carries across shows up here rather than in a year,
 * in front of somebody who needs the log because something already went wrong.
 */

import { after, before, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

const { createLogFile, encodeFrame } = await import('../src/main/logFormat.ts')

const SCRIPT = path.resolve('scripts/decrypt-log.mjs')
let dir = ''

before(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'cwlog-'))
})

after(() => {
  rmSync(dir, { recursive: true, force: true })
})

/** Writes the file the application would have written, and returns its path. */
function writeLog(
  masterKey: Buffer,
  payloads: string[],
  opts: { tail?: Buffer; sessionId?: string } = {}
): string {
  const created = createLogFile({
    sessionId: opts.sessionId ?? 'sess-1',
    label: 'web01',
    masterKey
  })
  const parts: Buffer[] = [Buffer.from(created.headerLine, 'utf8')]
  payloads.forEach((text, index) => {
    parts.push(
      encodeFrame({
        fileKey: created.fileKey,
        header: created.header,
        index,
        payload: Buffer.from(text, 'utf8')
      })
    )
  })
  if (opts.tail) parts.push(opts.tail)

  const file = path.join(dir, `transcript-${randomBytes(8).toString('hex')}.cwlog`)
  writeFileSync(file, Buffer.concat(parts))
  return file
}

/** stdout is the log's bytes; anything the tool wants to say goes to stderr. */
function decrypt(file: string, key: Buffer): string {
  return execFileSync(process.execPath, [SCRIPT, file, '--key', key.toString('base64')], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  })
}

function refusalFor(file: string, key: Buffer): string {
  try {
    execFileSync(process.execPath, [SCRIPT, file, '--key', key.toString('base64')], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    })
  } catch (err) {
    return String((err as { stderr?: string }).stderr ?? '')
  }
  assert.fail('the decryptor accepted a log it should have refused')
}

describe('a log ConsoleWard wrote opens without ConsoleWard', () => {
  test('the frames come back in order, byte for byte', () => {
    const master = randomBytes(32)
    const lines = ['stan@web01:~$ uptime\n', ' 21:04:11 up 9 days\n', 'stan@web01:~$ \n']
    assert.equal(
      decrypt(writeLog(master, lines), master),
      lines.join(''),
      'the standalone reader and the writer disagree about the format'
    )
  })

  test('an empty log is a header and nothing else', () => {
    const master = randomBytes(32)
    assert.equal(decrypt(writeLog(master, []), master), '')
  })

  test('a payload with every kind of byte survives the round trip', () => {
    // Terminal output is not text: it carries escape sequences, and a reader
    // that normalised anything would quietly rewrite the record.
    const master = randomBytes(32)
    // Built from char codes rather than written inline: a raw ESC in the source
    // makes this file binary to grep and invisible in a diff.
    const ESC = String.fromCharCode(0x1b)
    const BEL = String.fromCharCode(0x07)
    const payload = `${ESC}[31mred${ESC}[0m\r\n${BEL}tab\there\nnon-ascii: příliš žluťoučký\n`
    assert.equal(decrypt(writeLog(master, [payload]), master), payload)
  })

  test('a 16-byte master is enough, as the format says', () => {
    // The floor exists so an unset master cannot quietly derive a usable key.
    const master = randomBytes(16)
    assert.equal(decrypt(writeLog(master, ['short key\n']), master), 'short key\n')
  })
})

describe('the decryptor refuses what it cannot vouch for', () => {
  test('a wrong master key is refused, not read as garbage', () => {
    const file = writeLog(randomBytes(32), ['anything\n'])
    assert.match(
      refusalFor(file, randomBytes(32)),
      /did not unwrap/,
      'a wrong key produced something other than a clear refusal'
    )
  })

  test('a frame edited in place fails its tag', () => {
    const master = randomBytes(32)
    const file = writeLog(master, ['the original line\n'])
    const bytes = readFileSync(file)
    // Past the header line, the frame's 4-byte length and its 12-byte nonce:
    // inside the ciphertext, where an editor would actually be working.
    const at = bytes.indexOf(0x0a) + 1 + 4 + 12 + 2
    bytes[at] ^= 0x01
    writeFileSync(file, bytes)

    assert.match(refusalFor(file, master), /failed its tag/)
  })

  test('a frame moved within the file is caught by its index', () => {
    const master = randomBytes(32)
    const created = createLogFile({ sessionId: 'sess-1', label: 'web01', masterKey: master })
    const frames = ['one\n', 'two\n'].map((text, index) =>
      encodeFrame({
        fileKey: created.fileKey,
        header: created.header,
        index,
        payload: Buffer.from(text, 'utf8')
      })
    )
    const file = path.join(dir, `swapped-${randomBytes(8).toString('hex')}.cwlog`)
    // Swapped, both still under the right key: only the index in the nonce
    // separates this from an honest file.
    writeFileSync(file, Buffer.concat([Buffer.from(created.headerLine), frames[1], frames[0]]))

    assert.match(refusalFor(file, master), /missing or moved/)
  })

  test('a truncated tail keeps everything before the cut', () => {
    // The distinction matters to someone reading this because something already
    // went wrong: "the power went out" and "somebody edited this" are different
    // findings, and only one of them is about the file.
    const master = randomBytes(32)
    const file = writeLog(master, ['first frame\n'], { tail: Buffer.from([0x00, 0x00]) })
    assert.equal(decrypt(file, master), 'first frame\n', 'the frames before the cut were lost')
  })

  test('an impossible frame length is damage, not a truncation', () => {
    /*
      The ordering the format documents: check the bound BEFORE the short read.
      A length the writer could never have produced means the file was edited;
      reading it as a partial write would file the rest of the file away as an
      ordinary crash and report success.
    */
    const master = randomBytes(32)
    const file = writeLog(master, ['first\n'])
    const bytes = readFileSync(file)
    // The length prefix of the first frame, immediately after the header line.
    bytes.writeUInt32BE(0xfffffff0, bytes.indexOf(0x0a) + 1)
    writeFileSync(file, bytes)

    assert.match(refusalFor(file, master), /cannot write/)
  })

  test('a frame length below the minimum is refused too', () => {
    const master = randomBytes(32)
    const file = writeLog(master, ['first\n'])
    const bytes = readFileSync(file)
    bytes.writeUInt32BE(4, bytes.indexOf(0x0a) + 1)
    writeFileSync(file, bytes)

    assert.match(refusalFor(file, master), /cannot write/)
  })

  test('a file that is not a log at all is named as such', () => {
    const file = path.join(dir, 'not-a-log.cwlog')
    writeFileSync(file, '{"magic":"NOPE","version":1}\n')
    assert.match(refusalFor(file, randomBytes(32)), /not a ConsoleWard log/)
  })

  test('a future format version is refused rather than guessed at', () => {
    const master = randomBytes(32)
    const file = writeLog(master, ['hello\n'])
    const bytes = readFileSync(file)
    const nl = bytes.indexOf(0x0a)
    const header = JSON.parse(bytes.subarray(0, nl).toString('utf8')) as { version: number }
    header.version = 99
    writeFileSync(
      file,
      Buffer.concat([Buffer.from(JSON.stringify(header) + '\n'), bytes.subarray(nl + 1)])
    )

    assert.match(refusalFor(file, master), /format version 99/)
  })
})

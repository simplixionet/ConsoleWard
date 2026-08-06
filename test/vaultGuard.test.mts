// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { strict as assert } from 'node:assert'
import { after, describe, it } from 'node:test'
import fsp from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  GUARD_MAX_BYTES,
  GUARD_VERSION,
  parseGuard,
  readAnchorFile,
  removeAnchorFile,
  serializeGuard,
  verdict,
  writeAnchorFile,
  type Anchor,
  type GuardSealer
} from '../src/main/vaultGuard.ts'

/** Reverses bytes instead of encrypting — the tests cover shape and code paths, not crypto. */
function fakeSealer(available = true): GuardSealer {
  return {
    available: () => available,
    seal: (plain) => Buffer.from(plain, 'utf8').reverse(),
    open: (blob) => Buffer.from(blob).reverse().toString('utf8')
  }
}

/** A sealer whose open() always fails — a foreign profile, a different user. */
const brokenSealer: GuardSealer = {
  available: () => true,
  seal: (plain) => Buffer.from(plain, 'utf8'),
  open: () => {
    throw new Error('DPAPI: key not found')
  }
}

function anchor(counter: number, at = 1_700_000_000_000): Anchor {
  return { counter, at, protected: true }
}

describe('verdict', () => {
  it('a matching counter is fine', () => {
    assert.deepEqual(verdict(anchor(5), 5), { kind: 'ok' })
  })

  // The anchor is written only after the vault write succeeds, so a crash between
  // the two leaves it one behind -- ordinary, and not worth crying wolf over.
  it('a file newer than the anchor is no alarm', () => {
    assert.deepEqual(verdict(anchor(5), 6), { kind: 'ok' })
    assert.deepEqual(verdict(anchor(5), 500), { kind: 'ok' })
  })

  it('a file older than the anchor is a rollback', () => {
    assert.deepEqual(verdict(anchor(9, 123), 4), {
      kind: 'rollback',
      expected: 9,
      found: 4,
      at: 123
    })
  })

  it('one step back is caught too', () => {
    assert.equal(verdict(anchor(9), 8).kind, 'rollback')
  })

  it('with no anchor there is no verdict', () => {
    assert.deepEqual(verdict(null, 3), { kind: 'unknown' })
  })

  // NaN loses every comparison, so a naive `<` answers "ok" and turns the check
  // off for exactly the corrupt file worth looking at.
  it('a nonsense counter in the header gives neither ok nor an alarm', () => {
    for (const bad of [NaN, -1, 1.5, Infinity]) {
      assert.deepEqual(verdict(anchor(5), bad), { kind: 'unknown' }, `for ${bad}`)
    }
  })
})

describe('serializeGuard + parseGuard', () => {
  it('survives the round trip', () => {
    const sealer = fakeSealer()
    const read = parseGuard(serializeGuard(7, 1234, sealer), sealer)
    assert.equal(read.kind, 'ok')
    assert.deepEqual(read.kind === 'ok' && read.anchor, { counter: 7, at: 1234, protected: true })
  })

  // Decode before judging: base64 hides the plaintext either way, so asserting on
  // the raw file text also passes for an anchor that was never sealed.
  it('what gets written is really sealed, not just encoded', () => {
    const raw = serializeGuard(42, 1234, fakeSealer())
    assert.equal(JSON.parse(raw).protected, true)

    const decoded = Buffer.from(JSON.parse(raw).payload, 'base64').toString('utf8')
    assert.notEqual(decoded, JSON.stringify({ counter: 42, at: 1234 }))
    assert.ok(!decoded.includes('"counter"'), 'the counter must not be readable after decoding')
  })

  // Refusing to write an anchor without a keyring would switch rollback detection
  // off for a whole platform; unprotected still catches every honest rollback.
  it('with no keyring the anchor is written in plain text, but it admits it', () => {
    const sealer = fakeSealer(false)
    const raw = serializeGuard(7, 1234, sealer)
    assert.equal(JSON.parse(raw).protected, false)

    const read = parseGuard(raw, sealer)
    assert.equal(read.kind, 'ok')
    assert.equal(read.kind === 'ok' && read.anchor.protected, false)
    assert.equal(read.kind === 'ok' && read.anchor.counter, 7)
  })

  it('a machine that has a keyring still reads an unprotected anchor', () => {
    const written = serializeGuard(7, 1234, fakeSealer(false))
    const read = parseGuard(written, fakeSealer(true))
    assert.equal(read.kind, 'ok')
    assert.equal(read.kind === 'ok' && read.anchor.counter, 7)
  })

  it('without a keyring a protected anchor is unreadable, not discarded as missing', () => {
    const written = serializeGuard(7, 1234, fakeSealer(true))
    const read = parseGuard(written, fakeSealer(false))
    assert.equal(read.kind, 'unreadable')
  })

  it('a foreign seal is unreadable, not empty', () => {
    const written = serializeGuard(7, 1234, brokenSealer)
    assert.equal(parseGuard(written, brokenSealer).kind, 'unreadable')
  })

  it('the write refuses a negative or non-integer counter', () => {
    const sealer = fakeSealer()
    for (const bad of [-1, 1.5, NaN, Infinity]) {
      assert.throws(() => serializeGuard(bad, 1, sealer), /counter/, `for ${bad}`)
      assert.throws(() => serializeGuard(1, bad, sealer), /timestamp/, `for ${bad}`)
    }
  })
})

describe('parseGuard refuses a damaged file', () => {
  const sealer = fakeSealer()

  const broken: [string, string][] = [
    ['empty file', ''],
    ['not JSON', '{{{'],
    ['an array instead of an object', '[]'],
    ['null', 'null'],
    ['version missing', JSON.stringify({ protected: true, payload: 'eA==' })],
    ['payload missing', JSON.stringify({ version: 1, protected: true })],
    ['payload is not a string', JSON.stringify({ version: 1, protected: true, payload: 5 })],
    ['protected missing', JSON.stringify({ version: 1, payload: 'eA==' })],
    ['empty payload', JSON.stringify({ version: 1, protected: false, payload: '' })]
  ]

  for (const [name, raw] of broken) {
    it(name, () => {
      assert.equal(parseGuard(raw, sealer).kind, 'unreadable', name)
    })
  }

  // If an unknown version read as "absent" the caller would overwrite it, so
  // `version: 999` in the file would switch rollback detection off silently.
  it('an unknown version is unreadable, not missing', () => {
    const raw = JSON.stringify({ version: GUARD_VERSION + 1, protected: false, payload: 'eA==' })
    const read = parseGuard(raw, sealer)
    assert.equal(read.kind, 'unreadable')
    assert.match(read.kind === 'unreadable' ? read.reason : '', /version/)
  })

  it('a payload with nonsense inside it does not pass', () => {
    const bad = [
      JSON.stringify({ counter: -1, at: 1 }),
      JSON.stringify({ counter: 1.5, at: 1 }),
      JSON.stringify({ counter: '3', at: 1 }),
      JSON.stringify({ at: 1 }),
      JSON.stringify({ counter: 1 }),
      JSON.stringify({ counter: 1, at: -5 }),
      'nejsem json'
    ]
    for (const body of bad) {
      const raw = JSON.stringify({
        version: 1,
        protected: false,
        payload: Buffer.from(body, 'utf8').toString('base64')
      })
      assert.equal(parseGuard(raw, sealer).kind, 'unreadable', body)
    }
  })
})

describe('the module must not touch Electron', () => {
  // Four test files stub only `app` from electron, so importing safeStorage here
  // would take three of them down at import time. Hence the injected sealer.
  it('the source does not import electron', async () => {
    const fs = await import('node:fs/promises')
    const source = await fs.readFile(new URL('../src/main/vaultGuard.ts', import.meta.url), 'utf8')
    assert.ok(!/from ['"]electron['"]/.test(source), 'vaultGuard.ts must not import electron')
  })
})

describe('vault.guard on disk', () => {
  const sealer = fakeSealer()
  const dirs: string[] = []

  async function tmpDir(): Promise<string> {
    const made = await fsp.mkdtemp(path.join(os.tmpdir(), 'cw-guard-'))
    dirs.push(made)
    return made
  }

  after(async () => {
    for (const d of dirs) await fsp.rm(d, { recursive: true, force: true })
  })

  it('writes and reads back', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    await writeAnchorFile(file, 11, 4242, sealer)

    const read = await readAnchorFile(file, sealer)
    assert.equal(read.kind, 'ok')
    assert.deepEqual(read.kind === 'ok' && read.anchor, {
      counter: 11,
      at: 4242,
      protected: true
    })
  })

  it('a missing file is absent, not an error', async () => {
    const file = path.join(await tmpDir(), 'neni-tam.guard')
    assert.deepEqual(await readAnchorFile(file, sealer), { kind: 'absent' })
  })

  // The caller overwrites an absent anchor and refuses to touch an unreadable one,
  // so a corrupt file reading as absent would let an attacker switch rollback
  // detection off by damaging it -- which is exactly what this attacker can do.
  it('a corrupted file is unreadable, NEVER absent', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    for (const junk of ['', '{{{', '[]', '{"version":999}']) {
      await fsp.writeFile(file, junk, 'utf8')
      const read = await readAnchorFile(file, sealer)
      assert.equal(read.kind, 'unreadable', `for ${JSON.stringify(junk)}`)
    }
  })

  it('an oversized file is not read whole', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    await fsp.writeFile(file, 'x'.repeat(GUARD_MAX_BYTES + 10), 'utf8')
    const read = await readAnchorFile(file, sealer)
    assert.equal(read.kind, 'unreadable')
    assert.match(read.kind === 'unreadable' ? read.reason : '', /too large/)
  })

  // The case that actually measures the ceiling: JSON.parse accepts trailing
  // whitespace, so without a bound the read would truncate at the limit and hand
  // back a good anchor from a file it never finished looking at.
  it('a valid anchor with overflow trailing it does not pass either', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    const valid = serializeGuard(3, 1000, sealer)
    await fsp.writeFile(file, valid + ' '.repeat(GUARD_MAX_BYTES), 'utf8')

    const read = await readAnchorFile(file, sealer)
    assert.equal(read.kind, 'unreadable', 'must not return an anchor from a file it never finished')
  })

  it('a directory in place of the file does not crash the read', async () => {
    const dir = await tmpDir()
    const file = path.join(dir, 'vault.guard')
    await fsp.mkdir(file)
    assert.equal((await readAnchorFile(file, sealer)).kind, 'unreadable')
  })

  it('an overwrite leaves a valid anchor and no .tmp', async () => {
    const dir = await tmpDir()
    const file = path.join(dir, 'vault.guard')
    await writeAnchorFile(file, 1, 1000, sealer)
    await writeAnchorFile(file, 2, 2000, sealer)

    const read = await readAnchorFile(file, sealer)
    assert.equal(read.kind === 'ok' && read.anchor.counter, 2)
    assert.deepEqual(await fsp.readdir(dir), ['vault.guard'], 'no temp file may be left behind')
  })

  // An anchor outliving its vault reports a rollback that never happened: a fresh
  // vault starts at counter 0, below anything the old anchor recorded.
  it('deleting is quiet and repeatable', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    await writeAnchorFile(file, 5, 1000, sealer)
    await removeAnchorFile(file)
    assert.equal((await readAnchorFile(file, sealer)).kind, 'absent')
    await removeAnchorFile(file)
  })

  it('the anchor is written owner-only', { skip: process.platform === 'win32' }, async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    await writeAnchorFile(file, 1, 1000, sealer)
    const stat = await fsp.stat(file)
    assert.equal(stat.mode & 0o777, 0o600)
  })
})

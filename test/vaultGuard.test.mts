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
  it('shodný čítač je v pořádku', () => {
    assert.deepEqual(verdict(anchor(5), 5), { kind: 'ok' })
  })

  // The anchor is written only after the vault write succeeds, so a crash between
  // the two leaves it one behind -- ordinary, and not worth crying wolf over.
  it('novější soubor než kotva není poplach', () => {
    assert.deepEqual(verdict(anchor(5), 6), { kind: 'ok' })
    assert.deepEqual(verdict(anchor(5), 500), { kind: 'ok' })
  })

  it('starší soubor než kotva je vrácení', () => {
    assert.deepEqual(verdict(anchor(9, 123), 4), {
      kind: 'rollback',
      expected: 9,
      found: 4,
      at: 123
    })
  })

  it('o jedno zpátky se pozná taky', () => {
    assert.equal(verdict(anchor(9), 8).kind, 'rollback')
  })

  it('bez kotvy se nesoudí', () => {
    assert.deepEqual(verdict(null, 3), { kind: 'unknown' })
  })

  // NaN loses every comparison, so a naive `<` answers "ok" and turns the check
  // off for exactly the corrupt file worth looking at.
  it('nesmyslný čítač v hlavičce nedá ani ok, ani poplach', () => {
    for (const bad of [NaN, -1, 1.5, Infinity]) {
      assert.deepEqual(verdict(anchor(5), bad), { kind: 'unknown' }, `pro ${bad}`)
    }
  })
})

describe('serializeGuard + parseGuard', () => {
  it('projde tam a zpátky', () => {
    const sealer = fakeSealer()
    const read = parseGuard(serializeGuard(7, 1234, sealer), sealer)
    assert.equal(read.kind, 'ok')
    assert.deepEqual(read.kind === 'ok' && read.anchor, { counter: 7, at: 1234, protected: true })
  })

  // Decode before judging: base64 hides the plaintext either way, so asserting on
  // the raw file text also passes for an anchor that was never sealed.
  it('zapsané je opravdu zapečetěné, ne jen zakódované', () => {
    const raw = serializeGuard(42, 1234, fakeSealer())
    assert.equal(JSON.parse(raw).protected, true)

    const decoded = Buffer.from(JSON.parse(raw).payload, 'base64').toString('utf8')
    assert.notEqual(decoded, JSON.stringify({ counter: 42, at: 1234 }))
    assert.ok(!decoded.includes('"counter"'), 'čítač nesmí být čitelný po dekódování base64')
  })

  // Refusing to write an anchor without a keyring would switch rollback detection
  // off for a whole platform; unprotected still catches every honest rollback.
  it('bez keyringu se kotva zapíše jako prostý text, ale přizná to', () => {
    const sealer = fakeSealer(false)
    const raw = serializeGuard(7, 1234, sealer)
    assert.equal(JSON.parse(raw).protected, false)

    const read = parseGuard(raw, sealer)
    assert.equal(read.kind, 'ok')
    assert.equal(read.kind === 'ok' && read.anchor.protected, false)
    assert.equal(read.kind === 'ok' && read.anchor.counter, 7)
  })

  it('nechráněnou kotvu přečte i stroj, který keyring má', () => {
    const written = serializeGuard(7, 1234, fakeSealer(false))
    const read = parseGuard(written, fakeSealer(true))
    assert.equal(read.kind, 'ok')
    assert.equal(read.kind === 'ok' && read.anchor.counter, 7)
  })

  it('chráněnou kotvu bez keyringu nepřečte, ale nezahodí ji jako chybějící', () => {
    const written = serializeGuard(7, 1234, fakeSealer(true))
    const read = parseGuard(written, fakeSealer(false))
    assert.equal(read.kind, 'unreadable')
  })

  it('cizí zapečetění je nečitelné, ne prázdné', () => {
    const written = serializeGuard(7, 1234, brokenSealer)
    assert.equal(parseGuard(written, brokenSealer).kind, 'unreadable')
  })

  it('odmítne záporný i neceločíselný čítač při zápisu', () => {
    const sealer = fakeSealer()
    for (const bad of [-1, 1.5, NaN, Infinity]) {
      assert.throws(() => serializeGuard(bad, 1, sealer), /counter/, `pro ${bad}`)
      assert.throws(() => serializeGuard(1, bad, sealer), /timestamp/, `pro ${bad}`)
    }
  })
})

describe('parseGuard odmítá poškozený soubor', () => {
  const sealer = fakeSealer()

  const broken: [string, string][] = [
    ['prázdný soubor', ''],
    ['není JSON', '{{{'],
    ['pole místo objektu', '[]'],
    ['null', 'null'],
    ['chybí verze', JSON.stringify({ protected: true, payload: 'eA==' })],
    ['chybí payload', JSON.stringify({ version: 1, protected: true })],
    ['payload není řetězec', JSON.stringify({ version: 1, protected: true, payload: 5 })],
    ['chybí protected', JSON.stringify({ version: 1, payload: 'eA==' })],
    ['prázdný payload', JSON.stringify({ version: 1, protected: false, payload: '' })]
  ]

  for (const [name, raw] of broken) {
    it(name, () => {
      assert.equal(parseGuard(raw, sealer).kind, 'unreadable', name)
    })
  }

  // If an unknown version read as "absent" the caller would overwrite it, so
  // `version: 999` in the file would switch rollback detection off silently.
  it('neznámá verze je nečitelná, ne chybějící', () => {
    const raw = JSON.stringify({ version: GUARD_VERSION + 1, protected: false, payload: 'eA==' })
    const read = parseGuard(raw, sealer)
    assert.equal(read.kind, 'unreadable')
    assert.match(read.kind === 'unreadable' ? read.reason : '', /version/)
  })

  it('payload s nesmyslným obsahem neprojde', () => {
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

describe('modul nesmí sáhnout na Electron', () => {
  // Four test files stub only `app` from electron, so importing safeStorage here
  // would take three of them down at import time. Hence the injected sealer.
  it('zdroj neimportuje electron', async () => {
    const fs = await import('node:fs/promises')
    const source = await fs.readFile(new URL('../src/main/vaultGuard.ts', import.meta.url), 'utf8')
    assert.ok(!/from ['"]electron['"]/.test(source), 'vaultGuard.ts nesmí importovat electron')
  })
})

describe('vault.guard na disku', () => {
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

  it('zapíše a přečte zpátky', async () => {
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

  it('chybějící soubor je absent, ne chyba', async () => {
    const file = path.join(await tmpDir(), 'neni-tam.guard')
    assert.deepEqual(await readAnchorFile(file, sealer), { kind: 'absent' })
  })

  // The caller overwrites an absent anchor and refuses to touch an unreadable one,
  // so a corrupt file reading as absent would let an attacker switch rollback
  // detection off by damaging it -- which is exactly what this attacker can do.
  it('poškozený soubor je unreadable, NIKDY absent', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    for (const junk of ['', '{{{', '[]', '{"version":999}']) {
      await fsp.writeFile(file, junk, 'utf8')
      const read = await readAnchorFile(file, sealer)
      assert.equal(read.kind, 'unreadable', `pro ${JSON.stringify(junk)}`)
    }
  })

  it('přerostlý soubor se nenačte celý', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    await fsp.writeFile(file, 'x'.repeat(GUARD_MAX_BYTES + 10), 'utf8')
    const read = await readAnchorFile(file, sealer)
    assert.equal(read.kind, 'unreadable')
    assert.match(read.kind === 'unreadable' ? read.reason : '', /too large/)
  })

  // The case that actually measures the ceiling: JSON.parse accepts trailing
  // whitespace, so without a bound the read would truncate at the limit and hand
  // back a good anchor from a file it never finished looking at.
  it('platná kotva s přetečením za sebou taky neprojde', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    const valid = serializeGuard(3, 1000, sealer)
    await fsp.writeFile(file, valid + ' '.repeat(GUARD_MAX_BYTES), 'utf8')

    const read = await readAnchorFile(file, sealer)
    assert.equal(read.kind, 'unreadable', 'nesmí vrátit kotvu ze souboru, který nedočetl')
  })

  it('adresář místo souboru neshodí čtení', async () => {
    const dir = await tmpDir()
    const file = path.join(dir, 'vault.guard')
    await fsp.mkdir(file)
    assert.equal((await readAnchorFile(file, sealer)).kind, 'unreadable')
  })

  it('přepis nechá platnou kotvu a žádný .tmp', async () => {
    const dir = await tmpDir()
    const file = path.join(dir, 'vault.guard')
    await writeAnchorFile(file, 1, 1000, sealer)
    await writeAnchorFile(file, 2, 2000, sealer)

    const read = await readAnchorFile(file, sealer)
    assert.equal(read.kind === 'ok' && read.anchor.counter, 2)
    assert.deepEqual(await fsp.readdir(dir), ['vault.guard'], 'dočasný soubor nesmí zůstat')
  })

  // An anchor outliving its vault reports a rollback that never happened: a fresh
  // vault starts at counter 0, below anything the old anchor recorded.
  it('smazání je tiché a opakovatelné', async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    await writeAnchorFile(file, 5, 1000, sealer)
    await removeAnchorFile(file)
    assert.equal((await readAnchorFile(file, sealer)).kind, 'absent')
    await removeAnchorFile(file)
  })

  it('kotva se zapisuje jen pro majitele', { skip: process.platform === 'win32' }, async () => {
    const file = path.join(await tmpDir(), 'vault.guard')
    await writeAnchorFile(file, 1, 1000, sealer)
    const stat = await fsp.stat(file)
    assert.equal(stat.mode & 0o777, 0o600)
  })
})

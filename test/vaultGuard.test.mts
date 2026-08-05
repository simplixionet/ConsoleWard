// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import {
  GUARD_VERSION,
  parseGuard,
  serializeGuard,
  verdict,
  type Anchor,
  type GuardSealer
} from '../src/main/vaultGuard.ts'

/**
 * Pečetidlo, které jen otočí bajty. Nešifruje — ověřuje se tvar a cesty kódu,
 * ne kryptografie, tu dodává platforma.
 */
function fakeSealer(available = true): GuardSealer {
  return {
    available: () => available,
    seal: (plain) => Buffer.from(plain, 'utf8').reverse(),
    open: (blob) => Buffer.from(blob).reverse().toString('utf8')
  }
}

/** Pečetidlo, kterému se dešifrování nepovede — cizí profil, jiný uživatel. */
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

  /*
   * The one-way rule. The anchor is written only after the vault write
   * succeeds, so a crash in between leaves it one behind -- an ordinary event.
   * Alarming on it would mean crying wolf at every unclean shutdown, and a
   * warning that fires on the innocent gets clicked through blind inside a week.
   */
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

  /*
   * A header counter that is not a sane integer must not become a verdict.
   * NaN loses every comparison, so a naive `<` would answer "ok" and quietly
   * turn the check off for exactly the corrupt file worth looking at.
   */
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

  it('zapsané je opravdu zapečetěné, ne čitelné', () => {
    const raw = serializeGuard(42, 1234, fakeSealer())
    assert.equal(JSON.parse(raw).protected, true)
    // Číslo nesmí být v souboru vidět prostým okem.
    assert.ok(!raw.includes('"counter"'), 'čítač nesmí zůstat v otevřeném textu')
  })

  /*
   * Refusing to write an anchor without a keyring would switch rollback
   * detection off for a whole platform. It is written anyway, flagged as
   * unprotected, and it still catches every non-adversarial rollback.
   */
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

  /*
   * The forward-compatibility trap. If an unknown version read as "absent" the
   * caller would overwrite it, so writing `version: 999` into the file would be
   * enough to switch rollback detection off with no error anywhere.
   */
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
  /*
   * Four test files stub only `app` from electron. An import of safeStorage
   * here would take three of them down at import time rather than in one test,
   * which is why the sealer is injected instead.
   */
  it('zdroj neimportuje electron', async () => {
    const fs = await import('node:fs/promises')
    const source = await fs.readFile(new URL('../src/main/vaultGuard.ts', import.meta.url), 'utf8')
    assert.ok(!/from ['"]electron['"]/.test(source), 'vaultGuard.ts nesmí importovat electron')
  })
})

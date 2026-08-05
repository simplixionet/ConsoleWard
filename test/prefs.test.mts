// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The settings that live outside the vault.
 *
 * Only the language does, and only because it is needed before the vault is
 * unlocked — the unlock screen and its error messages have to be in the user's
 * language. Everything sensitive belongs in the vault, so the property worth
 * testing hardest is that this file stays boring: an unreadable, hostile or
 * absent prefs.json must never stop the app reaching its unlock screen.
 *
 * `readPrefs` memoises into a module-level `cache`, so these tests are written
 * to be order-independent around it rather than pretending it is not there.
 */

import { describe, test, mock, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

let dir = ''
let systemLocale = 'en-GB'

mock.module('electron', {
  exports: {
    app: {
      getPath: () => dir,
      getLocale: () => systemLocale,
      getSystemLocale: () => systemLocale
    }
  }
})

const { readPrefs, writePrefs } = await import('../src/main/prefs.ts')
const { SOURCE_LOCALE } = await import('../src/shared/i18n.ts')

const madeDirs: string[] = []

after(() => {
  for (const made of madeDirs) fs.rmSync(made, { recursive: true, force: true })
})

/**
 * A fresh profile directory, and a cache cleared through the public API.
 *
 * `writePrefs` is the only exported thing that replaces the cache, so it is
 * what these tests use to get back to a known state — reaching into the module
 * would test the reach rather than the behaviour.
 */
function fresh(): void {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-prefs-'))
  madeDirs.push(dir)
}

const prefsPath = (): string => path.join(dir, 'prefs.json')

describe('prefs', () => {
  test('a locale written is a locale read back', async () => {
    fresh()
    const saved = await writePrefs({ locale: 'cs' })
    assert.equal(saved.locale, 'cs')
    assert.equal(readPrefs().locale, 'cs')
    assert.equal(JSON.parse(fs.readFileSync(prefsPath(), 'utf8')).locale, 'cs')
  })

  test('the file is human-readable, because a human may have to fix it', async () => {
    fresh()
    await writePrefs({ locale: 'de' })
    const raw = fs.readFileSync(prefsPath(), 'utf8')
    assert.match(raw, /\n/, 'prefs.json was written as one line')
  })

  test('a locale this build does not ship falls back rather than sticking', async () => {
    fresh()
    const saved = await writePrefs({ locale: 'kl' })
    assert.equal(saved.locale, SOURCE_LOCALE, 'an unshipped locale was stored verbatim')
  })

  test('a region tag resolves to the language that ships', async () => {
    fresh()
    assert.equal((await writePrefs({ locale: 'cs-CZ' })).locale, 'cs')
  })

  test('nothing sensitive is written beside the vault', async () => {
    // The whole rule for this file. A regression here is a secret in plaintext
    // next to the encrypted vault, which is the one thing it must never be.
    fresh()
    await writePrefs({ locale: 'fr' })
    const stored = JSON.parse(fs.readFileSync(prefsPath(), 'utf8')) as Record<string, unknown>
    assert.deepEqual(Object.keys(stored), ['locale'], `prefs.json holds ${Object.keys(stored)}`)
  })

  test('a missing prefs.json is not an error', async () => {
    fresh()
    // Reset the cache through the public API, then delete the file behind it.
    await writePrefs({ locale: 'en' })
    fs.rmSync(prefsPath(), { force: true })
    assert.doesNotThrow(() => readPrefs(), 'a missing prefs.json threw')
  })

  test('a corrupt prefs.json does not stop the app reaching the unlock screen', async () => {
    // This runs before the vault is opened, so a throw here is an app that will
    // not start at all -- and the fix would be a file the user cannot see.
    for (const junk of ['not json', '', '[]', 'null', '{"locale":42}', '{"locale":null}']) {
      fresh()
      fs.writeFileSync(prefsPath(), junk)
      await writePrefs({ locale: 'en' })
      fs.writeFileSync(prefsPath(), junk)
      let out: { locale: string } | null = null
      assert.doesNotThrow(() => {
        out = readPrefs()
      }, `readPrefs threw on ${JSON.stringify(junk)}`)
      assert.equal(typeof out.locale, 'string', `no locale after ${JSON.stringify(junk)}`)
    }
  })

  test('an unsupported system locale still yields the source language', async () => {
    fresh()
    systemLocale = 'kl-GL'
    try {
      await writePrefs({ locale: 'xx' })
      assert.equal(readPrefs().locale, SOURCE_LOCALE)
    } finally {
      systemLocale = 'en-GB'
    }
  })

  test('a patch that names no locale leaves the stored one alone', async () => {
    fresh()
    await writePrefs({ locale: 'nl' })
    assert.equal((await writePrefs({})).locale, 'nl', 'an empty patch reset the language')
  })
})

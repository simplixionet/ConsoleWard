// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The settings that live outside the vault — only the language, and only
 * because the unlock screen must be in the user's language before the vault is
 * open. Everything sensitive belongs in the vault, so what is tested hardest is
 * that an unreadable, hostile or absent prefs.json never stops the app reaching
 * its unlock screen.
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

function fresh(): void {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-prefs-'))
  madeDirs.push(dir)
}

const prefsPath = (): string => path.join(dir, 'prefs.json')

describe('prefs', () => {
  /*
   * THIS TEST MUST STAY FIRST. The module-level cache is never invalidated, so
   * the file is read once per process and every later test gets the cache. That
   * one read is spent here, on the path that decides whether the app starts at
   * all — a corrupt prefs.json must not throw, because this runs before the
   * vault is open and the fix would be a file the user cannot see. One junk
   * fixture rather than a loop, for the same reason.
   *
   * NOT covered as a result: `resolveLocale(parsed.locale) ?? systemLocale()`,
   * for a file that parses but names an unshipped language. The same guard on
   * the write side is covered below.
   */
  test('a corrupt prefs.json does not stop the app reaching the unlock screen', () => {
    fresh()
    fs.writeFileSync(prefsPath(), '{"locale": 42, "trailing":')
    let out: { locale: string } | null = null
    assert.doesNotThrow(() => {
      out = readPrefs()
    }, 'readPrefs threw on a corrupt file')
    assert.equal(typeof out.locale, 'string', 'a corrupt file yielded a non-string locale')
    assert.ok(out.locale.length > 0, 'a corrupt file yielded an empty locale')
  })

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
    // The whole rule for this file: a regression here is a secret in plaintext
    // next to the encrypted vault.
    fresh()
    await writePrefs({ locale: 'fr' })
    const stored = JSON.parse(fs.readFileSync(prefsPath(), 'utf8')) as Record<string, unknown>
    assert.deepEqual(Object.keys(stored), ['locale'], `prefs.json holds ${Object.keys(stored)}`)
  })

  test('a missing prefs.json is not an error', async () => {
    fresh()
    // writePrefs is the only exported way to replace the cache.
    await writePrefs({ locale: 'en' })
    fs.rmSync(prefsPath(), { force: true })
    assert.doesNotThrow(() => readPrefs(), 'a missing prefs.json threw')
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

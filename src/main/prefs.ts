// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Settings that live outside the vault. The language choice is not a secret and
 * is needed before the vault is unlocked — the unlock screen and its error
 * messages have to be in the user's language. Anything sensitive belongs in the
 * vault, not here.
 */

import { app } from 'electron'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { resolveLocale, SOURCE_LOCALE } from '../shared/i18n'

interface Prefs {
  locale: string
}

let cache: Prefs | null = null

function prefsPath(): string {
  return path.join(app.getPath('userData'), 'prefs.json')
}

function systemLocale(): string {
  const candidates = [app.getLocale?.(), app.getSystemLocale?.(), process.env.LANG]
  for (const candidate of candidates) {
    const resolved = resolveLocale(candidate)
    if (resolved) return resolved
  }
  return SOURCE_LOCALE
}

export function readPrefs(): Prefs {
  if (cache) return cache
  try {
    const raw = fs.readFileSync(prefsPath(), 'utf8')
    const parsed = JSON.parse(raw) as Partial<Prefs>
    cache = { locale: resolveLocale(parsed.locale) ?? systemLocale() }
  } catch {
    cache = { locale: systemLocale() }
  }
  return cache
}

export async function writePrefs(patch: Partial<Prefs>): Promise<Prefs> {
  const next: Prefs = { ...readPrefs(), ...patch }
  if (patch.locale !== undefined) {
    next.locale = resolveLocale(patch.locale) ?? SOURCE_LOCALE
  }
  cache = next
  await fsp.mkdir(path.dirname(prefsPath()), { recursive: true })
  await fsp.writeFile(prefsPath(), JSON.stringify(next, null, 2), 'utf8')
  return next
}

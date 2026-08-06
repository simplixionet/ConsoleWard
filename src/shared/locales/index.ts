// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Dictionary registry. Adding a language = a JSON file next to this one, a line
 * in `LOADERS` and an entry in `LOCALES` in `../i18n.ts`.
 *
 * English is imported statically because the translator needs it synchronously
 * as the fallback dictionary; without it bare keys could briefly render. Other
 * languages load on switch, each in its own chunk.
 *
 * The `.default` at the end of every loader is mandatory: `import()` of JSON
 * yields the module namespace, not the data, and without it TypeScript stays
 * quiet while the language silently falls back to English at runtime.
 */

import type { Dictionary } from '../i18n'
import en from './en.json'

export const SOURCE_DICTIONARY: Dictionary = en

type Loader = () => Promise<Dictionary>

const LOADERS: Record<string, Loader> = {
  en: () => Promise.resolve(en),
  cs: () => import('./cs.json').then((m) => m.default),
  de: () => import('./de.json').then((m) => m.default),
  es: () => import('./es.json').then((m) => m.default),
  fr: () => import('./fr.json').then((m) => m.default),
  it: () => import('./it.json').then((m) => m.default),
  'pt-BR': () => import('./pt-BR.json').then((m) => m.default),
  nl: () => import('./nl.json').then((m) => m.default)
}

/** The locale's dictionary, or an empty object — the translator falls back to English. */
export async function dictionaryFor(locale: string): Promise<Dictionary> {
  const load = LOADERS[locale]
  if (!load) return {}
  try {
    return await load()
  } catch {
    return {}
  }
}

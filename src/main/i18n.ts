// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Error messages originate in the main process (vault, SSH, MCP) and users read
 * them, so they are translated. Strings the AI reads over MCP always stay
 * English — that is a machine interface, not text for a human.
 */

import { createTranslator, SOURCE_LOCALE, type Translator } from '../shared/i18n'
import { dictionaryFor, SOURCE_DICTIONARY } from '../shared/locales'
import { readPrefs } from './prefs'

let current: { locale: string; t: Translator } = {
  locale: SOURCE_LOCALE,
  t: createTranslator(SOURCE_LOCALE, SOURCE_DICTIONARY, SOURCE_DICTIONARY)
}

/** Must finish before anything calls appError() — see app.whenReady() in index.ts. */
export async function initI18n(): Promise<void> {
  const locale = readPrefs().locale ?? SOURCE_LOCALE
  const dictionary = await dictionaryFor(locale)
  current = { locale, t: createTranslator(locale, dictionary, SOURCE_DICTIONARY) }
}

export function currentLocale(): string {
  return current.locale
}

export async function setLocale(locale: string): Promise<void> {
  const dictionary = await dictionaryFor(locale)
  current = { locale, t: createTranslator(locale, dictionary, SOURCE_DICTIONARY) }
}

export const t: Translator = (key, params) => current.t(key, params)

/**
 * Error carrying a translation key. The message is rendered at construction
 * time, so a language switch applies to everything raised from then on.
 */
export class AppError extends Error {
  readonly key: string

  constructor(key: string, params?: Record<string, string | number>) {
    super(t(key, params))
    this.key = key
    this.name = 'AppError'
  }
}

export function appError(key: string, params?: Record<string, string | number>): AppError {
  return new AppError(key, params)
}

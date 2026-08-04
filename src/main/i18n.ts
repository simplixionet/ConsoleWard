/**
 * Překlady v hlavním procesu.
 *
 * Chybové hlášky vznikají tady (trezor, SSH, MCP) a uživatel je čte, takže
 * musí být přeložené. Řetězce, které čte AI přes MCP, zůstávají naopak vždy
 * anglicky — je to strojové rozhraní, ne text pro člověka.
 */

import { createTranslator, SOURCE_LOCALE, type Translator } from '../shared/i18n'
import { dictionaryFor, SOURCE_DICTIONARY } from '../shared/locales'
import { readPrefs } from './prefs'

let current: { locale: string; t: Translator } | null = null

function build(locale: string): { locale: string; t: Translator } {
  return {
    locale,
    t: createTranslator(locale, dictionaryFor(locale), SOURCE_DICTIONARY)
  }
}

export function currentLocale(): string {
  if (!current) current = build(readPrefs().locale ?? SOURCE_LOCALE)
  return current.locale
}

export function setLocale(locale: string): void {
  current = build(locale)
}

/** Přeloží klíč do aktuálně zvoleného jazyka. */
export const t: Translator = (key, params) => {
  if (!current) current = build(readPrefs().locale ?? SOURCE_LOCALE)
  return current.t(key, params)
}

/**
 * Chyba nesoucí překladový klíč.
 *
 * Zpráva se vyrábí až v okamžiku vzniku, takže po přepnutí jazyka platí nová
 * volba pro všechno, co teprve nastane.
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

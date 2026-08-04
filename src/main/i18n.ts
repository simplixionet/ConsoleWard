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

let current: { locale: string; t: Translator } = {
  locale: SOURCE_LOCALE,
  t: createTranslator(SOURCE_LOCALE, SOURCE_DICTIONARY, SOURCE_DICTIONARY)
}

/** Musí doběhnout dřív, než začne cokoliv volat appError() — viz index.ts app.whenReady(). */
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

/** Přeloží klíč do aktuálně zvoleného jazyka. */
export const t: Translator = (key, params) => current.t(key, params)

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

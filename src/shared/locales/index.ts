/**
 * Registr slovníků.
 *
 * Přidání jazyka = přidat JSON vedle tohohle souboru, doplnit jeden import
 * a jeden řádek do mapy, plus záznam do `LOCALES` v `../i18n.ts`.
 */

import type { Dictionary } from '../i18n'
import en from './en.json'
import cs from './cs.json'
import de from './de.json'

export const DICTIONARIES: Record<string, Dictionary> = {
  en,
  cs,
  de
}

export { en as SOURCE_DICTIONARY }

/** Slovník jazyka, nebo prázdný objekt – překladač si sáhne do angličtiny. */
export function dictionaryFor(locale: string): Dictionary {
  return DICTIONARIES[locale] ?? {}
}

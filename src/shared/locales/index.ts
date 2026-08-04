/**
 * Registr slovníků.
 *
 * Přidání jazyka = přidat JSON vedle tohohle souboru, doplnit jeden import
 * a jeden řádek do mapy, plus záznam do `LOCALES` v `../i18n.ts`.
 */

import type { Dictionary } from '../i18n'
import en from './en.json'

export const SOURCE_DICTIONARY: Dictionary = en

type Loader = () => Promise<Dictionary>

const LOADERS: Record<string, Loader> = {
  en: () => Promise.resolve(en),
  cs: () => import('./cs.json').then((m) => m.default),
  de: () => import('./de.json').then((m) => m.default)
}

/** Slovník jazyka, nebo prázdný objekt – překladač si sáhne do angličtiny. */
export async function dictionaryFor(locale: string): Promise<Dictionary> {
  const load = LOADERS[locale]
  if (!load) return {}
  try {
    return await load()
  } catch {
    return {}
  }
}

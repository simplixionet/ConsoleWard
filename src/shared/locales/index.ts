/**
 * Registr slovníků.
 *
 * Přidání jazyka = přidat JSON vedle tohohle souboru, doplnit jeden řádek do
 * `LOADERS` a záznam do `LOCALES` v `../i18n.ts`.
 *
 * Angličtina se importuje staticky, protože překladač ji potřebuje synchronně
 * jako záložní slovník — bez ní by šlo krátce vykreslit holé klíče. Ostatní
 * jazyky se načtou až při přepnutí, každý ve vlastním chunku.
 *
 * `import()` u JSON vrací namespace modulu, ne samotná data. To `.default`
 * na konci každého loaderu je proto povinné: bez něj TypeScript nic nevytkne,
 * ale za běhu se jazyk tiše propadne do angličtiny.
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

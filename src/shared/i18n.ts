/**
 * Překlady bez externí závislosti.
 *
 * U bezpečnostního nástroje je každý balíček navíc kus cizího kódu, který
 * musíš hlídat — a tohle zvládne platforma sama. Množná čísla řeší
 * `Intl.PluralRules`, takže čeština (1 / 2–4 / 5+), ruština i polština
 * fungují správně bez ručních tabulek.
 *
 * Formát klíčů:
 *   "conn.save": "Uložit"                     → t('conn.save')
 *   "term.count_one": "{{count}} relace"      → t('term.count', { count: 1 })
 *   "term.count_few": "{{count}} relace"
 *   "term.count_many": "{{count}} relací"
 *
 * Kategorie (one/two/few/many/other) jsou standardní CLDR. Jazyk, který
 * některou nemá, ji prostě neuvádí.
 */

export type Dictionary = Record<string, string>

export interface LocaleInfo {
  /** BCP 47 kód, např. `pt-BR` */
  code: string
  /** Název jazyka v tom jazyce – tak ho uživatel v seznamu pozná */
  nativeName: string
  englishName: string
}

/** Zdrojový jazyk projektu. Chybějící překlad spadne sem. */
export const SOURCE_LOCALE = 'en'

export const LOCALES: LocaleInfo[] = [
  { code: 'en', nativeName: 'English', englishName: 'English' },
  { code: 'cs', nativeName: 'Čeština', englishName: 'Czech' },
  { code: 'de', nativeName: 'Deutsch', englishName: 'German' },
  { code: 'es', nativeName: 'Español', englishName: 'Spanish' },
  { code: 'fr', nativeName: 'Français', englishName: 'French' },
  { code: 'it', nativeName: 'Italiano', englishName: 'Italian' },
  { code: 'pt-BR', nativeName: 'Português (Brasil)', englishName: 'Portuguese (Brazil)' },
  { code: 'nl', nativeName: 'Nederlands', englishName: 'Dutch' }
]

export const LOCALE_CODES = LOCALES.map((l) => l.code)

export type TranslateParams = Record<string, string | number>

export type Translator = (key: string, params?: TranslateParams) => string

/**
 * Vybere nejbližší podporovaný jazyk – `de-AT` → `de`, `zh-Hans-CN` → `zh-CN`.
 * Vrací `null`, když nic nesedí; volající pak sáhne po zdrojovém jazyce.
 */
export function resolveLocale(requested: string | undefined | null): string | null {
  if (!requested) return null
  const want = String(requested).replace('_', '-')

  const exact = LOCALE_CODES.find((c) => c.toLowerCase() === want.toLowerCase())
  if (exact) return exact

  const base = want.split('-')[0].toLowerCase()
  // Nejdřív holý kód jazyka, teprve pak libovolná regionální varianta.
  const bare = LOCALE_CODES.find((c) => c.toLowerCase() === base)
  if (bare) return bare
  return LOCALE_CODES.find((c) => c.toLowerCase().startsWith(base + '-')) ?? null
}

function interpolate(template: string, params?: TranslateParams): string {
  if (!params) return template
  return template.replace(/\{\{(\w+)\}\}/g, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole
  )
}

/**
 * Sestaví překladač nad slovníkem daného jazyka.
 * Pořadí hledání: jazyk → zdrojový jazyk → samotný klíč.
 */
export function createTranslator(
  locale: string,
  dictionary: Dictionary,
  fallback: Dictionary
): Translator {
  let plural: Intl.PluralRules | null = null
  try {
    plural = new Intl.PluralRules(locale)
  } catch {
    plural = null
  }

  const lookup = (key: string): string | undefined => dictionary[key] ?? fallback[key]

  return (key, params) => {
    if (params && typeof params.count === 'number' && plural) {
      const category = plural.select(params.count)
      const found =
        lookup(`${key}_${category}`) ?? lookup(`${key}_other`) ?? lookup(key)
      if (found !== undefined) return interpolate(found, params)
      return key
    }
    const found = lookup(key)
    return found === undefined ? key : interpolate(found, params)
  }
}

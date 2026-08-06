// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Translations without an external dependency. `Intl.PluralRules` supplies the
 * plural category, so languages with more than two forms work without tables.
 *
 * Plain keys are `"conn.save": "Save"` → `t('conn.save')`. A count-bearing key
 * is suffixed with the CLDR category — `"term.count_one"`, `"term.count_other"`
 * → `t('term.count', { count: 1 })` — and a language omits the ones it lacks.
 */

export type Dictionary = Record<string, string>

export interface LocaleInfo {
  /** BCP 47 code, e.g. `pt-BR` */
  code: string
  nativeName: string
  englishName: string
}

/** Source language of the project. A missing translation falls back to it. */
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
 * Nearest supported locale — `de-AT` → `de`, `zh-Hans-CN` → `zh-CN`.
 * `null` when nothing matches; the caller then falls back to the source language.
 */
export function resolveLocale(requested: string | undefined | null): string | null {
  if (!requested) return null
  const want = String(requested).replace('_', '-')

  const exact = LOCALE_CODES.find((c) => c.toLowerCase() === want.toLowerCase())
  if (exact) return exact

  const base = want.split('-')[0].toLowerCase()
  // Bare language code first, only then any regional variant.
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

/** Lookup order: the locale's dictionary → the source language → the key itself. */
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

  /**
   * Own property, and a string only. Plain `dictionary[key]` reaches into the
   * prototype, so a key like `toString` or `valueOf` returns a function that
   * `interpolate` then calls `.replace` on. The translator is the last layer
   * under the security messages: if it throws, the human never sees the warning
   * they were meant to see.
   */
  const own = (dict: Dictionary, key: string): string | undefined => {
    if (!Object.prototype.hasOwnProperty.call(dict, key)) return undefined
    const value = dict[key]
    return typeof value === 'string' ? value : undefined
  }

  const lookup = (key: string): string | undefined => own(dictionary, key) ?? own(fallback, key)

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

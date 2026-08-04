import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import {
  createTranslator,
  LOCALES,
  SOURCE_LOCALE,
  type Dictionary,
  type Translator
} from '@shared/i18n'
import { dictionaryFor, SOURCE_DICTIONARY } from '@shared/locales'
import { api } from './api'

interface I18nValue {
  locale: string
  t: Translator
  setLocale: (locale: string) => Promise<void>
}

const I18nContext = createContext<I18nValue | null>(null)

export function I18nProvider({
  initialLocale,
  initialDictionary,
  children
}: {
  initialLocale: string
  initialDictionary: Dictionary
  children: ReactNode
}) {
  const [locale, setLocaleState] = useState(initialLocale || SOURCE_LOCALE)
  const [dictionary, setDictionary] = useState<Dictionary>(initialDictionary)

  const t = useMemo(
    () => createTranslator(locale, dictionary, SOURCE_DICTIONARY),
    [locale, dictionary]
  )

  const setLocale = useCallback(async (next: string) => {
    const nextDictionary = next === SOURCE_LOCALE ? SOURCE_DICTIONARY : await dictionaryFor(next)
    // Jazyk uloží hlavní proces, aby ho znal i pro své chybové hlášky.
    await api.app.setLocale(next)
    setDictionary(nextDictionary)
    setLocaleState(next)
    document.documentElement.lang = next
  }, [])

  const value = useMemo<I18nValue>(() => ({ locale, t, setLocale }), [locale, t, setLocale])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used inside <I18nProvider>')
  return ctx
}

/** Zkratka pro komponenty, které potřebují jen překládat. */
export function useT(): Translator {
  return useI18n().t
}

export { LOCALES }

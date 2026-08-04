import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { I18nProvider } from './i18n'
import { api } from './api'
import { SOURCE_LOCALE } from '@shared/i18n'
import { dictionaryFor, SOURCE_DICTIONARY } from '@shared/locales'
import './styles.css'
import '@xterm/xterm/css/xterm.css'

/**
 * Jazyk načteme dřív než UI, aby ani odemykací obrazovka neproblikla
 * v angličtině.
 */
async function boot(): Promise<void> {
  let locale = SOURCE_LOCALE
  try {
    const result = await api.app.getLocale()
    if (result.ok) locale = result.value
  } catch {
    /* zůstane výchozí jazyk */
  }
  document.documentElement.lang = locale

  const dictionary = locale === SOURCE_LOCALE ? SOURCE_DICTIONARY : await dictionaryFor(locale)

  createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <I18nProvider initialLocale={locale} initialDictionary={dictionary}>
        <App />
      </I18nProvider>
    </React.StrictMode>
  )
}

void boot()

import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { WebLinksAddon } from '@xterm/addon-web-links'
import type { SessionInfo, Settings } from '@shared/types'
import { api } from '../api'
import { useT } from '../i18n'
import { registerFocus, registerSink } from '../terminalBus'

const THEME = {
  background: '#0b0e13',
  foreground: '#d7dde5',
  cursor: '#5ac8fa',
  cursorAccent: '#0b0e13',
  selectionBackground: '#2a4a6b',
  black: '#12161d',
  red: '#ff6b6b',
  green: '#7ee787',
  yellow: '#e3b341',
  blue: '#79c0ff',
  magenta: '#d2a8ff',
  cyan: '#56d4dd',
  white: '#c9d1d9',
  brightBlack: '#5a6472',
  brightRed: '#ff8585',
  brightGreen: '#95f7a0',
  brightYellow: '#f2cc60',
  brightBlue: '#a5d6ff',
  brightMagenta: '#e2c5ff',
  brightCyan: '#7ee8ef',
  brightWhite: '#f0f6fc'
}

interface Props {
  session: SessionInfo
  settings: Settings
  visible: boolean
}

export default function TerminalView({ session, settings, visible }: Props) {
  const t = useT()
  const hostRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const searchRef = useRef<SearchAddon | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const [query, setQuery] = useState('')

  // Vytvoření terminálu – jednou na relaci.
  useEffect(() => {
    if (!hostRef.current) return

    const term = new Terminal({
      fontFamily: '"Cascadia Mono", "JetBrains Mono", Consolas, "Courier New", monospace',
      fontSize: settings.fontSize,
      scrollback: settings.scrollback,
      cursorBlink: true,
      allowProposedApi: true,
      theme: THEME
    })
    const fit = new FitAddon()
    const search = new SearchAddon()
    term.loadAddon(fit)
    term.loadAddon(search)
    term.loadAddon(new WebLinksAddon())
    term.open(hostRef.current)

    termRef.current = term
    fitRef.current = fit
    searchRef.current = search

    const unregister = registerSink(session.id, (bytes) => term.write(bytes))
    const unregisterFocus = registerFocus(session.id, () => term.focus())

    const dataSub = term.onData((data) => {
      api.app.notifyActivity()
      void api.ssh.write(session.id, data)
    })

    // Klávesové zkratky terminálového typu (Ctrl+Shift+C/V, Ctrl+Shift+F).
    term.attachCustomKeyEventHandler((event) => {
      if (event.type !== 'keydown') return true
      if (event.ctrlKey && event.shiftKey) {
        const key = event.key.toLowerCase()
        if (key === 'c') {
          const selection = term.getSelection()
          if (selection) void api.clipboard.write(selection)
          return false
        }
        if (key === 'v') {
          void pasteFromClipboard(term)
          return false
        }
        if (key === 'f') {
          setSearchOpen(true)
          return false
        }
      }
      if (event.key === 'Escape' && searchOpen) {
        setSearchOpen(false)
        search.clearDecorations()
        return false
      }
      return true
    })

    return () => {
      unregister()
      unregisterFocus()
      dataSub.dispose()
      term.dispose()
      termRef.current = null
      fitRef.current = null
      searchRef.current = null
    }
    // Terminál se záměrně nevytváří znovu při změně nastavení – to řeší efekt níže.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id])

  // Změna nastavení bez ztráty historie.
  useEffect(() => {
    const term = termRef.current
    if (!term) return
    term.options.fontSize = settings.fontSize
    term.options.scrollback = settings.scrollback
    if (visible) doFit()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.fontSize, settings.scrollback])

  // Přizpůsobení velikosti okna / panelu.
  useEffect(() => {
    if (!hostRef.current) return
    const observer = new ResizeObserver(() => {
      if (visible) doFit()
    })
    observer.observe(hostRef.current)
    return () => observer.disconnect()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible])

  // Po přepnutí na tuto záložku dopočítat rozměry a vrátit fokus.
  useEffect(() => {
    if (!visible) return
    const id = window.setTimeout(() => {
      doFit()
      termRef.current?.focus()
    }, 0)
    return () => window.clearTimeout(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, session.status])

  function doFit(): void {
    const term = termRef.current
    const fit = fitRef.current
    if (!term || !fit || !hostRef.current) return
    if (hostRef.current.clientWidth === 0 || hostRef.current.clientHeight === 0) return
    try {
      fit.fit()
      void api.ssh.resize(session.id, term.cols, term.rows)
    } catch {
      /* rozměry ještě nejsou k dispozici */
    }
  }

  async function pasteFromClipboard(term: Terminal): Promise<void> {
    const res = await api.clipboard.read()
    if (res.ok && res.value) term.paste(res.value)
  }

  function onContextMenu(event: React.MouseEvent): void {
    // Chování jako v PuTTY: pravé tlačítko vloží obsah schránky.
    event.preventDefault()
    const term = termRef.current
    if (term) void pasteFromClipboard(term)
  }

  function runSearch(direction: 'next' | 'prev'): void {
    const search = searchRef.current
    if (!search || !query) return
    if (direction === 'next') search.findNext(query)
    else search.findPrevious(query)
  }

  return (
    <div className="terminal-wrap" style={{ display: visible ? 'flex' : 'none' }}>
      {searchOpen && (
        <div className="find-bar">
          <input
            autoFocus
            value={query}
            placeholder={t('term.search')}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') runSearch(e.shiftKey ? 'prev' : 'next')
              if (e.key === 'Escape') {
                setSearchOpen(false)
                searchRef.current?.clearDecorations()
                termRef.current?.focus()
              }
            }}
          />
          <button onClick={() => runSearch('prev')} title={t('term.searchPrev')}>
            ↑
          </button>
          <button onClick={() => runSearch('next')} title={t('term.searchNext')}>
            ↓
          </button>
          <button
            onClick={() => {
              setSearchOpen(false)
              searchRef.current?.clearDecorations()
              termRef.current?.focus()
            }}
            title={t('term.searchClose')}
          >
            ✕
          </button>
        </div>
      )}
      <div className="terminal-host" ref={hostRef} onContextMenu={onContextMenu} />
      {session.status !== 'ready' && (
        <div className="terminal-overlay">
          <div className={`overlay-card status-${session.status}`}>
            <div className="overlay-title">{t(STATUS_KEY[session.status])}</div>
            {session.message && <div className="overlay-msg">{session.message}</div>}
          </div>
        </div>
      )}
    </div>
  )
}

const STATUS_KEY: Record<SessionInfo['status'], string> = {
  connecting: 'term.statusConnecting',
  authenticating: 'term.statusAuthenticating',
  ready: 'term.statusReady',
  closed: 'term.statusClosed',
  error: 'term.statusError'
}

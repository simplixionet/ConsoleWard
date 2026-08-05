// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  CommandApproval,
  ConnectionMeta,
  HostKeyPrompt,
  SessionInfo,
  Settings,
  ShareRequest,
  Snippet,
  VaultStatus
} from '@shared/types'
import { api, errorMessage, unwrap } from './api'
import { reportActivity, resetActivityThrottle } from './activity'
import { useT } from './i18n'
import { dispatch, focusTerminal, forget } from './terminalBus'
import UnlockScreen from './components/UnlockScreen'
import Sidebar, { type SidebarTab } from './components/Sidebar'
import TerminalView from './components/TerminalView'
import ConnectionEditor from './components/ConnectionEditor'
import SnippetEditor from './components/SnippetEditor'
import HostKeyDialog from './components/HostKeyDialog'
import SettingsDialog from './components/SettingsDialog'
import RecoveryKeyDialog from './components/RecoveryKeyDialog'
import CommandApprovalDialog from './components/CommandApprovalDialog'
import OutputShareDialog from './components/OutputShareDialog'

const FALLBACK_SETTINGS: Settings = {
  autoLockMinutes: 15,
  disconnectOnLock: true,
  fontSize: 14,
  scrollback: 5000
}

const STATUS_BAR_KEY: Record<SessionInfo['status'], string> = {
  connecting: 'term.barConnecting',
  authenticating: 'term.barAuthenticating',
  ready: 'term.barReady',
  closed: 'term.barClosed',
  error: 'term.barError'
}

/** Co se právě potvrzuje ke smazání. */
type DeleteTarget =
  | { kind: 'connection'; item: ConnectionMeta }
  | { kind: 'snippet'; item: Snippet }

export default function App() {
  const t = useT()
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null)
  /** Časové razítko kotvy, jejíž varování už uživatel odklikl. */
  const [rollbackDismissed, setRollbackDismissed] = useState<number | null>(null)
  const [connections, setConnections] = useState<ConnectionMeta[]>([])
  const [snippets, setSnippets] = useState<Snippet[]>([])
  const [settings, setSettings] = useState<Settings>(FALLBACK_SETTINGS)
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [activeSession, setActiveSession] = useState<string | null>(null)
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>('connections')
  const [editor, setEditor] = useState<{ open: boolean; connection: ConnectionMeta | null }>({
    open: false,
    connection: null
  })
  const [snippetEditor, setSnippetEditor] = useState<{ open: boolean; snippet: Snippet | null }>({
    open: false,
    snippet: null
  })
  const [hostKeyQueue, setHostKeyQueue] = useState<HostKeyPrompt[]>([])
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null)
  const [pendingInsert, setPendingInsert] = useState<{
    snippet: Snippet
    withEnter: boolean
  } | null>(null)
  const [recoveryKeyToShow, setRecoveryKeyToShow] = useState<{
    key: string
    isNew: boolean
  } | null>(null)
  // Fronty, aby se souběžné žádosti od AI neztratily.
  const [commandQueue, setCommandQueue] = useState<CommandApproval[]>([])
  const [shareQueue, setShareQueue] = useState<ShareRequest[]>([])

  const activeRef = useRef<string | null>(null)
  activeRef.current = activeSession

  const showToast = useCallback((msg: string) => {
    setToast(msg)
    window.setTimeout(() => setToast(null), 4000)
  }, [])

  /* ---------------------------------------------------------- inicializace */

  const loadData = useCallback(async () => {
    const [list, snips, cfg] = await Promise.all([
      api.connections.list(),
      api.snippets.list(),
      api.settings.get()
    ])
    if (list.ok) setConnections(list.value)
    if (snips.ok) setSnippets(snips.value)
    if (cfg.ok) setSettings(cfg.value)
  }, [])

  const refreshVault = useCallback(async () => {
    try {
      const status = unwrap(await api.vault.status())
      setVaultStatus(status)
      if (status.unlocked) await loadData()
    } catch (err) {
      showToast(errorMessage(err))
    }
  }, [loadData, showToast])

  useEffect(() => {
    void refreshVault()
  }, [refreshVault])

  /* ------------------------------------------------------------- odposlechy */

  useEffect(() => {
    const offData = api.ssh.onData((sessionId, base64) => dispatch(sessionId, base64))

    const offStatus = api.ssh.onStatus((info) => {
      setSessions((prev) => {
        const idx = prev.findIndex((s) => s.id === info.id)
        if (idx < 0) return [...prev, info]
        const next = [...prev]
        next[idx] = info
        return next
      })
      if (info.status === 'error' && info.message) showToast(info.message)
    })

    const offHostKey = api.ssh.onHostKeyPrompt((prompt) => {
      setHostKeyQueue((prev) => [...prev, prompt])
    })

    const offCommand = api.mcp.onCommandRequest((req) =>
      setCommandQueue((prev) => [...prev, req])
    )
    const offShare = api.mcp.onShareRequest((req) => setShareQueue((prev) => [...prev, req]))

    const offLocked = api.vault.onLocked(() => {
      // The next keypress after a lock is the human coming back, and it must
      // reach the main process rather than being swallowed by a throttle
      // window that started before they walked away.
      resetActivityThrottle()
      setSessions([])
      setActiveSession(null)
      setConnections([])
      setSnippets([])
      setHostKeyQueue([])
      setEditor({ open: false, connection: null })
      setSnippetEditor({ open: false, snippet: null })
      setPendingInsert(null)
      setSettingsOpen(false)
      setCommandQueue([])
      setShareQueue([])
      void refreshVault()
    })

    return () => {
      offData()
      offStatus()
      offHostKey()
      offCommand()
      offShare()
      offLocked()
    }
  }, [refreshVault, showToast])

  // Aktivita uživatele odkládá automatické zamčení.
  useEffect(() => {
    const notify = (): void => reportActivity(() => api.app.notifyActivity())
    const events: (keyof WindowEventMap)[] = ['mousedown', 'keydown', 'wheel']
    for (const e of events) window.addEventListener(e, notify)
    return () => {
      for (const e of events) window.removeEventListener(e, notify)
    }
  }, [])

  /* ------------------------------------------------------------ připojení */

  async function connect(c: ConnectionMeta): Promise<void> {
    try {
      const sessionId = unwrap(await api.ssh.connect(c.id))
      setActiveSession(sessionId)
    } catch (err) {
      showToast(errorMessage(err))
    }
  }

  function closeSession(sessionId: string): void {
    void api.ssh.disconnect(sessionId)
    forget(sessionId)
    setSessions((prev) => {
      const next = prev.filter((s) => s.id !== sessionId)
      if (activeRef.current === sessionId) {
        setActiveSession(next.length ? next[next.length - 1].id : null)
      }
      return next
    })
  }

  async function duplicateConnection(c: ConnectionMeta): Promise<void> {
    try {
      unwrap(await api.connections.duplicate(c.id))
      setConnections(unwrap(await api.connections.list()))
    } catch (err) {
      showToast(errorMessage(err))
    }
  }

  /* ------------------------------------------------- příkazy a poznámky */

  async function duplicateSnippet(s: Snippet): Promise<void> {
    try {
      unwrap(await api.snippets.duplicate(s.id))
      setSnippets(unwrap(await api.snippets.list()))
    } catch (err) {
      showToast(errorMessage(err))
    }
  }

  async function copySnippet(s: Snippet): Promise<void> {
    await api.clipboard.write(s.body)
    showToast(t('snip.copied', { title: s.title }))
  }

  /**
   * Vložení do terminálu. Víceřádkový text potvrzujeme zvlášť – v shellu se
   * každý konec řádku chová jako Enter, takže by se spustilo víc příkazů.
   */
  function requestInsert(s: Snippet, withEnter: boolean): void {
    const active = sessions.find((x) => x.id === activeSession)
    if (!active || active.status !== 'ready') {
      showToast(t('snip.noSession'))
      return
    }
    if (s.body.includes('\n')) {
      setPendingInsert({ snippet: s, withEnter })
      return
    }
    void doInsert(s, withEnter)
  }

  async function doInsert(s: Snippet, withEnter: boolean): Promise<void> {
    const sessionId = activeRef.current
    if (!sessionId) return
    const text = withEnter ? s.body.replace(/\n?$/, '\n') : s.body
    try {
      unwrap(await api.ssh.write(sessionId, text))
      focusTerminal(sessionId)
    } catch (err) {
      showToast(errorMessage(err))
    }
  }

  /* ---------------------------------------------------------------- mazání */

  async function confirmDelete(): Promise<void> {
    if (!deleteTarget) return
    try {
      if (deleteTarget.kind === 'connection') {
        unwrap(await api.connections.remove(deleteTarget.item.id))
        setConnections(unwrap(await api.connections.list()))
        showToast(t('conn.deleted', { name: deleteTarget.item.name }))
      } else {
        unwrap(await api.snippets.remove(deleteTarget.item.id))
        setSnippets(unwrap(await api.snippets.list()))
        showToast(t('snip.deleted', { title: deleteTarget.item.title }))
      }
      setDeleteTarget(null)
    } catch (err) {
      showToast(errorMessage(err))
    }
  }

  async function answerHostKey(accept: boolean): Promise<void> {
    const current = hostKeyQueue[0]
    if (!current) return
    setHostKeyQueue((prev) => prev.slice(1))
    await api.ssh.answerHostKey(current.requestId, accept)
  }

  /* ------------------------------------------------------------------- view */

  if (!vaultStatus) {
    return <div className="boot">{t('common.loading')}</div>
  }

  // Obnovovací klíč se zobrazuje jen jednou, takže musí přežít i přepnutí obrazovky.
  const recoveryModal = recoveryKeyToShow ? (
    <RecoveryKeyDialog
      recoveryKey={recoveryKeyToShow.key}
      isNewVault={recoveryKeyToShow.isNew}
      onDone={() => {
        setRecoveryKeyToShow(null)
        void refreshVault()
      }}
    />
  ) : null

  if (!vaultStatus.unlocked) {
    return (
      <>
        <UnlockScreen
          exists={vaultStatus.exists}
          hasRecovery={vaultStatus.hasRecovery}
          vaultPath={vaultStatus.path}
          onCreated={(key) => setRecoveryKeyToShow({ key, isNew: true })}
          onUnlocked={refreshVault}
        />
        {recoveryModal}
      </>
    )
  }

  const active = sessions.find((s) => s.id === activeSession) ?? null
  const canInsert = active?.status === 'ready'
  /*
   * Odloží se konkrétní událost, ne „varování obecně". Kdyby se ukládalo jen
   * `true`, druhé vrácení souboru v témže běhu by zůstalo neviditelné, protože
   * ho umlčelo odkliknutí toho prvního.
   */
  const showRollback = vaultStatus.rollback !== null && rollbackDismissed !== vaultStatus.rollback.at

  return (
    <div className="app">
      <header className="titlebar">
        <div className="brand">
          <span className="brand-mark">⌘</span> ConsoleWard
        </div>
        <div className="titlebar-actions">
          <button className="btn small" onClick={() => setSettingsOpen(true)}>
            {t('app.settings')}
          </button>
          <button
            className="btn small"
            onClick={() => void api.vault.lock()}
            title={t('app.lockTitle')}
          >
            🔒 {t('app.lock')}
          </button>
        </div>
      </header>

      {/*
        Pruh, ne modál, a ne předčasný `return`.

        Modál se zavírá reflexem a tenhle stav se jedním kliknutím nespraví —
        trezor je už otevřený a jde o to, s čím v něm od teď počítat. Předčasný
        return by navíc přeskočil `recoveryModal` níž, takže kdo se sem dostal
        obnovovacím klíčem, by nikdy neuviděl ten nový, který mu právě vznikl.
      */}
      {showRollback && vaultStatus.rollback && (
        <div className="rollback-bar">
          <div className="rollback-text">
            <b>{t('vault.rollbackTitle')}</b>{' '}
            {t('vault.rollbackBody', {
              found: vaultStatus.rollback.found,
              expected: vaultStatus.rollback.expected,
              date: new Date(vaultStatus.rollback.at).toLocaleString()
            })}{' '}
            {t('vault.rollbackHostKeys')}
          </div>
          <button
            className="btn small"
            onClick={() => setRollbackDismissed(vaultStatus.rollback!.at)}
          >
            {t('vault.rollbackDismiss')}
          </button>
        </div>
      )}

      <div className="body">
        <Sidebar
          tab={sidebarTab}
          onTabChange={setSidebarTab}
          connections={connections}
          onConnect={connect}
          onNewConnection={() => setEditor({ open: true, connection: null })}
          onEditConnection={(c) => setEditor({ open: true, connection: c })}
          onDuplicateConnection={duplicateConnection}
          onDeleteConnection={(c) => setDeleteTarget({ kind: 'connection', item: c })}
          snippets={snippets}
          canInsert={canInsert}
          onInsertSnippet={requestInsert}
          onCopySnippet={copySnippet}
          onNewSnippet={() => setSnippetEditor({ open: true, snippet: null })}
          onEditSnippet={(s) => setSnippetEditor({ open: true, snippet: s })}
          onDuplicateSnippet={duplicateSnippet}
          onDeleteSnippet={(s) => setDeleteTarget({ kind: 'snippet', item: s })}
        />

        <main className="workspace">
          <div className="tabbar">
            {sessions.map((s) => (
              <div
                key={s.id}
                className={`tab-item ${s.id === activeSession ? 'active' : ''} status-${s.status}`}
                onClick={() => setActiveSession(s.id)}
              >
                <span className={`dot ${s.status}`} />
                <span className="tab-title">{s.title}</span>
                <button
                  className="tab-close"
                  title={t('term.closeSession')}
                  onClick={(e) => {
                    e.stopPropagation()
                    closeSession(s.id)
                  }}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>

          <div className="terminal-area">
            {sessions.length === 0 && (
              <div className="placeholder">
                <div className="placeholder-icon">▮</div>
                <h2>{t('term.noSession')}</h2>
                <p>{t('term.noSessionHint')}</p>
              </div>
            )}
            {sessions.map((s) => (
              <TerminalView
                key={s.id}
                session={s}
                settings={settings}
                visible={s.id === activeSession}
              />
            ))}
          </div>

          <footer className="statusbar">
            {active ? (
              <>
                <span className={`dot ${active.status}`} />
                <span>{active.title}</span>
                <span className="sep">·</span>
                <span>{active.message ?? t(STATUS_BAR_KEY[active.status])}</span>
              </>
            ) : (
              <span>
                {t('term.vaultUnlocked')} <span className="sep">·</span>{' '}
                {t('term.connCount', { count: connections.length })} <span className="sep">·</span>{' '}
                {t('term.snipCount', { count: snippets.length })}
              </span>
            )}
          </footer>
        </main>
      </div>

      {editor.open && (
        <ConnectionEditor
          connection={editor.connection}
          onCancel={() => setEditor({ open: false, connection: null })}
          onSaved={async () => {
            setEditor({ open: false, connection: null })
            setConnections(unwrap(await api.connections.list()))
          }}
        />
      )}

      {snippetEditor.open && (
        <SnippetEditor
          snippet={snippetEditor.snippet}
          onCancel={() => setSnippetEditor({ open: false, snippet: null })}
          onSaved={async () => {
            setSnippetEditor({ open: false, snippet: null })
            setSnippets(unwrap(await api.snippets.list()))
          }}
        />
      )}

      {hostKeyQueue.length > 0 && (
        <HostKeyDialog prompt={hostKeyQueue[0]} onAnswer={(accept) => void answerHostKey(accept)} />
      )}

      {/*
        The `key` is load-bearing, not tidiness. Without it React reconciles the
        same component across two different requests instead of remounting, so
        useState initialisers never re-run: the share dialog would keep request
        A's textarea while showing request B's header, and the auto-share
        checkbox would carry A's tick into B — the "memory of past approvals"
        DECISIONS.md says does not exist. Keying on the request id forces a
        fresh mount per request.
      */}
      {commandQueue.length > 0 && (
        <CommandApprovalDialog
          key={commandQueue[0].id}
          request={commandQueue[0]}
          onAnswer={(approved, autoShare) => {
            const req = commandQueue[0]
            setCommandQueue((prev) => prev.slice(1))
            void api.mcp.answerCommand(req.id, approved, autoShare)
          }}
        />
      )}

      {shareQueue.length > 0 && (
        <OutputShareDialog
          key={shareQueue[0].id}
          request={shareQueue[0]}
          /*
            Selecting in the console only means anything if the console on
            screen is the one the model asked about. Switching tabs for the
            human beats trusting them to notice they are highlighting the
            wrong session.
          */
          onShowSession={(sessionId) => setActiveSession(sessionId)}
          onAnswer={(shared, text) => {
            const req = shareQueue[0]
            setShareQueue((prev) => prev.slice(1))
            void api.mcp.answerShare(req.id, shared, text)
          }}
        />
      )}

      {settingsOpen && (
        <SettingsDialog
          settings={settings}
          vaultPath={vaultStatus.path}
          hasRecovery={vaultStatus.hasRecovery}
          onSaved={setSettings}
          onRecoveryKeyGenerated={(key) => setRecoveryKeyToShow({ key, isNew: false })}
          onRecoveryChanged={refreshVault}
          onClose={() => setSettingsOpen(false)}
        />
      )}

      {pendingInsert && (
        <div className="modal-backdrop" onMouseDown={() => setPendingInsert(null)}>
          <div className="modal wide-modal" onMouseDown={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <h2>{t('snip.confirmTitle')}</h2>
            </div>
            <div className="modal-body">
              <p>
                {t('snip.confirmBody', {
                  title: pendingInsert.snippet.title,
                  session: active?.title ?? ''
                })}
              </p>
              <pre className="snip-code preview">{pendingInsert.snippet.body}</pre>
            </div>
            <div className="modal-foot">
              <button className="btn" onClick={() => setPendingInsert(null)}>
                {t('common.cancel')}
              </button>
              <button
                className="btn primary"
                onClick={() => {
                  void doInsert(pendingInsert.snippet, pendingInsert.withEnter)
                  setPendingInsert(null)
                }}
              >
                {t('snip.confirmRun')}
              </button>
            </div>
          </div>
        </div>
      )}

      {deleteTarget && (
        <div className="modal-backdrop" onMouseDown={() => setDeleteTarget(null)}>
          <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <h2>
                {deleteTarget.kind === 'connection'
                  ? t('conn.deleteTitle')
                  : t('snip.deleteTitle')}
              </h2>
            </div>
            <div className="modal-body">
              <p>
                {deleteTarget.kind === 'connection'
                  ? t('conn.deleteBody', {
                      name: deleteTarget.item.name,
                      user: deleteTarget.item.username,
                      host: deleteTarget.item.host
                    })
                  : t('snip.deleteBody', { title: deleteTarget.item.title })}
              </p>
            </div>
            <div className="modal-foot">
              <button className="btn" onClick={() => setDeleteTarget(null)}>
                {t('common.cancel')}
              </button>
              <button className="btn danger" onClick={() => void confirmDelete()}>
                {t('common.delete')}
              </button>
            </div>
          </div>
        </div>
      )}

      {recoveryModal}

      {toast && <div className="toast">{toast}</div>}
    </div>
  )
}

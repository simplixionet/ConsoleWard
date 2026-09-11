// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  CommandApproval,
  ConnectionMeta,
  HostKeyPrompt,
  SaveCommandApproval,
  SessionInfo,
  UploadApproval,
  Settings,
  ShareRequest,
  Snippet,
  VaultStatus
} from '@shared/types'
import { api, errorMessage, unwrap } from './api'
import { reportActivity, resetActivityThrottle } from './activity'
import { useI18n } from './i18n'
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
import SaveCommandDialog from './components/SaveCommandDialog'
import UploadApprovalDialog from './components/UploadApprovalDialog'
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

type DeleteTarget =
  | { kind: 'connection'; item: ConnectionMeta }
  | { kind: 'snippet'; item: Snippet }

export default function App() {
  const { t, locale } = useI18n()
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null)
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
  // Queues, so concurrent requests from the model are never dropped.
  const [commandQueue, setCommandQueue] = useState<CommandApproval[]>([])
  const [saveQueue, setSaveQueue] = useState<SaveCommandApproval[]>([])
  const [uploadQueue, setUploadQueue] = useState<UploadApproval[]>([])
  const [shareQueue, setShareQueue] = useState<ShareRequest[]>([])

  const activeRef = useRef<string | null>(null)
  activeRef.current = activeSession

  const showToast = useCallback((msg: string) => {
    setToast(msg)
    window.setTimeout(() => setToast(null), 4000)
  }, [])

  /* ------------------------------------------------------------------ init */

  const loadData = useCallback(async () => {
    const [list, snips, cfg, live] = await Promise.all([
      api.connections.list(),
      api.snippets.list(),
      api.settings.get(),
      api.ssh.list()
    ])
    if (list.ok) setConnections(list.value)
    if (snips.ok) setSnippets(snips.value)
    if (cfg.ok) setSettings(cfg.value)
    // Main is the authority on live sessions. With `disconnectOnLock` off the
    // SSH clients survive a lock while `vault:locked` clears this list, so
    // without re-adopting them here they stay authenticated but unreachable —
    // no tab to read or close them, while MCP still runs commands on them.
    if (live.ok) setSessions(live.value)
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

  /* -------------------------------------------------------------- listeners */

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
    const offSaveCommand = api.mcp.onSaveCommandRequest((req) =>
      setSaveQueue((prev) => [...prev, req])
    )
    const offUpload = api.mcp.onUploadRequest((req) => setUploadQueue((prev) => [...prev, req]))
    const offShare = api.mcp.onShareRequest((req) => setShareQueue((prev) => [...prev, req]))

    const offLocked = api.vault.onLocked(() => {
      // The first keypress after a lock must reach the main process, not be
      // swallowed by a throttle window that opened before the user left.
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
      setSaveQueue([])
      setUploadQueue([])
      setShareQueue([])
      void refreshVault()
    })

    return () => {
      offData()
      offStatus()
      offHostKey()
      offCommand()
      offSaveCommand()
      offUpload()
      offShare()
      offLocked()
    }
  }, [refreshVault, showToast])

  // User activity defers the auto-lock. The capture flag is load-bearing:
  // xterm's own keydown handler calls stopPropagation() unconditionally, so on
  // the bubble phase typing into a session would count as idle. Only real DOM
  // input may defer the lock — never report from xterm's `onData`, see
  // activity.ts.
  useEffect(() => {
    const notify = (): void => reportActivity(() => api.app.notifyActivity())
    const events: (keyof WindowEventMap)[] = ['mousedown', 'keydown', 'wheel']
    for (const e of events) window.addEventListener(e, notify, true)
    return () => {
      for (const e of events) window.removeEventListener(e, notify, true)
    }
  }, [])

  /* ----------------------------------------------------------- connections */

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

  /* -------------------------------------------------------------- snippets */

  async function loadSnippets(): Promise<void> {
    try {
      setSnippets(unwrap(await api.snippets.list()))
    } catch (err) {
      showToast(errorMessage(err))
    }
  }

  async function duplicateSnippet(s: Snippet): Promise<void> {
    try {
      unwrap(await api.snippets.duplicate(s.id))
      await loadSnippets()
    } catch (err) {
      showToast(errorMessage(err))
    }
  }

  async function copySnippet(s: Snippet): Promise<void> {
    await api.clipboard.write(s.body)
    showToast(t('snip.copied', { title: s.title }))
  }

  // Multi-line bodies need their own confirmation: in a shell every newline
  // acts as Enter, so one insert would run several commands.
  function requestInsert(s: Snippet, withEnter: boolean): void {
    const active = sessions.find((x) => x.id === activeSession)
    if (!active || active.status !== 'ready') {
      showToast(t('snip.noSession'))
      return
    }
    /*
      An AI-written entry always confirms, whatever its length.

      A single-line snippet the user typed runs straight to the shell, which is
      right: they wrote it and they know what it does. One a model wrote was
      read once, at save time, and is run later out of that context — so without
      this line a useful-now, harmful-later suggestion reaches the shell with no
      dialog at all, days after the only review it ever got.
    */
    if (s.origin === 'ai' || s.body.includes('\n')) {
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

  /* -------------------------------------------------------------- deletion */

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

  // Shown exactly once, so the modal must survive the unlock-screen switch.
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
          onRecovered={(key) => setRecoveryKeyToShow({ key, isNew: false })}
          onUnlocked={refreshVault}
        />
        {recoveryModal}
      </>
    )
  }

  const active = sessions.find((s) => s.id === activeSession) ?? null
  const canInsert = active?.status === 'ready'
  // Dismissal is per event: a plain `true` would hide a second rollback in the
  // same run behind the first dismissal.
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
        A bar, not a modal, and never an early `return`: returning early skips
        `recoveryModal` below, so whoever unlocked with a recovery key would
        never see its replacement.
      */}
      {showRollback && vaultStatus.rollback && (
        <div className="rollback-bar">
          <div className="rollback-text">
            <b>{t('vault.rollbackTitle')}</b>{' '}
            {t('vault.rollbackBody', {
              found: vaultStatus.rollback.found,
              expected: vaultStatus.rollback.expected,
              // The app's language, not the system's.
              date: new Date(vaultStatus.rollback.at).toLocaleString(locale)
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

      {/*
        The three dialog conditions below must stay mutually exclusive. They
        share `.modal-backdrop` at one z-index, so concurrent dialogs occlude
        each other while `useArmedAfterPaint` arms the hidden one anyway
        (requestAnimationFrame is document-wide) — the covered dialog would
        expose a live danger button the frame its cover unmounts. Ordered by
        timeout, shortest fuse first: host key two minutes, approval five.
      */}
      {/*
        Before the approval dialogs on purpose. They share `.modal-backdrop`
        with no z-index between them, so DOM order decides what covers what —
        and an AI approval left underneath this one times out into a denial
        nobody saw. This is the human’s own action and can wait behind it.
      */}
      {pendingInsert && (
        <div className="modal-backdrop" onMouseDown={() => setPendingInsert(null)}>
          <div className="modal wide-modal" onMouseDown={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <h2>{t('snip.confirmTitle')}</h2>
            </div>
            <div className="modal-body">
              {/*
                Two reasons open this dialog and they are not interchangeable.
                A multi-line snippet is dangerous because every line ending acts
                as Enter; an AI-written one is dangerous because it was read once
                at save time and is being run now, out of that context. Telling
                someone their one-line command "has multiple lines" is both false
                and the wrong thing to check before saying yes.
              */}
              {pendingInsert.snippet.origin === 'ai' ? (
                <>
                  <div className="warn-box danger-box">
                    <b>{t('snip.confirmAiLead')}</b>{' '}
                    {t('snip.confirmAiBody', { session: active?.title ?? '' })}
                  </div>
                  {pendingInsert.snippet.body.includes('\n') && (
                    <div className="warn-box">{t('snip.multiline')}</div>
                  )}
                </>
              ) : (
                <p>
                  {t('snip.confirmBody', {
                    title: pendingInsert.snippet.title,
                    session: active?.title ?? ''
                  })}
                </p>
              )}
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

      {hostKeyQueue.length > 0 && (
        <HostKeyDialog
          key={hostKeyQueue[0].requestId}
          prompt={hostKeyQueue[0]}
          onAnswer={(accept) => void answerHostKey(accept)}
        />
      )}

      {/*
        The `key` is load-bearing: without a remount per request, useState
        initialisers never re-run and request A's edited text and auto-share
        tick leak into request B.
      */}
      {hostKeyQueue.length === 0 && commandQueue.length > 0 && (
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

      {hostKeyQueue.length === 0 && commandQueue.length === 0 && uploadQueue.length > 0 && (
        <UploadApprovalDialog
          key={uploadQueue[0].id}
          request={uploadQueue[0]}
          onAnswer={(approved) => {
            const req = uploadQueue[0]
            setUploadQueue((prev) => prev.slice(1))
            void api.mcp.answerUpload(req.id, approved)
          }}
        />
      )}

      {hostKeyQueue.length === 0 &&
        commandQueue.length === 0 &&
        uploadQueue.length === 0 &&
        saveQueue.length > 0 && (
        <SaveCommandDialog
          key={saveQueue[0].id}
          request={saveQueue[0]}
          onAnswer={(approved) => {
            const req = saveQueue[0]
            setSaveQueue((prev) => prev.slice(1))
            void api.mcp.answerSaveCommand(req.id, approved)
            if (approved) void loadSnippets()
          }}
        />
      )}

      {hostKeyQueue.length === 0 &&
        commandQueue.length === 0 &&
        uploadQueue.length === 0 &&
        saveQueue.length === 0 &&
        shareQueue.length > 0 && (
        <OutputShareDialog
          key={shareQueue[0].id}
          request={shareQueue[0]}
          /*
            A console selection only means anything if the visible tab is the
            session the model asked about, so switch for the user.
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

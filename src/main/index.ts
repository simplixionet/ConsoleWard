// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  ipcMain,
  safeStorage,
  session as electronSession,
  shell
} from 'electron'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { CH } from '../shared/channels'
import { contentSecurityPolicy } from '../shared/csp'
import type {
  ConnectionInput,
  ConnectionMeta,
  KeyGenerateInput,
  KeyImportInput,
  KnownHost,
  LogFileInfo,
  Result,
  Settings,
  Snippet,
  SnippetInput,
  SshKey,
  SshKeyMeta,
  VaultStatus
} from '../shared/types'
import type {
  CommandApproval,
  McpStatus,
  SaveCommandApproval,
  ShareRequest,
  UploadApproval
} from '../shared/types'
import { appError, currentLocale, initI18n, setLocale, t } from './i18n'
import { readPrefs, writePrefs } from './prefs'
import type { VaultData } from './vault'
import { migrateLegacyProfile, newId, vault } from './vault'
import {
  adoptEmbeddedKeys,
  assertKeyUnused,
  generateKey,
  hasKeysToAdopt,
  importKeyText,
  toKeyMeta
} from './sshKeys'
import { DEFAULT_SETTINGS, sanitizeSettings } from './settings'
import { ssh } from './ssh'
import { mcp } from './mcp'
import { approvals } from './approvals'
import { readSmallTextFile } from './textFile'
import { logs } from './logs'
import { aiLog } from './aiLog'

const isDev = !app.isPackaged
let mainWindow: BrowserWindow | null = null
let autoLockTimer: NodeJS.Timeout | null = null

/* ----------------------------------------------------------------- window */

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    show: false,
    backgroundColor: '#0e1116',
    title: 'ConsoleWard',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false
    }
  })

  mainWindow.once('ready-to-show', () => mainWindow?.show())

  // External links go to the system browser, never into the app window; the
  // anchored scheme test keeps `file:`, `javascript:` and SMB paths out. Prompt
  // anyway: `openExternal` bypasses CSP, and terminal output holds clickable
  // links the user never typed. Show the URL in full — truncation hides it.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!/^https?:\/\//.test(url)) return { action: 'deny' }

    const win = mainWindow
    if (!win) return { action: 'deny' }

    void dialog
      .showMessageBox(win, {
        type: 'question',
        buttons: [t('common.cancel'), t('link.open')],
        defaultId: 0,
        cancelId: 0,
        title: t('link.confirmTitle'),
        message: t('link.confirmBody'),
        detail: url,
        noLink: true
      })
      .then(({ response }) => {
        if (response === 1) void shell.openExternal(url)
      })

    return { action: 'deny' }
  })
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const devUrl = process.env['ELECTRON_RENDERER_URL']
    if (devUrl && url.startsWith(devUrl)) return
    event.preventDefault()
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })

  const devUrl = process.env['ELECTRON_RENDERER_URL']
  if (isDev && devUrl) {
    void mainWindow.loadURL(devUrl)
  } else {
    void mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'))
  }
}

function applyCsp(): void {
  // Must stay identical to the meta tag: both apply and CSP intersects them.
  const policy = contentSecurityPolicy(isDev)

  electronSession.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [policy]
      }
    })
  })

  // Both handlers are required: the request handler covers the asynchronous
  // prompts, the check handler the synchronous path several permissions take
  // instead — and an unset check handler defaults to allowing them.
  electronSession.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false))
  electronSession.defaultSession.setPermissionCheckHandler(() => false)
}

/* -------------------------------------------------------------- auto-lock */

function resetAutoLock(): void {
  if (autoLockTimer) clearTimeout(autoLockTimer)
  autoLockTimer = null
  if (!vault.isUnlocked()) return

  const minutes = vault.read().settings.autoLockMinutes
  if (!minutes || minutes <= 0) return

  autoLockTimer = setTimeout(() => doLock(), minutes * 60_000)
}

function doLock(): void {
  if (!vault.isUnlocked()) return
  const disconnect = vault.read().settings.disconnectOnLock
  if (disconnect) ssh.disconnectAll()
  void mcp.stopOnLock().then(pushMcpStatus)
  approvals.rejectAll()
  vault.lock()
  if (autoLockTimer) clearTimeout(autoLockTimer)
  autoLockTimer = null
  mainWindow?.webContents.send(CH.vaultLockedEvent)
}

/* ----------------------------------------------------- MCP approval queue */

function pushMcpStatus(): void {
  mainWindow?.webContents.send(CH.mcpStatusEvent, mcp.status())
}

async function syncMcp(): Promise<void> {
  if (!vault.isUnlocked()) return
  const wanted = Boolean(vault.read().settings.mcpEnabled)
  try {
    if (wanted) await mcp.start()
    else await mcp.stop()
  } catch (err) {
    console.error('MCP server:', err)
  } finally {
    pushMcpStatus()
  }
}

function registerMcpBridge(): void {
  approvals.bind({
    sendCommand: (req: CommandApproval) =>
      mainWindow?.webContents.send(CH.mcpCommandRequestEvent, req),

    sendSaveCommand: (req: SaveCommandApproval) =>
      mainWindow?.webContents.send(CH.mcpSaveCommandRequestEvent, req),

    sendUpload: (req: UploadApproval) => mainWindow?.webContents.send(CH.mcpUploadRequestEvent, req),

    sendShare: (req: ShareRequest) => mainWindow?.webContents.send(CH.mcpShareRequestEvent, req),

    // Raising is the queue's call, not the tool's: one raise per request means
    // flashFrame in a loop on Windows, and only the queue knows if a dialog is up.
    raiseWindow: () => {
      if (!mainWindow) return
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.show()
      mainWindow.focus()
      if (process.platform === 'win32') mainWindow.flashFrame(true)
    }
  })

  /*
    The queue answers the two questions it owns; saving needs a third step the
    queue must not have, because it writes to the vault and `approvals.ts`
    deliberately knows nothing about either Electron or the vault.
  */
  mcp.bind({
    askCommand: (req) => approvals.askCommand(req),
    askShare: (req) => approvals.askShare(req),
    askUpload: (req) => approvals.askUpload(req),
    saveCommand: async (req, skipApproval) => {
      if (!skipApproval) {
        const answer = await approvals.askSaveCommand(req)
        if (!answer.approved) return { approved: false }
      }
      await saveAiSnippet(req)
      return { approved: true }
    }
  })
}

/**
 * Writes a model-proposed command into the library, through the same rules
 * `snip:save` uses — including the newline normalisation, because a CRLF
 * reaching a shell as `^M` is no less of a problem for having come from an AI.
 */
async function saveAiSnippet(req: SaveCommandApproval): Promise<void> {
  await vault.mutate((data) => {
    const now = Date.now()
    data.snippets.push({
      id: newId(),
      title: req.title.trim().slice(0, 120),
      body: normalizeNewlines(req.body),
      note: req.note?.trim().slice(0, 500) || undefined,
      // A model-supplied folder places the entry wherever it likes, including
      // one the user trusts — so the dialog shows it, and the length is capped
      // here rather than letting a folder name become a paragraph.
      folder: req.folder?.trim().slice(0, 60) || undefined,
      kind: 'command',
      origin: 'ai',
      createdAt: now,
      updatedAt: now
    })
  })
}

/* ---------------------------------------------------------------- helpers */

function ok<T>(value: T): Result<T> {
  return { ok: true, value }
}

/**
 * The only error text the renderer may see. An `AppError` is ours — a translated
 * sentence meant for the user — so it passes through whole. Anything else came
 * from node, Electron or a library and can carry absolute paths, internal state
 * or a fragment of the offending input, so only the console gets it.
 */
function fail(err: unknown): Result<never> {
  const key = (err as { key?: unknown } | null | undefined)?.key
  if (typeof key === 'string' && err instanceof Error) {
    return { ok: false, error: err.message }
  }
  console.error('ipc:', err)
  return { ok: false, error: t('error.unexpected') }
}

function handle<T>(channel: string, fn: (...args: any[]) => Promise<T> | T): void {
  ipcMain.handle(channel, async (_event, ...args) => {
    try {
      return ok(await fn(...args))
    } catch (err) {
      return fail(err)
    }
  })
}

function toMeta(c: {
  id: string
  name: string
  host: string
  port: number
  username: string
  authKind: ConnectionMeta['authKind']
  keyId?: string
  logTranscript?: boolean
  password?: string
  privateKey?: string
  passphrase?: string
  agentSocket?: string
  folder?: string
  notes?: string
  createdAt: number
  updatedAt: number
}): ConnectionMeta {
  return {
    id: c.id,
    name: c.name,
    host: c.host,
    port: c.port,
    username: c.username,
    authKind: c.authKind,
    keyId: c.keyId,
    logTranscript: c.logTranscript,
    hasPassword: Boolean(c.password),
    hasPrivateKey: Boolean(c.privateKey),
    hasPassphrase: Boolean(c.passphrase),
    agentSocket: c.agentSocket,
    folder: c.folder,
    notes: c.notes,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt
  }
}

/**
 * Same three-state rule as the secrets, plus a check: an id that names no key
 * would leave the connection unable to authenticate, and the failure would only
 * show up at the next connect.
 */
function applyKeyId(
  data: VaultData,
  current: string | undefined,
  incoming: string | undefined
): string | undefined {
  if (incoming === undefined) return current
  if (incoming === '') return undefined
  if (!data.keys.some((k) => k.id === incoming)) throw appError('error.keyMissing')
  return incoming
}

/** `ConnectionInput` secrets: `undefined` keeps, `''` clears, anything else replaces. */
function applySecret(current: string | undefined, incoming: string | undefined): string | undefined {
  if (incoming === undefined) return current
  if (incoming === '') return undefined
  return incoming
}

function validateInput(input: ConnectionInput): void {
  if (!input.name?.trim()) throw appError('error.fillName')
  if (!input.host?.trim()) throw appError('error.fillHost')
  if (!input.username?.trim()) throw appError('error.fillUsername')
  const port = Number(input.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw appError('error.invalidPort')
  }
  if (!['password', 'key', 'agent'].includes(input.authKind)) {
    throw appError('error.invalidAuth')
  }
}

/* -------------------------------------------------------- rollback anchor */

/**
 * Hands the vault a sealer backed by the platform keyring. It lives here and not
 * in `vault.ts` because `safeStorage` is a named export of `electron` and the
 * test files stub only `app`, so importing it there breaks them all at load.
 *
 * Linux's `basic_text` fallback merely encodes the data, yet Electron reports
 * `isEncryptionAvailable()` as true for it — accepting that would mark the
 * anchor protected when it is not, which is worse than an admittedly bare one.
 */
function installGuardSealer(): void {
  let usable = false
  try {
    usable = safeStorage.isEncryptionAvailable()
    if (usable && process.platform === 'linux') {
      const backend = safeStorage.getSelectedStorageBackend?.()
      if (backend === 'basic_text') usable = false
    }
  } catch {
    usable = false
  }

  if (!usable) {
    console.warn('vault: no usable keyring — the rollback anchor will be stored unprotected')
  }

  vault.installGuardSealer({
    available: () => usable,
    seal: (plain) => safeStorage.encryptString(plain),
    open: (blob) => safeStorage.decryptString(blob)
  })
}

/** The caps are read from settings at every change; a writer already open keeps the ones it opened with. */
function applyLogLimits(settings: Settings): void {
  logs.setLimits({
    maxFileBytes: (settings.logMaxFileMb ?? 16) * 1024 * 1024,
    maxTotalBytes: (settings.logMaxTotalMb ?? 512) * 1024 * 1024
  })
}

/**
 * Moves key text off connections and into the key library, once, on unlock.
 *
 * It runs through `vault.mutate`, which clones, writes and only then adopts —
 * so a failed write leaves the vault exactly as it was rather than half
 * migrated. A failure is logged and not rethrown: the vault is open, every
 * connection still authenticates from its own key text, and refusing to unlock
 * over a convenience migration would be the worse outcome.
 */
async function moveKeysIntoLibrary(): Promise<void> {
  /*
    `mutate` always writes, and most unlocks have nothing to move. The predicate
    has to be the migration's OWN — asking only whether key text is present
    would keep returning true for a key `describeKey` cannot read, which the
    migration skips on purpose, and every unlock would then re-encrypt the whole
    vault, roll the backup and bump the counter to move nothing at all. Forever:
    the condition that triggers it is the one the migration will not clear.
  */
  if (!hasKeysToAdopt(vault.read())) return
  try {
    const moved = await vault.mutate(adoptEmbeddedKeys)
    if (moved > 0) console.log(`vault: moved ${moved} key(s) into the key library`)
  } catch (err) {
    console.warn('vault: key migration failed, connections keep their own keys:', err)
  }
}

/* --------------------------------------------------------------------- IPC */

function registerIpc(): void {
  /* vault */
  handle(CH.vaultStatus, async (): Promise<VaultStatus> => {
    const guard = vault.rollback
    return {
      exists: vault.exists(),
      unlocked: vault.isUnlocked(),
      hasRecovery: vault.isUnlocked() ? vault.hasRecoveryKey() : await vault.hasRecoveryOnDisk(),
      path: vault.filePath,
      rollback:
        guard.kind === 'rollback'
          ? { expected: guard.expected, found: guard.found, at: guard.at }
          : null
    }
  })

  handle(CH.vaultCreate, async (pw: string) => {
    const recoveryKey = await vault.create(pw)
    resetAutoLock()
    return recoveryKey
  })

  handle(CH.vaultUnlock, async (pw: string) => {
    await vault.unlock(pw)
    resetAutoLock()
    applyLogLimits(vault.read().settings)
    await moveKeysIntoLibrary()
    await syncMcp()
    return null
  })

  // Returns a fresh recovery key: recovery rotates the data key, so the one
  // just used is dead. The UI must show it or the user is left with no way in.
  handle(CH.vaultUnlockWithRecovery, async (recoveryKey: string, newPassword: string) => {
    const fresh = await vault.unlockWithRecovery(recoveryKey, newPassword)
    resetAutoLock()
    applyLogLimits(vault.read().settings)
    await moveKeysIntoLibrary()
    await syncMcp()
    return fresh
  })

  handle(CH.vaultLock, () => {
    doLock()
    return null
  })

  // Also returns a fresh recovery key if the vault had one: the DEK rotates and
  // the old wrap cannot be rebuilt, since the recovery key is never stored.
  handle(CH.vaultChangePassword, (oldPw: string, newPw: string) =>
    vault.changePassword(oldPw, newPw)
  )

  // The password is mandatory: rotating the DEK needs it, and without it an
  // unlocked session alone could mint a key that opens the vault forever.
  handle(CH.vaultRegenerateRecovery, (password: string) =>
    vault.regenerateRecoveryKey(password)
  )

  handle(CH.vaultRemoveRecovery, async (password: string) => {
    await vault.removeRecoveryKey(password)
    return null
  })

  /* connections */
  handle(CH.connList, (): ConnectionMeta[] =>
    vault
      .read()
      .connections.map(toMeta)
      .sort(byName)
  )

  handle(CH.connSave, async (input: ConnectionInput): Promise<ConnectionMeta> => {
    validateInput(input)
    return vault.mutate((data) => {
      const now = Date.now()
      const existing = input.id ? data.connections.find((c) => c.id === input.id) : undefined

      if (existing) {
        existing.name = input.name.trim()
        existing.host = input.host.trim()
        existing.port = Number(input.port)
        existing.username = input.username.trim()
        existing.authKind = input.authKind
        existing.keyId = applyKeyId(data, existing.keyId, input.keyId)
        existing.logTranscript = input.logTranscript === undefined ? existing.logTranscript : Boolean(input.logTranscript)
        existing.password = applySecret(existing.password, input.password)
        existing.privateKey = applySecret(existing.privateKey, input.privateKey)
        existing.passphrase = applySecret(existing.passphrase, input.passphrase)
        // Moving to a library key retires the copy this connection carried.
        // Leaving it behind would keep a private key in the vault that nothing
        // reads and no screen ever shows again.
        if (existing.keyId) {
          existing.privateKey = undefined
          existing.passphrase = undefined
        }
        existing.agentSocket = input.agentSocket?.trim() || undefined
        existing.folder = input.folder?.trim() || undefined
        existing.notes = input.notes ?? undefined
        existing.updatedAt = now
        return toMeta(existing)
      }

      const created = {
        id: newId(),
        name: input.name.trim(),
        host: input.host.trim(),
        port: Number(input.port),
        username: input.username.trim(),
        authKind: input.authKind,
        keyId: applyKeyId(data, undefined, input.keyId),
        logTranscript: input.logTranscript === undefined ? undefined : Boolean(input.logTranscript),
        password: input.password || undefined,
        privateKey: input.privateKey || undefined,
        passphrase: input.passphrase || undefined,
        agentSocket: input.agentSocket?.trim() || undefined,
        folder: input.folder?.trim() || undefined,
        notes: input.notes ?? undefined,
        createdAt: now,
        updatedAt: now
      }
      data.connections.push(created)
      return toMeta(created)
    })
  })

  handle(CH.connRemove, async (id: string) => {
    await vault.mutate((data) => {
      const idx = data.connections.findIndex((c) => c.id === id)
      if (idx < 0) throw appError('error.connNotFound')
      data.connections.splice(idx, 1)
    })
    return null
  })

  handle(CH.connDuplicate, async (id: string): Promise<ConnectionMeta> =>
    vault.mutate((data) => {
      const src = data.connections.find((c) => c.id === id)
      if (!src) throw appError('error.connNotFound')
      const now = Date.now()
      const copy = { ...src, id: newId(), name: `${src.name} (copy)`, createdAt: now, updatedAt: now }
      data.connections.push(copy)
      return toMeta(copy)
    })
  )

  /* ssh keys */
  handle(CH.keyList, (): SshKeyMeta[] => {
    const data = vault.read()
    return data.keys
      .map((k) => toKeyMeta(k, data.connections))
      .sort((a, b) => collator().compare(a.name, b.name))
  })

  handle(CH.keyImport, async (input: KeyImportInput): Promise<SshKeyMeta> => {
    if (!input?.name?.trim()) throw appError('error.fillName')
    const facts = importKeyText(input.privateKey ?? '', input.passphrase)
    return vault.mutate((data) => {
      // One entry per key is the point of the library, so a re-import is an
      // error rather than a second copy that quietly diverges from the first.
      const clash = data.keys.find((k) => k.fingerprint === facts.fingerprint)
      if (clash) throw appError('error.keyDuplicate', { name: clash.name })

      const key: SshKey = {
        id: newId(),
        name: input.name.trim(),
        privateKey: facts.privateKey,
        passphrase: input.passphrase || undefined,
        keyType: facts.keyType,
        publicKey: facts.publicKey,
        fingerprint: facts.fingerprint,
        origin: 'imported',
        createdAt: Date.now()
      }
      data.keys.push(key)
      return toKeyMeta(key, data.connections)
    })
  })

  handle(CH.keyGenerate, async (input: KeyGenerateInput): Promise<SshKeyMeta> => {
    if (!input?.name?.trim()) throw appError('error.fillName')
    if (input.type !== 'ed25519' && input.type !== 'rsa') throw appError('error.invalidKind')
    // RSA 4096 takes seconds; generating before the write keeps that time out
    // of the vault's write queue, which every other mutation waits behind.
    const generated = generateKey(input.type, input.passphrase)
    return vault.mutate((data) => {
      const key: SshKey = {
        id: newId(),
        name: input.name.trim(),
        privateKey: generated.privateKey,
        passphrase: input.passphrase || undefined,
        keyType: generated.facts.keyType,
        publicKey: generated.facts.publicKey,
        fingerprint: generated.facts.fingerprint,
        origin: 'generated',
        createdAt: Date.now()
      }
      data.keys.push(key)
      return toKeyMeta(key, data.connections)
    })
  })

  handle(CH.keyRename, async (id: string, name: string): Promise<SshKeyMeta> => {
    if (!name?.trim()) throw appError('error.fillName')
    return vault.mutate((data) => {
      const key = data.keys.find((k) => k.id === id)
      if (!key) throw appError('error.keyMissing')
      key.name = name.trim()
      return toKeyMeta(key, data.connections)
    })
  })

  handle(CH.keyRemove, async (id: string) => {
    await vault.mutate((data) => {
      const idx = data.keys.findIndex((k) => k.id === id)
      if (idx < 0) throw appError('error.keyMissing')
      assertKeyUnused(data, id)
      data.keys.splice(idx, 1)
    })
    return null
  })

  /* commands and notes */
  handle(CH.snipList, (): Snippet[] =>
    [...vault.read().snippets].sort((a, b) => collator().compare(a.title, b.title))
  )

  handle(CH.snipSave, async (input: SnippetInput): Promise<Snippet> => {
    if (!input.title?.trim()) throw appError('error.fillName')
    if (!input.body?.trim()) throw appError('error.fillBody')
    if (!['command', 'note'].includes(input.kind)) throw appError('error.invalidKind')

    // Normalize line endings to LF — CRLF shows up as ^M in the shell.
    const body = normalizeNewlines(input.body)

    return vault.mutate((data) => {
      const now = Date.now()
      const existing = input.id ? data.snippets.find((s) => s.id === input.id) : undefined

      if (existing) {
        existing.title = input.title.trim()
        existing.body = body
        existing.note = input.note?.trim() || undefined
        existing.folder = input.folder?.trim() || undefined
        existing.kind = input.kind
        // A human opened this, read the body and saved it. That is exactly what
        // the mark exists to force, so it has served its purpose and goes.
        existing.origin = 'human'
        existing.updatedAt = now
        return existing
      }

      const created: Snippet = {
        id: newId(),
        title: input.title.trim(),
        body,
        note: input.note?.trim() || undefined,
        folder: input.folder?.trim() || undefined,
        kind: input.kind,
        origin: 'human',
        createdAt: now,
        updatedAt: now
      }
      data.snippets.push(created)
      return created
    })
  })

  handle(CH.snipRemove, async (id: string) => {
    await vault.mutate((data) => {
      const idx = data.snippets.findIndex((s) => s.id === id)
      if (idx < 0) throw appError('error.snipNotFound')
      data.snippets.splice(idx, 1)
    })
    return null
  })

  handle(CH.snipDuplicate, (id: string): Promise<Snippet> =>
    vault.mutate((data) => {
      const src = data.snippets.find((s) => s.id === id)
      if (!src) throw appError('error.snipNotFound')
      const now = Date.now()
      const copy: Snippet = {
        ...src,
        id: newId(),
        title: `${src.title} (copy)`,
        createdAt: now,
        updatedAt: now
      }
      data.snippets.push(copy)
      return copy
    })
  )

  /* settings */
  handle(CH.settingsGet, (): Settings => {
    const d = vault.read()
    return { ...DEFAULT_SETTINGS, ...d.settings, hasAiApiKey: Boolean(d.aiApiKey) }
  })

  handle(CH.settingsSave, async (patch: Partial<Settings>): Promise<Settings> => {
    const saved = await vault.mutate((data) => {
      // Throws before anything is assigned, so a refused patch writes nothing.
      data.settings = sanitizeSettings(data.settings, patch)
      return data.settings
    })
    applyLogLimits(saved)
    resetAutoLock()
    return { ...saved, hasAiApiKey: Boolean(vault.read().aiApiKey) }
  })

  /* known hosts */
  handle(CH.hostsList, (): KnownHost[] =>
    // `hostKey` is `host:port`, a name the user reads — sort it like the rest.
    [...vault.read().knownHosts].sort((a, b) => collator().compare(a.hostKey, b.hostKey))
  )

  handle(CH.hostsForget, async (hostKey: string) => {
    await vault.mutate((data) => {
      data.knownHosts = data.knownHosts.filter((h) => h.hostKey !== hostKey)
    })
    return null
  })

  /* SSH */
  // Every SSH I/O path goes through `requireUnlockedPublic()`: the renderer
  // drops its tab list on `vault:locked` but the main process keeps the clients,
  // so an unguarded `write`/`resize` would still type into the remote shell.
  //
  // `sshList` exists because locking is not disconnecting — with
  // `disconnectOnLock` off the clients stay connected on purpose, and with no
  // way to re-adopt them after unlock they stay live, authenticated and
  // invisible while MCP can still run commands on them.
  handle(CH.sshList, () => {
    vault.requireUnlockedPublic()
    return ssh.list()
  })
  handle(CH.sshConnect, (connectionId: string) => {
    vault.requireUnlockedPublic()
    return ssh.connect(connectionId)
  })
  handle(CH.sshWrite, (sessionId: string, data: string) => {
    vault.requireUnlockedPublic()
    ssh.write(sessionId, data)
    return null
  })
  handle(CH.sshResize, (sessionId: string, cols: number, rows: number) => {
    vault.requireUnlockedPublic()
    ssh.resize(sessionId, cols, rows)
    return null
  })
  handle(CH.sshDisconnect, (sessionId: string) => {
    ssh.disconnect(sessionId)
    return null
  })
  handle(CH.sshAnswerHostKey, (requestId: string, accept: boolean) => {
    ssh.answerHostKey(requestId, Boolean(accept))
    return null
  })

  /* dialogs */
  handle(CH.dialogReadTextFile, async (title: string) => {
    if (!mainWindow) return null
    const res = await dialog.showOpenDialog(mainWindow, {
      title: title || t('dialog.selectFile'),
      properties: ['openFile'],
      filters: [
        {
          name: t('dialog.privateKeys'),
          extensions: ['pem', 'key', 'ppk', 'rsa', 'ed25519', 'pub', '']
        },
        { name: t('dialog.allFiles'), extensions: ['*'] }
      ]
    })
    if (res.canceled || res.filePaths.length === 0) return null
    // The picker can hand back a FIFO or a named pipe, and both lie to `stat`.
    return readSmallTextFile(res.filePaths[0])
  })

  handle(CH.dialogSaveTextFile, async (suggestedName: string, content: string) => {
    if (!mainWindow) return null
    const res = await dialog.showSaveDialog(mainWindow, {
      title: t('dialog.saveFile'),
      defaultPath: suggestedName,
      filters: [{ name: t('dialog.textFile'), extensions: ['txt'] }]
    })
    if (res.canceled || !res.filePath) return null
    await fsp.writeFile(res.filePath, String(content ?? ''), { encoding: 'utf8', mode: 0o600 })
    return res.filePath
  })

  /* logs */
  handle(CH.logList, (): Promise<LogFileInfo[]> => logs.list())

  handle(CH.logSize, (): Promise<number> => logs.totalBytes())

  /*
    The one place a log becomes plaintext. The warning belongs on the button
    that calls this, not on the switch that started the logging — this is where
    the decision is actually made.
  */
  handle(CH.logExport, async (id: string): Promise<string | null> => {
    if (!mainWindow) return null
    const decrypted = await logs.decrypt(id)
    const res = await dialog.showSaveDialog(mainWindow, {
      title: t('dialog.saveFile'),
      defaultPath: `${decrypted.info.kind}-${new Date(decrypted.info.createdAt)
        .toISOString()
        .slice(0, 19)
        .replace(/[:T]/g, '-')}.txt`,
      filters: [{ name: t('dialog.textFile'), extensions: ['txt'] }]
    })
    if (res.canceled || !res.filePath) return null
    const banner = decrypted.truncated ? `${t('logs.truncatedNote')}\n\n` : ''
    await fsp.writeFile(res.filePath, banner + decrypted.text, { encoding: 'utf8', mode: 0o600 })
    return res.filePath
  })

  handle(CH.logRemove, async (id: string) => {
    await logs.remove(id)
    return null
  })

  handle(CH.logPurge, (): Promise<number> => logs.purge())

  handle(CH.logReveal, async () => {
    await fsp.mkdir(logs.dir, { recursive: true })
    await shell.openPath(logs.dir)
    return null
  })

  /* MCP */
  handle(CH.mcpStatus, (): McpStatus => mcp.status())

  handle(CH.mcpSetEnabled, async (enabled: boolean): Promise<McpStatus> => {
    await vault.mutate((data) => {
      data.settings = { ...data.settings, mcpEnabled: Boolean(enabled) }
    })
    if (enabled) await mcp.start()
    else await mcp.stop()
    const status = mcp.status()
    pushMcpStatus()
    return status
  })

  handle(CH.mcpSetPort, async (port: number): Promise<McpStatus> => {
    const n = Number(port)
    if (!Number.isInteger(n) || n < 1024 || n > 65535) {
      throw appError('error.invalidMcpPort')
    }
    await vault.mutate((data) => {
      data.settings = { ...data.settings, mcpPort: n }
    })
    if (mcp.status().running) await mcp.restart()
    const status = mcp.status()
    pushMcpStatus()
    return status
  })

  handle(CH.mcpToken, () => mcp.readToken())
  handle(CH.mcpRegenerateToken, () => mcp.regenerateToken())

  handle(CH.mcpAnswerCommand, (id: string, approved: boolean, autoShare: boolean) => {
    approvals.answerCommand(id, approved, autoShare)
    return null
  })

  handle(CH.mcpAnswerSaveCommand, (id: string, approved: boolean) => {
    approvals.answerSaveCommand(id, approved)
    return null
  })

  handle(CH.mcpAnswerUpload, (id: string, approved: boolean) => {
    approvals.answerUpload(id, approved)
    return null
  })

  handle(CH.mcpAnswerShare, (id: string, shared: boolean, text: string) => {
    approvals.answerShare(id, shared, text)
    return null
  })

  /* clipboard (the sandboxed preload has no direct access to it) */
  handle(CH.clipboardRead, () => clipboard.readText())
  handle(CH.clipboardWrite, (text: string) => {
    clipboard.writeText(String(text ?? ''))
    return null
  })

  /* app */
  ipcMain.on(CH.appActivity, () => resetAutoLock())
  handle(CH.appVersion, () => app.getVersion())

  handle(CH.appGetLocale, () => currentLocale())
  handle(CH.appSetLocale, async (locale: string) => {
    const saved = await writePrefs({ locale })
    await setLocale(saved.locale)
    return saved.locale
  })
}

/**
 * Built per call, not cached: the locale changes while the app runs, and a
 * collator captured at module load would keep sorting by the old one.
 */
function collator(): Intl.Collator {
  return new Intl.Collator(currentLocale(), { sensitivity: 'base', numeric: true })
}

function byName(a: { name: string }, b: { name: string }): number {
  return collator().compare(a.name, b.name)
}

function normalizeNewlines(text: string): string {
  return String(text ?? '').replace(/\r\n?/g, '\n')
}

/* ------------------------------------------------------------------ start */

const gotLock = app.requestSingleInstanceLock()
if (!gotLock) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.focus()
    }
  })

  void app.whenReady().then(async () => {
    const migratedFrom = await migrateLegacyProfile(['PuttyUI', 'putty-ui']).catch(
      (err: unknown) => {
        // Non-fatal: a failed move must not block startup. But this is the
        // upgrade path, so the log is the only sign the vault did not vanish.
        console.error('Legacy profile migration failed:', err)
        return null
      }
    )
    if (migratedFrom) console.log('Vault migrated from legacy profile directory:', migratedFrom)

    await initI18n()

    logs.setDirectory(path.join(app.getPath('userData'), 'logs'))

    installGuardSealer()

    applyCsp()
    registerIpc()

    ssh.bind({
      data: (sessionId, base64) =>
        mainWindow?.webContents.send(CH.sshDataEvent, sessionId, base64),
      status: (info) => mainWindow?.webContents.send(CH.sshStatusEvent, info),
      hostKeyPrompt: (prompt) => mainWindow?.webContents.send(CH.sshHostKeyEvent, prompt)
    })
    registerMcpBridge()

    createWindow()

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow()
    })
  })

  /**
   * On macOS the process stays resident after the last window closes and
   * `before-quit` does not run, so without this the vault would sit unlocked in
   * memory while the MCP gateway kept answering tool calls whose approval dialog
   * has nowhere to appear. `activate` rebuilds a window onto the lock screen.
   */
  app.on('window-all-closed', () => {
    ssh.disconnectAll()
    if (process.platform !== 'darwin') {
      app.quit()
      return
    }
    doLock()
  })

  app.on('before-quit', () => {
    approvals.rejectAll()
    void mcp.stop()
    ssh.disconnectAll()
    // Belt and braces: every AI event is already flushed as it is recorded, so
    // there should be nothing buffered here. `before-quit` is synchronous and
    // will not wait for this, which is exactly why the flush is not here.
    void aiLog.closeAll()
    vault.lock()
  })
}

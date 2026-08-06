// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { contextBridge, ipcRenderer } from 'electron'
import { CH } from '../shared/channels'
import type {
  AppApi,
  CommandApproval,
  ConnectionInput,
  HostKeyPrompt,
  McpStatus,
  SessionInfo,
  Settings,
  ShareRequest,
  SnippetInput
} from '../shared/types'

/** Odhlašovací funkce pro posluchače událostí. */
function on<A extends unknown[]>(channel: string, cb: (...args: A) => void): () => void {
  const listener = (_e: unknown, ...args: unknown[]) => cb(...(args as A))
  ipcRenderer.on(channel, listener)
  return () => ipcRenderer.removeListener(channel, listener)
}

const api: AppApi = {
  vault: {
    status: () => ipcRenderer.invoke(CH.vaultStatus),
    create: (pw) => ipcRenderer.invoke(CH.vaultCreate, pw),
    unlock: (pw) => ipcRenderer.invoke(CH.vaultUnlock, pw),
    unlockWithRecovery: (recoveryKey, newPassword) =>
      ipcRenderer.invoke(CH.vaultUnlockWithRecovery, recoveryKey, newPassword),
    lock: () => ipcRenderer.invoke(CH.vaultLock),
    changePassword: (oldPw, newPw) => ipcRenderer.invoke(CH.vaultChangePassword, oldPw, newPw),
    regenerateRecoveryKey: (password) =>
      ipcRenderer.invoke(CH.vaultRegenerateRecovery, password),
    removeRecoveryKey: (password) => ipcRenderer.invoke(CH.vaultRemoveRecovery, password),
    onLocked: (cb) => on(CH.vaultLockedEvent, cb)
  },
  connections: {
    list: () => ipcRenderer.invoke(CH.connList),
    save: (input: ConnectionInput) => ipcRenderer.invoke(CH.connSave, input),
    remove: (id) => ipcRenderer.invoke(CH.connRemove, id),
    duplicate: (id) => ipcRenderer.invoke(CH.connDuplicate, id)
  },
  snippets: {
    list: () => ipcRenderer.invoke(CH.snipList),
    save: (input: SnippetInput) => ipcRenderer.invoke(CH.snipSave, input),
    remove: (id) => ipcRenderer.invoke(CH.snipRemove, id),
    duplicate: (id) => ipcRenderer.invoke(CH.snipDuplicate, id)
  },
  settings: {
    get: () => ipcRenderer.invoke(CH.settingsGet),
    save: (patch: Partial<Settings>) => ipcRenderer.invoke(CH.settingsSave, patch)
  },
  hosts: {
    list: () => ipcRenderer.invoke(CH.hostsList),
    forget: (hostKey) => ipcRenderer.invoke(CH.hostsForget, hostKey)
  },
  ssh: {
    list: () => ipcRenderer.invoke(CH.sshList),
    connect: (connectionId) => ipcRenderer.invoke(CH.sshConnect, connectionId),
    write: (sessionId, data) => ipcRenderer.invoke(CH.sshWrite, sessionId, data),
    resize: (sessionId, cols, rows) => ipcRenderer.invoke(CH.sshResize, sessionId, cols, rows),
    disconnect: (sessionId) => ipcRenderer.invoke(CH.sshDisconnect, sessionId),
    answerHostKey: (requestId, accept) =>
      ipcRenderer.invoke(CH.sshAnswerHostKey, requestId, accept),
    onData: (cb) => on<[string, string]>(CH.sshDataEvent, cb),
    onStatus: (cb) => on<[SessionInfo]>(CH.sshStatusEvent, cb),
    onHostKeyPrompt: (cb) => on<[HostKeyPrompt]>(CH.sshHostKeyEvent, cb)
  },
  dialog: {
    readTextFile: (title) => ipcRenderer.invoke(CH.dialogReadTextFile, title),
    saveTextFile: (suggestedName, content) =>
      ipcRenderer.invoke(CH.dialogSaveTextFile, suggestedName, content)
  },
  clipboard: {
    read: () => ipcRenderer.invoke(CH.clipboardRead),
    write: (text) => ipcRenderer.invoke(CH.clipboardWrite, text)
  },
  mcp: {
    status: () => ipcRenderer.invoke(CH.mcpStatus),
    setEnabled: (enabled) => ipcRenderer.invoke(CH.mcpSetEnabled, enabled),
    setPort: (port) => ipcRenderer.invoke(CH.mcpSetPort, port),
    token: () => ipcRenderer.invoke(CH.mcpToken),
    regenerateToken: () => ipcRenderer.invoke(CH.mcpRegenerateToken),
    answerCommand: (id, approved, autoShare) =>
      ipcRenderer.invoke(CH.mcpAnswerCommand, id, approved, autoShare),
    answerShare: (id, shared, text) => ipcRenderer.invoke(CH.mcpAnswerShare, id, shared, text),
    onCommandRequest: (cb) => on<[CommandApproval]>(CH.mcpCommandRequestEvent, cb),
    onShareRequest: (cb) => on<[ShareRequest]>(CH.mcpShareRequestEvent, cb),
    onStatus: (cb) => on<[McpStatus]>(CH.mcpStatusEvent, cb)
  },
  app: {
    notifyActivity: () => ipcRenderer.send(CH.appActivity),
    version: () => ipcRenderer.invoke(CH.appVersion),
    getLocale: () => ipcRenderer.invoke(CH.appGetLocale),
    setLocale: (locale) => ipcRenderer.invoke(CH.appSetLocale, locale)
  }
}

contextBridge.exposeInMainWorld('api', api)

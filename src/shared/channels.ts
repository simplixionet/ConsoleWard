// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/** IPC channel names — the single source of truth for main and preload. */
export const CH = {
  vaultStatus: 'vault:status',
  vaultCreate: 'vault:create',
  vaultUnlock: 'vault:unlock',
  vaultLock: 'vault:lock',
  vaultChangePassword: 'vault:changePassword',
  vaultUnlockWithRecovery: 'vault:unlockWithRecovery',
  vaultRegenerateRecovery: 'vault:regenerateRecovery',
  vaultRemoveRecovery: 'vault:removeRecovery',
  vaultLockedEvent: 'vault:locked',

  connList: 'conn:list',
  connSave: 'conn:save',
  connRemove: 'conn:remove',
  connDuplicate: 'conn:duplicate',

  keyList: 'key:list',
  keyImport: 'key:import',
  keyGenerate: 'key:generate',
  keyRename: 'key:rename',
  keyRemove: 'key:remove',

  snipList: 'snip:list',
  snipSave: 'snip:save',
  snipRemove: 'snip:remove',
  snipDuplicate: 'snip:duplicate',

  mcpSaveCommandRequestEvent: 'mcp:saveCommandRequest',
  mcpAnswerSaveCommand: 'mcp:answerSaveCommand',
  mcpUploadRequestEvent: 'mcp:uploadRequest',
  mcpAnswerUpload: 'mcp:answerUpload',

  logList: 'log:list',
  logSize: 'log:size',
  logExport: 'log:export',
  logRemove: 'log:remove',
  logPurge: 'log:purge',
  logReveal: 'log:reveal',

  settingsGet: 'settings:get',
  settingsSave: 'settings:save',

  hostsList: 'hosts:list',
  hostsForget: 'hosts:forget',

  sshList: 'ssh:list',
  sshConnect: 'ssh:connect',
  sshWrite: 'ssh:write',
  sshResize: 'ssh:resize',
  sshDisconnect: 'ssh:disconnect',
  sshAnswerHostKey: 'ssh:answerHostKey',
  sshDataEvent: 'ssh:data',
  sshStatusEvent: 'ssh:status',
  sshHostKeyEvent: 'ssh:hostKeyPrompt',

  dialogReadTextFile: 'dialog:readTextFile',
  dialogSaveTextFile: 'dialog:saveTextFile',

  clipboardRead: 'clipboard:read',
  clipboardWrite: 'clipboard:write',


  mcpStatus: 'mcp:status',
  mcpSetEnabled: 'mcp:setEnabled',
  mcpSetPort: 'mcp:setPort',
  mcpToken: 'mcp:token',
  mcpRegenerateToken: 'mcp:regenerateToken',
  mcpAnswerCommand: 'mcp:answerCommand',
  mcpAnswerShare: 'mcp:answerShare',
  mcpCommandRequestEvent: 'mcp:commandRequest',
  mcpShareRequestEvent: 'mcp:shareRequest',
  mcpStatusEvent: 'mcp:statusChanged',

  appActivity: 'app:activity',
  appVersion: 'app:version',
  appGetLocale: 'app:getLocale',
  appSetLocale: 'app:setLocale'
} as const

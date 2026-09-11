// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Types shared between the main process, the preload and the renderer.
 *
 * Invariant: the renderer NEVER receives secrets (passwords, private keys,
 * passphrases, API key) — only metadata (`ConnectionMeta`) and `has*` flags.
 */

export type AuthKind = 'password' | 'key' | 'agent'

/** Full connection definition — lives only in the main process, inside the vault. */
export interface Connection {
  id: string
  name: string
  host: string
  port: number
  username: string
  authKind: AuthKind
  /** Secrets — never leave the main process. */
  password?: string
  privateKey?: string
  passphrase?: string
  /** Path to the SSH agent socket/pipe. Empty = auto-detect. */
  agentSocket?: string
  folder?: string
  notes?: string
  createdAt: number
  updatedAt: number
}

/** Safe projection of a connection for the renderer. */
export interface ConnectionMeta {
  id: string
  name: string
  host: string
  port: number
  username: string
  authKind: AuthKind
  hasPassword: boolean
  hasPrivateKey: boolean
  hasPassphrase: boolean
  agentSocket?: string
  folder?: string
  notes?: string
  createdAt: number
  updatedAt: number
}

/**
 * Form input. Secret semantics:
 *  - `undefined` = leave unchanged
 *  - `''` = clear
 *  - anything else = set the new value
 */
export interface ConnectionInput {
  id?: string
  name: string
  host: string
  port: number
  username: string
  authKind: AuthKind
  password?: string
  privateKey?: string
  passphrase?: string
  agentSocket?: string
  folder?: string
  notes?: string
}

/**
 * Saved command or note. Unlike secrets, the body IS sent to the renderer — the
 * user has to see and edit it. On disk it is encrypted like everything else.
 */
export interface Snippet {
  id: string
  title: string
  body: string
  note?: string
  folder?: string
  kind: SnippetKind
  createdAt: number
  updatedAt: number
}

export type SnippetKind = 'command' | 'note'

export interface SnippetInput {
  id?: string
  title: string
  body: string
  note?: string
  folder?: string
  kind: SnippetKind
}

export interface KnownHost {
  /** `host:port` */
  hostKey: string
  keyType: string
  /** `SHA256:...` in OpenSSH format */
  fingerprint: string
  addedAt: number
}

export interface Settings {
  /** 0 = never lock */
  autoLockMinutes: number
  disconnectOnLock: boolean
  fontSize: number
  scrollback: number
  /**
   * Run what the AI proposes without asking, and hand back the whole output.
   *
   * The approval dialog is what this application is for, so switching it off is
   * a separate, deliberate decision with its own warnings — never a side effect
   * of enabling the gateway.
   */
  dangerousMode?: boolean
  /**
   * While dangerousMode is on, still refuse the destructive list. On by default;
   * see src/shared/dangerousCommands.ts for what it does and does not catch.
   */
  dangerousGuard?: boolean
  /** Local MCP server for AI clients. Off by default. */
  mcpEnabled?: boolean
  mcpPort?: number
  /** Reserved for phase 2 (AI assistant). */
  aiModel?: string
  aiEffort?: string
  hasAiApiKey?: boolean
}

/**
 * The file on disk is older than the one last seen for this vault — an older
 * copy was swapped in, or a backup was restored. Not a reason to refuse to open
 * it, but a reason to say that stored host fingerprints may be stale: after a
 * rollback a "server key changed" warning degrades into a plain "trust this new
 * key?" question.
 */
export interface RollbackWarning {
  expected: number
  found: number
  /** When the anchor was written (ms since epoch). */
  at: number
}

export interface VaultStatus {
  exists: boolean
  unlocked: boolean
  /** Does the vault have a recovery key? Read from the unencrypted header. */
  hasRecovery: boolean
  path: string
  /** Null until unlocked, even when nothing is wrong. */
  rollback: RollbackWarning | null
}

export type SessionStatus =
  | 'connecting'
  | 'authenticating'
  | 'ready'
  | 'closed'
  | 'error'

export interface SessionInfo {
  id: string
  connectionId: string
  title: string
  status: SessionStatus
  /** Set on `error` / `closed`. */
  message?: string
}

export interface HostKeyPrompt {
  requestId: string
  host: string
  port: number
  keyType: string
  fingerprint: string
  /** true = the key differs from the stored one (warning!) */
  changed: boolean
  knownFingerprint?: string
}

/* ------------------------------------------------------------------- MCP */

export interface McpStatus {
  running: boolean
  port: number
  enabled: boolean
  hasToken: boolean
  error: string | null
}

/** AI request to run a command — waits for a human decision. */
export interface CommandApproval {
  id: string
  sessionId: string
  sessionName: string
  command: string
  /** Control characters made visible, so an extra line cannot hide in it. */
  commandVisualized: string
  reason: string
}

/** AI request for output — the human picks exactly what gets sent. */
export interface ShareRequest {
  id: string
  sessionId: string
  sessionName: string
  reason: string
  origin: 'read_terminal' | 'command_output'
  /** Pre-filled text (ANSI sequences already stripped). */
  text: string
  /**
   * Auto-share was ticked but the output tripped the secret detector, so the
   * dialog opened anyway. The dialog must say so — an unexplained override
   * reads as a broken checkbox. It also tells the approval queue to raise the
   * window: the human was promised no dialog here, so an unnoticed one would be
   * denied on their behalf by the timeout.
   */
  autoShareOverridden?: boolean
}

/** IPC result envelope — no exceptions cross the process boundary. */
export type Result<T> = { ok: true; value: T } | { ok: false; error: string }

export interface AppApi {
  vault: {
    status(): Promise<Result<VaultStatus>>
    /** Returns the generated recovery key — show it to the user, it is stored nowhere. */
    create(masterPassword: string): Promise<Result<string>>
    unlock(masterPassword: string): Promise<Result<null>>
    /**
     * Unlocks with a recovery key and sets a new master password. Rotates the
     * data key, so **the recovery key used here stops working**. Returns a new
     * one — show it to the user, it is stored nowhere.
     */
    unlockWithRecovery(recoveryKey: string, newPassword: string): Promise<Result<string>>
    lock(): Promise<Result<null>>
    /**
     * Rotates the data key. Returns a new recovery key if the vault had one,
     * else `null`; the old one cannot be rebuilt. **Show it to the user** —
     * discarding it silently removes their only rescue for a forgotten password.
     */
    changePassword(oldPw: string, newPw: string): Promise<Result<string | null>>
    /** The password is mandatory — this issues a key that opens the vault forever. */
    regenerateRecoveryKey(password: string): Promise<Result<string>>
    /** The password is mandatory. Rotates the data key, so revocation really takes effect. */
    removeRecoveryKey(password: string): Promise<Result<null>>
    onLocked(cb: () => void): () => void
  }
  connections: {
    list(): Promise<Result<ConnectionMeta[]>>
    save(input: ConnectionInput): Promise<Result<ConnectionMeta>>
    remove(id: string): Promise<Result<null>>
    duplicate(id: string): Promise<Result<ConnectionMeta>>
  }
  snippets: {
    list(): Promise<Result<Snippet[]>>
    save(input: SnippetInput): Promise<Result<Snippet>>
    remove(id: string): Promise<Result<null>>
    duplicate(id: string): Promise<Result<Snippet>>
  }
  settings: {
    get(): Promise<Result<Settings>>
    save(patch: Partial<Settings>): Promise<Result<Settings>>
  }
  hosts: {
    list(): Promise<Result<KnownHost[]>>
    forget(hostKey: string): Promise<Result<null>>
  }
  ssh: {
    /** Sessions the main process holds — the list is rebuilt from these after unlock. */
    list(): Promise<Result<SessionInfo[]>>
    connect(connectionId: string): Promise<Result<string>>
    write(sessionId: string, data: string): Promise<Result<null>>
    resize(sessionId: string, cols: number, rows: number): Promise<Result<null>>
    disconnect(sessionId: string): Promise<Result<null>>
    answerHostKey(requestId: string, accept: boolean): Promise<Result<null>>
    onData(cb: (sessionId: string, data: string) => void): () => void
    onStatus(cb: (info: SessionInfo) => void): () => void
    onHostKeyPrompt(cb: (prompt: HostKeyPrompt) => void): () => void
  }
  dialog: {
    readTextFile(title: string): Promise<Result<{ name: string; content: string } | null>>
    /** null when cancelled. */
    saveTextFile(
      suggestedName: string,
      content: string
    ): Promise<Result<string | null>>
  }
  clipboard: {
    read(): Promise<Result<string>>
    write(text: string): Promise<Result<null>>
  }
  mcp: {
    status(): Promise<Result<McpStatus>>
    setEnabled(enabled: boolean): Promise<Result<McpStatus>>
    setPort(port: number): Promise<Result<McpStatus>>
    token(): Promise<Result<string | null>>
    regenerateToken(): Promise<Result<string>>
    answerCommand(id: string, approved: boolean, autoShare: boolean): Promise<Result<null>>
    /** `text` is what actually gets sent. */
    answerShare(id: string, shared: boolean, text: string): Promise<Result<null>>
    onCommandRequest(cb: (req: CommandApproval) => void): () => void
    onShareRequest(cb: (req: ShareRequest) => void): () => void
    onStatus(cb: (status: McpStatus) => void): () => void
  }
  app: {
    notifyActivity(): void
    version(): Promise<Result<string>>
    /** Selected locale; derived from the system locale on first run. */
    getLocale(): Promise<Result<string>>
    setLocale(locale: string): Promise<Result<string>>
  }
}

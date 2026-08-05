// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Typy sdílené mezi hlavním procesem, preloadem a rendererem.
 *
 * Zásada: renderer NIKDY nedostane tajemství (hesla, privátní klíče, passphrase,
 * API klíč). Dostává jen metadata (`ConnectionMeta`) a příznaky `has*`.
 */

export type AuthKind = 'password' | 'key' | 'agent'

/** Plná definice připojení – žije pouze v hlavním procesu, uvnitř trezoru. */
export interface Connection {
  id: string
  name: string
  host: string
  port: number
  username: string
  authKind: AuthKind
  /** Tajemství – nikdy neopouští hlavní proces. */
  password?: string
  privateKey?: string
  passphrase?: string
  /** Cesta k socketu/pipe SSH agenta. Prázdné = automatická detekce. */
  agentSocket?: string
  folder?: string
  notes?: string
  createdAt: number
  updatedAt: number
}

/** Bezpečná projekce připojení pro renderer. */
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
 * Vstup z formuláře.
 *
 * Sémantika tajemství:
 *  - `undefined` = ponechat beze změny
 *  - `''` (prázdný řetězec) = smazat
 *  - jinak = nastavit novou hodnotu
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
 * Uložený příkaz nebo poznámka.
 *
 * Na rozdíl od hesel se obsah do rendereru posílá – uživatel ho musí vidět
 * a upravovat. V souboru trezoru je ale šifrovaný stejně jako zbytek.
 */
export interface Snippet {
  id: string
  title: string
  /** Text příkazu nebo poznámky. */
  body: string
  /** Volitelný popis / kontext. */
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
  /** `SHA256:...` ve formátu OpenSSH */
  fingerprint: string
  addedAt: number
}

export interface Settings {
  /** 0 = nikdy nezamykat */
  autoLockMinutes: number
  /** Ukončit SSH relace při zamčení trezoru. */
  disconnectOnLock: boolean
  fontSize: number
  scrollback: number
  /** Lokální MCP server pro AI klienty. Ve výchozím stavu vypnutý. */
  mcpEnabled?: boolean
  mcpPort?: number
  /** Rezervováno pro 2. fázi (AI asistent). */
  aiModel?: string
  aiEffort?: string
  hasAiApiKey?: boolean
}

export interface VaultStatus {
  exists: boolean
  unlocked: boolean
  /** Je pro trezor nastavený obnovovací klíč? Čte se z nešifrované hlavičky. */
  hasRecovery: boolean
  path: string
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
  /** Vyplněno při `error` / `closed`. */
  message?: string
}

export interface HostKeyPrompt {
  requestId: string
  host: string
  port: number
  keyType: string
  fingerprint: string
  /** true = klíč se změnil oproti uloženému (varování!) */
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

/** Žádost AI o spuštění příkazu – čeká na rozhodnutí člověka. */
export interface CommandApproval {
  id: string
  sessionId: string
  sessionName: string
  command: string
  /** Znění se zviditelněnými řídicími znaky – aby v něm nešel schovat řádek navíc. */
  commandVisualized: string
  reason: string
}

/** Žádost AI o výstup – člověk vybere, co přesně se pošle. */
export interface ShareRequest {
  id: string
  sessionId: string
  sessionName: string
  reason: string
  origin: 'read_terminal' | 'command_output'
  /** Předvyplněný text (už bez ANSI sekvencí). */
  text: string
  /**
   * The human ticked auto-share, but the output tripped the secret detector and
   * the dialog opened anyway. The dialog must say so — an override it cannot
   * explain reads as the checkbox being broken. It also tells the approval
   * queue to raise the window: on this path the human was promised no dialog,
   * so an unnoticed one would be denied on their behalf by the timeout.
   */
  autoShareOverridden?: boolean
}

/** Obálka pro výsledky IPC – žádné výjimky přes hranici procesu. */
export type Result<T> = { ok: true; value: T } | { ok: false; error: string }

export interface AppApi {
  vault: {
    status(): Promise<Result<VaultStatus>>
    /** Vrací vygenerovaný obnovovací klíč – zobraz ho uživateli, uložený nikde není. */
    create(masterPassword: string): Promise<Result<string>>
    unlock(masterPassword: string): Promise<Result<null>>
    /**
     * Odemkne obnovovacím klíčem a zároveň nastaví nové hlavní heslo.
     *
     * Rotuje datový klíč, takže **použitý obnovovací klíč přestane platit**.
     * Vrací nový — zobraz ho uživateli, uložený nikde není.
     */
    unlockWithRecovery(recoveryKey: string, newPassword: string): Promise<Result<string>>
    lock(): Promise<Result<null>>
    /**
     * Změní hlavní heslo a rotuje datový klíč.
     *
     * Vrací nový obnovovací klíč, pokud trezor nějaký měl, jinak `null`. Starý
     * pod novým datovým klíčem postavit nejde — neukládá se nikde. **Zobraz
     * návratovou hodnotu uživateli**; zahodit ji znamená připravit ho o jedinou
     * záchranu pro zapomenuté heslo, aniž by se to dozvěděl.
     */
    changePassword(oldPw: string, newPw: string): Promise<Result<string | null>>
    /** Heslo je povinné — operace vydává klíč, který trezor otevírá navždy. */
    regenerateRecoveryKey(password: string): Promise<Result<string>>
    /** Heslo je povinné. Rotuje datový klíč, takže odvolání skutečně platí. */
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
    /** Vrací cestu k uloženému souboru, nebo null při zrušení. */
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
    /** Odpověď na dialog se schválením příkazu. */
    answerCommand(id: string, approved: boolean, autoShare: boolean): Promise<Result<null>>
    /** Odpověď na dialog s výběrem výstupu; `text` je to, co se skutečně pošle. */
    answerShare(id: string, shared: boolean, text: string): Promise<Result<null>>
    onCommandRequest(cb: (req: CommandApproval) => void): () => void
    onShareRequest(cb: (req: ShareRequest) => void): () => void
    onStatus(cb: (status: McpStatus) => void): () => void
  }
  app: {
    notifyActivity(): void
    version(): Promise<Result<string>>
    /** Zvolený jazyk; při prvním spuštění odvozený z jazyka systému. */
    getLocale(): Promise<Result<string>>
    setLocale(locale: string): Promise<Result<string>>
  }
}

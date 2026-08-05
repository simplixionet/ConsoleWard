// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Správa SSH relací.
 *
 * Bezpečnostní body:
 *  - tajemství (heslo/klíč) se čtou z trezoru až tady, renderer je nikdy nevidí
 *  - host key se ověřuje proti uloženým otiskům (TOFU); změna otisku = tvrdé odmítnutí
 *    dokud ji uživatel výslovně nepotvrdí
 */

import { createHash, randomUUID } from 'node:crypto'
import { Client } from 'ssh2'
import type { ClientChannel } from 'ssh2'
import type { Connection, HostKeyPrompt, SessionInfo, SessionStatus } from '../shared/types'
import { vault } from './vault'
import { cleanTerminalText, tailLines, visualizeControlChars } from './ansi'
import { appError, t } from './i18n'

/** Kolik bajtů výstupu držet v paměti na relaci (podklad pro AI ve 2. fázi). */
const SCROLL_MEMORY_BYTES = 256 * 1024

/** Strop výstupu jednoho MCP příkazu. */
const RUN_OUTPUT_BYTES = 128 * 1024

/** Tvrdý strop na dobu běhu jednoho MCP příkazu. */
const RUN_TIMEOUT_MS = 30_000

export interface RunOptions {
  timeoutMs?: number
  maxBytes?: number
}

/** Výsledek jednoho příkazu z MCP. */
export interface RunResult {
  /** stdout; stderr follows under a label when the command wrote any. */
  output: string
  /** Exit status from the server. null when it died on a signal or reported none. */
  exitCode: number | null
  /** Signal name (`SIGKILL`) when the command was killed rather than exiting. */
  signal: string | null
  /** The time limit fired; the channel was closed and the command may still run. */
  timedOut: boolean
  /** Output passed the byte cap; only its beginning is present. */
  truncated: boolean
}

/** The projection of a session that `list_sessions` hands to the model. */
export interface ModelSession {
  id: string
  name: string
  status: SessionStatus
}

interface Session {
  id: string
  connectionId: string
  /** What the human reads: the tab, the status bar and `sessionName` in both dialogs. */
  title: string
  /** What the model is told this session is called; never a host, never a username. */
  modelName: string
  client: Client
  stream: ClientChannel | null
  status: SessionStatus
  message?: string
  buffer: Buffer[]
  bufferBytes: number
  /** Běží právě příkaz z MCP? Brána drží jeden příkaz na relaci. */
  running: boolean
}

type Emitter = {
  data: (sessionId: string, base64: string) => void
  status: (info: SessionInfo) => void
  hostKeyPrompt: (prompt: HostKeyPrompt) => void
}

class SshManager {
  private sessions = new Map<string, Session>()
  /** connectionId -> placeholder name for a connection with none; see modelNameFor. */
  private aliases = new Map<string, string>()
  private pendingHostKeys = new Map<string, (accept: boolean) => void>()
  private emit: Emitter | null = null

  bind(emit: Emitter): void {
    this.emit = emit
  }

  list(): SessionInfo[] {
    return [...this.sessions.values()].map(toInfo)
  }

  /**
   * The sessions as the model is allowed to see them.
   *
   * A separate shape from `list()`, not a projection of it. `SessionInfo` is the
   * human's view and it will grow — the day someone adds a host to it so two
   * tabs with the same name can be told apart, a `list_sessions` that mapped
   * over `list()` would ship the address the tool promises to withhold, with no
   * change anywhere near mcp.ts. Here every published field is written out, so
   * widening what the model sees is a decision rather than a side effect.
   */
  listForModel(): ModelSession[] {
    return [...this.sessions.values()].map((s) => ({
      id: s.id,
      name: s.modelName,
      status: s.status
    }))
  }

  /** Existuje relace a je připravená přijímat vstup? */
  isReady(sessionId: string): boolean {
    return this.sessions.get(sessionId)?.status === 'ready'
  }

  /** The human's label. Feeds `sessionName` in the dialogs — never given to the model. */
  title(sessionId: string): string {
    return this.sessions.get(sessionId)?.title ?? sessionId
  }

  /** Poslední výstup relace jako čitelný text (bez ANSI sekvencí). */
  readText(sessionId: string, maxLines = 200): string {
    const s = this.sessions.get(sessionId)
    if (!s) throw appError('error.sessionNotFound')
    return tailLines(cleanTerminalText(Buffer.concat(s.buffer).toString('utf8')), maxLines)
  }

  /**
   * Runs an MCP command in its own `exec` channel on the existing connection.
   *
   * Deliberately NOT the interactive shell. Writing into the shell put the AI
   * and the human on one byte stream: the PTY echoes every keystroke back, so
   * the capture collected what the human typed — a sudo password included — and
   * offered it to the model. The shell also gives no end-of-command signal, so
   * the old code guessed from 900 ms of silence and reported the fragment of a
   * paused command as its complete output.
   *
   * A separate channel has its own stream, its own end, and a real exit status.
   * The command text is sent verbatim: there is no PTY here, so no ICRNL, and
   * rewriting the bytes the human approved would now be what changes them.
   */
  async runOnce(sessionId: string, command: string, opts: RunOptions = {}): Promise<RunResult> {
    const s = this.sessions.get(sessionId)
    if (!s || s.status !== 'ready') throw appError('error.sessionNotReady')
    if (s.running) throw appError('error.commandRunning')

    s.running = true
    this.echo(s, `${t('term.runHeader')}\r\n$ ${visualizeControlChars(command)}`)
    try {
      const result = await runExec(s.client, command, opts)
      this.echo(s, `${result.output}\r\n${describeExit(result)}`)
      return result
    } finally {
      s.running = false
    }
  }

  /**
   * Mirrors an AI command run into the visible terminal.
   *
   * The command no longer runs in the human's shell, so without this it leaves
   * no trace anywhere they look — and this app exists to be looked at. The text
   * goes to the display only, never through appendBuffer: putting it in the
   * scrollback would let the model read its own output back through
   * `read_terminal` as if the shell had produced it.
   */
  private echo(session: Session, text: string): void {
    const block = `\r\n${text.replace(/\n/g, '\r\n')}\r\n`
    this.emit?.data(session.id, Buffer.from(block, 'utf8').toString('base64'))
  }

  async connect(connectionId: string): Promise<string> {
    const data = vault.read()
    const conn = data.connections.find((c) => c.id === connectionId)
    if (!conn) throw appError('error.connNotFound')

    const id = randomUUID()
    const client = new Client()
    const session: Session = {
      id,
      connectionId,
      title: conn.name || `${conn.username}@${conn.host}`,
      modelName: modelNameFor(conn, this.aliases),
      client,
      stream: null,
      status: 'connecting',
      buffer: [],
      bufferBytes: 0,
      running: false
    }
    this.sessions.set(id, session)
    this.pushStatus(session)

    client.on('ready', () => {
      this.setStatus(session, 'authenticating')
      client.shell({ term: 'xterm-256color', cols: 80, rows: 24 }, (err, stream) => {
        if (err) {
          this.setStatus(session, 'error', t('error.shellFailed', { message: err.message }))
          client.end()
          return
        }
        session.stream = stream
        this.setStatus(session, 'ready')

        stream.on('data', (chunk: Buffer) => {
          this.appendBuffer(session, chunk)
          this.emit?.data(id, chunk.toString('base64'))
        })
        stream.stderr?.on('data', (chunk: Buffer) => {
          this.appendBuffer(session, chunk)
          this.emit?.data(id, chunk.toString('base64'))
        })
        stream.on('close', () => {
          this.setStatus(session, 'closed', t('error.sessionEnded'))
          client.end()
        })
      })
    })

    client.on('keyboard-interactive', (_name, _instr, _lang, prompts, finish) => {
      // Many servers deliver the password through keyboard-interactive rather
      // than `password`, so this path has to answer — but only for a prompt
      // that is actually a password prompt.
      //
      // It used to answer *every* prompt with the stored password:
      // `finish(prompts.map(() => conn.password))`. Prompt text, the echo flag
      // and the prompt count all come from the server, so a hostile or
      // compromised host could ask "Enter your GitHub token:" and be handed the
      // account password. A second round could ask again and get it again.
      //
      // Now: exactly one prompt, and it must have echo off, which is how a
      // server marks a field whose input should not be displayed. Anything else
      // — a second factor, an OTP, a multi-question round — is answered with
      // nothing, and authentication fails visibly rather than leaking.
      const isSinglePasswordPrompt = prompts.length === 1 && prompts[0]?.echo === false

      if (conn.authKind === 'password' && conn.password && isSinglePasswordPrompt) {
        finish([conn.password])
      } else {
        finish([])
      }
    })

    client.on('error', (err: Error & { level?: string }) => {
      const msg =
        err.level === 'client-authentication'
          ? t('error.authFailed')
          : err.message
      this.setStatus(session, 'error', msg)
    })

    client.on('close', () => {
      if (session.status !== 'error') this.setStatus(session, 'closed')
      this.sessions.delete(id)
    })

    try {
      client.connect(this.buildConfig(conn, session))
    } catch (err) {
      this.setStatus(session, 'error', (err as Error).message)
      this.sessions.delete(id)
      throw err
    }

    return id
  }

  write(sessionId: string, data: string): void {
    const s = this.sessions.get(sessionId)
    if (!s?.stream) throw appError('error.sessionNotReady')
    s.stream.write(Buffer.from(data, 'utf8'))
  }

  resize(sessionId: string, cols: number, rows: number): void {
    const s = this.sessions.get(sessionId)
    if (!s?.stream) return
    s.stream.setWindow(rows, cols, 0, 0)
  }

  disconnect(sessionId: string): void {
    const s = this.sessions.get(sessionId)
    if (!s) return
    s.stream?.end()
    s.client.end()
    // Pojistka, kdyby server nereagoval na korektní ukončení.
    setTimeout(() => s.client.destroy(), 1500)
  }

  disconnectAll(): void {
    for (const id of [...this.sessions.keys()]) this.disconnect(id)
  }

  answerHostKey(requestId: string, accept: boolean): void {
    const resolve = this.pendingHostKeys.get(requestId)
    if (!resolve) return
    this.pendingHostKeys.delete(requestId)
    resolve(accept)
  }

  private buildConfig(conn: Connection, session: Session) {
    const base = {
      host: conn.host,
      port: conn.port || 22,
      username: conn.username,
      // ssh2 starts readyTimeout on socket connect and clears it only on
      // `ready`, so it runs *while the host-key dialog is open*. At the old
      // 25 s the real decision budget was 25 seconds, not the 120 the prompt
      // allows — and a user who took the time to verify a fingerprint out of
      // band was punished for it. Long enough now that the dialog's own
      // timeout is the one that fires.
      readyTimeout: 150_000,
      keepaliveInterval: 25_000,
      keepaliveCountMax: 4,
      hostVerifier: (key: Buffer, cb: (valid: boolean) => void) => {
        this.verifyHostKey(conn, key, session)
          .then(cb)
          .catch((err) => {
            this.setStatus(session, 'error', (err as Error).message)
            cb(false)
          })
      }
    }

    switch (conn.authKind) {
      case 'password':
        return { ...base, password: conn.password ?? '', tryKeyboard: true }
      case 'key':
        return {
          ...base,
          privateKey: conn.privateKey ?? '',
          passphrase: conn.passphrase || undefined
        }
      case 'agent':
        return { ...base, agent: resolveAgent(conn.agentSocket) }
    }
  }

  private async verifyHostKey(conn: Connection, key: Buffer, session: Session): Promise<boolean> {
    const fingerprint = sha256Fingerprint(key)
    const keyType = parseKeyType(key)
    const hostKey = `${conn.host}:${conn.port || 22}`

    const data = vault.read()
    const known = data.knownHosts.find((h) => h.hostKey === hostKey)

    if (known && known.fingerprint === fingerprint) return true

    const requestId = randomUUID()
    const prompt: HostKeyPrompt = {
      requestId,
      host: conn.host,
      port: conn.port || 22,
      keyType,
      fingerprint,
      changed: Boolean(known),
      knownFingerprint: known?.fingerprint
    }

    const accepted = await new Promise<boolean>((resolve) => {
      this.pendingHostKeys.set(requestId, resolve)
      this.emit?.hostKeyPrompt(prompt)
      // Bez odpovědi do 2 minut raději odmítnout.
      setTimeout(() => {
        if (this.pendingHostKeys.delete(requestId)) resolve(false)
      }, 120_000)
    })

    if (!accepted) return false

    // Trust is only recorded if the answer can still be acted on. If the
    // connection died while the dialog was open — readyTimeout, a dropped
    // socket, the user quitting — persisting here would grant permanent trust
    // to a key whose session never completed. The user would see a timeout
    // error, have no idea trust was granted, and the *next* connect would
    // succeed silently with no changed-key warning. That turns careful
    // out-of-band verification into a silent MITM acceptance.
    if (session.status === 'error' || session.status === 'closed') return false

    await vault.mutate((d) => {
      const idx = d.knownHosts.findIndex((h) => h.hostKey === hostKey)
      const entry = { hostKey, keyType, fingerprint, addedAt: Date.now() }
      if (idx >= 0) d.knownHosts[idx] = entry
      else d.knownHosts.push(entry)
    })
    return true
  }

  private appendBuffer(session: Session, chunk: Buffer): void {
    session.buffer.push(chunk)
    session.bufferBytes += chunk.length
    while (session.bufferBytes > SCROLL_MEMORY_BYTES && session.buffer.length > 1) {
      const dropped = session.buffer.shift()!
      session.bufferBytes -= dropped.length
    }
  }

  private setStatus(session: Session, status: SessionStatus, message?: string): void {
    session.status = status
    if (message) session.message = message
    this.pushStatus(session)
  }

  private pushStatus(session: Session): void {
    this.emit?.status(toInfo(session))
  }
}

function toInfo(s: Session): SessionInfo {
  return {
    id: s.id,
    connectionId: s.connectionId,
    title: s.title,
    status: s.status,
    message: s.message
  }
}

/**
 * The name the model is given for a session.
 *
 * `title` cannot be it. That falls back to `username@host` for a connection with
 * no name, while `list_sessions` promises in its own description that the
 * address, the port and the username are withheld — so such a connection made
 * the tool lie. Weakening the title instead would be worse: it is what the human
 * reads on the tab and in the approval dialog, and someone deciding whether to
 * let an AI run a command has to be able to tell which server it lands on.
 * "Session 1" and "Session 2" in that dialog is a security regression, not a fix.
 *
 * So the two split here. The human keeps `username@host`; the model gets the
 * name the owner typed, or a placeholder that says nothing about the machine.
 *
 * The placeholder is keyed by connection, not by session, so reconnecting the
 * same server hands the model the same name back and whatever it noted about
 * which box is which does not silently point somewhere else. It is not
 * persisted: after a restart the numbering starts again, which is safe because
 * the session ids are fresh too and any client has to re-read `list_sessions`.
 *
 * English, never translated, for the reason RUN_ERRORS gives in mcp.ts: this is
 * a machine interface, and a Czech user must not ship Czech identifiers to an
 * English-speaking tool that would then change under it at the next language
 * switch.
 */
export function modelNameFor(
  conn: Pick<Connection, 'id' | 'name'>,
  aliases: Map<string, string>
): string {
  const named = conn.name?.trim()
  if (named) return named
  const existing = aliases.get(conn.id)
  if (existing) return existing
  const alias = `Session ${aliases.size + 1}`
  aliases.set(conn.id, alias)
  return alias
}

/**
 * Runs a command in its own `exec` channel and returns what arrived in it.
 *
 * Takes the client rather than a session on purpose: this reads exactly one
 * channel, the one `exec` hands back, and has no way to reach the interactive
 * stream even by accident.
 *
 * No PTY is requested. With one, the kernel line discipline folds stderr into
 * stdout, escape sequences come back, and `sudo` would sit at a password prompt
 * that neither the model nor the human has any channel to answer — it would
 * hang for the full time limit with a half-read prompt in the output. Without
 * one, `sudo` fails immediately with `a terminal is required` on stderr and a
 * real exit status, which is information rather than a stall. `allowHalfOpen`
 * is left at ssh2's default of true: setting it false makes `end()` send
 * CHANNEL_CLOSE and kill the command we just started.
 */
export function runExec(
  client: Pick<Client, 'exec'>,
  command: string,
  { timeoutMs = RUN_TIMEOUT_MS, maxBytes = RUN_OUTPUT_BYTES }: RunOptions = {}
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const out: Buffer[] = []
    const err: Buffer[] = []
    let bytes = 0
    let truncated = false
    let exitCode: number | null = null
    let signal: string | null = null
    let timedOut = false
    let settled = false
    let channel: ClientChannel | null = null

    // Keep the head, not the tail. The start of the output is what the human
    // reads first, and a server that floods must not be able to push it off the
    // top. Chunks past the cap are dropped rather than refused — refusing would
    // stall the channel, and the exit status with it.
    const collect =
      (into: Buffer[]) =>
      (chunk: Buffer): void => {
        const room = maxBytes - bytes
        if (room <= 0) {
          truncated = true
          return
        }
        if (chunk.length > room) {
          truncated = true
          into.push(chunk.subarray(0, room))
          bytes = maxBytes
          return
        }
        into.push(chunk)
        bytes += chunk.length
      }

    const finish = (): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ output: joinStreams(out, err), exitCode, signal, timedOut, truncated })
    }

    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(appError('error.execFailed', { message: error.message }))
    }

    const timer = setTimeout(() => {
      timedOut = true
      // close() sends CHANNEL_CLOSE. sshd normally hangs up the process, but
      // nothing guarantees it, so the result says the command may still run
      // rather than claiming it finished.
      channel?.close()
      finish()
    }, timeoutMs)

    try {
      client.exec(command, { pty: false }, (error, chan) => {
        if (error) {
          fail(error)
          return
        }
        if (settled) {
          // The time limit won the race; do not leave the channel open.
          chan.close()
          return
        }
        channel = chan
        chan.on('data', collect(out))
        chan.stderr.on('data', collect(err))
        chan.on('exit', (code: number | null, sig?: string) => {
          exitCode = typeof code === 'number' ? code : null
          signal = typeof sig === 'string' ? sig : null
        })
        // `close` is the end, not `exit`: exit-status is optional in the SSH
        // spec and can arrive before the last data packet.
        chan.on('close', finish)
        // A Duplex with no error listener takes the main process down. Whatever
        // we already collected is still worth returning.
        chan.on('error', finish)
        chan.stderr.on('error', finish)
        // No stdin. Anything reading it gets EOF at once instead of waiting for
        // input this channel has no way to deliver.
        chan.end()
      })
    } catch (error) {
      // ssh2 throws synchronously when the socket is already gone.
      fail(error as Error)
    }
  })
}

/**
 * Joins stdout and stderr into one text for both the human and the model.
 *
 * They stay separate. stdout and stderr are two independent SSH data types with
 * no ordering guarantee between them, so interleaving would produce a
 * transcript that looks authoritative and is not. The label matters too:
 * `permission denied` on stderr is a different fact from the same words on
 * stdout, and both the human deciding what to share and the model reading it
 * have to be able to tell.
 */
function joinStreams(out: Buffer[], err: Buffer[]): string {
  const stdout = cleanTerminalText(Buffer.concat(out).toString('utf8'))
  const stderr = cleanTerminalText(Buffer.concat(err).toString('utf8'))
  if (!stderr.trim()) return stdout
  const head = stdout.trim() ? stdout.replace(/\n?$/, '\n') : ''
  return `${head}--- stderr ---\n${stderr}`
}

/** Jednořádkový závěr běhu pro viditelný terminál. */
function describeExit(result: RunResult): string {
  if (result.timedOut) return t('term.runTimedOut')
  if (result.signal) return t('term.runSignal', { signal: result.signal })
  return t('term.runExit', { code: result.exitCode ?? -1 })
}

/** Otisk ve formátu OpenSSH: `SHA256:<base64 bez zarovnání>`. */
export function sha256Fingerprint(key: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '')
}

/** Typ klíče je první SSH string v blobu (délka 4 B + data). */
export function parseKeyType(key: Buffer): string {
  try {
    const len = key.readUInt32BE(0)
    if (len > 0 && len < 64 && key.length >= 4 + len) {
      return key.subarray(4, 4 + len).toString('ascii')
    }
  } catch {
    /* ignorujeme – jen popisek */
  }
  return 'neznámý'
}

function resolveAgent(configured?: string): string {
  if (configured && configured.trim()) return configured.trim()
  if (process.env.SSH_AUTH_SOCK) return process.env.SSH_AUTH_SOCK
  // Windows: Pageant (PuTTY). Alternativa: \\.\pipe\openssh-ssh-agent
  return process.platform === 'win32' ? 'pageant' : ''
}

export const ssh = new SshManager()

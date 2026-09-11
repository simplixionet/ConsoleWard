// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * SSH session management. Secrets (password/key) are read from the vault only
 * here — the renderer never sees them. Host keys are checked against stored
 * fingerprints (TOFU); a changed fingerprint is refused until the user
 * explicitly confirms it.
 */

import { createHash, randomUUID } from 'node:crypto'
import { Client } from 'ssh2'
import type { ClientChannel, SFTPWrapper } from 'ssh2'
import type { Connection, HostKeyPrompt, SessionInfo, SessionStatus } from '../shared/types'
import { vault } from './vault'
import { logs, type LogWriter } from './logs'
import { aiLog } from './aiLog'
import { cleanTerminalText, tailLines, visualizeControlChars } from './ansi'
import { appError, t } from './i18n'

const SCROLL_MEMORY_BYTES = 256 * 1024

const RUN_OUTPUT_BYTES = 128 * 1024

/**
 * An upload is a whole file carried through a JSON tool call, so it is bounded
 * twice over: once here, and once by the MCP request cap. A megabyte covers a
 * config file, a unit file or a script, which is what this is for.
 */
export const UPLOAD_MAX_BYTES = 1024 * 1024

/** Extra budget for stderr, so a stdout flood cannot drop the line explaining a failure. */
const STDERR_RESERVE_BYTES = 16 * 1024

const RUN_TIMEOUT_MS = 30_000

/** Grace period after `exit` for trailing data, short enough not to read as a hang. */
const EXIT_GRACE_MS = 250

/** Cap on peer-supplied error text, so it cannot run away with the status bar. */
const SERVER_MESSAGE_CHARS = 200

/**
 * Peer-chosen text on its way into our own error UI. ssh2's `err.message`
 * carries the peer's SSH_MSG_DISCONNECT description, emitted *before* key
 * exchange finishes — an on-path attacker who merely accepts the TCP connection
 * can put words on screen right before the host-key prompt asks for a trust
 * decision. Clean it, flatten newlines it could use to fake structure, and cap
 * it; the caller attributes it to the peer via `error.sshReported`.
 */
export function serverText(raw: string): string {
  const cleaned = cleanTerminalText(raw).replace(/\s+/g, ' ').trim()
  if (!cleaned) return t('error.noDetail')
  return cleaned.length > SERVER_MESSAGE_CHARS
    ? cleaned.slice(0, SERVER_MESSAGE_CHARS) + '…'
    : cleaned
}

export interface RunOptions {
  timeoutMs?: number
  maxBytes?: number
}

export interface RunResult {
  /** stdout; stderr follows under a label when the command wrote any. */
  output: string
  exitCode: number | null
  signal: string | null
  /** The time limit fired; the channel was closed and the command may still run. */
  timedOut: boolean
  /** Output hit the byte cap; only its head is present. */
  truncated: boolean
}

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
  /** An MCP command is in flight; the gate allows one per session. */
  running: boolean
  /** The encrypted transcript, if this connection writes one. */
  log: LogWriter | null
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
   * The sessions as the model is allowed to see them. A separate shape from
   * `list()`, not a projection: `SessionInfo` is the human's view and it will
   * grow, and mapping over it would ship whatever gets added there — a host,
   * say — to the model, with no change anywhere near mcp.ts.
   */
  listForModel(): ModelSession[] {
    return [...this.sessions.values()].map((s) => ({
      id: s.id,
      name: s.modelName,
      status: s.status
    }))
  }

  isReady(sessionId: string): boolean {
    return this.sessions.get(sessionId)?.status === 'ready'
  }

  /** The human's label. Feeds `sessionName` in the dialogs — never given to the model. */
  title(sessionId: string): string {
    return this.sessions.get(sessionId)?.title ?? sessionId
  }

  readText(sessionId: string, maxLines = 200): string {
    const s = this.sessions.get(sessionId)
    if (!s) throw appError('error.sessionNotFound')
    return tailLines(cleanTerminalText(Buffer.concat(s.buffer).toString('utf8')), maxLines)
  }

  /**
   * Runs an MCP command in its own `exec` channel, deliberately NOT the
   * interactive shell: that PTY echoes every keystroke, so the capture would
   * collect what the human typed — a sudo password included — and offer it to
   * the model, and it gives no end-of-command signal. The command text is sent
   * verbatim; with no PTY there is no ICRNL, and rewriting the approved bytes
   * would itself be the tampering.
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
   * Mirrors an AI command run into the visible terminal, its only trace. Display
   * only, never through appendBuffer: from the scrollback the model could read
   * its own output back via `read_terminal` as if the shell had produced it.
   */
  private echo(session: Session, text: string): void {
    const block = `\r\n${text.replace(/\n/g, '\r\n')}\r\n`
    this.emit?.data(session.id, Buffer.from(block, 'utf8').toString('base64'))
    session.log?.append(block)
  }

  /**
   * Opens the transcript for a session, if this connection writes one.
   *
   * The key is resolved here and held by the writer: the session may outlive a
   * vault lock, and a write path that had to read the vault would stop
   * recording at exactly the moment a record matters most.
   *
   * A failure here is logged and dropped. Refusing to connect because a log
   * could not be opened would make logging a reason sessions fail.
   */
  private async openTranscript(
    session: Session,
    conn: Connection,
    settings: { sessionLogs?: boolean }
  ): Promise<void> {
    if (!logs.configured) return
    if (settings.sessionLogs === false) return
    if (conn.logTranscript === false) return
    try {
      const writer = await logs.open('transcript', session.id, session.title)
      // The session can end while the file is being created.
      if (this.sessions.has(session.id)) session.log = writer
      else await writer.close()
    } catch (err) {
      console.warn('logs: transcript not started', err)
    }
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
      running: false,
      log: null
    }
    this.sessions.set(id, session)
    this.pushStatus(session)
    void this.openTranscript(session, conn, data.settings)

    client.on('ready', () => {
      this.setStatus(session, 'authenticating')
      client.shell({ term: 'xterm-256color', cols: 80, rows: 24 }, (err, stream) => {
        if (err) {
          this.setStatus(
            session,
            'error',
            t('error.shellFailed', { message: serverText(err.message) })
          )
          client.end()
          return
        }
        session.stream = stream
        this.setStatus(session, 'ready')

        stream.on('data', (chunk: Buffer) => {
          this.appendBuffer(session, chunk)
          session.log?.append(chunk.toString('utf8'))
          this.emit?.data(id, chunk.toString('base64'))
        })
        stream.stderr?.on('data', (chunk: Buffer) => {
          this.appendBuffer(session, chunk)
          session.log?.append(chunk.toString('utf8'))
          this.emit?.data(id, chunk.toString('base64'))
        })
        stream.on('close', () => {
          this.setStatus(session, 'closed', t('error.sessionEnded'))
          void session.log?.close()
          void aiLog.close(id)
          client.end()
        })
      })
    })

    client.on('keyboard-interactive', (_name, _instr, _lang, prompts, finish) => {
      // Many servers deliver the password through keyboard-interactive rather
      // than `password`, so this path has to answer — but only a real password
      // prompt. Prompt text, echo flag and prompt count all come from the
      // server, so answering every prompt would hand the stored password to a
      // host that asked "Enter your GitHub token:". Exactly one prompt, echo
      // off; anything else gets nothing and auth fails visibly rather than
      // leaking.
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
          : t('error.sshReported', { message: serverText(err.message) })
      this.setStatus(session, 'error', msg)
    })

    client.on('close', () => {
      if (session.status !== 'error') this.setStatus(session, 'closed')
      // Idempotent: a session can arrive here after stream close or disconnect
      // already flushed it, and every path has to end with the tail on disk.
      void session.log?.close()
      void aiLog.close(id)
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
    // Both directions, because a transcript holding only the server's half
    // cannot show which command produced which output.
    s.log?.append(data)
  }

  /**
   * Writes a file over SFTP on the same connection.
   *
   * SFTP rather than `cat > file`: a here-doc has to escape the content against
   * the remote shell, and getting that wrong turns file content into commands.
   * SFTP carries bytes.
   *
   * The remote path is passed to the server verbatim. It is not this method's
   * job to decide whether the destination is reasonable — that decision belongs
   * to the human, in front of the dialog, with `uploadPaths.ts` telling them
   * what they are looking at.
   */
  async upload(sessionId: string, remotePath: string, content: Buffer): Promise<void> {
    const s = this.sessions.get(sessionId)
    if (!s || s.status !== 'ready') throw appError('error.sessionNotReady')
    if (content.length > UPLOAD_MAX_BYTES) throw appError('error.uploadTooLarge')

    const sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
      s.client.sftp((err, handle) => (err ? reject(err) : resolve(handle)))
    })

    try {
      await new Promise<void>((resolve, reject) => {
        const stream = sftp.createWriteStream(remotePath)
        stream.on('error', reject)
        stream.on('close', () => resolve())
        stream.end(content)
      })
    } finally {
      sftp.end()
    }
  }

  resize(sessionId: string, cols: number, rows: number): void {
    const s = this.sessions.get(sessionId)
    if (!s?.stream) return
    s.stream.setWindow(rows, cols, 0, 0)
  }

  disconnect(sessionId: string): void {
    const s = this.sessions.get(sessionId)
    if (!s) return
    void s.log?.close()
    void aiLog.close(sessionId)
    s.stream?.end()
    s.client.end()
    // Fallback in case the server ignores the graceful shutdown.
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
      // ssh2 clears readyTimeout only on `ready`, so it runs *while the host-key
      // dialog is open*. It must outlast that dialog's own 120 s timeout, or
      // verifying a fingerprint out of band gets punished with a disconnect.
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
      case 'key': {
        if (conn.keyId) {
          const key = vault.read().keys.find((k) => k.id === conn.keyId)
          // Deleting a key in use is refused, so a dangling id means the vault
          // was edited somewhere else. Saying that beats letting ssh2 report a
          // parse error on an empty string.
          if (!key) throw appError('error.keyMissing')
          return { ...base, privateKey: key.privateKey, passphrase: key.passphrase || undefined }
        }
        // Key text still on the connection: a vault from before the key library,
        // or a key the migration could not parse. Either must keep working.
        return {
          ...base,
          privateKey: conn.privateKey ?? '',
          passphrase: conn.passphrase || undefined
        }
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
      // No answer within two minutes: refuse.
      setTimeout(() => {
        if (this.pendingHostKeys.delete(requestId)) resolve(false)
      }, 120_000)
    })

    if (!accepted) return false

    // Record trust only if the answer can still be acted on. If the connection
    // died while the dialog was open, this would grant permanent trust to a key
    // whose session never completed: the user sees a timeout, and the *next*
    // connect succeeds silently with no changed-key warning — a silent MITM.
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
 * Not `title`: that falls back to `username@host`, while `list_sessions`
 * promises the address, port and username are withheld. Weakening `title` is
 * not the fix either — the human reads it in the approval dialog and has to be
 * able to tell which server a command lands on. The placeholder is keyed by
 * connection, not by session, so a reconnect hands the model the same name back
 * rather than silently pointing it elsewhere. English, never translated: a
 * machine interface must not shift under the model at the next language switch
 * (see RUN_ERRORS in mcp.ts).
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
 * Takes the client, not a session, on purpose: it reads exactly one channel and
 * cannot reach the interactive stream even by accident.
 *
 * No PTY. With one, the line discipline folds stderr into stdout, escape
 * sequences come back, and `sudo` blocks on a password prompt nobody here can
 * answer until the time limit expires; without one it fails at once with a real
 * exit status. `allowHalfOpen` stays at ssh2's default of true: false makes
 * `end()` send CHANNEL_CLOSE and kill the command we just started.
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
    let exitTimer: NodeJS.Timeout | null = null

    // Keep the head, not the tail: the start is what the human reads first and a
    // flooding server must not push it off the top. Chunks past the cap are
    // dropped, not refused — refusing stalls the channel and the exit status.
    // stderr's slice is ON TOP of `maxBytes`, not carved out of it: carving would
    // shrink the stdout cap the caller asked for, and at a small `maxBytes` the
    // reserve would swallow the whole budget.
    const budget = { out: maxBytes, err: Math.min(STDERR_RESERVE_BYTES, maxBytes) }

    const collect =
      (into: Buffer[], stream: 'out' | 'err') =>
      (chunk: Buffer): void => {
        const room = budget[stream]
        if (room <= 0) {
          truncated = true
          return
        }
        if (chunk.length > room) {
          truncated = true
          into.push(chunk.subarray(0, room))
          budget[stream] = 0
          return
        }
        into.push(chunk)
        budget[stream] -= chunk.length
      }

    const stopTimers = (): void => {
      clearTimeout(timer)
      if (exitTimer) clearTimeout(exitTimer)
    }

    const finish = (): void => {
      if (settled) return
      settled = true
      stopTimers()
      resolve({ output: joinStreams(out, err), exitCode, signal, timedOut, truncated })
    }

    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      stopTimers()
      reject(appError('error.execFailed', { message: error.message }))
    }

    const timer = setTimeout(() => {
      timedOut = true
      // close() sends CHANNEL_CLOSE. sshd normally hangs up the process, but
      // nothing guarantees it, so the result says the command may still run.
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
        chan.on('data', collect(out, 'out'))
        chan.stderr.on('data', collect(err, 'err'))
        chan.on('exit', (code: number | null, sig?: string) => {
          exitCode = typeof code === 'number' ? code : null
          signal = signalName(sig)
          // `close` is the real end: exit-status is optional in the SSH spec and
          // can arrive before the last data packet, so finishing here would
          // truncate. But `ForceCommand` and some appliance stacks send
          // exit-status and never close, so give `close` a grace period only.
          clearTimeout(timer)
          exitTimer = setTimeout(finish, EXIT_GRACE_MS)
        })
        chan.on('close', finish)
        // A Duplex with no error listener takes the main process down, and what
        // we already collected is still worth returning.
        chan.on('error', finish)
        chan.stderr.on('error', finish)
        // No stdin: a reader gets EOF at once rather than waiting for input this
        // channel cannot deliver.
        chan.end()
      })
    } catch (error) {
      // ssh2 throws synchronously when the socket is already gone.
      fail(error as Error)
    }
  })
}

/**
 * Joins stdout and stderr into one text. They stay separate: the two are
 * independent SSH data types with no ordering guarantee, so interleaving would
 * produce a transcript that looks authoritative and is not. The label matters
 * too — `permission denied` on stderr is a different fact from it on stdout.
 */
function joinStreams(out: Buffer[], err: Buffer[]): string {
  const stdout = cleanTerminalText(Buffer.concat(out).toString('utf8'))
  const stderr = cleanTerminalText(Buffer.concat(err).toString('utf8'))
  if (!stderr.trim()) return stdout
  const head = stdout.trim() ? stdout.replace(/\n?$/, '\n') : ''
  return `${head}--- stderr ---\n${stderr}`
}

/**
 * The signal name from an SSH `exit-signal`, or nothing.
 *
 * RFC 4254 types this field as a `string`, so it is whatever the server says —
 * and it lands in the note `describeRun` builds for the model, which rides
 * ALONGSIDE the shared text: the human edits the output in the share dialog,
 * never the note, so an unfiltered value here bypasses the gate entirely. Only
 * a signal-shaped name is passed on, the pattern kept a little wider than RFC
 * 4254's list so a legitimate but unusual name is not reported as unsignalled.
 * Refusal yields `null`, read downstream as "no signal": silence, not a megaphone.
 */
function signalName(sig: unknown): string | null {
  if (typeof sig !== 'string') return null
  return /^[A-Z][A-Z0-9]{1,14}$/.test(sig) ? sig : null
}

function describeExit(result: RunResult): string {
  if (result.timedOut) return t('term.runTimedOut')
  if (result.signal) return t('term.runSignal', { signal: result.signal })
  return t('term.runExit', { code: result.exitCode ?? -1 })
}

/** OpenSSH-format fingerprint: `SHA256:<unpadded base64>`. */
export function sha256Fingerprint(key: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '')
}

/**
 * The key type is the first SSH string in the blob: 4-byte length, then data.
 *
 * The fallback is deliberately not translated. This value is shown in the
 * host-key dialog but it is also persisted into the known-hosts entry, so a
 * localised string would write whatever language happened to be selected into
 * the vault and leave stored entries disagreeing with each other. Key types
 * (`ssh-ed25519`, `ssh-rsa`) are protocol identifiers and are never translated
 * either, so an untranslated placeholder is also the consistent choice.
 */
export function parseKeyType(key: Buffer): string {
  try {
    const len = key.readUInt32BE(0)
    if (len > 0 && len < 64 && key.length >= 4 + len) {
      return key.subarray(4, 4 + len).toString('ascii')
    }
  } catch {
    /* ignored — this is only a label */
  }
  return 'unknown'
}

function resolveAgent(configured?: string): string {
  if (configured && configured.trim()) return configured.trim()
  if (process.env.SSH_AUTH_SOCK) return process.env.SSH_AUTH_SOCK
  // Windows: Pageant (PuTTY). Alternative: \\.\pipe\openssh-ssh-agent
  return process.platform === 'win32' ? 'pageant' : ''
}

export const ssh = new SshManager()

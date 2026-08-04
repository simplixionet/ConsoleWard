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
import { cleanTerminalText, tailLines } from './ansi'
import { appError, t } from './i18n'

/** Kolik bajtů výstupu držet v paměti na relaci (podklad pro AI ve 2. fázi). */
const SCROLL_MEMORY_BYTES = 256 * 1024

interface Session {
  id: string
  connectionId: string
  title: string
  client: Client
  stream: ClientChannel | null
  status: SessionStatus
  message?: string
  buffer: Buffer[]
  bufferBytes: number
  /** Aktivní odchyt výstupu (běží jen po dobu jednoho příkazu z MCP). */
  capture: ((chunk: Buffer) => void) | null
}

type Emitter = {
  data: (sessionId: string, base64: string) => void
  status: (info: SessionInfo) => void
  hostKeyPrompt: (prompt: HostKeyPrompt) => void
}

class SshManager {
  private sessions = new Map<string, Session>()
  private pendingHostKeys = new Map<string, (accept: boolean) => void>()
  private emit: Emitter | null = null

  bind(emit: Emitter): void {
    this.emit = emit
  }

  list(): SessionInfo[] {
    return [...this.sessions.values()].map(toInfo)
  }

  /** Existuje relace a je připravená přijímat vstup? */
  isReady(sessionId: string): boolean {
    return this.sessions.get(sessionId)?.status === 'ready'
  }

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
   * Odešle příkaz a zachytí výstup, který po něm přijde.
   *
   * Konec poznáme podle ticha na lince – interaktivní shell nedává žádný jiný
   * signál. Není to spolehlivé pro dlouho běžící příkazy, proto tvrdý strop.
   */
  async runAndCapture(
    sessionId: string,
    command: string,
    { idleMs = 900, timeoutMs = 30_000 }: { idleMs?: number; timeoutMs?: number } = {}
  ): Promise<{ output: string; timedOut: boolean }> {
    const s = this.sessions.get(sessionId)
    if (!s?.stream || s.status !== 'ready') throw appError('error.sessionNotReady')
    if (s.capture) throw appError('error.commandRunning')

    const chunks: Buffer[] = []
    let lastAt = Date.now()
    s.capture = (chunk) => {
      chunks.push(chunk)
      lastAt = Date.now()
    }

    try {
      s.stream.write(Buffer.from(command.replace(/\n?$/, '\n'), 'utf8'))
      const startedAt = Date.now()
      let timedOut = false
      await new Promise<void>((resolve) => {
        const tick = setInterval(() => {
          const idle = Date.now() - lastAt >= idleMs
          const expired = Date.now() - startedAt >= timeoutMs
          if (idle || expired) {
            timedOut = expired && !idle
            clearInterval(tick)
            resolve()
          }
        }, 100)
      })
      return {
        output: cleanTerminalText(Buffer.concat(chunks).toString('utf8')),
        timedOut
      }
    } finally {
      s.capture = null
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
      client,
      stream: null,
      status: 'connecting',
      buffer: [],
      bufferBytes: 0,
      capture: null
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
      // Řada serverů posílá heslo přes keyboard-interactive místo `password`.
      if (conn.authKind === 'password' && conn.password) {
        finish(prompts.map(() => conn.password as string))
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
      readyTimeout: 25_000,
      keepaliveInterval: 25_000,
      keepaliveCountMax: 4,
      hostVerifier: (key: Buffer, cb: (valid: boolean) => void) => {
        this.verifyHostKey(conn, key)
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

  private async verifyHostKey(conn: Connection, key: Buffer): Promise<boolean> {
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

    await vault.mutate((d) => {
      const idx = d.knownHosts.findIndex((h) => h.hostKey === hostKey)
      const entry = { hostKey, keyType, fingerprint, addedAt: Date.now() }
      if (idx >= 0) d.knownHosts[idx] = entry
      else d.knownHosts.push(entry)
    })
    return true
  }

  private appendBuffer(session: Session, chunk: Buffer): void {
    session.capture?.(chunk)
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

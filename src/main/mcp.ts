// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Lokální MCP server.
 *
 * Umožní AI klientovi (Claude Code apod.) vidět názvy relací, navrhovat příkazy
 * a číst výstup – ale vždy jen přes bránu, kterou drží člověk:
 *
 *   run_command   → dialog se schválením doslovného znění příkazu
 *   read_terminal → dialog, kde vybereš/upravíš, co přesně se pošle
 *   list_sessions → jen názvy a stavy; adresy, uživatele ani hesla nikdy
 *
 * Zásady:
 *  - posloucháme výhradně na 127.0.0.1, nikdy na 0.0.0.0
 *  - povinný bearer token + ochrana proti DNS rebindingu (kontrola Host/Origin)
 *  - ve výchozím stavu vypnuto, funguje jen při odemčeném trezoru
 *  - žádné „schválit vše" – každý příkaz zvlášť
 */

import { createServer, type Server as HttpServer } from 'node:http'
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { z } from 'zod'
import type { CommandApproval, McpStatus, ShareRequest } from '../shared/types'
import type { RunResult } from './ssh'
import { scanSecrets } from '../shared/secretPatterns'
import { isQueueFull, MAX_PENDING_APPROVALS } from './approvals'
import { visualizeControlChars } from './ansi'
import { ssh } from './ssh'
import { vault } from './vault'
import { appError, t } from './i18n'

export interface McpBridge {
  /**
   * Zobrazí dialog se schválením příkazu.
   *
   * Rejects with an ApprovalQueueFullError when the human already has the
   * maximum number of approvals waiting — see `isQueueFull`. That is the only
   * rejection; a human decision always resolves.
   */
  askCommand: (req: CommandApproval) => Promise<{ approved: boolean; autoShare: boolean }>
  /** Zobrazí dialog pro výběr části výstupu. Rejects like `askCommand`. */
  askShare: (req: ShareRequest) => Promise<{ shared: boolean; text: string }>
}

const DEFAULT_PORT = 7345

/**
 * English on purpose — everything the model reads is a machine interface, not
 * text for a person. It names the limit so a well-behaved client can throttle
 * itself, and it says nothing was queued so the model does not wait for a
 * dialog that will never appear.
 */
const QUEUE_FULL_MESSAGE =
  `The human already has ${MAX_PENDING_APPROVALS} approvals waiting, so this request ` +
  'was not shown to them and nothing was queued. Wait for the pending ones to be ' +
  'answered before sending another; retrying immediately will get the same answer.'

class McpService {
  private http: HttpServer | null = null
  private bridge: McpBridge | null = null
  private lastError: string | null = null
  private port = DEFAULT_PORT

  bind(bridge: McpBridge): void {
    this.bridge = bridge
  }

  status(): McpStatus {
    const settings = vault.isUnlocked() ? vault.read().settings : null
    return {
      running: this.http !== null,
      port: this.port,
      enabled: Boolean(settings?.mcpEnabled),
      hasToken: Boolean(vault.isUnlocked() && vault.read().mcpToken),
      error: this.lastError
    }
  }

  /** Token se generuje při prvním zapnutí a žije v trezoru. */
  async ensureToken(): Promise<string> {
    const existing = vault.read().mcpToken
    if (existing) return existing
    const token = randomBytes(32).toString('base64url')
    await vault.mutate((data) => {
      data.mcpToken = token
    })
    return token
  }

  async regenerateToken(): Promise<string> {
    const token = randomBytes(32).toString('base64url')
    await vault.mutate((data) => {
      data.mcpToken = token
    })
    if (this.http) await this.restart()
    return token
  }

  readToken(): string | null {
    return vault.isUnlocked() ? (vault.read().mcpToken ?? null) : null
  }

  async start(): Promise<void> {
    if (this.http) return
    if (!vault.isUnlocked()) throw appError('error.mcpVaultLocked')

    const settings = vault.read().settings
    this.port = clampPort(settings.mcpPort ?? DEFAULT_PORT)
    const token = await this.ensureToken()
    this.lastError = null

    const allowedHosts = [`127.0.0.1:${this.port}`, `localhost:${this.port}`]
    // Běžný MCP klient hlavičku Origin neposílá; pokud ji někdo pošle, musí sedět.
    // Brání tomu, aby na server zaútočila webová stránka otevřená v prohlížeči.
    const allowedOrigins = [`http://127.0.0.1:${this.port}`, `http://localhost:${this.port}`]

    const server = createServer((req, res) => {
      void (async () => {
        // Bezstavový režim: server i transport vznikají pro každý požadavek zvlášť.
        // Sdílená instance zvládne jen první volání a další skončí chybou.
        let mcpServer: McpServer | null = null
        let transport: StreamableHTTPServerTransport | null = null
        try {
          if (!this.checkAuth(req.headers.authorization, token)) {
            res.writeHead(401, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: 'unauthorized' }))
            return
          }
          if (!vault.isUnlocked()) {
            res.writeHead(503, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: 'vault_locked' }))
            return
          }

          const body = await readJsonBody(req)
          mcpServer = this.buildServer()
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            enableJsonResponse: true,
            enableDnsRebindingProtection: true,
            allowedHosts,
            allowedOrigins
          })
          await mcpServer.connect(transport)
          await transport.handleRequest(req, res, body)
        } catch (err) {
          if (!res.headersSent) {
            res.writeHead(500, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: String(err) }))
          } else {
            res.end()
          }
        } finally {
          // Úklid až po odeslání odpovědi, jinak bychom uřízli běžící stream.
          res.on('close', () => {
            void transport?.close()
            void mcpServer?.close()
          })
        }
      })()
    })

    await new Promise<void>((resolve, reject) => {
      server.once('error', (err) => {
        this.lastError = describeListenError(err, this.port)
        reject(new Error(this.lastError))
      })
      // Výhradně smyčka zpět – server nesmí být vidět ze sítě.
      server.listen(this.port, '127.0.0.1', resolve)
    })

    this.http = server
  }

  async stop(): Promise<void> {
    const server = this.http
    this.http = null
    if (!server) return
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }

  async restart(): Promise<void> {
    await this.stop()
    await this.start()
  }

  /** Volá se při zamčení trezoru – bez klíčů nemá server co nabízet. */
  async stopOnLock(): Promise<void> {
    await this.stop()
  }

  private checkAuth(header: string | undefined, token: string): boolean {
    const prefix = 'Bearer '
    if (!header || !header.startsWith(prefix)) return false
    const provided = Buffer.from(header.slice(prefix.length))
    const expected = Buffer.from(token)
    if (provided.length !== expected.length) return false
    return timingSafeEqual(provided, expected)
  }

  private buildServer(): McpServer {
    const server = new McpServer(
      { name: 'consoleward', version: '0.1.0' },
      {
        instructions: [
          'Access to the SSH sessions of ConsoleWard.',
          'Server addresses, usernames and passwords are not available and never will be.',
          'A human approves every command, and decides what part of its output reaches you — sometimes in advance, sometimes only after seeing it. Respect a refusal and do not retry it in a different shape.',
          'Whatever output you receive may be trimmed or edited by the human, so never assume you are seeing everything.',
          'Commands run in their own channel, not in the terminal the human is looking at: a fresh non-interactive shell in the home directory, with no terminal and no state carried over from your previous calls.'
        ].join(' ')
      }
    )

    server.registerTool(
      'list_sessions',
      {
        title: 'List the open SSH sessions',
        description:
          'Returns the open sessions with only their id, name and status. The address, port and username are deliberately withheld.',
        inputSchema: {},
        annotations: { readOnlyHint: true }
      },
      async () => {
        const sessions = ssh.list().map((s) => ({ id: s.id, name: s.title, status: s.status }))
        return {
          content: [{ type: 'text' as const, text: JSON.stringify({ sessions }, null, 2) }]
        }
      }
    )

    server.registerTool(
      'read_terminal',
      {
        title: 'Ask for terminal output',
        description:
          'Asks the human for the session output. They pick or edit exactly what reaches you, so ' +
          'expect an excerpt rather than the full output. Say in `reason` what you are looking for.',
        inputSchema: {
          session_id: z.string().describe('session id from list_sessions'),
          reason: z.string().describe('why you need the output; the human reads this in the dialog')
        },
        annotations: { readOnlyHint: true, openWorldHint: false }
      },
      async ({ session_id, reason }) => {
        const bridge = this.requireBridge()
        if (!ssh.isReady(session_id)) return toolError('The session does not exist or is not ready.')

        let preview: string
        try {
          preview = ssh.readText(session_id, 400)
        } catch (err) {
          return toolError((err as Error).message)
        }

        let answer: { shared: boolean; text: string }
        try {
          answer = await bridge.askShare({
            id: randomUUID(),
            sessionId: session_id,
            sessionName: ssh.title(session_id),
            reason,
            origin: 'read_terminal',
            text: preview
          })
        } catch (err) {
          if (!isQueueFull(err)) throw err
          return toolError(QUEUE_FULL_MESSAGE)
        }

        if (!answer.shared) return toolError('The human declined to share the output.')
        return sharedResult(answer.text)
      }
    )

    server.registerTool(
      'run_command',
      {
        title: 'Propose a command to run',
        description:
          'Proposes a command in the given session. It does not run until a human approves it in the app. ' +
          'It runs in its own channel on the same connection: a fresh non-interactive, non-login shell ' +
          'starting in the home directory, so shell aliases, shell functions and any PATH set in the ' +
          'login files are absent, and nothing carries over between calls — chain steps with && or ; in ' +
          'one command rather than relying on a directory you changed earlier. There is no terminal, so ' +
          'anything that would prompt (sudo without NOPASSWD, an editor, a pager) fails instead of waiting. ' +
          'You receive the output only if the human chooses to share it, and the exit status with it. ' +
          'Send one command per call and explain in `reason` what you are trying to achieve.',
        inputSchema: {
          session_id: z.string().describe('session id from list_sessions'),
          command: z.string().describe('the exact command text'),
          reason: z.string().describe('why you want to run it; the human reads this in the dialog')
        },
        annotations: { destructiveHint: true, openWorldHint: false }
      },
      async ({ session_id, command, reason }) => {
        const bridge = this.requireBridge()
        if (!ssh.isReady(session_id)) return toolError('The session does not exist or is not ready.')
        if (!command.trim()) return toolError('Empty command.')

        let approval: { approved: boolean; autoShare: boolean }
        try {
          approval = await bridge.askCommand({
            id: randomUUID(),
            sessionId: session_id,
            sessionName: ssh.title(session_id),
            command,
            commandVisualized: visualizeControlChars(command),
            reason
          })
        } catch (err) {
          if (!isQueueFull(err)) throw err
          return toolError(QUEUE_FULL_MESSAGE)
        }

        if (!approval.approved) return toolError('The human did not approve the command.')

        let result: RunResult
        try {
          result = await ssh.runOnce(session_id, command)
        } catch (err) {
          return toolError(runErrorFor(err))
        }

        // The tick was given while reading the COMMAND, before a single byte of
        // output existed, so it cannot be a promise about text nobody has seen.
        // It is revoked whenever the captured output looks like it carries a
        // credential — see outputNeedsReview for why only `high` counts.
        const overridden = approval.autoShare && outputNeedsReview(result)
        if (approval.autoShare && !overridden) {
          return sharedResult(result.output, result)
        }

        // No queue-full guard: `origin: 'command_output'` is the cap exemption
        // in approvals.ts, because the human already approved the command that
        // produced this output. Change the origin and this call can reject.
        // `autoShareOverridden` is also the queue's force-raise flag: on this
        // path the human was told they would not be asked, so a dialog left
        // behind the terminal would be denied on their behalf by the timer.
        const answer = await bridge.askShare({
          id: randomUUID(),
          sessionId: session_id,
          sessionName: ssh.title(session_id),
          reason: `Command output: ${command}`,
          origin: 'command_output',
          text: result.output,
          autoShareOverridden: overridden
        })

        if (!answer.shared) {
          return {
            content: [
              {
                type: 'text' as const,
                text: 'The command ran, but the human chose not to share its output.'
              }
            ]
          }
        }
        return sharedResult(answer.text, result)
      }
    )

    return server
  }

  private requireBridge(): McpBridge {
    if (!this.bridge) throw appError('error.mcpBridgeMissing')
    return this.bridge
  }
}

/**
 * Model musí vědět, že vidí výřez – jinak by z neúplného výstupu tiše
 * vyvozoval závěry, jako by viděl všechno.
 */
function sharedResult(text: string, run?: RunResult): {
  content: { type: 'text'; text: string }[]
} {
  const notes = [
    'Note: a human selected and possibly edited this content, so it may be incomplete.',
    run ? describeRun(run, text) : null
  ].filter(Boolean)

  return {
    content: [{ type: 'text' as const, text: `${notes.join(' ')}\n\n${text}` }]
  }
}

/** Bez terminálu se sudo a spol. neptají, ale spadnou — model musí vědět proč. */
const NEEDS_TTY = /a terminal is required|no tty present|must be run from a terminal|not a tty/i

/**
 * Describes the run for the model. A machine interface, so always English.
 *
 * The exit status is the whole point of the exec channel: the old capture ended
 * on silence and could never say whether the command worked.
 *
 * The TTY hint is derived from `shared` — the text actually being sent — and
 * never from the raw capture. Reading the raw output would turn this note into
 * a one-bit oracle over a line the human had just chosen to redact, which is
 * exactly the leak the share dialog exists to prevent.
 */
function describeRun(run: RunResult, shared: string): string {
  const parts: string[] = []
  if (run.timedOut) {
    parts.push(
      'The command hit the time limit and its channel was closed before it reported an exit ' +
        'status, so it may still be running on the server.'
    )
  } else if (run.signal) {
    parts.push(`The command was killed by ${run.signal} and reported no exit status.`)
  } else if (run.exitCode === null) {
    parts.push('The server reported no exit status for the command.')
  } else {
    parts.push(`Exit status ${run.exitCode}.`)
  }
  if (run.truncated) {
    parts.push('The output passed the size limit, so only its beginning is here.')
  }
  if (NEEDS_TTY.test(shared)) {
    parts.push(
      'The command wanted a terminal. Commands run in a channel with no terminal and no way to ' +
        'answer a prompt, so propose a form that does not need one.'
    )
  }
  return parts.join(' ')
}

/**
 * Run errors for the model, in English and keyed rather than translated.
 *
 * `runOnce` throws an AppError whose message is already translated for the
 * human. Passing that on means a Czech user ships Czech diagnostics to an
 * English-speaking tool, and the text changes whenever they change language.
 * The key does not. A Map rather than an object literal so a key like
 * `constructor` cannot reach Object.prototype.
 */
const RUN_ERRORS = new Map<string, string>([
  ['error.sessionNotReady', 'The session does not exist or is not ready.'],
  ['error.commandRunning', 'A command from an earlier call is still running in this session.'],
  [
    'error.execFailed',
    'The server refused to open a channel for the command, so it did not run. ConsoleWard does ' +
      'not fall back to typing into the interactive session.'
  ]
])

function runErrorFor(err: unknown): string {
  const key = (err as { key?: string }).key
  return (key && RUN_ERRORS.get(key)) || 'The command could not be run.'
}

/**
 * Must this output be shown to the human even though they ticked auto-share?
 *
 * The tick is given while reading the *command*, before a single byte of output
 * exists. It is therefore a promise about text nobody has seen, and it is revoked
 * here the moment the text turns out to look like a credential.
 *
 * `truncated` rather than a second length cap: runExec already refuses to collect
 * more than RUN_OUTPUT_BYTES, and an output that hit that ceiling is exactly the
 * case where the human cannot have known what they agreed to. It also bounds how
 * much attacker-controlled text the regexes below see on the main process event
 * loop, where a pathological input would freeze every session at once.
 *
 * Only `high` forces the dialog. `medium` covers dotted quads and any 40-character
 * base64-ish run, which every `ip a`, `git log` and `sha256sum` produces; forcing
 * on those would mean the checkbox never applies, and a control that silently does
 * nothing is worse than no control — it is the habituation `secretPatterns.ts`
 * names in its own header as the failure mode.
 *
 * `clipped` for the same reason as `truncated`: scanSecrets stops at
 * MAX_SCAN_CHARS and everything past it is unread, so a credential down there
 * would pass this check by never having been looked at. RUN_OUTPUT_BYTES is
 * half MAX_SCAN_CHARS, so today this cannot fire — the check is here so that
 * raising one of the two constants cannot silently open the hole.
 *
 * `incomplete` deliberately does NOT force the dialog. The hit cap is per
 * pattern, so a capped pattern never stops another one from scanning the whole
 * text, and a high-severity pattern that reaches its cap has already produced
 * two thousand high matches — the branch below is already true. The cap can
 * therefore only ever hide `medium` findings, and forcing on those would fire
 * on every routing table, which is the habituation this file's header names.
 */
export function outputNeedsReview(run: RunResult): boolean {
  if (run.truncated) return true
  const scan = scanSecrets(run.output)
  if (scan.clipped) return true
  return scan.matches.some((m) => m.severity === 'high')
}

function toolError(message: string): {
  isError: true
  content: { type: 'text'; text: string }[]
} {
  return { isError: true, content: [{ type: 'text' as const, text: message }] }
}

function clampPort(port: number): number {
  const n = Number(port)
  if (!Number.isInteger(n) || n < 1024 || n > 65535) return DEFAULT_PORT
  return n
}

function describeListenError(err: unknown, port: number): string {
  const code = (err as NodeJS.ErrnoException)?.code
  if (code === 'EADDRINUSE') return t('error.portInUse', { port })
  if (code === 'EACCES') return t('error.portNotAllowed', { port })
  return t('error.serverStartFailed', { message: String(err) })
}

/** Načte tělo požadavku; transport ho chce jako už rozparsovaný JSON. */
async function readJsonBody(req: import('node:http').IncomingMessage): Promise<unknown> {
  if (req.method !== 'POST') return undefined
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    size += (chunk as Buffer).length
    if (size > 4 * 1024 * 1024) throw appError('error.requestTooLarge')
    chunks.push(chunk as Buffer)
  }
  if (chunks.length === 0) return undefined
  const raw = Buffer.concat(chunks).toString('utf8')
  if (!raw.trim()) return undefined
  return JSON.parse(raw)
}

export const mcp = new McpService()

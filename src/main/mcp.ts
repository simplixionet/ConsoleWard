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

import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server as HttpServer,
  type ServerResponse
} from 'node:http'
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
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
import { appError, t, type AppError } from './i18n'

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

/**
 * How many requests may be in flight at once.
 *
 * Not a rate limit — the point is memory. Every request buffers its body, up to
 * the limit `readJsonBody` allows, and one that reaches a dialog holds an
 * McpServer and a transport for as long as the human takes, which
 * APPROVAL_TIMEOUT_MS bounds at five minutes. Node bounds none of this on its
 * own: maxConnections is unset and maxRequestsPerSocket is 0. The approval
 * queue caps the human's side at three, so eight leaves room for an initialize
 * and a tools/list alongside three blocked dialogs.
 */
export const MAX_INFLIGHT_REQUESTS = 8

/**
 * How much of a request body is buffered before it is refused.
 *
 * A JSON-RPC call from an MCP client is kilobytes. Four megabytes is far more
 * than any of them needs and small enough that `MAX_INFLIGHT_REQUESTS` of them
 * cannot exhaust memory.
 */
export const MAX_BODY_BYTES = 4 * 1024 * 1024

const BUSY_MESSAGE =
  `ConsoleWard is already handling ${MAX_INFLIGHT_REQUESTS} requests and will not start ` +
  'another. This one was not queued. Let the earlier ones finish and send it again.'

class McpService {
  private http: HttpServer | null = null
  private bridge: McpBridge | null = null
  private lastError: string | null = null
  private port = DEFAULT_PORT
  /** Requests past the gate and not yet finished — see MAX_INFLIGHT_REQUESTS. */
  private inFlight = 0

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
        //
        // Not because a shared McpServer is unusable — close() then connect()
        // again works and the registered tools survive it. Because neither half
        // can serve two requests AT ONCE: the stateless transport refuses its
        // second request outright, and a Protocol holds exactly one transport
        // and throws on a second connect. Sharing would therefore mean
        // serialising every request, and a run_command holds its request for up
        // to five minutes waiting on a human — the whole server would sit behind
        // one dialog. Closing to admit the next request is no better: close()
        // aborts the in-flight handler, which is the one that is waiting.
        let mcpServer: McpServer | null = null
        let transport: StreamableHTTPServerTransport | null = null
        let slot = false
        try {
          // The name first, the credentials second, and both every time.
          //
          // A page in a browser can only ever put its own name in Host — that is
          // the whole of DNS rebinding — so the name is what tells a client apart
          // from an attack. Checking the token first meant a foreign Host never
          // reached the rebinding guard at all and got a 401 instead of a 403,
          // and the difference between the two answers is the page learning that
          // ConsoleWard is listening on this port. Neither check may
          // short-circuit the other, or the time to the rejection says which one
          // failed; `&&` here would put the oracle straight back.
          const named = hostAllowed(req.headers, allowedHosts, allowedOrigins)
          const authed = this.checkAuth(req.headers.authorization, token)
          if (!named || !authed) {
            sendJson(res, 403, REJECTED)
            return
          }
          // Behind the gate on purpose: a caller that has not proved both is not
          // entitled to know whether the vault happens to be open.
          if (!vault.isUnlocked()) {
            sendJson(res, 503, 'The ConsoleWard vault is locked.', 'vault_locked')
            return
          }

          // POST only. The cap exists for the memory a call can pin: a buffered
          // body, plus an McpServer and a transport parked for however long a
          // human takes to answer a dialog. A GET is the notification stream —
          // the SDK client opens one right after the handshake and holds it for
          // the whole session, deliberately. Counting those meant an ordinary
          // client spent a slot just by connecting, and eight of them wedged the
          // gateway into a permanent 503 with nothing wrong.
          //
          // Streams are still bounded, just not here: nothing reaches this line
          // without the Host gate and a valid bearer token, and the thing the
          // cap really protects — the human's attention — is bounded by
          // MAX_PENDING_APPROVALS in approvals.ts.
          if (takesSlot(req.method)) {
            if (this.inFlight >= MAX_INFLIGHT_REQUESTS) {
              sendJson(res, 503, BUSY_MESSAGE, 'busy')
              return
            }
            this.inFlight++
            slot = true
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
            // `String(err)` used to land here. It shipped `AppError: Požadavek je
            // příliš velký.` to an English-speaking client, and it echoed the
            // caller's own bytes back inside a SyntaxError. Both go through the
            // same keyed map the tools use.
            const tooLarge = (err as { key?: unknown } | null)?.key === 'error.requestTooLarge'
            sendJson(
              res,
              tooLarge ? 413 : 500,
              modelErrorFor(err),
              tooLarge ? 'too_large' : 'failed'
            )
          } else {
            res.end()
          }
        } finally {
          if (slot) this.inFlight--
          // Úklid až po odeslání odpovědi, jinak bychom uřízli běžící stream.
          //
          // `onceClosed` and not `res.on` because a client that gave up has
          // closed the response ALREADY, and a listener added to a closed stream
          // is never called — the transport and the server were then never
          // closed at all. Measured: on an aborted request `res.closed` is true
          // by the time this runs.
          onceClosed(res, () => {
            void transport?.close()
            void mcpServer?.close()
          })
        }
      })()
    })

    await new Promise<void>((resolve, reject) => {
      server.once('error', (err) => {
        const failure = listenError(err, this.port)
        this.lastError = failure.message
        reject(failure)
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

  /**
   * Constant-time for any input, including the wrong length.
   *
   * `timingSafeEqual` throws on unequal lengths, so the obvious code returns
   * early on a length mismatch — and that early return leaks the token's
   * length. Hashing both sides first makes every comparison 32 bytes against
   * 32 bytes, so a wrong token costs the same as a right one and the same as
   * no token at all.
   */
  private checkAuth(header: string | undefined, token: string): boolean {
    const prefix = 'Bearer '
    const offered = header?.startsWith(prefix) === true ? header.slice(prefix.length) : ''
    const provided = createHash('sha256').update(offered).digest()
    const expected = createHash('sha256').update(token).digest()
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
          'Returns the open sessions with only their id, name and status. The name is the label ' +
          'the human gave the connection, or a neutral placeholder when they gave none. The ' +
          'address, port and username are deliberately withheld.',
        inputSchema: {},
        annotations: { readOnlyHint: true }
      },
      async () => {
        // `listForModel`, never `ssh.list()`: that returns the human's SessionInfo,
        // whose `title` falls back to `username@host` — the address this tool's own
        // description promises to withhold.
        const sessions = ssh.listForModel()
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
        const bridge = this.bridge
        if (!bridge) return toolError(modelErrorFor({ key: 'error.mcpBridgeMissing' }))
        if (!ssh.isReady(session_id)) return toolError('The session does not exist or is not ready.')

        let preview: string
        try {
          preview = ssh.readText(session_id, 400)
        } catch (err) {
          return toolError(modelErrorFor(err))
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
        const bridge = this.bridge
        if (!bridge) return toolError(modelErrorFor({ key: 'error.mcpBridgeMissing' }))
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
          return toolError(modelErrorFor(err))
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
 * Errors for the model, in English and keyed rather than translated.
 *
 * Everything below throws an AppError whose message has already been through
 * `t()` for the human. Passing that on means a Czech user ships Czech
 * diagnostics to an English-speaking tool, and the text changes whenever they
 * change language. The key does not. A Map rather than an object literal so a
 * key like `constructor` cannot reach Object.prototype.
 *
 * The list is the complete set that can arrive: `error.mcpBridgeMissing` from
 * the bridge check, `error.sessionNotFound` from `ssh.readText`,
 * `error.sessionNotReady`, `error.commandRunning` and `error.execFailed` from
 * `ssh.runOnce`, and `error.requestTooLarge` from `readJsonBody`. Nothing else
 * in the app sits on a path the model can reach — the tools never touch the
 * vault, `ssh.connect` or `ssh.write`.
 */
export const MODEL_ERRORS = new Map<string, string>([
  ['error.mcpBridgeMissing', 'ConsoleWard cannot show approval dialogs right now.'],
  ['error.sessionNotFound', 'The session does not exist or is not ready.'],
  ['error.sessionNotReady', 'The session does not exist or is not ready.'],
  ['error.commandRunning', 'A command from an earlier call is still running in this session.'],
  [
    'error.execFailed',
    'The server refused to open a channel for the command, so it did not run. ConsoleWard does ' +
      'not fall back to typing into the interactive session.'
  ],
  ['error.requestTooLarge', 'The request body is too large.']
])

/**
 * The fallback names nothing on purpose.
 *
 * An unmapped error is a path nobody traced, so its message may carry a path
 * from this machine, a sentence in the human's language, or a server's own
 * words. `err` is typed unknown and read defensively because it also receives
 * plain JS errors — a `SyntaxError` from `JSON.parse` has no `key` at all.
 */
export function modelErrorFor(err: unknown): string {
  const key = (err as { key?: unknown } | null | undefined)?.key
  const mapped = typeof key === 'string' ? MODEL_ERRORS.get(key) : undefined
  return mapped ?? 'ConsoleWard could not carry out the request.'
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

/**
 * The transport's Host/Origin rule, run before anything else touches the request.
 *
 * Mirrors `validateRequestHeaders` in the SDK exactly — the same two arrays, an
 * exact string match, and an Origin rejected only when it is present and wrong,
 * because an ordinary MCP client sends none. Exactly, and not approximately: a
 * looser check lets a request through to the transport and get a *different*
 * answer, which is the oracle this exists to remove, and a stricter one refuses
 * a client the transport would have taken.
 *
 * The exact match is what handles the interesting names without a single line
 * about any of them. `[::1]:7345`, `127.0.0.2:7345`, `LOCALHOST:7345`,
 * `127.0.0.1` without a port and `localhost.evil.com:7345` are simply not in
 * the list. A rebound name is refused because a browser puts the NAME in Host,
 * never the address it resolved to — which is the only reason this defence
 * works at all.
 */
export function hostAllowed(
  headers: IncomingHttpHeaders,
  hosts: string[],
  origins: string[]
): boolean {
  const host = headers.host
  if (typeof host !== 'string' || !hosts.includes(host)) return false
  const origin = headers.origin
  if (typeof origin === 'string' && !origins.includes(origin)) return false
  return true
}

/**
 * One answer for a wrong token and for a wrong name alike.
 *
 * It names both causes and says which applied to neither. That is enough for
 * the operator of a real client — those are the only two things they can have
 * got wrong — and nothing at all for a page that is guessing whether anything
 * is listening on this port.
 */
const REJECTED =
  'Rejected. ConsoleWard needs the bearer token from its settings, and it must be reached at ' +
  '127.0.0.1 or localhost on its own port. A request arriving under any other name is refused ' +
  'whatever token it carries.'

/**
 * A JSON-RPC error response, in fixed English.
 *
 * Fixed length as well as fixed text: the SDK echoes the offending Host back,
 * so its content-length alone told `[::1]` apart from `127.0.0.2`. `reason` is
 * for the causes a client may legitimately distinguish, and the rejection above
 * deliberately carries none.
 */
function sendJson(res: ServerResponse, status: number, message: string, reason?: string): void {
  const error = reason ? { code: -32000, message, data: { reason } } : { code: -32000, message }
  const body = JSON.stringify({ jsonrpc: '2.0', error, id: null })
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body)
  })
  res.end(body)
}

/**
 * Runs `cleanup` when the response is finished with — including when it is
 * finished with already.
 *
 * A client that gives up mid-request (a cancelled tool call, a timeout, a
 * process that exits) closes the socket while the handler is still waiting on a
 * human. By the time the handler returns, `res` has already emitted `close`,
 * and `res.on('close', ...)` on a closed stream is never called: the transport
 * and the server would be left open for good.
 *
 * Deliberately not eager — this does not close anything AT the abort. The
 * transport's own close() does not resolve the promise `handleRequest` is
 * waiting on, so tearing down early would strand the handler for ever instead
 * of for at most one approval timeout.
 */
/**
 * Does this request count against `MAX_INFLIGHT_REQUESTS`?
 *
 * Only a POST, and exported rather than inlined so a test can ask the real
 * predicate. A test that restates the rule beside the code passes against a
 * build where the rule was deleted, which is worse than no test.
 */
export function takesSlot(method: string | undefined): boolean {
  return method === 'POST'
}

export function onceClosed(
  res: { closed: boolean; once: (event: 'close', listener: () => void) => unknown },
  cleanup: () => void
): void {
  if (res.closed) cleanup()
  else res.once('close', cleanup)
}

function clampPort(port: number): number {
  const n = Number(port)
  if (!Number.isInteger(n) || n < 1024 || n > 65535) return DEFAULT_PORT
  return n
}

/**
 * Why the server would not listen, as an AppError.
 *
 * An `AppError` and not a bare `Error`, because `fail()` in index.ts now only
 * forwards a message to the renderer when the error carries a translation key —
 * anything else becomes a generic sentence so that node's own text, with its
 * absolute paths, never reaches the UI. That guard turned the one message the
 * user can actually act on ("port 7345 is already in use, pick another") into
 * "something went wrong", which is the opposite of the intent.
 */
function listenError(err: unknown, port: number): AppError {
  const code = (err as NodeJS.ErrnoException)?.code
  if (code === 'EADDRINUSE') return appError('error.portInUse', { port })
  if (code === 'EACCES') return appError('error.portNotAllowed', { port })
  // The raw text is deliberate here and only here: an unrecognised listen
  // failure is not actionable without it, and it is a socket error rather than
  // anything carrying a filesystem path.
  return appError('error.serverStartFailed', { message: String(err) })
}

/** Načte tělo požadavku; transport ho chce jako už rozparsovaný JSON. */
/**
 * Reads the JSON-RPC body, refusing anything that is not a bounded POST.
 *
 * Exported for the same reason `hostAllowed` and `onceClosed` are: the request
 * handler cannot be reached from a test — it closes over the listening server —
 * so the parts of it that decide anything are lifted out and checked directly.
 *
 * The size guard counts as it goes rather than after, because the point is to
 * stop buffering a body that is already too large, not to notice afterwards
 * that it was.
 */
export async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  if (req.method !== 'POST') return undefined
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    size += (chunk as Buffer).length
    if (size > MAX_BODY_BYTES) throw appError('error.requestTooLarge')
    chunks.push(chunk as Buffer)
  }
  if (chunks.length === 0) return undefined
  const raw = Buffer.concat(chunks).toString('utf8')
  if (!raw.trim()) return undefined
  return JSON.parse(raw)
}

export const mcp = new McpService()

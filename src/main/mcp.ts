// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Local MCP server: an AI client sees session names, proposes commands and reads
 * output through a gate a human holds.
 *
 * Invariants that hold in every mode — 127.0.0.1 only, never 0.0.0.0; bearer
 * token plus Host/Origin DNS-rebinding protection; off unless enabled and
 * unlocked; addresses, usernames and passwords never reach the model.
 *
 * The gate itself is NOT one of them any more. `dangerousMode` in the settings
 * removes the approval dialog and returns output unedited, leaving the
 * destructive list in `dangerousCommands.ts` — itself switchable — as the only
 * thing in the path. Both default off and on respectively, both have to be
 * changed by hand, and `instructionsFor` tells the model which of the two
 * worlds it is in, because a model told a human is reading its proposals
 * behaves differently from one that knows nobody is.
 *
 * There is still no "approve all" while the gate is on: the choice is the gate
 * or no gate, never a dialog that remembers a previous yes.
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
import type {
  CommandApproval,
  McpStatus,
  SaveCommandApproval,
  ShareRequest,
  UploadApproval
} from '../shared/types'
import type { RunResult } from './ssh'
import { scanSecrets } from '../shared/secretPatterns'
import { deniedAfterFlag, matchDangerous } from '../shared/dangerousCommands'
import { matchSensitivePath, normaliseRemotePath } from '../shared/uploadPaths'
import { isQueueFull, MAX_PENDING_APPROVALS } from './approvals'
import { visualizeControlChars } from './ansi'
import { UPLOAD_MAX_BYTES, ssh } from './ssh'
import { aiLog } from './aiLog'
import { vault } from './vault'
import { appError, t, type AppError } from './i18n'

export interface McpBridge {
  /**
   * Rejects only with ApprovalQueueFullError, when the queue is full — see
   * `isQueueFull`. A human decision always resolves, never rejects.
   */
  askCommand: (req: CommandApproval) => Promise<{ approved: boolean; autoShare: boolean }>
  /** Rejects like `askCommand`. */
  askShare: (req: ShareRequest) => Promise<{ shared: boolean; text: string }>
  /** Rejects like `askCommand`. Writes the snippet itself when approved. */
  saveCommand: (req: SaveCommandApproval, skipApproval: boolean) => Promise<{ approved: boolean }>
  /** Rejects like `askCommand`. */
  askUpload: (req: UploadApproval) => Promise<{ approved: boolean }>
}

const DEFAULT_PORT = 7345

/** English and never translated: everything the model reads is a machine interface. */
const QUEUE_FULL_MESSAGE =
  `The human already has ${MAX_PENDING_APPROVALS} approvals waiting, so this request ` +
  'was not shown to them and nothing was queued. Wait for the pending ones to be ' +
  'answered before sending another; retrying immediately will get the same answer.'

/**
 * A memory bound, not a rate limit: each request buffers a body, and one waiting
 * on a dialog pins an McpServer and a transport for up to APPROVAL_TIMEOUT_MS.
 * Node bounds none of this itself. Eight leaves room for an initialize and a
 * tools/list alongside the three dialogs MAX_PENDING_APPROVALS allows.
 *
 * The ceiling is a count, so raising APPROVAL_TIMEOUT_MS does not raise what
 * this can hold: eight bodies at MAX_BODY_BYTES is the worst case whether they
 * are held for five minutes or fifteen. What a longer wait does change is how
 * long a slot stays taken, and the answer to a full gateway is already the
 * right one — BUSY_MESSAGE refuses immediately and queues nothing, so a client
 * is told to wait rather than left to discover it by timing out.
 */
export const MAX_INFLIGHT_REQUESTS = 8

/** Small enough that MAX_INFLIGHT_REQUESTS bodies cannot exhaust memory. */
export const MAX_BODY_BYTES = 4 * 1024 * 1024

/**
 * How often a call parked on a dialog reports that it is still parked.
 *
 * Belt and braces rather than the load-bearing part: the transport already
 * keeps the SSE connection warm by itself, so the bytes flow with or without
 * this. What progress adds is a client-visible reason for the wait — an idle
 * window is reset either way, but only this says *why* nothing has come back.
 *
 * Under the transport's own 15s keep-alive so the two never coincide for long,
 * and far under any client's idle window.
 */
export const PROGRESS_INTERVAL_MS = 20_000

/**
 * Awaits a human decision, saying so periodically while it waits.
 *
 * A no-op passthrough unless the caller asked to be kept informed: progress is
 * addressed to a `progressToken` the client mints per request, and there is
 * nothing to address a notification to when the client did not send one. That
 * is a real case, not a defensive one — the token is optional in the protocol —
 * so the waiting itself must not depend on it.
 *
 * Notification failures are swallowed on purpose. A client that has gone away
 * must not turn into a rejected tool call for a human who is still deciding,
 * and whose answer is still worth delivering if the stream survives.
 */
export async function whileAwaitingHuman<T>(
  extra: {
    _meta?: { progressToken?: string | number }
    sendNotification: (notification: {
      method: 'notifications/progress'
      params: { progressToken: string | number; progress: number; message?: string }
    }) => Promise<void>
  },
  pending: Promise<T>
): Promise<T> {
  const progressToken = extra._meta?.progressToken
  if (progressToken === undefined) return pending

  let progress = 0
  const timer = setInterval(() => {
    progress++
    void extra
      .sendNotification({
        method: 'notifications/progress',
        // No total: nobody knows how long a person takes, and a made-up
        // denominator would render as a progress bar that lies.
        params: { progressToken, progress, message: 'Waiting for the human to decide.' }
      })
      .catch(() => {})
  }, PROGRESS_INTERVAL_MS)
  timer.unref?.()

  try {
    return await pending
  } finally {
    clearInterval(timer)
  }
}

const BUSY_MESSAGE =
  `ConsoleWard is already handling ${MAX_INFLIGHT_REQUESTS} requests and will not start ` +
  'another. This one was not queued. Let the earlier ones finish and send it again.'

/**
 * Whether the approval gate is currently switched off, and whether the list is
 * still under it.
 *
 * Read per call rather than captured at start-up: the settings dialog can move
 * either of these while a client is connected, and the value that matters is
 * the one at the moment the command arrives. A locked vault has no settings to
 * read and no sessions to run on, so it reports the safe answer.
 */
/** The head of a file, for a dialog: enough to recognise it, never the whole thing. */
const UPLOAD_PREVIEW_LINES = 40
const UPLOAD_PREVIEW_CHARS = 4000

function previewOf(content: string): { text: string; truncated: boolean } {
  const lines = content.split('\n')
  const head = lines.slice(0, UPLOAD_PREVIEW_LINES).join('\n')
  const text = head.slice(0, UPLOAD_PREVIEW_CHARS)
  return { text, truncated: text.length < content.length }
}

function gateState(): { dangerous: boolean; guard: boolean; upload: boolean } {
  if (!vault.isUnlocked()) return { dangerous: false, guard: true, upload: false }
  const s = vault.read().settings
  return {
    dangerous: s.dangerousMode === true,
    guard: s.dangerousGuard !== false,
    // Its own switch, and only meaningful while unattended mode is on.
    upload: s.dangerousUpload === true
  }
}

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
    // An ordinary MCP client sends no Origin; when one is sent it must match.
    // Stops a page open in a browser from attacking the server.
    const allowedOrigins = [`http://127.0.0.1:${this.port}`, `http://localhost:${this.port}`]

    const server = createServer((req, res) => {
      void (async () => {
        // Stateless: fresh server and transport per request. Neither half can
        // serve two requests AT ONCE, so sharing would serialise every request
        // behind a run_command waiting up to five minutes on a human, and closing
        // one to admit the next aborts the handler that is doing the waiting.
        let mcpServer: McpServer | null = null
        let transport: StreamableHTTPServerTransport | null = null
        let slot = false
        try {
          // Name first, credentials second, both every time, one answer for
          // either failure: a browser page can only put its own name in Host, and
          // a distinct status for a bad name tells a guessing page we are here.
          // Neither may short-circuit the other — `&&` reinstates a timing oracle.
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

          // POST only, and it must stay that way: a GET is the notification
          // stream the SDK client holds for its whole session, so counting those
          // spends a slot on merely connecting and wedges the gateway at 503.
          // Streams stay bounded by the Host gate, the token and the approval cap.
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
          /*
            SSE, not buffered JSON, and the difference is the whole reason a
            call can wait on a human at all.

            Under `enableJsonResponse: true` the transport returns a promise
            that only settles once every response is ready, so not one byte —
            not even the status line — leaves before the tool handler returns.
            Our handlers return when a person answers a dialog. Clients time out
            on the first response byte: Claude Code allows 60 seconds for an
            HTTP MCP server, which is nowhere near long enough to read a command
            and decide. The call died while the dialog was still open, and the
            human's eventual answer landed on a request nobody was listening to.

            With SSE the transport writes the headers and hands back a live
            stream immediately, then pushes the result into it whenever it
            arrives. It also keeps the connection warm on its own — a
            `: keepalive` comment every 15s by default — which holds open the
            separate idle window clients apply after the first byte.

            Switching cannot break a client that works today: the transport
            already requires `Accept: text/event-stream` on every POST, in both
            modes, so anything talking to us has always had to accept a stream.
          */
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            enableDnsRebindingProtection: true,
            allowedHosts,
            allowedOrigins
          })
          await mcpServer.connect(transport)
          await transport.handleRequest(req, res, body)
        } catch (err) {
          /*
            Which branch runs is decided by SSE, so the split is worth stating.

            Everything that can be refused deliberately — a bad name or token,
            a locked vault, a full gateway, a body over the cap — happens above,
            before `handleRequest` is ever called, so the headers are still
            unsent and those callers get the status and JSON-RPC error they got
            before. `readJsonBody` in particular runs first, which is what keeps
            413 intact.

            The other branch is now reachable only for a failure inside
            `handleRequest` itself, once the stream is live. There is no status
            code left to send at that point — 200 went out with the headers — so
            the client sees a stream that ends without ever carrying a response
            to its request id. Its own request timeout is what surfaces that,
            and there is no way to do better without inventing a JSON-RPC error
            for an id we may not have parsed. Ending the response rather than
            leaving it open is the part that matters: a dangling stream would
            keep the client waiting for the full idle window instead.
          */
          if (!res.headersSent) {
            // Never `String(err)`: it ships the human's translated message to the
            // client and echoes the caller's own bytes back inside a SyntaxError.
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
          // Cleanup only once the response is done, or a live stream is cut short.
          // `onceClosed` and not `res.on`: a client that gave up has already closed
          // the response, and a listener added then never fires — nothing closed.
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
      // Loopback only — the server must not be reachable from the network.
      server.listen(this.port, '127.0.0.1', resolve)
    })

    this.http = server
  }

  /**
   * `closeAllConnections()` is required, not belt-and-braces: `server.close()`
   * waits for open sockets, and the MCP notification stream is one the client
   * holds for its whole session — without it this never resolves and neither
   * does `restart()`. Dropping mid-request is intended; the vault has locked or
   * the gateway is off, so there is nothing left to answer.
   */
  async stop(): Promise<void> {
    const server = this.http
    this.http = null
    if (!server) return
    await new Promise<void>((resolve) => {
      server.close(() => resolve())
      server.closeAllConnections()
    })
  }

  async restart(): Promise<void> {
    await this.stop()
    await this.start()
  }

  async stopOnLock(): Promise<void> {
    await this.stop()
  }

  /**
   * Constant-time for any input, including the wrong length. Hashing both sides
   * first is what buys that: `timingSafeEqual` throws on unequal lengths, and
   * the early return that avoids the throw leaks the token's length.
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
        /*
          Written from the gate's actual state, not from what the product is
          usually true of. The old text promised "a human approves every
          command" unconditionally; with dangerous mode on, that sentence is a
          falsehood told to the party least able to check it, and a model that
          believes a person is reading its proposals behaves differently from
          one that knows nobody is.
        */
        instructions: instructionsFor(gateState())
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
        // `listForModel`, never `ssh.list()`: the latter returns SessionInfo, whose
        // `title` falls back to `username@host` — the address this tool withholds.
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
      async ({ session_id, reason }, extra) => {
        const bridge = this.bridge
        if (!bridge) return toolError(modelErrorFor({ key: 'error.mcpBridgeMissing' }))
        if (!ssh.isReady(session_id)) return toolError('The session does not exist or is not ready.')

        let preview: string
        try {
          preview = ssh.readText(session_id, 400)
        } catch (err) {
          return toolError(modelErrorFor(err))
        }

        // Unattended: the output goes back whole, with no one deciding what
        // part of it should. The session is still echoed to the terminal, so a
        // person returning to the window can at least see what was read.
        if (gateState().dangerous) {
          await aiLog.record(session_id, ssh.title(session_id), {
            kind: 'readTerminal',
            reason,
            chars: preview.length
          })
          return sharedResult(preview)
        }

        let answer: { shared: boolean; text: string }
        try {
          answer = await whileAwaitingHuman(
            extra,
            bridge.askShare({
              id: randomUUID(),
              sessionId: session_id,
              sessionName: ssh.title(session_id),
              reason,
              origin: 'read_terminal',
              text: preview
            })
          )
        } catch (err) {
          if (!isQueueFull(err)) throw err
          return toolError(QUEUE_FULL_MESSAGE)
        }

        if (!answer.shared) {
          await aiLog.record(session_id, ssh.title(session_id), {
            kind: 'withheld',
            origin: 'read_terminal',
            reason
          })
          return toolError('The human declined to share the output.')
        }
        await aiLog.record(session_id, ssh.title(session_id), {
          kind: 'shared',
          origin: 'read_terminal',
          chars: answer.text.length,
          edited: answer.text !== preview
        })
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
      async ({ session_id, command, reason }, extra) => {
        const bridge = this.bridge
        if (!bridge) return toolError(modelErrorFor({ key: 'error.mcpBridgeMissing' }))
        if (!ssh.isReady(session_id)) return toolError('The session does not exist or is not ready.')
        if (!command.trim()) return toolError('Empty command.')

        const gate = gateState()
        /*
          Unattended mode is a statement about trust, not about supervision: the
          AI works on its own and the human reads the record afterwards. The list
          is not a wall across that — it decides the few cases where working on
          its own stops being reasonable, and escalates those to the ordinary
          dialog with the offending span highlighted.

          A refusal was the first shape this took, and it was the wrong one. It
          left the model arguing with a regular expression and the human unable
          to say yes to something they would have approved in a second.
        */
        const hit = gate.dangerous && gate.guard ? matchDangerous(command) : null
        /*
          The span is translated here, into coordinates over the visualised text
          the dialog actually renders. Visualising is a per-character
          substitution, so it composes: visualising the three pieces and joining
          them gives the same string as visualising the whole, and the lengths of
          the first two pieces are the offsets the renderer needs. Doing it there
          instead would mean shipping the raw command and the visualiser to the
          renderer, for a highlight.
        */
        const flagged = hit
          ? {
              id: hit.id,
              what: hit.what,
              span: hit.span
                ? {
                    start: visualizeControlChars(command.slice(0, hit.span.start)).length,
                    end:
                      visualizeControlChars(command.slice(0, hit.span.start)).length +
                      visualizeControlChars(command.slice(hit.span.start, hit.span.end)).length
                  }
                : null
            }
          : null

        if (gate.dangerous && !flagged) {
          // Nobody is asked on this path, so the log is the only record that it
          // happened at all. Recorded before the run, or a command that hangs
          // leaves nothing behind.
          const name = ssh.title(session_id)
          await aiLog.record(session_id, name, { kind: 'unattended', command, reason })
          let ran: RunResult
          try {
            ran = await ssh.runOnce(session_id, command)
          } catch (err) {
            await aiLog.record(session_id, name, {
              kind: 'ran',
              command,
              exitCode: null,
              output: modelErrorFor(err)
            })
            return toolError(modelErrorFor(err))
          }
          await aiLog.record(session_id, name, {
            kind: 'ran',
            command,
            exitCode: ran.exitCode,
            output: ran.output
          })
          return sharedResult(ran.output, ran)
        }

        await aiLog.record(session_id, ssh.title(session_id), {
          kind: 'proposed',
          command,
          reason,
          ...(flagged ? { flagged: flagged.id } : {})
        })

        let approval: { approved: boolean; autoShare: boolean }
        try {
          approval = await whileAwaitingHuman(
            extra,
            bridge.askCommand({
              id: randomUUID(),
              sessionId: session_id,
              sessionName: ssh.title(session_id),
              command,
              commandVisualized: visualizeControlChars(command),
              reason,
              ...(flagged ? { flagged } : {})
            })
          )
        } catch (err) {
          if (!isQueueFull(err)) throw err
          return toolError(QUEUE_FULL_MESSAGE)
        }

        if (!approval.approved) {
          await aiLog.record(session_id, ssh.title(session_id), {
            kind: 'denied',
            command,
            ...(flagged ? { flagged: flagged.id } : {})
          })
          // A flagged command earns a more specific answer than the generic
          // refusal: the model should learn it was singled out for review, which
          // is the difference between rewording it and not sending it again.
          return toolError(
            flagged ? deniedAfterFlag(flagged) : 'The human did not approve the command.'
          )
        }

        await aiLog.record(session_id, ssh.title(session_id), {
          kind: 'approved',
          command,
          autoShare: approval.autoShare
        })

        let result: RunResult
        try {
          result = await ssh.runOnce(session_id, command)
        } catch (err) {
          await aiLog.record(session_id, ssh.title(session_id), {
            kind: 'ran',
            command,
            exitCode: null,
            output: modelErrorFor(err)
          })
          return toolError(modelErrorFor(err))
        }

        await aiLog.record(session_id, ssh.title(session_id), {
          kind: 'ran',
          command,
          exitCode: result.exitCode,
          output: result.output
        })

        // The tick was given while reading the COMMAND, before any output existed,
        // so it is revoked when the output looks like it carries a credential.
        const overridden = approval.autoShare && outputNeedsReview(result)
        if (approval.autoShare && !overridden) {
          return sharedResult(result.output, result)
        }

        // No queue-full guard: `origin: 'command_output'` is the cap exemption in
        // approvals.ts, so changing it makes this call able to reject.
        // `autoShareOverridden` is also the queue's force-raise flag — the human
        // was promised no dialog, so a hidden one would time out into a denial.
        const answer = await whileAwaitingHuman(
          extra,
          bridge.askShare({
            id: randomUUID(),
            sessionId: session_id,
            sessionName: ssh.title(session_id),
            reason: `Command output: ${command}`,
            origin: 'command_output',
            text: result.output,
            autoShareOverridden: overridden
          })
        )

        if (!answer.shared) {
          await aiLog.record(session_id, ssh.title(session_id), {
            kind: 'withheld',
            origin: 'command_output',
            reason: command
          })
          return {
            content: [
              {
                type: 'text' as const,
                text: 'The command ran, but the human chose not to share its output.'
              }
            ]
          }
        }
        // `edited` is the part the model cannot see: what it receives may be a
        // trimmed version of what actually came back, and only the log holds both.
        await aiLog.record(session_id, ssh.title(session_id), {
          kind: 'shared',
          origin: 'command_output',
          chars: answer.text.length,
          edited: answer.text !== result.output
        })
        return sharedResult(answer.text, result)
      }
    )

    server.registerTool(
      'save_command',
      {
        title: 'Keep a command in the human’s library',
        description:
          'Proposes a command for the saved-command library, so a sequence worked out once can be kept. ' +
          'It is not run. A human approves the text before it is stored, and anything stored this way is ' +
          'marked as written by an AI and asks for confirmation every time it is run afterwards. ' +
          'Use it for something worth running again, not as a way to leave notes — and say in `reason` ' +
          'why it is worth keeping. You cannot read, edit or delete what is already in the library.',
        inputSchema: {
          title: z.string().describe('short name the human will see in the list'),
          body: z.string().describe('the exact command text'),
          note: z.string().optional().describe('what it does and when to use it'),
          folder: z.string().optional().describe('existing or new folder to file it under'),
          reason: z.string().describe('why it is worth keeping; the human reads this in the dialog')
        },
        annotations: { destructiveHint: false, openWorldHint: false }
      },
      async ({ title, body, note, folder, reason }, extra) => {
        const bridge = this.bridge
        if (!bridge) return toolError(modelErrorFor({ key: 'error.mcpBridgeMissing' }))
        if (!title.trim()) return toolError('Empty title.')
        if (!body.trim()) return toolError('Empty command.')

        /*
          Unattended mode skips this approval too, deliberately: carving out an
          exception for saving would make the mode mean something different
          depending on which tool was called.

          The cost lands entirely on the provenance mark. A saved command is
          persistent, is echoed nowhere, and is trusted later out of the context
          it was written in — so the `ai` origin and the confirm-on-run it forces
          are the whole difference between this and an unreviewed one-liner the
          user runs next week believing they wrote it. The log below is the other
          half: without it an unattended write leaves no record at all.
        */
        const unattended = gateState().dangerous
        const request: SaveCommandApproval = {
          id: randomUUID(),
          title: title.trim(),
          body,
          bodyVisualized: visualizeControlChars(body),
          note,
          folder,
          reason
        }

        let answer: { approved: boolean }
        try {
          answer = await whileAwaitingHuman(extra, bridge.saveCommand(request, unattended))
        } catch (err) {
          if (!isQueueFull(err)) throw err
          return toolError(QUEUE_FULL_MESSAGE)
        }

        await aiLog.record('library', 'Saved commands', {
          kind: 'savedCommand',
          title: request.title,
          body,
          approved: answer.approved
        })

        if (!answer.approved) return toolError('The human did not approve saving this command.')
        return {
          content: [
            {
              type: 'text' as const,
              text:
                `Saved as "${request.title}". It is marked as written by an AI, so the human is ` +
                'asked to confirm each time they run it.'
            }
          ]
        }
      }
    )

    server.registerTool(
      'upload_file',
      {
        title: 'Write a file on the server',
        description:
          'Writes a text file at the given path over SFTP, on the same connection as the session. ' +
          'A human approves the destination and the content unless they have turned that off. ' +
          'It creates or overwrites — there is no append, and no way to read a file back. ' +
          'Paths are POSIX and ~ expands on the server. Keep it to configuration, unit files and ' +
          'scripts: the limit is 1 MB and the content travels inside this call. ' +
          'Say in `reason` what the file is for.',
        inputSchema: {
          session_id: z.string().describe('session id from list_sessions'),
          path: z.string().describe('absolute or ~-relative destination path on the server'),
          content: z.string().describe('the exact file content'),
          reason: z.string().describe('what the file is for; the human reads this in the dialog')
        },
        annotations: { destructiveHint: true, openWorldHint: false }
      },
      async ({ session_id, path, content, reason }, extra) => {
        const bridge = this.bridge
        if (!bridge) return toolError(modelErrorFor({ key: 'error.mcpBridgeMissing' }))
        if (!ssh.isReady(session_id)) return toolError('The session does not exist or is not ready.')
        if (!path.trim()) return toolError('Empty path.')

        const bytes = Buffer.byteLength(content, 'utf8')
        if (bytes > UPLOAD_MAX_BYTES) {
          return toolError(
            `The file is ${bytes} bytes; the limit is ${UPLOAD_MAX_BYTES}. Write it in pieces with ` +
              'run_command, or fetch it on the server instead.'
          )
        }

        const resolvedPath = normaliseRemotePath(path)
        const sensitive = matchSensitivePath(resolvedPath)

        /*
          Three switches decide this, and only all three together skip the human:
          unattended mode, its own upload switch, and a destination that is not
          on the list. The upload switch is separate from unattended mode because
          a file lands once and is then run by something else, at a time nobody
          is watching — which is a different trade from a command whose output
          echoes into a session the human can read back.
        */
        const gate = gateState()
        const unattended = gate.dangerous && gate.upload && !sensitive

        const name = ssh.title(session_id)
        if (!unattended) {
          const preview = previewOf(content)
          let answer: { approved: boolean }
          try {
            answer = await whileAwaitingHuman(
              extra,
              bridge.askUpload({
                id: randomUUID(),
                sessionId: session_id,
                sessionName: name,
                path,
                resolvedPath,
                bytes,
                preview: visualizeControlChars(preview.text),
                previewTruncated: preview.truncated,
                reason,
                ...(sensitive ? { flagged: { id: sensitive.id, what: sensitive.what } } : {})
              })
            )
          } catch (err) {
            if (!isQueueFull(err)) throw err
            return toolError(QUEUE_FULL_MESSAGE)
          }

          if (!answer.approved) {
            await aiLog.record(session_id, name, {
              kind: 'uploadDenied',
              path: resolvedPath,
              bytes
            })
            return toolError(
              sensitive
                ? `The human did not approve writing to ${resolvedPath}. It was flagged as ` +
                    `${sensitive.what} (rule ${sensitive.id}) and shown to them with that warning. ` +
                    'Do not rephrase the path to get around it — ask for what you need instead.'
                : 'The human did not approve the upload.'
            )
          }
        }

        try {
          await ssh.upload(session_id, path, Buffer.from(content, 'utf8'))
        } catch (err) {
          return toolError(modelErrorFor(err))
        }

        await aiLog.record(session_id, name, {
          kind: 'uploaded',
          path: resolvedPath,
          bytes,
          content,
          unattended
        })

        return {
          content: [
            { type: 'text' as const, text: `Wrote ${bytes} bytes to ${resolvedPath}.` }
          ]
        }
      }
    )

    return server
  }

}

/** The model must be told it sees an excerpt, or it reasons as if it saw all. */
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

/** With no terminal, sudo and friends fail instead of prompting; say why. */
const NEEDS_TTY = /a terminal is required|no tty present|must be run from a terminal|not a tty/i

/**
 * Describes the run for the model, so always English. The TTY hint must come
 * from `shared` — the text actually being sent — and never from the raw
 * capture, or the note becomes a one-bit oracle over a redacted line.
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
 * Errors for the model: keyed, never the translated AppError message, which
 * carries the human's language and changes when they switch it. A Map, not an
 * object literal, so a key like `constructor` cannot reach Object.prototype.
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
 * The fallback names nothing: an unmapped error may carry a local path or a
 * server's own words. Read defensively — a `SyntaxError` has no `key` at all.
 */
/**
 * What the model is told about the gate it is behind. Fixed English throughout.
 *
 * The unattended wording is deliberately blunt. A model that knows nothing will
 * stop it is the one that should be most careful, and telling it otherwise
 * would be both untrue and counterproductive.
 */
export function instructionsFor(state: { dangerous: boolean; guard: boolean }): string {
  const common = [
    'Access to the SSH sessions of ConsoleWard.',
    'Server addresses, usernames and passwords are not available and never will be.',
    'Commands run in their own channel, not in the terminal the human is looking at: a fresh non-interactive shell in the home directory, with no terminal and no state carried over from your previous calls.'
  ]

  if (!state.dangerous) {
    return [
      common[0],
      common[1],
      'A human approves every command, and decides what part of its output reaches you — sometimes in advance, sometimes only after seeing it. Respect a refusal and do not retry it in a different shape.',
      'Whatever output you receive may be trimmed or edited by the human, so never assume you are seeing everything.',
      common[2]
    ].join(' ')
  }

  return [
    common[0],
    common[1],
    'The human has switched off the approval step. Commands you propose RUN IMMEDIATELY on a real machine, and you receive the output in full. Nobody is reading these first, so there is no one to catch a mistake before it lands.',
    state.guard
      ? 'A short list of irreversible commands is still shown to the human for approval rather than running straight away — the destination or the offending part is highlighted for them. That list catches accidents, not intent, and it is not permission to try things: anything it does not recognise runs with nobody looking.'
      : 'Nothing is checked. Every command you send runs exactly as written.',
    'Prefer reading over writing, make one change at a time, and say what you are about to do before you do it. If a command would be hard to undo, ask the human instead of running it.',
    common[2]
  ].join(' ')
}

export function modelErrorFor(err: unknown): string {
  const key = (err as { key?: unknown } | null | undefined)?.key
  const mapped = typeof key === 'string' ? MODEL_ERRORS.get(key) : undefined
  return mapped ?? 'ConsoleWard could not carry out the request.'
}

/**
 * Must this output be shown despite the auto-share tick? The tick was a promise
 * about text nobody had seen, revoked when the text looks like a credential.
 *
 * `truncated` and `clipped` mean part of it went unread — by RUN_OUTPUT_BYTES or
 * MAX_SCAN_CHARS — so a credential could sit there. `clipped` cannot fire while
 * RUN_OUTPUT_BYTES is half MAX_SCAN_CHARS; it guards a later change to either.
 * Only `high` forces the dialog: `medium` fires on every `ip a` and `sha256sum`,
 * and a checkbox that never applies is the habituation `secretPatterns.ts` names.
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
 * Must mirror `validateRequestHeaders` in the SDK exactly — same arrays, exact
 * string match, Origin rejected only when present and wrong. Looser and the
 * request reaches the transport and gets a *different* answer, the oracle this
 * removes; stricter and it refuses a client the transport accepts. The exact
 * match is what rejects `[::1]:7345`, `LOCALHOST:7345`, `localhost.evil.com` and
 * a rebound name, since a browser puts the NAME in Host, not the address.
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
 * One answer for a wrong token and a wrong name alike: enough for the operator
 * of a real client, nothing for a page guessing whether we are listening here.
 */
const REJECTED =
  'Rejected. ConsoleWard needs the bearer token from its settings, and it must be reached at ' +
  '127.0.0.1 or localhost on its own port. A request arriving under any other name is refused ' +
  'whatever token it carries.'

/**
 * Fixed length as well as fixed text: the SDK echoes the offending Host back, so
 * content-length alone tells `[::1]` apart from `127.0.0.2`. `reason` is only
 * for causes a client may legitimately distinguish; the rejection carries none.
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

/** Only a POST counts against `MAX_INFLIGHT_REQUESTS`. Exported for the tests. */
export function takesSlot(method: string | undefined): boolean {
  return method === 'POST'
}

/**
 * Runs `cleanup` when the response is done — including when it is done already,
 * which is the case whenever a client gave up while the handler waited on a
 * human: a listener added then never fires and leaks server and transport.
 * Deliberately not eager, since the transport's close() does not resolve the
 * promise `handleRequest` awaits and would strand the handler for ever.
 */
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
 * Must carry a translation key: `fail()` in index.ts forwards a message to the
 * renderer only when it has one, so a bare `Error` turns "port 7345 is already
 * in use" — the one message the user can act on — into a generic sentence.
 */
function listenError(err: unknown, port: number): AppError {
  const code = (err as NodeJS.ErrnoException)?.code
  if (code === 'EADDRINUSE') return appError('error.portInUse', { port })
  if (code === 'EACCES') return appError('error.portNotAllowed', { port })
  // The raw text is deliberate here and only here: an unrecognised listen failure
  // is not actionable without it, and a socket error carries no path.
  return appError('error.serverStartFailed', { message: String(err) })
}

/**
 * Reads the JSON-RPC body — the transport wants it already parsed. The size
 * guard counts as it goes, so an oversized body stops being buffered rather
 * than being noticed afterwards.
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

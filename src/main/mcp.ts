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
import { visualizeControlChars } from './ansi'
import { ssh } from './ssh'
import { vault } from './vault'
import { appError, t } from './i18n'

export interface McpBridge {
  /** Zobrazí dialog se schválením příkazu. */
  askCommand: (req: CommandApproval) => Promise<{ approved: boolean; autoShare: boolean }>
  /** Zobrazí dialog pro výběr části výstupu. */
  askShare: (req: ShareRequest) => Promise<{ shared: boolean; text: string }>
  /** Vytáhne okno dopředu, aby dialog nezůstal schovaný. */
  focusWindow: () => void
}

const DEFAULT_PORT = 7345

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
          'A human approves every command and every read of the output inside the app. Respect a refusal and do not retry it in a different shape.',
          'Whatever output you receive may be trimmed or edited by the human, so never assume you are seeing everything.'
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

        bridge.focusWindow()
        const answer = await bridge.askShare({
          id: randomUUID(),
          sessionId: session_id,
          sessionName: ssh.title(session_id),
          reason,
          origin: 'read_terminal',
          text: preview
        })

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
          'You receive the output only if the human chooses to share it. ' +
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

        bridge.focusWindow()
        const approval = await bridge.askCommand({
          id: randomUUID(),
          sessionId: session_id,
          sessionName: ssh.title(session_id),
          command,
          commandVisualized: visualizeControlChars(command),
          reason
        })

        if (!approval.approved) return toolError('The human did not approve the command.')

        let result: { output: string; timedOut: boolean }
        try {
          result = await ssh.runAndCapture(session_id, command)
        } catch (err) {
          return toolError((err as Error).message)
        }

        if (approval.autoShare) {
          return sharedResult(result.output, result.timedOut)
        }

        const answer = await bridge.askShare({
          id: randomUUID(),
          sessionId: session_id,
          sessionName: ssh.title(session_id),
          reason: `Command output: ${command}`,
          origin: 'command_output',
          text: result.output
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
        return sharedResult(answer.text, result.timedOut)
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
function sharedResult(text: string, timedOut = false): {
  content: { type: 'text'; text: string }[]
} {
  const notes = [
    'Note: a human selected and possibly edited this content, so it may be incomplete.',
    timedOut ? 'Output capture hit its time limit, so the command may still be running.' : null
  ].filter(Boolean)

  return {
    content: [{ type: 'text' as const, text: `${notes.join(' ')}\n\n${text}` }]
  }
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

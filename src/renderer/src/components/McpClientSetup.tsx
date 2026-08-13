// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useState } from 'react'
import { api } from '../api'
import { useT } from '../i18n'

interface Props {
  port: number
  token: string | null
  /** Shared with the token field above, so revealing once reveals everywhere. */
  tokenVisible: boolean
  onCopied: (message: string) => void
}

type ClientId = 'claudeCode' | 'claudeDesktop' | 'vscode' | 'chatgpt'

const CLIENTS: { id: ClientId; labelKey: string }[] = [
  { id: 'claudeCode', labelKey: 'mcpSetup.claudeCode' },
  { id: 'claudeDesktop', labelKey: 'mcpSetup.claudeDesktop' },
  { id: 'vscode', labelKey: 'mcpSetup.vscode' },
  { id: 'chatgpt', labelKey: 'mcpSetup.chatgpt' }
]

/**
 * Per-client connection instructions for the gateway.
 *
 * The three that can connect need three different things, and getting any of
 * them slightly wrong produces a client that silently lists no tools — so the
 * snippet is built here from the live port and token rather than left to be
 * assembled by hand.
 *
 * ChatGPT is listed even though it cannot connect. Leaving it out invites the
 * question every few weeks; saying why once, in the place someone looks, is the
 * shorter answer. See the note in `snippetFor`.
 */
export default function McpClientSetup({ port, token, tokenVisible, onCopied }: Props) {
  const t = useT()
  const [client, setClient] = useState<ClientId>('claudeCode')

  const base = `http://127.0.0.1:${port}/`
  /** What goes on screen: the real token only once the human has revealed it. */
  const shown = tokenVisible ? (token ?? '') : '•'.repeat(32)
  /** What goes on the clipboard: always the real thing, or nothing at all. */
  const real = token ?? ''

  function snippetFor(secret: string): string {
    switch (client) {
      case 'claudeCode':
        return (
          `claude mcp add --scope user --transport http consoleward ${base} ` +
          `--header "Authorization: Bearer ${secret}"`
        )

      /*
        Claude Desktop speaks stdio to local servers and reaches HTTP ones only
        as a Custom Connector, which wants a public URL and runs its own auth —
        there is nowhere to put a bearer token, and nowhere to put a loopback
        address. `mcp-remote` bridges the two: a stdio process the app can
        launch, forwarding to our HTTP endpoint with the header attached.
      */
      case 'claudeDesktop':
        return JSON.stringify(
          {
            mcpServers: {
              consoleward: {
                command: 'npx',
                args: ['-y', 'mcp-remote@latest', base, '--header', `Authorization: Bearer ${secret}`]
              }
            }
          },
          null,
          2
        )

      case 'vscode':
        return JSON.stringify(
          {
            servers: {
              consoleward: {
                type: 'http',
                url: base,
                headers: { Authorization: `Bearer ${secret}` }
              }
            }
          },
          null,
          2
        )

      /*
        Not an oversight and not a gap to close later. ChatGPT refuses loopback
        addresses and requires a server reachable over public HTTPS, so the only
        way to satisfy it is to put this gateway on the internet behind a tunnel.
        That would hand every SSH session in the vault to anyone who guesses or
        steals one bearer token, and 127.0.0.1-only is the first invariant this
        application claims. So the instructions here are the reason, not a
        workaround: offering the tunnel would be the bug.
      */
      case 'chatgpt':
        return ''
    }
  }

  const snippet = snippetFor(shown)
  const copyable = client !== 'chatgpt' && Boolean(token)

  async function copy(): Promise<void> {
    await api.clipboard.write(snippetFor(real))
    onCopied(t('mcpSetup.copied'))
  }

  return (
    <div className="mcp-setup">
      <div className="meta-label">{t('mcpSetup.title')}</div>
      <p className="hint">{t('mcpSetup.intro')}</p>

      <div className="client-tabs">
        {CLIENTS.map((c) => (
          <button
            key={c.id}
            type="button"
            className={client === c.id ? 'tab active' : 'tab'}
            onClick={() => setClient(c.id)}
          >
            {t(c.labelKey)}
          </button>
        ))}
      </div>

      {client === 'chatgpt' ? (
        <div className="warn-box">{t('mcpSetup.chatgptWhyNot')}</div>
      ) : (
        <>
          <p className="hint">{t(`mcpSetup.${client}Step`)}</p>

          {client !== 'claudeCode' && (
            <div className="path-row">
              <code className="mono">{t(`mcpSetup.${client}Path`)}</code>
            </div>
          )}

          <pre className="setup-snippet">{snippet}</pre>

          <div className="secret-row">
            <button type="button" className="btn small" disabled={!copyable} onClick={() => void copy()}>
              {t('mcpSetup.copy')}
            </button>
            {!tokenVisible && <span className="hint">{t('mcpSetup.hiddenNote')}</span>}
          </div>

          {client === 'claudeDesktop' && <p className="hint">{t('mcpSetup.claudeDesktopNode')}</p>}
        </>
      )}

      <p className="hint">{t('mcpSetup.lockedNote')}</p>
    </div>
  )
}

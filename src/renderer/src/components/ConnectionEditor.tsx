// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useState } from 'react'
import type { AuthKind, ConnectionInput, ConnectionMeta } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'

interface Props {
  /** null = new connection */
  connection: ConnectionMeta | null
  onSaved: (saved: ConnectionMeta) => void
  onCancel: () => void
}

/**
 * Secrets are never sent to the renderer, so the fields start out empty and are
 * submitted only when the user actually fills them in.
 */
export default function ConnectionEditor({ connection, onSaved, onCancel }: Props) {
  const t = useT()
  const isNew = connection === null

  const [name, setName] = useState(connection?.name ?? '')
  const [host, setHost] = useState(connection?.host ?? '')
  const [port, setPort] = useState(String(connection?.port ?? 22))
  const [username, setUsername] = useState(connection?.username ?? '')
  const [authKind, setAuthKind] = useState<AuthKind>(connection?.authKind ?? 'password')
  const [folder, setFolder] = useState(connection?.folder ?? '')
  const [notes, setNotes] = useState(connection?.notes ?? '')
  const [agentSocket, setAgentSocket] = useState(connection?.agentSocket ?? '')

  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [keyFileName, setKeyFileName] = useState<string | null>(null)

  const [clearPassword, setClearPassword] = useState(false)
  const [clearKey, setClearKey] = useState(false)
  const [clearPassphrase, setClearPassphrase] = useState(false)

  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const keptPassword = !isNew && connection.hasPassword && !clearPassword && !password
  const keptKey = !isNew && connection.hasPrivateKey && !clearKey && !privateKey
  const keptPassphrase = !isNew && connection.hasPassphrase && !clearPassphrase && !passphrase

  /** undefined = leave unchanged, '' = delete, anything else = the new value */
  function secret(value: string, clear: boolean): string | undefined {
    if (value) return value
    if (clear) return ''
    return undefined
  }

  async function loadKeyFile(): Promise<void> {
    try {
      const file = unwrap(await api.dialog.readTextFile(t('conn.privateKey')))
      if (!file) return
      if (file.content.includes('PuTTY-User-Key-File')) {
        setError(t('conn.ppkError'))
        return
      }
      setPrivateKey(file.content)
      setKeyFileName(file.name)
      setClearKey(false)
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setError(null)

    if (authKind === 'key' && !privateKey && !keptKey) {
      setError(t('conn.keyRequired'))
      return
    }

    const input: ConnectionInput = {
      id: connection?.id,
      name,
      host,
      port: Number(port),
      username,
      authKind,
      folder,
      notes,
      agentSocket,
      password: secret(password, clearPassword),
      privateKey: secret(privateKey, clearKey),
      passphrase: secret(passphrase, clearPassphrase)
    }

    setBusy(true)
    try {
      onSaved(unwrap(await api.connections.save(input)))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onCancel}>
      <form className="modal wide-modal" onMouseDown={(e) => e.stopPropagation()} onSubmit={submit}>
        <div className="modal-head">
          <h2>{isNew ? t('conn.newTitle') : t('conn.editTitle', { name: connection.name })}</h2>
          <button type="button" className="icon-btn" onClick={onCancel} title={t('common.close')}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          <div className="grid-2">
            <label>
              {t('conn.name')}
              <input
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('conn.namePlaceholder')}
              />
            </label>
            <label>
              {t('conn.folder')} <span className="hint">{t('common.optional')}</span>
              <input
                value={folder}
                onChange={(e) => setFolder(e.target.value)}
                placeholder={t('conn.folderPlaceholder')}
              />
            </label>
          </div>

          <div className="grid-3">
            <label className="span-2">
              {t('conn.host')}
              <input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder={t('conn.hostPlaceholder')}
              />
            </label>
            <label>
              {t('conn.port')}
              <input
                value={port}
                onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))}
                inputMode="numeric"
              />
            </label>
          </div>

          <div className="grid-2">
            <label>
              {t('conn.username')}
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={t('conn.usernamePlaceholder')}
              />
            </label>
            <label>
              {t('conn.auth')}
              <select value={authKind} onChange={(e) => setAuthKind(e.target.value as AuthKind)}>
                <option value="password">{t('conn.authPassword')}</option>
                <option value="key">{t('conn.authKey')}</option>
                <option value="agent">{t('conn.authAgent')}</option>
              </select>
            </label>
          </div>

          {authKind === 'password' && (
            <label>
              {t('conn.password')}
              <div className="secret-row">
                <input
                  type="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value)
                    setClearPassword(false)
                  }}
                  placeholder={
                    keptPassword ? t('conn.passwordStored') : t('conn.passwordPlaceholder')
                  }
                />
                {keptPassword && (
                  <button type="button" className="btn small" onClick={() => setClearPassword(true)}>
                    {t('common.delete')}
                  </button>
                )}
                {clearPassword && <span className="badge warn">{t('conn.willBeDeleted')}</span>}
              </div>
            </label>
          )}

          {authKind === 'key' && (
            <>
              <label>
                {t('conn.privateKey')}
                <div className="secret-row">
                  <button type="button" className="btn small" onClick={loadKeyFile}>
                    {t('conn.loadFromFile')}
                  </button>
                  {keyFileName && <span className="badge ok">{keyFileName}</span>}
                  {keptKey && !keyFileName && (
                    <span className="badge ok">{t('conn.keyStored')}</span>
                  )}
                  {keptKey && !keyFileName && (
                    <button type="button" className="btn small" onClick={() => setClearKey(true)}>
                      {t('common.delete')}
                    </button>
                  )}
                  {clearKey && <span className="badge warn">{t('conn.willBeDeleted')}</span>}
                </div>
                <textarea
                  rows={5}
                  value={privateKey}
                  onChange={(e) => {
                    setPrivateKey(e.target.value)
                    setClearKey(false)
                    setKeyFileName(null)
                  }}
                  placeholder={
                    keptKey ? t('conn.keyStoredPlaceholder') : t('conn.keyPlaceholder')
                  }
                  spellCheck={false}
                />
              </label>

              <label>
                {t('conn.passphrase')} <span className="hint">{t('conn.passphraseHint')}</span>
                <div className="secret-row">
                  <input
                    type="password"
                    value={passphrase}
                    onChange={(e) => {
                      setPassphrase(e.target.value)
                      setClearPassphrase(false)
                    }}
                    placeholder={keptPassphrase ? t('conn.passphraseStored') : ''}
                  />
                  {keptPassphrase && (
                    <button
                      type="button"
                      className="btn small"
                      onClick={() => setClearPassphrase(true)}
                    >
                      {t('common.delete')}
                    </button>
                  )}
                  {clearPassphrase && <span className="badge warn">{t('conn.willBeDeleted')}</span>}
                </div>
              </label>
            </>
          )}

          {authKind === 'agent' && (
            <label>
              {t('conn.agentSocket')} <span className="hint">{t('conn.agentSocketHint')}</span>
              <input
                value={agentSocket}
                onChange={(e) => setAgentSocket(e.target.value)}
                placeholder="pageant"
              />
            </label>
          )}

          <label>
            {t('conn.notes')}
            <textarea
              rows={2}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={t('conn.notesPlaceholder')}
            />
          </label>

          {error && <div className="form-error">{error}</div>}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn" onClick={onCancel}>
            {t('common.cancel')}
          </button>
          <button type="submit" className="btn primary" disabled={busy}>
            {busy ? t('common.saving') : t('common.save')}
          </button>
        </div>
      </form>
    </div>
  )
}

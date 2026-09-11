// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useState } from 'react'
import type { AuthKind, ConnectionInput, ConnectionMeta, SshKeyMeta } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'
import KeyEditor from './KeyEditor'

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
  const [logTranscript, setLogTranscript] = useState(connection?.logTranscript !== false)

  const [password, setPassword] = useState('')

  const [keys, setKeys] = useState<SshKeyMeta[]>([])
  const [keyId, setKeyId] = useState(connection?.keyId ?? '')
  const [addingKey, setAddingKey] = useState(false)

  const [clearPassword, setClearPassword] = useState(false)

  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const keptPassword = !isNew && connection.hasPassword && !clearPassword && !password
  /**
   * Key text still on the connection, from a vault written before the key
   * library — or one the migration could not parse. It keeps authenticating, so
   * the editor says so rather than showing an empty picker that looks broken.
   */
  const legacyKey = !isNew && connection.hasPrivateKey && !connection.keyId

  useEffect(() => {
    void (async () => {
      try {
        setKeys(unwrap(await api.keys.list()))
      } catch (err) {
        setError(errorMessage(err))
      }
    })()
  }, [])

  /** undefined = leave unchanged, '' = delete, anything else = the new value */
  function secret(value: string, clear: boolean): string | undefined {
    if (value) return value
    if (clear) return ''
    return undefined
  }

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setError(null)

    if (authKind === 'key' && !keyId && !legacyKey) {
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
      keyId,
      logTranscript,
      password: secret(password, clearPassword)
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
            <label>
              {t('conn.key')}
              <div className="secret-row">
                <select value={keyId} onChange={(e) => setKeyId(e.target.value)}>
                  <option value="">
                    {legacyKey ? t('conn.keyOnConnection') : t('conn.keyNone')}
                  </option>
                  {keys.map((k) => (
                    <option key={k.id} value={k.id}>
                      {k.name} · {k.keyType}
                    </option>
                  ))}
                </select>
                <button type="button" className="btn small" onClick={() => setAddingKey(true)}>
                  {t('keys.add')}
                </button>
              </div>
              <span className="hint">
                {legacyKey && !keyId ? t('conn.keyLegacyHint') : t('conn.keyHint')}
              </span>
            </label>
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

          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={logTranscript}
              onChange={(e) => setLogTranscript(e.target.checked)}
            />
            {t('conn.transcript')}
          </label>
          <span className="hint">{t('conn.transcriptHint')}</span>

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

      {addingKey && (
        <KeyEditor
          onSaved={(key) => {
            setKeys((prev) => [...prev, key])
            setKeyId(key.id)
            setAddingKey(false)
          }}
          onCancel={() => setAddingKey(false)}
        />
      )}
    </div>
  )
}

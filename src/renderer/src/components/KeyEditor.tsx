// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useState } from 'react'
import type { SshKeyMeta } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'

interface Props {
  onSaved: (key: SshKeyMeta) => void
  onCancel: () => void
}

type Mode = 'import' | 'generate'

/**
 * Adds a key to the library, by import or by generation.
 *
 * The private half is written straight into the vault and is never read back.
 * Generation shows the public key afterwards and nothing else — a screenshot of
 * this dialog has to be harmless.
 */
export default function KeyEditor({ onSaved, onCancel }: Props) {
  const t = useT()
  const [mode, setMode] = useState<Mode>('import')
  const [name, setName] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [type, setType] = useState<'ed25519' | 'rsa'>('ed25519')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function loadFile(): Promise<void> {
    try {
      const file = unwrap(await api.dialog.readTextFile(t('keys.privateKey')))
      if (!file) return
      setPrivateKey(file.content)
      setFileName(file.name)
      // The name is the one field the user would otherwise have to invent.
      if (!name.trim()) setName(file.name.replace(/\.(ppk|pem|key)$/i, ''))
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const saved =
        mode === 'import'
          ? unwrap(await api.keys.import({ name, privateKey, passphrase: passphrase || undefined }))
          : unwrap(await api.keys.generate({ name, type, passphrase: passphrase || undefined }))
      onSaved(saved)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onCancel}>
      <form className="modal" onMouseDown={(e) => e.stopPropagation()} onSubmit={submit}>
        <div className="modal-head">
          <h2>{t('keys.addTitle')}</h2>
          <button type="button" className="icon-btn" onClick={onCancel} title={t('common.close')}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          <div className="tabs">
            <button
              type="button"
              className={mode === 'import' ? 'tab active' : 'tab'}
              onClick={() => setMode('import')}
            >
              {t('keys.tabImport')}
            </button>
            <button
              type="button"
              className={mode === 'generate' ? 'tab active' : 'tab'}
              onClick={() => setMode('generate')}
            >
              {t('keys.tabGenerate')}
            </button>
          </div>

          <label>
            {t('keys.name')}
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('keys.namePlaceholder')}
            />
          </label>

          {mode === 'import' && (
            <label>
              {t('keys.privateKey')}
              <div className="secret-row">
                <button type="button" className="btn small" onClick={loadFile}>
                  {t('conn.loadFromFile')}
                </button>
                {fileName && <span className="badge ok">{fileName}</span>}
              </div>
              <textarea
                rows={5}
                value={privateKey}
                onChange={(e) => {
                  setPrivateKey(e.target.value)
                  setFileName(null)
                }}
                placeholder={t('conn.keyPlaceholder')}
                spellCheck={false}
              />
              <span className="hint">{t('keys.importHint')}</span>
            </label>
          )}

          {mode === 'generate' && (
            <label>
              {t('keys.type')}
              <select value={type} onChange={(e) => setType(e.target.value as 'ed25519' | 'rsa')}>
                <option value="ed25519">{t('keys.typeEd25519')}</option>
                <option value="rsa">{t('keys.typeRsa')}</option>
              </select>
              <span className="hint">{t('keys.typeHint')}</span>
            </label>
          )}

          <label>
            {t('conn.passphrase')} <span className="hint">{t('common.optional')}</span>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
            />
            <span className="hint">
              {mode === 'import' ? t('keys.passphraseImportHint') : t('keys.passphraseHint')}
            </span>
          </label>

          {error && <div className="form-error">{error}</div>}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn" onClick={onCancel}>
            {t('common.cancel')}
          </button>
          <button type="submit" className="btn primary" disabled={busy}>
            {busy ? t('common.saving') : mode === 'import' ? t('keys.doImport') : t('keys.doGenerate')}
          </button>
        </div>
      </form>
    </div>
  )
}

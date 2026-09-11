// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useState } from 'react'
import type { SshKeyMeta } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'
import KeyEditor from './KeyEditor'

interface Props {
  keys: SshKeyMeta[]
  onChanged: () => void
}

/**
 * The key library, shown in Settings next to the known hosts — both are stored
 * crypto material the user occasionally has to clean up.
 *
 * Only public halves reach this component, so everything here is safe to show.
 */
export default function KeyManager({ keys, onChanged }: Props) {
  const t = useT()
  const [adding, setAdding] = useState(false)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [draftName, setDraftName] = useState('')
  const [shown, setShown] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function remove(key: SshKeyMeta): Promise<void> {
    setError(null)
    try {
      unwrap(await api.keys.remove(key.id))
      onChanged()
    } catch (err) {
      // Including the refusal when the key is in use, which names the
      // connections — the whole point of refusing instead of cascading.
      setError(errorMessage(err))
    }
  }

  async function commitRename(id: string): Promise<void> {
    setError(null)
    try {
      unwrap(await api.keys.rename(id, draftName))
      setRenaming(null)
      onChanged()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function copyPublic(key: SshKeyMeta): Promise<void> {
    try {
      unwrap(await api.clipboard.write(key.publicKey))
      setCopied(key.id)
      setTimeout(() => setCopied(null), 2000)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  return (
    <div className="host-list">
      <div className="keys-head">
        <span className="hint">{t('keys.intro')}</span>
        <button className="btn small primary" onClick={() => setAdding(true)}>
          {t('keys.add')}
        </button>
      </div>

      {keys.length === 0 && <div className="empty">{t('keys.empty')}</div>}

      {keys.map((k) => (
        <div className="host-row key-row" key={k.id}>
          <div className="key-main">
            {renaming === k.id ? (
              <div className="secret-row">
                <input
                  autoFocus
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void commitRename(k.id)
                    if (e.key === 'Escape') setRenaming(null)
                  }}
                />
                <button className="btn small primary" onClick={() => void commitRename(k.id)}>
                  {t('common.save')}
                </button>
                <button className="btn small" onClick={() => setRenaming(null)}>
                  {t('common.cancel')}
                </button>
              </div>
            ) : (
              <div className="host-name">
                {k.name}
                {k.origin === 'generated' && <span className="badge ok">{t('keys.generated')}</span>}
                {k.hasPassphrase && <span className="badge">{t('keys.protected')}</span>}
              </div>
            )}
            <div className="host-fp">
              {k.keyType} · {k.fingerprint}
            </div>
            {k.usedBy.length > 0 && (
              <div className="host-fp">{t('keys.usedBy', { names: k.usedBy.join(', ') })}</div>
            )}
            {shown === k.id && <textarea className="pubkey" readOnly rows={3} value={k.publicKey} />}
          </div>
          <div className="key-actions">
            <button className="btn small" onClick={() => setShown(shown === k.id ? null : k.id)}>
              {shown === k.id ? t('keys.hidePublic') : t('keys.showPublic')}
            </button>
            <button className="btn small" onClick={() => void copyPublic(k)}>
              {copied === k.id ? t('common.copied') : t('keys.copyPublic')}
            </button>
            <button
              className="btn small"
              onClick={() => {
                setRenaming(k.id)
                setDraftName(k.name)
              }}
            >
              {t('common.rename')}
            </button>
            <button className="btn small danger" onClick={() => void remove(k)}>
              {t('common.delete')}
            </button>
          </div>
        </div>
      ))}

      {error && <div className="form-error">{error}</div>}

      {adding && (
        <KeyEditor
          onSaved={() => {
            setAdding(false)
            onChanged()
          }}
          onCancel={() => setAdding(false)}
        />
      )}
    </div>
  )
}

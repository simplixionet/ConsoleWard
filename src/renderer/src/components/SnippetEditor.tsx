// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useState } from 'react'
import type { Snippet, SnippetInput, SnippetKind } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'

interface Props {
  /** null = nová položka */
  snippet: Snippet | null
  onSaved: (saved: Snippet) => void
  onCancel: () => void
}

export default function SnippetEditor({ snippet, onSaved, onCancel }: Props) {
  const t = useT()
  const isNew = snippet === null

  const [title, setTitle] = useState(snippet?.title ?? '')
  const [kind, setKind] = useState<SnippetKind>(snippet?.kind ?? 'command')
  const [folder, setFolder] = useState(snippet?.folder ?? '')
  const [body, setBody] = useState(snippet?.body ?? '')
  const [note, setNote] = useState(snippet?.note ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setError(null)

    const input: SnippetInput = {
      id: snippet?.id,
      title,
      body,
      note,
      folder,
      kind
    }

    setBusy(true)
    try {
      onSaved(unwrap(await api.snippets.save(input)))
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
          <h2>{isNew ? t('snip.newTitle') : t('snip.editTitle', { title: snippet.title })}</h2>
          <button type="button" className="icon-btn" onClick={onCancel} title={t('common.close')}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          <div className="grid-3">
            <label className="span-2">
              {t('snip.title')}
              <input
                autoFocus
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder={
                  kind === 'command'
                    ? t('snip.titlePlaceholderCommand')
                    : t('snip.titlePlaceholderNote')
                }
              />
            </label>
            <label>
              {t('snip.kind')}
              <select value={kind} onChange={(e) => setKind(e.target.value as SnippetKind)}>
                <option value="command">{t('snip.kindCommand')}</option>
                <option value="note">{t('snip.kindNote')}</option>
              </select>
            </label>
          </div>

          <label>
            {t('snip.folder')} <span className="hint">{t('common.optional')}</span>
            <input
              value={folder}
              onChange={(e) => setFolder(e.target.value)}
              placeholder={t('snip.folderPlaceholder')}
            />
          </label>

          <label>
            {kind === 'command' ? t('snip.bodyCommand') : t('snip.bodyNote')}
            <textarea
              rows={kind === 'command' ? 5 : 8}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder={
                kind === 'command'
                  ? t('snip.bodyPlaceholderCommand')
                  : t('snip.bodyPlaceholderNote')
              }
              spellCheck={false}
            />
          </label>

          <label>
            {t('snip.note')} <span className="hint">{t('common.optional')}</span>
            <textarea
              rows={2}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={t('snip.notePlaceholder')}
            />
          </label>

          {kind === 'command' && body.includes('\n') && (
            <div className="warn-box">{t('snip.multilineWarn')}</div>
          )}

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

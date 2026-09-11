// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useMemo, useState } from 'react'
import type { Snippet } from '@shared/types'
import { useT } from '../i18n'

interface Props {
  snippets: Snippet[]
  /** Is there an open, ready session to insert into? */
  canInsert: boolean
  onInsert: (s: Snippet, withEnter: boolean) => void
  onCopy: (s: Snippet) => void
  onEdit: (s: Snippet) => void
  onDuplicate: (s: Snippet) => void
  onDelete: (s: Snippet) => void
  onNew: () => void
}

export default function SnippetList({
  snippets,
  canInsert,
  onInsert,
  onCopy,
  onEdit,
  onDuplicate,
  onDelete,
  onNew
}: Props) {
  const t = useT()
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = q
      ? snippets.filter((s) =>
          [s.title, s.body, s.note ?? '', s.folder ?? ''].join(' ').toLowerCase().includes(q)
        )
      : snippets

    const map = new Map<string, Snippet[]>()
    for (const s of filtered) {
      const key = s.folder?.trim() || ''
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(s)
    }
    return [...map.entries()].sort(([a], [b]) => {
      if (a === '') return -1
      if (b === '') return 1
      return a.localeCompare(b)
    })
  }, [snippets, query])

  return (
    <>
      <div className="sidebar-head">
        <input
          className="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('sidebar.searchSnippets')}
        />
        <button className="btn primary small" onClick={onNew} title={t('snip.newTooltip')}>
          {t('sidebar.new')}
        </button>
      </div>

      <div className="conn-list">
        {snippets.length === 0 && (
          <div className="empty">
            {t('snip.empty')}
            <br />
            {t('snip.emptyHint')}
          </div>
        )}

        {groups.map(([folder, items]) => (
          <div className="conn-group" key={folder || '__root__'}>
            {folder && <div className="group-title">{folder}</div>}
            {items.map((s) => {
              const isOpen = expanded === s.id
              const multiline = s.body.includes('\n')
              return (
                <div className={`snip-item ${isOpen ? 'open' : ''}`} key={s.id}>
                  <div
                    className="snip-head"
                    onClick={() => setExpanded(isOpen ? null : s.id)}
                    title={s.note || s.title}
                  >
                    <span className={`kind-tag ${s.kind}`}>
                      {s.kind === 'command' ? '›_' : '✎'}
                    </span>
                    <div className="snip-main">
                      <div className="snip-title">
                        {s.title}
                        {/* In the list, not only in a tooltip: the mark is the
                            reason this entry asks again before it runs, and it
                            has to be visible at the moment of choosing it. */}
                        {s.origin === 'ai' && <span className="badge ai">{t('snip.byAi')}</span>}
                      </div>
                      <div className="snip-preview">{firstLine(s.body)}</div>
                    </div>
                    <span className="chevron">{isOpen ? '▾' : '▸'}</span>
                  </div>

                  {isOpen && (
                    <div className="snip-body">
                      {s.note && <div className="snip-note">{s.note}</div>}
                      <pre className="snip-code">{s.body}</pre>

                      <div className="snip-actions">
                        {s.kind === 'command' && (
                          <>
                            <button
                              className="btn small"
                              disabled={!canInsert}
                              title={canInsert ? t('snip.insertTitle') : t('snip.needSession')}
                              onClick={() => onInsert(s, false)}
                            >
                              {t('snip.insert')}
                            </button>
                            <button
                              className="btn small primary"
                              disabled={!canInsert}
                              title={canInsert ? t('snip.runTitle') : t('snip.needSession')}
                              onClick={() => onInsert(s, true)}
                            >
                              {t('snip.run')}
                            </button>
                          </>
                        )}
                        <button className="btn small" onClick={() => onCopy(s)}>
                          {t('common.copy')}
                        </button>
                        <div className="spacer" />
                        <button
                          className="icon-btn"
                          title={t('common.edit')}
                          onClick={() => onEdit(s)}
                        >
                          ✎
                        </button>
                        <button
                          className="icon-btn"
                          title={t('common.duplicate')}
                          onClick={() => onDuplicate(s)}
                        >
                          ⧉
                        </button>
                        <button
                          className="icon-btn danger"
                          title={t('common.delete')}
                          onClick={() => onDelete(s)}
                        >
                          🗑
                        </button>
                      </div>

                      {s.kind === 'command' && multiline && (
                        <div className="snip-warn">{t('snip.multiline')}</div>
                      )}

                      {s.origin === 'ai' && <div className="snip-warn">{t('snip.byAiWarn')}</div>}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        ))}
      </div>
    </>
  )
}

function firstLine(body: string): string {
  const line = body.split('\n')[0].trim()
  const rest = body.includes('\n') ? ' …' : ''
  return line.length > 60 ? line.slice(0, 60) + '…' : line + rest
}

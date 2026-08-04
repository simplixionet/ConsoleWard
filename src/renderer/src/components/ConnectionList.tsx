// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useMemo, useState } from 'react'
import type { ConnectionMeta } from '@shared/types'
import { useT } from '../i18n'

interface Props {
  connections: ConnectionMeta[]
  onConnect: (c: ConnectionMeta) => void
  onEdit: (c: ConnectionMeta) => void
  onDuplicate: (c: ConnectionMeta) => void
  onDelete: (c: ConnectionMeta) => void
  onNew: () => void
}

const AUTH_KEY: Record<ConnectionMeta['authKind'], string> = {
  password: 'conn.tagPassword',
  key: 'conn.tagKey',
  agent: 'conn.tagAgent'
}

export default function ConnectionList({
  connections,
  onConnect,
  onEdit,
  onDuplicate,
  onDelete,
  onNew
}: Props) {
  const t = useT()
  const [query, setQuery] = useState('')

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = q
      ? connections.filter((c) =>
          [c.name, c.host, c.username, c.folder ?? ''].join(' ').toLowerCase().includes(q)
        )
      : connections

    const map = new Map<string, ConnectionMeta[]>()
    for (const c of filtered) {
      const key = c.folder?.trim() || ''
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(c)
    }
    return [...map.entries()].sort(([a], [b]) => {
      if (a === '') return -1
      if (b === '') return 1
      return a.localeCompare(b)
    })
  }, [connections, query])

  return (
    <>
      <div className="sidebar-head">
        <input
          className="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('sidebar.searchConnections')}
        />
        <button className="btn primary small" onClick={onNew} title={t('conn.newTooltip')}>
          {t('sidebar.new')}
        </button>
      </div>

      <div className="conn-list">
        {connections.length === 0 && (
          <div className="empty">
            {t('conn.empty')}
            <br />
            {t('conn.emptyHint')}
          </div>
        )}

        {groups.map(([folder, items]) => (
          <div className="conn-group" key={folder || '__root__'}>
            {folder && <div className="group-title">{folder}</div>}
            {items.map((c) => (
              <div
                className="conn-item"
                key={c.id}
                onDoubleClick={() => onConnect(c)}
                title={`${c.username}@${c.host}:${c.port}`}
              >
                <div className="conn-main" onClick={() => onConnect(c)}>
                  <div className="conn-name">{c.name}</div>
                  <div className="conn-sub">
                    {c.username}@{c.host}
                    {c.port !== 22 ? `:${c.port}` : ''}
                    <span className="auth-tag">{t(AUTH_KEY[c.authKind])}</span>
                  </div>
                </div>
                <div className="conn-actions">
                  <button className="icon-btn" title={t('common.edit')} onClick={() => onEdit(c)}>
                    ✎
                  </button>
                  <button
                    className="icon-btn"
                    title={t('common.duplicate')}
                    onClick={() => onDuplicate(c)}
                  >
                    ⧉
                  </button>
                  <button
                    className="icon-btn danger"
                    title={t('common.delete')}
                    onClick={() => onDelete(c)}
                  >
                    🗑
                  </button>
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </>
  )
}

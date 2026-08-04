// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import type { ConnectionMeta, Snippet } from '@shared/types'
import { useT } from '../i18n'
import ConnectionList from './ConnectionList'
import SnippetList from './SnippetList'

export type SidebarTab = 'connections' | 'snippets'

interface Props {
  tab: SidebarTab
  onTabChange: (tab: SidebarTab) => void

  connections: ConnectionMeta[]
  onConnect: (c: ConnectionMeta) => void
  onEditConnection: (c: ConnectionMeta) => void
  onDuplicateConnection: (c: ConnectionMeta) => void
  onDeleteConnection: (c: ConnectionMeta) => void
  onNewConnection: () => void

  snippets: Snippet[]
  canInsert: boolean
  onInsertSnippet: (s: Snippet, withEnter: boolean) => void
  onCopySnippet: (s: Snippet) => void
  onEditSnippet: (s: Snippet) => void
  onDuplicateSnippet: (s: Snippet) => void
  onDeleteSnippet: (s: Snippet) => void
  onNewSnippet: () => void
}

export default function Sidebar(props: Props) {
  const t = useT()
  const { tab, onTabChange } = props

  return (
    <aside className="sidebar">
      <div className="sidebar-tabs">
        <button
          className={tab === 'connections' ? 'side-tab active' : 'side-tab'}
          onClick={() => onTabChange('connections')}
        >
          {t('sidebar.connections')}
          <span className="count">{props.connections.length}</span>
        </button>
        <button
          className={tab === 'snippets' ? 'side-tab active' : 'side-tab'}
          onClick={() => onTabChange('snippets')}
        >
          {t('sidebar.snippets')}
          <span className="count">{props.snippets.length}</span>
        </button>
      </div>

      {tab === 'connections' ? (
        <ConnectionList
          connections={props.connections}
          onConnect={props.onConnect}
          onEdit={props.onEditConnection}
          onDuplicate={props.onDuplicateConnection}
          onDelete={props.onDeleteConnection}
          onNew={props.onNewConnection}
        />
      ) : (
        <SnippetList
          snippets={props.snippets}
          canInsert={props.canInsert}
          onInsert={props.onInsertSnippet}
          onCopy={props.onCopySnippet}
          onEdit={props.onEditSnippet}
          onDuplicate={props.onDuplicateSnippet}
          onDelete={props.onDeleteSnippet}
          onNew={props.onNewSnippet}
        />
      )}
    </aside>
  )
}

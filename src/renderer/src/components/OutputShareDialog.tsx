// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useMemo, useRef, useState } from 'react'
import type { ShareRequest } from '@shared/types'
import { findSecrets, summarizeSecrets } from '@shared/secretPatterns'
import { useT } from '../i18n'

interface Props {
  request: ShareRequest
  onAnswer: (shared: boolean, text: string) => void
}

/**
 * Výběr toho, co z výstupu skutečně odejde AI.
 *
 * Text je editovatelný, takže cokoliv můžeš přepsat nebo smazat. Podezřelá
 * místa se podbarvují — regulární výrazy nezachytí všechno, jde jen o to, aby
 * ti nápadné věci padly do oka, když je pozdě večer a proklikáváš dvacátý dialog.
 */
export default function OutputShareDialog({ request, onAnswer }: Props) {
  const t = useT()
  const [text, setText] = useState(request.text)
  const [selection, setSelection] = useState<{ start: number; end: number }>({ start: 0, end: 0 })
  const areaRef = useRef<HTMLTextAreaElement>(null)
  const backdropRef = useRef<HTMLDivElement>(null)

  const matches = useMemo(() => findSecrets(text), [text])
  const summary = useMemo(() => summarizeSecrets(matches), [matches])
  const highSeverity = matches.some((m) => m.severity === 'high')

  const selectedLength = Math.max(0, selection.end - selection.start)
  const hasSelection = selectedLength > 0

  function syncSelection(): void {
    const el = areaRef.current
    if (!el) return
    setSelection({ start: el.selectionStart, end: el.selectionEnd })
  }

  function syncScroll(): void {
    const el = areaRef.current
    const back = backdropRef.current
    if (!el || !back) return
    back.scrollTop = el.scrollTop
    back.scrollLeft = el.scrollLeft
  }

  function selectLastLines(count: number): void {
    const el = areaRef.current
    if (!el) return
    const lines = text.split('\n')
    const from = Math.max(0, lines.length - count)
    const start = lines.slice(0, from).join('\n').length + (from > 0 ? 1 : 0)
    el.focus()
    el.setSelectionRange(start, text.length)
    setSelection({ start, end: text.length })
  }

  function redactSelection(): void {
    if (!hasSelection) return
    const marker = t('mcp.redacted')
    const next = text.slice(0, selection.start) + marker + text.slice(selection.end)
    setText(next)
    const caret = selection.start + marker.length
    setSelection({ start: caret, end: caret })
    requestAnimationFrame(() => areaRef.current?.setSelectionRange(caret, caret))
  }

  const originLabel =
    request.origin === 'command_output' ? t('mcp.shareTitleOutput') : t('mcp.shareTitleRead')

  const summaryText = summary
    .map(({ labelKey, count }) => (count > 1 ? `${count}× ${t(labelKey)}` : t(labelKey)))
    .join(', ')

  return (
    <div className="modal-backdrop">
      <div className="modal share-modal">
        <div className="modal-head">
          <h2>{originLabel}</h2>
        </div>

        <div className="modal-body">
          <div className="approval-meta">
            <div>
              <span className="meta-label">{t('mcp.session')}</span>
              <span className="meta-value">{request.sessionName}</span>
            </div>
          </div>

          <div>
            <div className="meta-label">{t('mcp.aiReason')}</div>
            <div className="ai-reason">{request.reason || t('mcp.noReason')}</div>
          </div>

          {matches.length > 0 && (
            <div className={highSeverity ? 'warn-box danger-box' : 'warn-box'}>
              <b>{t('mcp.detectedLead')}</b> {summaryText}. {t('mcp.detectedTail')}
            </div>
          )}

          <div className="share-toolbar">
            <button type="button" className="btn small" onClick={() => selectLastLines(20)}>
              {t('mcp.selectLast')}
            </button>
            <button
              type="button"
              className="btn small"
              disabled={!hasSelection}
              onClick={redactSelection}
              title={t('mcp.redactTitle')}
            >
              {t('mcp.redact')}
            </button>
            <div className="spacer" />
            <span className="share-count">
              {hasSelection
                ? t('mcp.selectedCount', { selected: selectedLength, total: text.length })
                : t('mcp.totalCount', { count: text.length })}
            </span>
          </div>

          <div className="hl-wrap">
            <div className="hl-backdrop" ref={backdropRef} aria-hidden="true">
              {renderHighlighted(text, matches)}
            </div>
            <textarea
              ref={areaRef}
              className="hl-input"
              value={text}
              spellCheck={false}
              onChange={(e) => {
                setText(e.target.value)
                syncSelection()
              }}
              onSelect={syncSelection}
              onKeyUp={syncSelection}
              onMouseUp={syncSelection}
              onScroll={syncScroll}
            />
          </div>

          <div className="hint">{t('mcp.shareHint')}</div>
        </div>

        <div className="modal-foot">
          <button className="btn" onClick={() => onAnswer(false, '')}>
            {t('mcp.sendNothing')}
          </button>
          <button
            className="btn"
            disabled={!hasSelection}
            onClick={() => onAnswer(true, text.slice(selection.start, selection.end))}
          >
            {t('mcp.sendSelected')}
          </button>
          <button className="btn primary" onClick={() => onAnswer(true, text)}>
            {t('mcp.sendAll')}
          </button>
        </div>
      </div>
    </div>
  )
}

function renderHighlighted(
  text: string,
  matches: { start: number; end: number; severity: 'high' | 'medium' }[]
): React.ReactNode[] {
  const nodes: React.ReactNode[] = []
  let pos = 0
  matches.forEach((m, i) => {
    if (m.start > pos) nodes.push(text.slice(pos, m.start))
    nodes.push(
      <mark key={i} className={`hl-${m.severity}`}>
        {text.slice(m.start, m.end)}
      </mark>
    )
    pos = m.end
  })
  // Koncová mezera drží poslední (prázdný) řádek, aby podbarvení nesjelo.
  nodes.push(text.slice(pos) + '\n ')
  return nodes
}

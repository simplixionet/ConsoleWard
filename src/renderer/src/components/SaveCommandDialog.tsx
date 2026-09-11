// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import type { SaveCommandApproval } from '@shared/types'
import { useT } from '../i18n'
import { useArmedAfterPaint } from '../armDelay'
import { useClippedBox } from '../useClipped'

interface Props {
  request: SaveCommandApproval
  onAnswer: (approved: boolean) => void
}

/**
 * Approves a command the AI wants to keep in the library.
 *
 * It shows the body with control characters made visible for the same reason
 * the run dialog does — a saved command is a command — and it shows the folder
 * prominently, because a model-supplied folder files the entry wherever it
 * likes, including one the user already trusts.
 *
 * The line that matters most is the last one: what is stored is marked as
 * AI-written and asks again before it ever runs. Saving is not running, and the
 * dialog should not read as though it were.
 */
export default function SaveCommandDialog({ request, onAnswer }: Props) {
  const t = useT()
  const armed = useArmedAfterPaint()
  // Same reason as the run dialog: what is stored is what runs later, and the
  // box hides anything past its cap behind a scrollbar in the footer's shadow.
  const [bodyRef, bodyClipped] = useClippedBox<HTMLPreElement>(request.bodyVisualized)

  return (
    <div className="modal-backdrop">
      <div className="modal wide-modal">
        <div className="modal-head">
          <h2>{t('mcp.saveTitle')}</h2>
        </div>

        <div className="modal-body">
          <div className="approval-meta">
            {/*
              Both come from the model and both are capped on the way into the
              vault — 120 and 60 characters. Showing the raw value would put a
              different string in front of the human than the one that gets
              stored, and a long one would push the rest of the dialog off screen.
            */}
            <div>
              <span className="meta-label">{t('mcp.saveName')}</span>
              <span className="meta-value">{request.title.trim().slice(0, 120)}</span>
            </div>
            <div>
              <span className="meta-label">{t('conn.folder')}</span>
              <span className="meta-value">
                {request.folder?.trim().slice(0, 60) || t('mcp.saveNoFolder')}
              </span>
            </div>
          </div>

          <div>
            <div className="meta-label">{t('mcp.aiReason')}</div>
            <div className="ai-reason">{request.reason || t('mcp.noReason')}</div>
          </div>

          <div>
            <div className="meta-label meta-label-row">
              <span>{t('mcp.saveBody')}</span>
              <span className="meta-count">
                {t('mcp.totalCount', { count: request.body.length })}
              </span>
            </div>
            <pre className="command-box" ref={bodyRef}>
              {request.bodyVisualized}
            </pre>
            {bodyClipped && <div className="warn-box">{t('mcp.previewClippedWarn')}</div>}
          </div>

          {request.note && (
            <div>
              <div className="meta-label">{t('snip.note')}</div>
              <div className="ai-reason">{request.note}</div>
            </div>
          )}

          <div className="note-box">{t('mcp.saveNotRun')}</div>
          <div className="warn-box">{t('mcp.saveLaterWarn')}</div>
        </div>

        <div className="modal-foot">
          <button className="btn" autoFocus onClick={() => onAnswer(false)}>
            {t('mcp.deny')}
          </button>
          <button className="btn primary" disabled={!armed} onClick={() => onAnswer(true)}>
            {t('mcp.saveIt')}
          </button>
        </div>
      </div>
    </div>
  )
}

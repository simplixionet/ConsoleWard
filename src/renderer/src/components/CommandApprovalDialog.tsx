// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { CommandApproval } from '@shared/types'
import { useT } from '../i18n'
import { useArmedAfterPaint } from '../armDelay'

interface Props {
  request: CommandApproval
  onAnswer: (approved: boolean, autoShare: boolean) => void
}

/**
 * Deliberately offers no "approve all" and no "remember this": the whole point
 * of the gate is that every AI-proposed command is reviewed on its own, with
 * control characters made visible so no extra line can hide in it.
 */
export default function CommandApprovalDialog({ request, onAnswer }: Props) {
  const t = useT()
  const armed = useArmedAfterPaint()
  const [autoShare, setAutoShare] = useState(false)
  // \n still separates commands: the text runs as a script on the remote shell.
  // A bare \r no longer becomes Enter (the exec channel has no PTY, so no ICRNL)
  // but is still an invisible byte that changes what runs, so it stays flagged.
  const multiline = /[\n\r]/.test(request.command)

  // `.command-box` is capped at 220px with `overflow-y: auto`, so a long command
  // scrolls out of sight behind an easily missed scrollbar while Run stays in the
  // footer — and the gate is only worth anything if the human sees every byte.
  // Measured rather than guessed from a character count: the real threshold
  // depends on font, DPI and how the lines wrap.
  const boxRef = useRef<HTMLPreElement>(null)
  const [clipped, setClipped] = useState(false)
  useEffect(() => {
    const el = boxRef.current
    if (!el) return
    setClipped(el.scrollHeight > el.clientHeight + 1)
  }, [request.commandVisualized])

  /*
    The flagged span, rendered rather than described.

    In unattended mode this dialog only appears because the destructive list
    matched, so the first question the reader has is "which part". Answering it
    with a sentence makes them find it themselves in a command they did not
    write; answering it with a highlight costs one span.

    The offsets arrive already translated into `commandVisualized` coordinates.
    They cannot be computed here: the visualiser substitutes glyphs and shifts
    everything after them, and it lives in the main process — which is also the
    only side that has the raw command to measure against.
  */
  function flaggedBody(): ReactNode {
    const span = request.flagged?.span
    if (!span) return request.commandVisualized
    const text = request.commandVisualized
    return (
      <>
        {text.slice(0, span.start)}
        <mark className="danger-span">{text.slice(span.start, span.end)}</mark>
        {text.slice(span.end)}
      </>
    )
  }

  return (
    <div className="modal-backdrop">
      <div className="modal wide-modal danger-modal">
        <div className="modal-head">
          <h2>{t('mcp.approveTitle')}</h2>
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

          <div>
            <div className="meta-label meta-label-row">
              <span>{t('mcp.commandToRun')}</span>
              {/* The length of what RUNS, not of the visualised copy: the
                  control-character glyphs expand the text on screen. */}
              <span className="meta-count">{t('mcp.totalCount', { count: request.command.length })}</span>
            </div>
            <pre className="command-box" ref={boxRef}>
              {flaggedBody()}
            </pre>
          </div>

          {request.flagged && (
            <div className="warn-box danger-box">
              <b>{t('mcp.flaggedLead')}</b> {t('mcp.flaggedBody', { what: request.flagged.what })}
            </div>
          )}

          <div className="note-box">{t('mcp.separateShellWarn')}</div>

          {clipped && <div className="warn-box">{t('mcp.commandClippedWarn')}</div>}

          {multiline && <div className="warn-box">{t('mcp.multilineWarn')}</div>}

          <div className="warn-box">{t('mcp.injectionWarn')}</div>

          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={autoShare}
              onChange={(e) => setAutoShare(e.target.checked)}
            />
            {t('mcp.autoShare')}
          </label>
        </div>

        <div className="modal-foot">
          <button className="btn" autoFocus onClick={() => onAnswer(false, false)}>
            {t('mcp.deny')}
          </button>
          <button
            className="btn danger"
            disabled={!armed}
            onClick={() => onAnswer(true, autoShare)}
          >
            {t('mcp.runCommand')}
          </button>
        </div>
      </div>
    </div>
  )
}

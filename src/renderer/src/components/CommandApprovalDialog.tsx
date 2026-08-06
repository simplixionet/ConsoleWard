// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useRef, useState } from 'react'
import type { CommandApproval } from '@shared/types'
import { useT } from '../i18n'
import { useArmedAfterPaint } from '../armDelay'

interface Props {
  request: CommandApproval
  onAnswer: (approved: boolean, autoShare: boolean) => void
}

/**
 * Schválení příkazu navrženého AI.
 *
 * Záměrně tu není žádné „schválit vše" ani „zapamatovat" – celý smysl brány je,
 * že každý příkaz vidíš zvlášť. Znění se zobrazuje se zviditelněnými řídicími
 * znaky, aby v něm nešel schovat řádek navíc.
 */
export default function CommandApprovalDialog({ request, onAnswer }: Props) {
  const t = useT()
  const armed = useArmedAfterPaint()
  const [autoShare, setAutoShare] = useState(false)
  // \n still separates commands: the text is handed to the remote shell as a
  // script. A bare \r no longer becomes Enter — the exec channel has no PTY and
  // so no ICRNL — but it is still an invisible byte that changes what runs, so
  // it stays in the warning.
  const multiline = /[\n\r]/.test(request.command)

  /*
    Whether the command is taller than the box that shows it.

    `.command-box` is capped at 220px with `overflow-y: auto`, so a long enough
    command is simply scrolled out of sight while the Run button stays pinned in
    the footer. The scrollbar is the only cue, and against the box's dark
    background it is easy to miss — worst of all when the overflow is slight,
    because then the thumb is nearly full height and reads as no scrollbar.

    That matters more here than the cap itself does: the gate's whole value is
    that the human sees the exact bytes that will run, and mcp.injectionWarn
    tells them to read it even when it looks harmless. Measured rather than
    guessed from a character count, because the real threshold depends on the
    font, the DPI and the width of the wrapped lines.
  */
  const boxRef = useRef<HTMLPreElement>(null)
  const [clipped, setClipped] = useState(false)
  useEffect(() => {
    const el = boxRef.current
    if (!el) return
    setClipped(el.scrollHeight > el.clientHeight + 1)
  }, [request.commandVisualized])

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
              {request.commandVisualized}
            </pre>
          </div>

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

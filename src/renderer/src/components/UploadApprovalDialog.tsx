// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import type { UploadApproval } from '@shared/types'
import { useT } from '../i18n'
import { useArmedAfterPaint } from '../armDelay'

interface Props {
  request: UploadApproval
  onAnswer: (approved: boolean) => void
}

/**
 * Approves writing a file on the server.
 *
 * The destination leads, not the content. `~/.ssh/authorized_keys` decides the
 * answer on its own, whatever the file says, and a path the model asked for may
 * not be the path the server opens — so both are shown when they differ.
 */
export default function UploadApprovalDialog({ request, onAnswer }: Props) {
  const t = useT()
  const armed = useArmedAfterPaint()
  const rewritten = request.resolvedPath !== request.path.trim()

  return (
    <div className="modal-backdrop">
      <div className={request.flagged ? 'modal wide-modal danger-modal' : 'modal wide-modal'}>
        <div className="modal-head">
          <h2>{t('mcp.uploadTitle')}</h2>
        </div>

        <div className="modal-body">
          <div className="approval-meta">
            <div>
              <span className="meta-label">{t('mcp.session')}</span>
              <span className="meta-value">{request.sessionName}</span>
            </div>
            <div>
              <span className="meta-label">{t('mcp.uploadSize')}</span>
              <span className="meta-value">{t('mcp.uploadBytes', { count: request.bytes })}</span>
            </div>
          </div>

          <div>
            <div className="meta-label">{t('mcp.uploadDestination')}</div>
            <pre className="command-box">{request.resolvedPath}</pre>
            {/* `/etc/nginx/../cron.d/x` is `/etc/cron.d/x`, and the difference is
                the whole question. Shown only when they differ, so the ordinary
                case stays one line. */}
            {rewritten && (
              <div className="warn-box">
                {t('mcp.uploadRewritten', { asked: request.path.trim() })}
              </div>
            )}
          </div>

          {request.flagged && (
            <div className="warn-box danger-box">
              <b>{t('mcp.uploadFlaggedLead')}</b>{' '}
              {t('mcp.uploadFlaggedBody', { what: request.flagged.what })}
            </div>
          )}

          <div>
            <div className="meta-label">{t('mcp.aiReason')}</div>
            <div className="ai-reason">{request.reason || t('mcp.noReason')}</div>
          </div>

          <div>
            <div className="meta-label">{t('mcp.uploadContent')}</div>
            <pre className="command-box">{request.preview}</pre>
            {request.previewTruncated && (
              <div className="warn-box">{t('mcp.uploadPreviewWarn')}</div>
            )}
          </div>

          <div className="note-box">{t('mcp.uploadOverwriteWarn')}</div>
        </div>

        <div className="modal-foot">
          <button className="btn" autoFocus onClick={() => onAnswer(false)}>
            {t('mcp.deny')}
          </button>
          <button
            className={request.flagged ? 'btn danger' : 'btn primary'}
            disabled={!armed}
            onClick={() => onAnswer(true)}
          >
            {t('mcp.uploadIt')}
          </button>
        </div>
      </div>
    </div>
  )
}

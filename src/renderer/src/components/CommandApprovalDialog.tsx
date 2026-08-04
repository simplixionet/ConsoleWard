import { useState } from 'react'
import type { CommandApproval } from '@shared/types'
import { useT } from '../i18n'

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
  const [autoShare, setAutoShare] = useState(false)
  const multiline = request.command.includes('\n')

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
            <div className="meta-label">{t('mcp.commandToRun')}</div>
            <pre className="command-box">{request.commandVisualized}</pre>
          </div>

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
          <button className="btn danger" onClick={() => onAnswer(true, autoShare)}>
            {t('mcp.runCommand')}
          </button>
        </div>
      </div>
    </div>
  )
}

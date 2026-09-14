// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import type { SessionInfo } from '@shared/types'
import { useT } from '../i18n'
import { useArmedAfterPaint } from '../armDelay'

interface Props {
  session: SessionInfo
  /** The global destructive-command guard — it still applies to an armed session. */
  guard: boolean
  onAnswer: (arm: boolean) => void
}

/**
 * Confirms switching one session to unattended.
 *
 * Turning the gate OFF for a session is consequential, so it is a deliberate
 * act with the consequence stated — the same reason the settings panel warns.
 * Turning it back on is always safe and never comes through here. The confirm
 * button arms after paint, as the approval dialogs do: this is triggered from
 * the status bar, but a human about to disarm should not confirm arming by a
 * stray second click.
 */
export default function ArmSessionDialog({ session, guard, onAnswer }: Props) {
  const t = useT()
  const armed = useArmedAfterPaint()

  return (
    <div className="modal-backdrop" onMouseDown={() => onAnswer(false)}>
      <div className="modal danger-modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>{t('term.armTitle', { session: session.title })}</h2>
        </div>

        <div className="modal-body">
          <div className="warn-box danger-box">{t('term.armBody')}</div>
          <p className="hint">{t(guard ? 'term.armGuardOn' : 'term.armGuardOff')}</p>
        </div>

        <div className="modal-foot">
          <button className="btn" autoFocus onClick={() => onAnswer(false)}>
            {t('common.cancel')}
          </button>
          <button className="btn danger" disabled={!armed} onClick={() => onAnswer(true)}>
            {t('term.armConfirm')}
          </button>
        </div>
      </div>
    </div>
  )
}

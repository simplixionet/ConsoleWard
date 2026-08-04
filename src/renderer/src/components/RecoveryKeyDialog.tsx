import { useState } from 'react'
import { api } from '../api'
import { useT } from '../i18n'

interface Props {
  recoveryKey: string
  /** true = klíč se zobrazuje hned po založení trezoru */
  isNewVault: boolean
  onDone: () => void
}

/**
 * Obnovovací klíč se nikam neukládá – tohle je jediná chvíle, kdy ho lze vidět.
 * Proto je potvrzení podmíněné zaškrtnutím.
 */
export default function RecoveryKeyDialog({ recoveryKey, isNewVault, onDone }: Props) {
  const t = useT()
  const [confirmed, setConfirmed] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  async function copy(): Promise<void> {
    await api.clipboard.write(recoveryKey)
    setNotice(t('recovery.copied'))
    window.setTimeout(() => setNotice(null), 2500)
  }

  async function saveToFile(): Promise<void> {
    const content = [
      t('recovery.fileHeader'),
      '',
      recoveryKey,
      '',
      t('recovery.fileBody1'),
      t('recovery.fileBody2'),
      ''
    ].join('\r\n')

    const res = await api.dialog.saveTextFile('consoleward-recovery-key.txt', content)
    if (res.ok && res.value) {
      setNotice(t('recovery.savedTo', { path: res.value }))
      window.setTimeout(() => setNotice(null), 5000)
    }
  }

  const groups = recoveryKey.split('-')

  return (
    <div className="modal-backdrop">
      <div className="modal wide-modal">
        <div className="modal-head">
          <h2>🔑 {t('recovery.title')}</h2>
        </div>

        <div className="modal-body">
          <p>{isNewVault ? t('recovery.introNew') : t('recovery.introRegenerated')}</p>

          <div className="recovery-key">
            {groups.map((g, i) => (
              <span className="rk-group" key={i}>
                {g}
              </span>
            ))}
          </div>

          <div className="recovery-actions">
            <button className="btn small" onClick={copy}>
              {t('common.copy')}
            </button>
            <button className="btn small" onClick={saveToFile}>
              {t('recovery.saveToFile')}
            </button>
          </div>

          <div className="warn-box">
            <b>{t('recovery.warningLead')}</b> {t('recovery.warningBody')}
          </div>

          {notice && <div className="form-notice">{notice}</div>}

          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            {t('recovery.confirm')}
          </label>
        </div>

        <div className="modal-foot">
          <button className="btn primary" disabled={!confirmed} onClick={onDone}>
            {t('recovery.continue')}
          </button>
        </div>
      </div>
    </div>
  )
}

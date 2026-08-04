import type { HostKeyPrompt } from '@shared/types'
import { useT } from '../i18n'

interface Props {
  prompt: HostKeyPrompt
  onAnswer: (accept: boolean) => void
}

export default function HostKeyDialog({ prompt, onAnswer }: Props) {
  const t = useT()
  const target = { host: prompt.host, port: prompt.port }

  return (
    <div className="modal-backdrop">
      <div className={`modal ${prompt.changed ? 'danger-modal' : ''}`}>
        <div className="modal-head">
          <h2>
            {prompt.changed ? `⚠ ${t('hostkey.titleChanged')}` : t('hostkey.titleUnknown')}
          </h2>
        </div>

        <div className="modal-body">
          <p className={prompt.changed ? 'danger-text' : undefined}>
            {prompt.changed ? t('hostkey.bodyChanged', target) : t('hostkey.bodyUnknown', target)}
          </p>

          <div className="fingerprint-block">
            <div className="fp-label">{t('hostkey.keyType')}</div>
            <div className="fp-value">{prompt.keyType}</div>

            <div className="fp-label">{t('hostkey.newFingerprint')}</div>
            <div className="fp-value strong">{prompt.fingerprint}</div>

            {prompt.changed && prompt.knownFingerprint && (
              <>
                <div className="fp-label">{t('hostkey.storedFingerprint')}</div>
                <div className="fp-value old">{prompt.knownFingerprint}</div>
              </>
            )}
          </div>
        </div>

        <div className="modal-foot">
          <button className="btn" onClick={() => onAnswer(false)} autoFocus>
            {t('hostkey.reject')}
          </button>
          <button
            className={`btn ${prompt.changed ? 'danger' : 'primary'}`}
            onClick={() => onAnswer(true)}
          >
            {prompt.changed ? t('hostkey.acceptAnyway') : t('hostkey.accept')}
          </button>
        </div>
      </div>
    </div>
  )
}

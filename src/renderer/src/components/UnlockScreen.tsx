import { useState } from 'react'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'

interface Props {
  exists: boolean
  hasRecovery: boolean
  vaultPath: string
  /** Po založení trezoru dorazí obnovovací klíč k zobrazení. */
  onCreated: (recoveryKey: string) => void
  onUnlocked: () => void
}

type Mode = 'normal' | 'recovery'

export default function UnlockScreen({
  exists,
  hasRecovery,
  vaultPath,
  onCreated,
  onUnlocked
}: Props) {
  const t = useT()
  const [mode, setMode] = useState<Mode>('normal')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [recoveryKey, setRecoveryKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function reset(): void {
    setPassword('')
    setConfirm('')
    setRecoveryKey('')
    setError(null)
  }

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setError(null)

    if ((mode === 'recovery' || !exists) && password !== confirm) {
      setError(t('unlock.mismatch'))
      return
    }

    setBusy(true)
    try {
      if (mode === 'recovery') {
        unwrap(await api.vault.unlockWithRecovery(recoveryKey, password))
        reset()
        onUnlocked()
      } else if (exists) {
        unwrap(await api.vault.unlock(password))
        reset()
        onUnlocked()
      } else {
        const key = unwrap(await api.vault.create(password))
        reset()
        onCreated(key)
      }
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const title =
    mode === 'recovery'
      ? t('unlock.titleRecovery')
      : exists
        ? t('unlock.titleUnlock')
        : t('unlock.titleCreate')

  const subtitle =
    mode === 'recovery'
      ? t('unlock.subRecovery')
      : exists
        ? t('unlock.subUnlock')
        : t('unlock.subCreate')

  const submitLabel = busy
    ? t('common.working')
    : mode === 'recovery'
      ? t('unlock.btnRecover')
      : exists
        ? t('unlock.btnUnlock')
        : t('unlock.btnCreate')

  const canSubmit =
    mode === 'recovery'
      ? Boolean(recoveryKey && password && confirm)
      : exists
        ? Boolean(password)
        : Boolean(password && confirm)

  return (
    <div className="unlock-screen">
      <form className="unlock-card" onSubmit={submit}>
        <div className="unlock-logo">{mode === 'recovery' ? '🔑' : '⌘'}</div>
        <h1>{title}</h1>
        <p className="unlock-sub">{subtitle}</p>

        {mode === 'recovery' && (
          <label>
            {t('unlock.recoveryKey')}
            <input
              autoFocus
              className="mono"
              value={recoveryKey}
              onChange={(e) => setRecoveryKey(e.target.value)}
              placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
              spellCheck={false}
              autoComplete="off"
            />
          </label>
        )}

        <label>
          {mode === 'recovery' ? t('unlock.newMasterPassword') : t('unlock.masterPassword')}
          <input
            type="password"
            autoFocus={mode === 'normal'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={exists && mode === 'normal' ? '' : t('unlock.minChars')}
          />
        </label>

        {(mode === 'recovery' || !exists) && (
          <label>
            {t('unlock.repeatPassword')}
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
        )}

        {error && <div className="form-error">{error}</div>}

        <button className="btn primary wide" type="submit" disabled={busy || !canSubmit}>
          {submitLabel}
        </button>

        {exists && hasRecovery && (
          <button
            type="button"
            className="link-btn"
            onClick={() => {
              setMode(mode === 'recovery' ? 'normal' : 'recovery')
              reset()
            }}
          >
            {mode === 'recovery' ? t('unlock.backToPassword') : t('unlock.forgot')}
          </button>
        )}

        {exists && !hasRecovery && mode === 'normal' && (
          <div className="unlock-note">{t('unlock.noRecovery')}</div>
        )}

        <div className="unlock-path" title={vaultPath}>
          {vaultPath}
        </div>
      </form>
    </div>
  )
}

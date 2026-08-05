// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useMemo, useState } from 'react'
import {
  estimatePasswordStrength,
  MIN_PASSWORD_LENGTH
} from '@shared/passwordStrength'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'

interface Props {
  exists: boolean
  hasRecovery: boolean
  vaultPath: string
  /** Po založení trezoru dorazí obnovovací klíč k zobrazení. */
  onCreated: (recoveryKey: string) => void
  /**
   * Po obnově obnovovacím klíčem dorazí **nový** klíč k zobrazení.
   *
   * Obnova rotuje DEK, čímž použitý klíč přestane platit. Kdyby se návratová
   * hodnota zahodila, uživatel by přišel o jedinou záchranu pro zapomenuté
   * heslo a nedozvěděl by se to — přesně před tím varuje komentář nad
   * `unlockWithRecovery` ve `vault.ts`.
   */
  onRecovered: (recoveryKey: string) => void
  onUnlocked: () => void
}

type Mode = 'normal' | 'recovery'

export default function UnlockScreen({
  exists,
  hasRecovery,
  vaultPath,
  onCreated,
  onRecovered,
  onUnlocked
}: Props) {
  const t = useT()
  const [mode, setMode] = useState<Mode>('normal')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [recoveryKey, setRecoveryKey] = useState('')
  const strength = useMemo(() => estimatePasswordStrength(password), [password])
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
        // Návratovou hodnotu NELZE zahodit: obnova rotuje DEK, takže právě
        // použitý klíč přestal platit a tenhle je jediný, který zbyl.
        const freshKey = unwrap(await api.vault.unlockWithRecovery(recoveryKey, password))
        reset()
        onRecovered(freshKey)
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
            placeholder={
              exists && mode === 'normal'
                ? ''
                : t('unlock.minChars', { length: MIN_PASSWORD_LENGTH })
            }
          />
        </label>

        {/*
          Only where a password is being CHOSEN. On the ordinary unlock screen
          the password already exists, and rating it there would be telling the
          user their vault is weak at the one moment they can do nothing about
          it — while painting a live gauge of a secret that is merely being
          re-typed.
        */}
        {(mode === 'recovery' || !exists) && password.length > 0 && (
          <div className={`pw-meter pw-${strength.verdict}`}>
            <div className="pw-bar">
              <span style={{ width: `${Math.min(100, (strength.bits / 80) * 100)}%` }} />
            </div>
            <div className="pw-note">
              {strength.verdict === 'tooShort'
                ? t('error.passwordTooShort', { length: MIN_PASSWORD_LENGTH })
                : t(`password.${strength.verdict}`)}
            </div>
          </div>
        )}

        {(mode === 'recovery' || !exists) && (
          <label>
            {t('unlock.repeatPassword')}
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
        )}

        {(mode === 'recovery' || !exists) && <div className="hint">{t('password.hint')}</div>}

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

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useRef, useState } from 'react'
import type { KnownHost, McpStatus, Settings, SshKeyMeta } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { LOCALES, useI18n } from '../i18n'
import KeyManager from './KeyManager'
import LogManager from './LogManager'
import McpClientSetup from './McpClientSetup'

interface Props {
  settings: Settings
  vaultPath: string
  hasRecovery: boolean
  onSaved: (next: Settings) => void
  onRecoveryKeyGenerated: (key: string) => void
  onRecoveryChanged: () => void
  onClose: () => void
}

type Tab = 'general' | 'security' | 'mcp' | 'keys' | 'logs' | 'hosts'

export default function SettingsDialog({
  settings,
  vaultPath,
  hasRecovery,
  onSaved,
  onRecoveryKeyGenerated,
  onRecoveryChanged,
  onClose
}: Props) {
  const { t, locale, setLocale } = useI18n()
  const [tab, setTab] = useState<Tab>('general')
  const [draft, setDraft] = useState<Settings>(settings)
  const [hosts, setHosts] = useState<KnownHost[]>([])
  const [keys, setKeys] = useState<SshKeyMeta[]>([])
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [newPw2, setNewPw2] = useState('')
  const [recoveryAction, setRecoveryAction] = useState<'regenerate' | 'remove' | null>(null)
  const [recoveryPw, setRecoveryPw] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const noticeTimer = useRef<number | null>(null)
  const [mcpStatus, setMcpStatus] = useState<McpStatus | null>(null)
  const [mcpToken, setMcpToken] = useState<string | null>(null)
  const [tokenVisible, setTokenVisible] = useState(false)
  const [mcpPort, setMcpPort] = useState(String(settings.mcpPort ?? 7345))

  useEffect(() => {
    void refreshHosts()
    void refreshKeys()
    void refreshMcp()
    const off = api.mcp.onStatus(setMcpStatus)
    return off
  }, [])

  /**
   * Cancelling the pending timer is required: otherwise an earlier short notice
   * clips a later long one — the 3 s "command copied" would cut the 6 s token
   * warning short.
   */
  function flash(message: string, ms = 2500): void {
    if (noticeTimer.current !== null) window.clearTimeout(noticeTimer.current)
    setNotice(message)
    noticeTimer.current = window.setTimeout(() => {
      noticeTimer.current = null
      setNotice(null)
    }, ms)
  }

  async function refreshHosts(): Promise<void> {
    try {
      setHosts(unwrap(await api.hosts.list()))
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function refreshKeys(): Promise<void> {
    try {
      setKeys(unwrap(await api.keys.list()))
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function refreshMcp(): Promise<void> {
    const [status, token] = await Promise.all([api.mcp.status(), api.mcp.token()])
    if (status.ok) setMcpStatus(status.value)
    if (token.ok) setMcpToken(token.value)
  }

  async function save(): Promise<void> {
    setError(null)
    try {
      const next = unwrap(await api.settings.save(draft))
      setDraft(next)
      onSaved(next)
      flash(t('settings.saved'))
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function changePassword(): Promise<void> {
    setError(null)
    setNotice(null)
    if (newPw !== newPw2) {
      setError(t('settings.passwordMismatch'))
      return
    }
    try {
      // Changing the password rotates the data key, so the old recovery key stops
      // working and a new one comes back. Showing it is not optional — dropping it
      // leaves the user with no way back into the vault.
      const freshRecoveryKey = unwrap(await api.vault.changePassword(oldPw, newPw))
      setOldPw('')
      setNewPw('')
      setNewPw2('')
      if (freshRecoveryKey) {
        onRecoveryKeyGenerated(freshRecoveryKey)
        onRecoveryChanged()
      } else {
        setNotice(t('settings.passwordChanged'))
      }
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function confirmRecoveryAction(): Promise<void> {
    if (!recoveryAction || !recoveryPw) return
    setError(null)
    const action = recoveryAction
    const password = recoveryPw
    try {
      if (action === 'regenerate') {
        const key = unwrap(await api.vault.regenerateRecoveryKey(password))
        onRecoveryKeyGenerated(key)
      } else {
        unwrap(await api.vault.removeRecoveryKey(password))
        setNotice(t('settings.recoveryRemoved'))
      }
      onRecoveryChanged()
      setRecoveryAction(null)
      setRecoveryPw('')
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function forget(hostKey: string): Promise<void> {
    try {
      unwrap(await api.hosts.forget(hostKey))
      await refreshHosts()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function toggleMcp(enabled: boolean): Promise<void> {
    setError(null)
    try {
      setMcpStatus(unwrap(await api.mcp.setEnabled(enabled)))
      await refreshMcp()
    } catch (err) {
      setError(errorMessage(err))
      await refreshMcp()
    }
  }

  async function savePort(): Promise<void> {
    setError(null)
    try {
      setMcpStatus(unwrap(await api.mcp.setPort(Number(mcpPort))))
      flash(t('settings.mcpPortSaved'))
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function regenerateToken(): Promise<void> {
    setError(null)
    try {
      setMcpToken(unwrap(await api.mcp.regenerateToken()))
      setTokenVisible(true)
      setNotice(t('settings.mcpRegenerated'))
      await refreshMcp()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  /**
   * The clipboard is readable by every process in the session, and on Windows the
   * token also lands in Clipboard History and Cloud Clipboard. Electron cannot
   * mark content transient, so the warning notice is the whole mitigation: it
   * tells the user to regenerate, the only revocation there is. Do not drop it.
   */
  async function copyToken(): Promise<void> {
    await api.clipboard.write(mcpToken ?? '')
    flash(t('settings.mcpTokenCopied'), 6000)
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="modal wide-modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>{t('settings.title')}</h2>
          <button className="icon-btn" onClick={onClose} title={t('common.close')}>
            ✕
          </button>
        </div>

        <div className="tabs">
          <button
            className={tab === 'general' ? 'tab active' : 'tab'}
            onClick={() => setTab('general')}
          >
            {t('settings.tabGeneral')}
          </button>
          <button
            className={tab === 'security' ? 'tab active' : 'tab'}
            onClick={() => setTab('security')}
          >
            {t('settings.tabSecurity')}
          </button>
          <button className={tab === 'mcp' ? 'tab active' : 'tab'} onClick={() => setTab('mcp')}>
            {t('settings.tabMcp')}
          </button>
          <button className={tab === 'keys' ? 'tab active' : 'tab'} onClick={() => setTab('keys')}>
            {t('settings.tabKeys', { count: keys.length })}
          </button>
          <button className={tab === 'logs' ? 'tab active' : 'tab'} onClick={() => setTab('logs')}>
            {t('settings.tabLogs')}
          </button>
          <button
            className={tab === 'hosts' ? 'tab active' : 'tab'}
            onClick={() => setTab('hosts')}
          >
            {t('settings.tabHosts', { count: hosts.length })}
          </button>
        </div>

        <div className="modal-body">
          {tab === 'general' && (
            <>
              <label>
                {t('settings.language')}
                <select value={locale} onChange={(e) => void setLocale(e.target.value)}>
                  {LOCALES.map((l) => (
                    <option key={l.code} value={l.code}>
                      {l.nativeName}
                      {l.code === 'en' ? '' : ` — ${l.englishName}`}
                    </option>
                  ))}
                </select>
              </label>
              <div className="hint">{t('settings.languageHint')}</div>

              <div className="grid-2">
                <label>
                  {t('settings.fontSize')}
                  <input
                    type="number"
                    min={8}
                    max={32}
                    value={draft.fontSize}
                    onChange={(e) => setDraft({ ...draft, fontSize: Number(e.target.value) })}
                  />
                </label>
                <label>
                  {t('settings.scrollback')}
                  <input
                    type="number"
                    min={500}
                    max={200000}
                    step={500}
                    value={draft.scrollback}
                    onChange={(e) => setDraft({ ...draft, scrollback: Number(e.target.value) })}
                  />
                </label>
              </div>
            </>
          )}

          {tab === 'security' && (
            <>
              <div className="grid-2">
                <label>
                  {t('settings.autoLock')} <span className="hint">{t('settings.autoLockHint')}</span>
                  <input
                    type="number"
                    min={0}
                    max={1440}
                    value={draft.autoLockMinutes}
                    onChange={(e) =>
                      setDraft({ ...draft, autoLockMinutes: Number(e.target.value) })
                    }
                  />
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={draft.disconnectOnLock}
                    onChange={(e) => setDraft({ ...draft, disconnectOnLock: e.target.checked })}
                  />
                  {t('settings.disconnectOnLock')}
                </label>
              </div>

              <hr />

              <h3>{t('settings.recoveryTitle')}</h3>
              <p className="hint">{t('settings.recoveryHint')}</p>
              <div className="recovery-status">
                <span className={`badge ${hasRecovery ? 'ok' : 'warn'}`}>
                  {hasRecovery ? t('settings.recoverySet') : t('settings.recoveryNotSet')}
                </span>
                <div className="recovery-status-actions">
                  <button className="btn small" onClick={() => setRecoveryAction('regenerate')}>
                    {hasRecovery
                      ? t('settings.recoveryRegenerate')
                      : t('settings.recoveryCreate')}
                  </button>
                  {hasRecovery && (
                    <button
                      className="btn small danger"
                      onClick={() => setRecoveryAction('remove')}
                    >
                      {t('settings.recoveryRemove')}
                    </button>
                  )}
                </div>
              </div>
              {hasRecovery && <p className="hint">{t('settings.recoveryWarn')}</p>}

              {/*
                Both operations demand the master password: each rotates the
                vault's data key. An unlocked session alone must never be enough
                to mint or void a recovery key.
              */}
              {recoveryAction && (
                <div className="recovery-confirm">
                  <p className="hint">{t('settings.recoveryConfirmHint')}</p>
                  <label>
                    {t('unlock.masterPassword')}
                    <input
                      type="password"
                      autoFocus
                      value={recoveryPw}
                      onChange={(e) => setRecoveryPw(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void confirmRecoveryAction()
                      }}
                    />
                  </label>
                  <div className="recovery-status-actions">
                    <button
                      className={`btn small ${recoveryAction === 'remove' ? 'danger' : ''}`}
                      disabled={!recoveryPw}
                      onClick={() => void confirmRecoveryAction()}
                    >
                      {recoveryAction === 'remove'
                        ? t('settings.recoveryRemove')
                        : t('settings.recoveryRegenerate')}
                    </button>
                    <button
                      className="btn small"
                      autoFocus={recoveryAction === 'remove'}
                      onClick={() => {
                        setRecoveryAction(null)
                        setRecoveryPw('')
                      }}
                    >
                      {t('common.cancel')}
                    </button>
                  </div>
                </div>
              )}

              <hr />

              <h3>{t('settings.changePassword')}</h3>
              <p className="hint">{t('settings.changePasswordHint')}</p>
              <div className="grid-3">
                <label>
                  {t('settings.oldPassword')}
                  <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
                </label>
                <label>
                  {t('settings.newPassword')}
                  <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
                </label>
                <label>
                  {t('settings.repeatNewPassword')}
                  <input
                    type="password"
                    value={newPw2}
                    onChange={(e) => setNewPw2(e.target.value)}
                  />
                </label>
              </div>
              <button
                className="btn"
                onClick={changePassword}
                disabled={!oldPw || !newPw || !newPw2}
              >
                {t('settings.changeButton')}
              </button>

              <hr />
              <div className="hint">
                {t('settings.vaultFile')} <code>{vaultPath}</code>
              </div>
            </>
          )}

          {tab === 'mcp' && (
            <>
              <p className="hint">{t('settings.mcpIntro')}</p>

              <div className="warn-box">
                <b>{t('settings.mcpWarnLead')}</b> {t('settings.mcpWarn')}
              </div>

              <div className="recovery-status">
                <span
                  className={`badge ${mcpStatus?.running ? 'ok' : mcpStatus?.error ? 'warn' : ''}`}
                >
                  {mcpStatus?.running
                    ? t('settings.mcpRunning', { port: mcpStatus.port })
                    : mcpStatus?.error
                      ? t('settings.mcpError')
                      : t('settings.mcpOff')}
                </span>
                <div className="recovery-status-actions">
                  <button
                    className={mcpStatus?.running ? 'btn small danger' : 'btn small primary'}
                    onClick={() => void toggleMcp(!mcpStatus?.running)}
                  >
                    {mcpStatus?.running ? t('settings.mcpDisable') : t('settings.mcpEnable')}
                  </button>
                </div>
              </div>

              {mcpStatus?.error && <div className="form-error">{mcpStatus.error}</div>}

              {/*
                Switching the gate off is the one setting here that changes what
                the product IS, so it states the consequence rather than naming
                the feature. Off by default, and the net under it defaults on —
                both have to be turned off by hand, one at a time.
              */}
              <div className={draft.dangerousMode === true ? 'danger-panel on' : 'danger-panel'}>
                <div className="meta-label">{t('settings.dangerousTitle')}</div>

                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={draft.dangerousMode === true}
                    onChange={(e) => setDraft({ ...draft, dangerousMode: e.target.checked })}
                  />
                  {t('settings.dangerousToggle')}
                </label>

                {draft.dangerousMode !== true ? (
                  <p className="hint">{t('settings.dangerousOffNote')}</p>
                ) : (
                  <>
                    <div className="warn-box danger-box">{t('settings.dangerousWhatChanges')}</div>

                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={draft.dangerousGuard !== false}
                        onChange={(e) => setDraft({ ...draft, dangerousGuard: e.target.checked })}
                      />
                      {t('settings.dangerousGuard')}
                    </label>

                    {draft.dangerousGuard !== false ? (
                      <p className="hint">{t('settings.dangerousGuardOn')}</p>
                    ) : (
                      <div className="warn-box danger-box">{t('settings.dangerousGuardOff')}</div>
                    )}

                    {/* Its own switch inside the mode, and off by default: a
                        file lands once and is run later by something else, so
                        trusting the agent to run commands is not the same
                        decision as letting it write to disk unwatched. */}
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={draft.dangerousUpload === true}
                        onChange={(e) => setDraft({ ...draft, dangerousUpload: e.target.checked })}
                      />
                      {t('settings.dangerousUpload')}
                    </label>

                    {draft.dangerousUpload === true ? (
                      <div className="warn-box danger-box">{t('settings.dangerousUploadOn')}</div>
                    ) : (
                      <p className="hint">{t('settings.dangerousUploadOff')}</p>
                    )}
                  </>
                )}
              </div>

              <div className="grid-3">
                <label>
                  {t('settings.mcpPort')}
                  <input
                    value={mcpPort}
                    onChange={(e) => setMcpPort(e.target.value.replace(/\D/g, ''))}
                    inputMode="numeric"
                  />
                </label>
                <label className="checkbox-label">
                  <button type="button" className="btn small" onClick={savePort}>
                    {t('settings.mcpSavePort')}
                  </button>
                </label>
              </div>

              <label>
                {t('settings.mcpToken')}
                <div className="secret-row">
                  <input
                    readOnly
                    className="mono"
                    type={tokenVisible ? 'text' : 'password'}
                    value={mcpToken ?? ''}
                    placeholder={t('settings.mcpTokenPlaceholder')}
                    onFocus={(e) => e.currentTarget.select()}
                  />
                  <button
                    type="button"
                    className="btn small"
                    onClick={() => setTokenVisible(!tokenVisible)}
                  >
                    {tokenVisible ? t('common.hide') : t('common.show')}
                  </button>
                  <button
                    type="button"
                    className="btn small"
                    disabled={!mcpToken}
                    onClick={() => void copyToken()}
                  >
                    {t('common.copy')}
                  </button>
                </div>
              </label>

              <div className="secret-row">
                <button type="button" className="btn small danger" onClick={regenerateToken}>
                  {t('settings.mcpRegenerate')}
                </button>
              </div>

              <p className="hint">{t('settings.mcpTokenHint')}</p>

              <McpClientSetup
                port={mcpStatus?.port ?? Number(mcpPort)}
                token={mcpToken}
                tokenVisible={tokenVisible}
                onCopied={(msg) => flash(msg, 6000)}
              />
            </>
          )}

          {tab === 'keys' && <KeyManager keys={keys} onChanged={() => void refreshKeys()} />}

          {tab === 'logs' && (
            <LogManager draft={draft} onChange={(p) => setDraft({ ...draft, ...p })} />
          )}

          {tab === 'hosts' && (
            <div className="host-list">
              {hosts.length === 0 && <div className="empty">{t('settings.hostsEmpty')}</div>}
              {hosts.map((h) => (
                <div className="host-row" key={h.hostKey}>
                  <div>
                    <div className="host-name">{h.hostKey}</div>
                    <div className="host-fp">
                      {h.keyType} · {h.fingerprint}
                    </div>
                  </div>
                  <button className="btn small danger" onClick={() => forget(h.hostKey)}>
                    {t('settings.forget')}
                  </button>
                </div>
              ))}
            </div>
          )}

          {error && <div className="form-error">{error}</div>}
          {notice && <div className="form-notice">{notice}</div>}
        </div>

        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            {t('common.close')}
          </button>
          {/*
            'mcp' belongs here and did not before 1.2: the unattended-mode and
            guard switches live on that tab and write to `draft`, so without a
            Save the user toggled the gate, saw the panel change colour, closed
            the dialog and lost it. The direction that matters is turning the
            gate back ON.
          */}
          {(tab === 'general' || tab === 'security' || tab === 'logs' || tab === 'mcp') && (
            <button className="btn primary" onClick={save}>
              {t('common.save')}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

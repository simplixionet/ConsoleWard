// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useState } from 'react'
import type { KnownHost, McpStatus, Settings } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { LOCALES, useI18n } from '../i18n'

interface Props {
  settings: Settings
  vaultPath: string
  hasRecovery: boolean
  onSaved: (next: Settings) => void
  onRecoveryKeyGenerated: (key: string) => void
  onRecoveryChanged: () => void
  onClose: () => void
}

type Tab = 'general' | 'security' | 'mcp' | 'hosts'

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
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [newPw2, setNewPw2] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [mcpStatus, setMcpStatus] = useState<McpStatus | null>(null)
  const [mcpToken, setMcpToken] = useState<string | null>(null)
  const [tokenVisible, setTokenVisible] = useState(false)
  const [mcpPort, setMcpPort] = useState(String(settings.mcpPort ?? 7345))

  useEffect(() => {
    void refreshHosts()
    void refreshMcp()
    const off = api.mcp.onStatus(setMcpStatus)
    return off
  }, [])

  function flash(message: string, ms = 2500): void {
    setNotice(message)
    window.setTimeout(() => setNotice(null), ms)
  }

  async function refreshHosts(): Promise<void> {
    try {
      setHosts(unwrap(await api.hosts.list()))
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
      unwrap(await api.vault.changePassword(oldPw, newPw))
      setOldPw('')
      setNewPw('')
      setNewPw2('')
      setNotice(t('settings.passwordChanged'))
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function regenerateRecovery(): Promise<void> {
    setError(null)
    try {
      const key = unwrap(await api.vault.regenerateRecoveryKey())
      onRecoveryKeyGenerated(key)
      onRecoveryChanged()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function removeRecovery(): Promise<void> {
    setError(null)
    try {
      unwrap(await api.vault.removeRecoveryKey())
      onRecoveryChanged()
      setNotice(t('settings.recoveryRemoved'))
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

  async function copyAddCommand(): Promise<void> {
    const port = mcpStatus?.port ?? Number(mcpPort)
    const cmd =
      `claude mcp add --transport http consoleward http://127.0.0.1:${port}/ ` +
      `--header "Authorization: Bearer ${mcpToken ?? '<token>'}"`
    await api.clipboard.write(cmd)
    flash(t('settings.mcpCommandCopied'), 3000)
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
                  <button className="btn small" onClick={regenerateRecovery}>
                    {hasRecovery
                      ? t('settings.recoveryRegenerate')
                      : t('settings.recoveryCreate')}
                  </button>
                  {hasRecovery && (
                    <button className="btn small danger" onClick={removeRecovery}>
                      {t('settings.recoveryRemove')}
                    </button>
                  )}
                </div>
              </div>
              {hasRecovery && <p className="hint">{t('settings.recoveryWarn')}</p>}

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
                    onClick={() => void api.clipboard.write(mcpToken ?? '')}
                  >
                    {t('common.copy')}
                  </button>
                </div>
              </label>

              <div className="secret-row">
                <button
                  type="button"
                  className="btn small"
                  disabled={!mcpToken}
                  onClick={copyAddCommand}
                >
                  {t('settings.mcpCopyCommand')}
                </button>
                <button type="button" className="btn small danger" onClick={regenerateToken}>
                  {t('settings.mcpRegenerate')}
                </button>
              </div>

              <p className="hint">{t('settings.mcpTokenHint')}</p>
            </>
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
          {(tab === 'general' || tab === 'security') && (
            <button className="btn primary" onClick={save}>
              {t('common.save')}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

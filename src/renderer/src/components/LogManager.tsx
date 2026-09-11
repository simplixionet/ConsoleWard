// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useState } from 'react'
import type { LogFileInfo, Settings } from '@shared/types'
import { api, errorMessage, unwrap } from '../api'
import { useT } from '../i18n'

interface Props {
  draft: Settings
  onChange: (patch: Partial<Settings>) => void
}

/**
 * The logs, in Settings: what is being recorded, how much disk it uses, and how
 * to read one or get rid of it. A log the user cannot find or remove is worse
 * than no log.
 */
export default function LogManager({ draft, onChange }: Props) {
  const t = useT()
  const [files, setFiles] = useState<LogFileInfo[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [confirmPurge, setConfirmPurge] = useState(false)

  useEffect(() => {
    void refresh()
  }, [])

  async function refresh(): Promise<void> {
    try {
      setFiles(unwrap(await api.logs.list()))
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function exportOne(file: LogFileInfo): Promise<void> {
    setError(null)
    setBusy(true)
    try {
      const written = unwrap(await api.logs.export(file.id))
      if (written) setNotice(t('logs.exported', { path: written }))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function removeOne(file: LogFileInfo): Promise<void> {
    setError(null)
    try {
      unwrap(await api.logs.remove(file.id))
      await refresh()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  async function purge(): Promise<void> {
    setError(null)
    setConfirmPurge(false)
    try {
      const gone = unwrap(await api.logs.purge())
      setNotice(t('logs.purged', { count: gone }))
      await refresh()
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  const total = files.reduce((sum, f) => sum + f.bytes, 0)

  return (
    <div className="host-list">
      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={draft.sessionLogs !== false}
          onChange={(e) => onChange({ sessionLogs: e.target.checked })}
        />
        {t('logs.transcripts')}
      </label>
      <span className="hint">{t('logs.transcriptsHint')}</span>

      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={draft.aiLog !== false}
          onChange={(e) => onChange({ aiLog: e.target.checked })}
        />
        {t('logs.aiLog')}
      </label>
      <span className="hint">{t('logs.aiLogHint')}</span>

      <div className="grid-2">
        <label>
          {t('logs.maxFile')}
          <input
            type="number"
            min={1}
            max={256}
            value={draft.logMaxFileMb ?? 16}
            onChange={(e) => onChange({ logMaxFileMb: Number(e.target.value) })}
          />
        </label>
        <label>
          {t('logs.maxTotal')}
          <input
            type="number"
            min={16}
            max={10240}
            value={draft.logMaxTotalMb ?? 512}
            onChange={(e) => onChange({ logMaxTotalMb: Number(e.target.value) })}
          />
        </label>
      </div>
      <span className="hint">{t('logs.capsHint')}</span>

      <div className="keys-head">
        <span className="hint">{t('logs.usage', { count: files.length, size: mb(total) })}</span>
        <div className="key-actions">
          <button className="btn small" onClick={() => void api.logs.reveal()}>
            {t('logs.openFolder')}
          </button>
          <button
            className="btn small danger"
            disabled={files.length === 0}
            onClick={() => setConfirmPurge(true)}
          >
            {t('logs.deleteAll')}
          </button>
        </div>
      </div>

      {confirmPurge && (
        <div className="form-error">
          {t('logs.purgeConfirm')}
          <div className="key-actions">
            <button className="btn small danger" onClick={() => void purge()}>
              {t('common.delete')}
            </button>
            <button className="btn small" onClick={() => setConfirmPurge(false)}>
              {t('common.cancel')}
            </button>
          </div>
        </div>
      )}

      {files.length === 0 && <div className="empty">{t('logs.empty')}</div>}

      {files.map((f) => (
        <div className="host-row key-row" key={f.id}>
          <div className="key-main">
            <div className="host-name">
              {f.label || f.sessionId}
              <span className="badge">{t(f.kind === 'ai' ? 'logs.kindAi' : 'logs.kindTranscript')}</span>
            </div>
            <div className="host-fp">
              {new Date(f.createdAt).toLocaleString()} · {mb(f.bytes)}
            </div>
          </div>
          <div className="key-actions">
            <button className="btn small" disabled={busy} onClick={() => void exportOne(f)}>
              {t('logs.export')}
            </button>
            <button className="btn small danger" onClick={() => void removeOne(f)}>
              {t('common.delete')}
            </button>
          </div>
        </div>
      ))}

      {/* On the export button, not on the switch: this is where plaintext is created. */}
      <span className="hint">{t('logs.exportWarning')}</span>

      {error && <div className="form-error">{error}</div>}
      {notice && <div className="form-notice">{notice}</div>}
    </div>
  )
}

function mb(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} kB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

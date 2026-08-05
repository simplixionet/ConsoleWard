// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * What may be written into the vault's settings, and what each field may hold.
 *
 * `settings:save` used to merge the caller's object straight into the stored
 * settings, so the settings block was whatever the caller said it was. Three
 * things followed from that. An unrecognised key was persisted verbatim inside
 * the encrypted vault and handed back by `settings:get`. `mcpPort` reached the
 * vault without the check `mcp:setPort` performs, and `mcpEnabled` was never
 * even coerced, so `'0'` was stored as a string and read back through
 * `Boolean()` as an enabled MCP gateway. And `Number(x) || 0` turned any
 * nonsense in `autoLockMinutes` into `0`, which is this file's encoding for
 * *never lock* — the one value here that must never be reachable by accident.
 *
 * The renderer is the only caller today. That is the argument for writing this
 * down now rather than later: a whitelist is worth having while it is still
 * cheap, not after the assumption that made it unnecessary has stopped holding.
 *
 * It lives outside `index.ts` because nothing in that file is reachable from a
 * test — it exports nothing and calls `app.requestSingleInstanceLock()` at
 * module scope. Same reason the approval queue moved to `approvals.ts`.
 */

import type { Settings } from '../shared/types'
import { appError } from './i18n'

/** Also `DEFAULT_PORT` in mcp.ts. The two must not drift apart. */
const DEFAULT_MCP_PORT = 7345

export const DEFAULT_SETTINGS: Settings = {
  autoLockMinutes: 15,
  disconnectOnLock: true,
  fontSize: 14,
  scrollback: 5000,
  mcpEnabled: false,
  mcpPort: DEFAULT_MCP_PORT,
  aiModel: 'claude-opus-5',
  aiEffort: 'high'
}

/** Inclusive bounds, in the units the settings dialog shows. */
export const SETTINGS_LIMITS = {
  autoLockMinutes: { min: 0, max: 24 * 60 },
  fontSize: { min: 8, max: 32 },
  scrollback: { min: 500, max: 200_000 }
} as const

/**
 * Every key of `Settings` and what `sanitizeSettings` does about it.
 *
 * Nothing reads this at runtime. It is here so that adding a field to
 * `Settings` without deciding about it is a type error rather than a field that
 * silently never persists — the failure a whitelist otherwise introduces.
 *
 *   saved      the general and security tabs own it; validated below
 *   elsewhere  stored, but only by its own handler. A copy of it in a patch is
 *              stale by construction — the settings dialog reads it once, when
 *              it opens — so writing it here undoes `mcp:setEnabled` or
 *              `mcp:setPort` whenever the human saves the other tab afterwards
 *   unused     reserved for the AI assistant. Nothing writes or reads either
 *              one; they need a real validator (a fixed set for `aiEffort`, a
 *              length and charset bound for `aiModel`) the day something does.
 *              Until then this is the record that they were considered, not
 *              forgotten — the dead-code pass decides their fate, not this file
 *   derived    computed by `settings:get` from `aiApiKey`, never stored
 */
export const SETTINGS_FIELDS: Record<
  keyof Settings,
  'saved' | 'elsewhere' | 'unused' | 'derived'
> = {
  autoLockMinutes: 'saved',
  disconnectOnLock: 'saved',
  fontSize: 'saved',
  scrollback: 'saved',
  mcpEnabled: 'elsewhere',
  mcpPort: 'elsewhere',
  aiModel: 'unused',
  aiEffort: 'unused',
  hasAiApiKey: 'derived'
}

/**
 * `hasOwnProperty`, never `in` and never `obj[key]`.
 *
 * Both reach the prototype, so `{ toString: 1 }` would pass for a known field.
 * Same reason `mcp.ts` keeps its error table in a `Map` and `shared/i18n.ts`
 * looks keys up through `own()`.
 */
function has(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

function invalid(field: string): Error {
  return appError('error.invalidSetting', { field })
}

/**
 * A whole number inside `range`, clamped.
 *
 * With `fallback` it repairs, without it refuses, and the two callers are not
 * the same. A value the caller just sent must fail loudly, because inventing
 * one is exactly how `Number('x') || 0` switched auto-lock off. A value already
 * in the vault must not, because refusing it would make Save impossible over a
 * number the human never typed and cannot see.
 */
function whole(
  value: unknown,
  field: string,
  range: { min: number; max: number },
  fallback?: number
): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    if (fallback === undefined) throw invalid(field)
    return fallback
  }
  return Math.min(range.max, Math.max(range.min, Math.round(value)))
}

/** A real boolean. `'false'` is not one, and `Boolean('false')` is `true`. */
function flag(value: unknown, field: string, fallback?: boolean): boolean {
  if (typeof value !== 'boolean') {
    if (fallback === undefined) throw invalid(field)
    return fallback
  }
  return value
}

/** Carried over only. Repairs to the default, which is what `clampPort` binds. */
function port(value: unknown): number {
  const ok = typeof value === 'number' && Number.isInteger(value) && value >= 1024 && value <= 65535
  return ok ? value : DEFAULT_MCP_PORT
}

/**
 * The settings to store, from the ones already stored plus a patch.
 *
 * Absent field: unchanged. Present and legal: written, clamped into range.
 * Present and not legal: the whole save fails and nothing is written.
 *
 * Unknown keys are refused rather than dropped. Dropping is how "the setting
 * did not stick" bugs are born — a field is added to the dialog, nobody adds it
 * here, Save reports success and changes nothing. Refusing costs nothing:
 * renderer and main process ship as one build, so they cannot disagree about
 * which keys exist, and the only things that can send an unknown one are a bug
 * and a caller that is not this application. Both deserve to be seen.
 */
export function sanitizeSettings(current: Settings, patch: unknown): Settings {
  if (typeof patch !== 'object' || patch === null) throw appError('error.unknownSetting')
  const incoming = patch as Record<string, unknown>

  for (const key of Object.keys(incoming)) {
    if (has(SETTINGS_FIELDS, key)) continue
    // The key is the caller's own text, so it goes to the log rather than into a
    // translated string that ends up in front of the user.
    console.warn('settings: refusing unknown key', JSON.stringify(key).slice(0, 80))
    throw appError('error.unknownSetting')
  }

  // Rebuilt field by field rather than spread, so whatever a previous build may
  // have left in the settings block is gone after one save.
  const next: Settings = {
    autoLockMinutes: whole(
      current.autoLockMinutes,
      'autoLockMinutes',
      SETTINGS_LIMITS.autoLockMinutes,
      DEFAULT_SETTINGS.autoLockMinutes
    ),
    disconnectOnLock: flag(
      current.disconnectOnLock,
      'disconnectOnLock',
      DEFAULT_SETTINGS.disconnectOnLock
    ),
    fontSize: whole(
      current.fontSize,
      'fontSize',
      SETTINGS_LIMITS.fontSize,
      DEFAULT_SETTINGS.fontSize
    ),
    scrollback: whole(
      current.scrollback,
      'scrollback',
      SETTINGS_LIMITS.scrollback,
      DEFAULT_SETTINGS.scrollback
    ),
    // Never from the patch: see `elsewhere` above.
    mcpEnabled: flag(current.mcpEnabled, 'mcpEnabled', false),
    mcpPort: port(current.mcpPort)
  }

  if (has(incoming, 'autoLockMinutes')) {
    next.autoLockMinutes = whole(
      incoming.autoLockMinutes,
      'autoLockMinutes',
      SETTINGS_LIMITS.autoLockMinutes
    )
  }
  if (has(incoming, 'disconnectOnLock')) {
    next.disconnectOnLock = flag(incoming.disconnectOnLock, 'disconnectOnLock')
  }
  if (has(incoming, 'fontSize')) {
    next.fontSize = whole(incoming.fontSize, 'fontSize', SETTINGS_LIMITS.fontSize)
  }
  if (has(incoming, 'scrollback')) {
    next.scrollback = whole(incoming.scrollback, 'scrollback', SETTINGS_LIMITS.scrollback)
  }
  return next
}

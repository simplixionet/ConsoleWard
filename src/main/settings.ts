// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * What may be written into the vault's settings, and what each field may hold.
 * A whitelist and not a merge of what the caller sent: a merge persists unknown
 * keys inside the encrypted vault, lets `mcpPort` skip the check `mcp:setPort`
 * performs, reads an uncoerced `mcpEnabled` of `'0'` back as an enabled gateway,
 * and turns nonsense in `autoLockMinutes` into `0` — the encoding for *never
 * lock*, the one value that must not be reachable by accident.
 */

import type { Settings } from '../shared/types'
import { appError } from './i18n'

/** Also `DEFAULT_PORT` in mcp.ts. The two must not drift apart. */
const DEFAULT_MCP_PORT = 7345

/**
 * `aiModel` and `aiEffort` are deliberately absent: `sanitizeSettings` does not
 * persist them, so a default here would be handed out by `settings:get` and
 * dropped by the first save — a stored value that is not stored.
 */
export const DEFAULT_SETTINGS: Settings = {
  autoLockMinutes: 15,
  disconnectOnLock: true,
  fontSize: 14,
  scrollback: 5000,
  mcpEnabled: false,
  mcpPort: DEFAULT_MCP_PORT,
  // Both defaults point the same way: the gate is on, and the net under it is
  // on too. Turning either off has to be something a person did on purpose.
  dangerousMode: false,
  dangerousGuard: true
}

/** Inclusive bounds, in the units the settings dialog shows. */
export const SETTINGS_LIMITS = {
  autoLockMinutes: { min: 0, max: 24 * 60 },
  fontSize: { min: 8, max: 32 },
  scrollback: { min: 500, max: 200_000 }
} as const

/**
 * Nothing reads this at runtime; it exists so adding a field to `Settings`
 * without deciding about it is a type error, not a field that never persists.
 *
 *   saved      validated below
 *   elsewhere  stored only by its own handler; a copy in a patch is stale by
 *              construction and would undo `mcp:setEnabled` or `mcp:setPort`
 *   unused     reserved for the AI assistant; needs its own validator the day
 *              something reads or writes it
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
  dangerousMode: 'saved',
  dangerousGuard: 'saved',
  aiModel: 'unused',
  aiEffort: 'unused',
  hasAiApiKey: 'derived'
}

/** Never `in` or `obj[key]`: both reach the prototype, so `{ toString: 1 }` passes. */
function has(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key)
}

function invalid(field: string): Error {
  return appError('error.invalidSetting', { field })
}

/**
 * A whole number inside `range`, clamped. With `fallback` it repairs, without it
 * refuses, and the two must stay distinct: a value the caller just sent has to
 * fail loudly — inventing one is how `Number('x') || 0` switched auto-lock off —
 * while a value already in the vault must not block Save.
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

/** Carried over only; repairs to the default that `clampPort` also binds. */
function port(value: unknown): number {
  const ok = typeof value === 'number' && Number.isInteger(value) && value >= 1024 && value <= 65535
  return ok ? value : DEFAULT_MCP_PORT
}

/**
 * Absent field: unchanged. Present and legal: written, clamped into range.
 * Present and not legal: the whole save fails and nothing is written.
 *
 * Unknown keys are refused, never dropped: an unknown key is either a field
 * someone forgot to add here — dropping it gives a silent "the setting did not
 * stick" — or a caller that is not this application. Both deserve to be seen.
 */
export function sanitizeSettings(current: Settings, patch: unknown): Settings {
  if (typeof patch !== 'object' || patch === null) throw appError('error.unknownSetting')
  const incoming = patch as Record<string, unknown>

  for (const key of Object.keys(incoming)) {
    if (has(SETTINGS_FIELDS, key)) continue
    // The caller's own text: to the log, never into a string shown to the user.
    console.warn('settings: refusing unknown key', JSON.stringify(key).slice(0, 80))
    throw appError('error.unknownSetting')
  }

  // Rebuilt field by field, not spread, so anything a previous build left in the
  // settings block is gone after one save.
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
    mcpPort: port(current.mcpPort),
    dangerousMode: flag(current.dangerousMode, 'dangerousMode', DEFAULT_SETTINGS.dangerousMode),
    dangerousGuard: flag(current.dangerousGuard, 'dangerousGuard', DEFAULT_SETTINGS.dangerousGuard)
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
  /*
    No default on this path, unlike the block above: `flag` throws on anything
    that is not a boolean. A patch carrying `"false"` or `0` has to fail rather
    than be coerced, because the direction a wrong reading falls in is straight
    through the approval gate.
  */
  if (has(incoming, 'dangerousMode')) {
    next.dangerousMode = flag(incoming.dangerousMode, 'dangerousMode')
  }
  if (has(incoming, 'dangerousGuard')) {
    next.dangerousGuard = flag(incoming.dangerousGuard, 'dangerousGuard')
  }
  return next
}

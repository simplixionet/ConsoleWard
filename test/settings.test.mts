// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The settings whitelist. Merging a caller's object straight into the stored
 * settings has three consequences pinned below: an unknown key persisted in the
 * encrypted vault, `mcpPort` reaching the vault without the check `mcp:setPort`
 * performs, and `Number(x) || 0` turning nonsense in `autoLockMinutes` into 0,
 * the encoding for *never lock*.
 */

import { describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'

mock.module('electron', { exports: { app: { getPath: () => '' } } })

const { sanitizeSettings, DEFAULT_SETTINGS, SETTINGS_LIMITS, SETTINGS_FIELDS } = await import(
  '../src/main/settings.ts'
)

const stored = (): typeof DEFAULT_SETTINGS => ({ ...DEFAULT_SETTINGS })

function throwsWithKey(run: () => unknown, key: string, note = ''): void {
  let caught: (Error & { key?: string }) | null = null
  try {
    run()
  } catch (err) {
    caught = err as Error & { key?: string }
  }
  assert.ok(caught, `${note || 'call'}: expected a throw of ${key}, but it returned`)
  assert.equal(caught.key, key, `${note || 'call'}: expected ${key}, got ${caught.key}`)
}

describe('sanitizeSettings', () => {
  test('leaves a field the patch does not mention alone', () => {
    const current = { ...stored(), fontSize: 19 }
    assert.equal(sanitizeSettings(current, {}).fontSize, 19, 'an untouched field changed')
  })

  test('applies a legal value', () => {
    assert.equal(sanitizeSettings(stored(), { fontSize: 22 }).fontSize, 22)
    assert.equal(sanitizeSettings(stored(), { disconnectOnLock: false }).disconnectOnLock, false)
  })

  test('clamps a number into range rather than storing it', () => {
    assert.equal(sanitizeSettings(stored(), { fontSize: 999 }).fontSize, SETTINGS_LIMITS.fontSize.max)
    assert.equal(sanitizeSettings(stored(), { fontSize: 1 }).fontSize, SETTINGS_LIMITS.fontSize.min)
    assert.equal(sanitizeSettings(stored(), { scrollback: 0 }).scrollback, SETTINGS_LIMITS.scrollback.min)
  })

  test('refuses nonsense instead of inventing a value for it', () => {
    // `Number('x') || 0` lands on 0, which means never lock — auto-lock
    // switching itself off without anyone choosing that.
    for (const bad of ['soon', null, undefined, NaN, Infinity, {}, []]) {
      throwsWithKey(
        () => sanitizeSettings(stored(), { autoLockMinutes: bad }),
        'error.invalidSetting',
        `autoLockMinutes = ${JSON.stringify(bad)}`
      )
    }
  })

  test('will not take a truthy string for a boolean', () => {
    // Boolean('false') is true, which is how '0' became an enabled gateway.
    for (const bad of ['false', 'true', 0, 1, 'yes']) {
      throwsWithKey(
        () => sanitizeSettings(stored(), { disconnectOnLock: bad }),
        'error.invalidSetting',
        `disconnectOnLock = ${JSON.stringify(bad)}`
      )
    }
  })

  test('refuses an unknown key rather than dropping it', () => {
    throwsWithKey(() => sanitizeSettings(stored(), { nonsense: 1 }), 'error.unknownSetting')
    // JSON.parse, not a literal: `{ __proto__: … }` in a literal sets the
    // prototype rather than creating an own property, so Object.keys sees
    // nothing. Over IPC the patch arrives parsed, which is this shape.
    throwsWithKey(
      () => sanitizeSettings(stored(), JSON.parse('{"__proto__":{"fontSize":99}}')),
      'error.unknownSetting',
      'a __proto__ key crossed the whitelist'
    )
  })

  test('does not mistake a prototype member for a known field', () => {
    // `in` and `obj[key]` both reach the prototype, so { toString: 1 } would
    // pass for a known field under either.
    throwsWithKey(
      () => sanitizeSettings(stored(), { toString: 1 }),
      'error.unknownSetting',
      'toString was accepted as a settings field'
    )
    throwsWithKey(() => sanitizeSettings(stored(), { constructor: 1 }), 'error.unknownSetting')
  })

  test('refuses a patch that is not an object', () => {
    for (const bad of [null, undefined, 'x', 42, true]) {
      throwsWithKey(
        () => sanitizeSettings(stored(), bad),
        'error.unknownSetting',
        `patch = ${JSON.stringify(bad)}`
      )
    }
  })

  test('never takes the MCP port or the MCP switch from the patch', () => {
    // Carrying the stored value over rather than validating the patched one is
    // the stronger rule: this channel simply cannot set the port.
    const current = { ...stored(), mcpPort: 7345, mcpEnabled: true }
    const saved = sanitizeSettings(current, { mcpPort: 22, mcpEnabled: false })
    assert.equal(saved.mcpPort, 7345, 'settings:save wrote the MCP port')
    assert.equal(saved.mcpEnabled, true, 'settings:save wrote the MCP switch')
  })

  test('repairs a stored value it would refuse in a patch', () => {
    // A value the human never typed and cannot see must not make Save
    // impossible, and must not survive either.
    const damaged = { ...stored(), fontSize: 'huge' as never, mcpPort: -1 as never }
    const saved = sanitizeSettings(damaged, { scrollback: 900 })
    assert.equal(saved.fontSize, DEFAULT_SETTINGS.fontSize, 'a damaged stored value survived')
    assert.equal(saved.mcpPort, DEFAULT_SETTINGS.mcpPort, 'a damaged port survived')
    assert.equal(saved.scrollback, 900, 'the legal part of the patch was lost')
  })

  test('drops anything a previous build left in the settings block', () => {
    const stale = { ...stored(), leftover: 'from an older version' } as never
    const saved = sanitizeSettings(stale, {}) as Record<string, unknown>
    assert.ok(!('leftover' in saved), 'the settings block is merged rather than rebuilt')
  })

  test('never stores the derived hasAiApiKey flag', () => {
    const saved = sanitizeSettings(stored(), { hasAiApiKey: true }) as Record<string, unknown>
    assert.ok(!('hasAiApiKey' in saved), 'a computed field was written into the vault')
  })

  test('every Settings field has a decision recorded against it', () => {
    // The failure a whitelist introduces: a field is added to the dialog,
    // nobody adds it here, and Save reports success while changing nothing.
    for (const [field, kind] of Object.entries(SETTINGS_FIELDS)) {
      assert.match(kind, /^(saved|elsewhere|unused|derived)$/, `${field} has no decision`)
    }
    for (const field of Object.keys(DEFAULT_SETTINGS)) {
      assert.ok(field in SETTINGS_FIELDS, `${field} is a default but has no decision recorded`)
    }
  })
})

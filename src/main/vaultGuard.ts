// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Rollback anchor for `vault.enc`. The v3 header's AAD-covered `counter` cannot
 * be forged, but says nothing about a whole older file being swapped in — its
 * counter is valid too, just smaller. The last seen value therefore lives
 * outside the vault, in `vault.guard`.
 *
 * Scope, which SECURITY.md must keep stating: sealing via `safeStorage` stops
 * whoever can only *write files* (sync client, restored backup, share with bad
 * permissions), and nothing that runs as this user — such code can seal anything
 * itself, or just delete `vault.guard`.
 *
 * The sealer is injected rather than imported: `safeStorage` at import time
 * would break the test files that stub only `app`.
 */

import { constants as fsConstants } from 'node:fs'
import fsp from 'node:fs/promises'

export const GUARD_VERSION = 1 as const

/**
 * Read cap. The anchor is a few hundred bytes; its directory is writable by
 * other things, and an unbounded read would be a cheap way to hang unlocking.
 */
export const GUARD_MAX_BYTES = 64 * 1024

// Windows has no O_NONBLOCK, and referencing it directly would turn the whole
// flag word into NaN. Same reason as in textFile.ts.
const O_NONBLOCK = (fsConstants as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0

/**
 * `available()` is false on Linux without a keyring, and for the `basic_text`
 * backend that only pretends to encrypt.
 */
export interface GuardSealer {
  available(): boolean
  seal(plain: string): Buffer
  open(blob: Buffer): string
}

export interface Anchor {
  counter: number
  /** When the anchor was written (ms since epoch); shown in the warning. */
  at: number
  protected: boolean
}

export type GuardRead =
  | { kind: 'ok'; anchor: Anchor }
  | { kind: 'absent' }
  | { kind: 'unreadable'; reason: string }

export type GuardVerdict =
  | { kind: 'ok' }
  | { kind: 'unknown' }
  | { kind: 'rollback'; expected: number; found: number; at: number }

/**
 * One-directional on purpose: `found > expected` is **not** an alarm. The anchor
 * is written only after a successful vault write, so a crash between the two
 * leaves it one behind — normal, not an attack. Alarming on that would fire
 * after every unclean shutdown, until the warning gets clicked away unread.
 */
export function verdict(anchor: Anchor | null, fileCounter: number): GuardVerdict {
  if (anchor === null) return { kind: 'unknown' }
  if (!Number.isSafeInteger(fileCounter) || fileCounter < 0) return { kind: 'unknown' }
  if (fileCounter >= anchor.counter) return { kind: 'ok' }
  return { kind: 'rollback', expected: anchor.counter, found: fileCounter, at: anchor.at }
}

export function serializeGuard(counter: number, at: number, sealer: GuardSealer): string {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new Error('vaultGuard: counter must be a non-negative safe integer')
  }
  if (!Number.isSafeInteger(at) || at < 0) {
    throw new Error('vaultGuard: timestamp must be a non-negative safe integer')
  }

  const body = JSON.stringify({ counter, at })
  const isProtected = sealer.available()
  /*
   * Without a keyring the anchor is plain text rather than absent — refusing it
   * would disable detection on a whole platform, and an unsealed anchor still
   * catches accidental rollbacks. `protected` keeps it from posing as security.
   */
  const payload = isProtected
    ? sealer.seal(body).toString('base64')
    : Buffer.from(body, 'utf8').toString('base64')

  return JSON.stringify({ version: GUARD_VERSION, protected: isProtected, payload }, null, 2)
}

/** Never throws — a failure is a return value. */
export function parseGuard(raw: string, sealer: GuardSealer): GuardRead {
  let outer: unknown
  try {
    outer = JSON.parse(raw)
  } catch {
    return { kind: 'unreadable', reason: 'not JSON' }
  }
  if (typeof outer !== 'object' || outer === null || Array.isArray(outer)) {
    return { kind: 'unreadable', reason: 'not an object' }
  }

  const file = outer as Record<string, unknown>
  /*
   * An unknown version is not read, and the caller must not overwrite it —
   * otherwise planting a `version: 999` anchor silently switches detection off.
   */
  if (file.version !== GUARD_VERSION) {
    return { kind: 'unreadable', reason: `unsupported version ${String(file.version)}` }
  }
  if (typeof file.protected !== 'boolean') {
    return { kind: 'unreadable', reason: 'protected flag missing' }
  }
  if (typeof file.payload !== 'string') {
    return { kind: 'unreadable', reason: 'payload missing' }
  }

  const blob = Buffer.from(file.payload, 'base64')
  if (blob.length === 0) return { kind: 'unreadable', reason: 'payload empty' }

  let body: string
  if (file.protected) {
    if (!sealer.available()) {
      // Sealed anchor on a machine without a keyring: unknown, not invalid.
      return { kind: 'unreadable', reason: 'sealed anchor, no keyring available' }
    }
    try {
      body = sealer.open(blob)
    } catch {
      return { kind: 'unreadable', reason: 'cannot decrypt' }
    }
  } else {
    body = blob.toString('utf8')
  }

  let inner: unknown
  try {
    inner = JSON.parse(body)
  } catch {
    return { kind: 'unreadable', reason: 'payload not JSON' }
  }
  if (typeof inner !== 'object' || inner === null || Array.isArray(inner)) {
    return { kind: 'unreadable', reason: 'payload not an object' }
  }

  const data = inner as Record<string, unknown>
  if (typeof data.counter !== 'number' || !Number.isSafeInteger(data.counter) || data.counter < 0) {
    return { kind: 'unreadable', reason: 'counter invalid' }
  }
  if (typeof data.at !== 'number' || !Number.isSafeInteger(data.at) || data.at < 0) {
    return { kind: 'unreadable', reason: 'timestamp invalid' }
  }

  return {
    kind: 'ok',
    anchor: { counter: data.counter, at: data.at, protected: file.protected }
  }
}

/* ------------------------------------------------------------------ file access */

/**
 * A missing file is `absent`, anything else `unreadable` — never merge the two.
 * The caller overwrites the first and not the second; merged, a corrupted anchor
 * would switch detection off by itself.
 *
 * Opened before it is questioned: `fstat` on the descriptor reports
 * `isFile() === false` for a named pipe that `stat` on the path calls a file,
 * and such a pipe would pass the size check and hang the read uncancellably.
 */
export async function readAnchorFile(file: string, sealer: GuardSealer): Promise<GuardRead> {
  let handle: fsp.FileHandle
  try {
    handle = await fsp.open(file, fsConstants.O_RDONLY | O_NONBLOCK)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'unreadable', reason: `cannot open: ${(err as Error).message}` }
  }

  try {
    const stat = await handle.stat()
    if (!stat.isFile()) return { kind: 'unreadable', reason: 'not a regular file' }
    if (stat.size > GUARD_MAX_BYTES) return { kind: 'unreadable', reason: 'too large' }

    /*
     * Second cap behind `stat.size`: the stat result describes the past and the
     * file may have grown since. Both are needed; neither alone is sound.
     */
    const buf = Buffer.alloc(GUARD_MAX_BYTES + 1)
    let filled = 0
    while (filled < buf.length) {
      const { bytesRead } = await handle.read(buf, filled, buf.length - filled, filled)
      if (bytesRead === 0) break
      filled += bytesRead
    }
    if (filled > GUARD_MAX_BYTES) return { kind: 'unreadable', reason: 'too large' }

    return parseGuard(buf.subarray(0, filled).toString('utf8'), sealer)
  } catch (err) {
    return { kind: 'unreadable', reason: `cannot read: ${(err as Error).message}` }
  } finally {
    await handle.close().catch(() => {})
  }
}

/**
 * Writes via a temp file and `rename`: a truncated anchor would read back as
 * `unreadable`, so a power cut must not silently disable detection.
 *
 * **Call only after a successful vault write, never before.** The reverse order
 * leaves the anchor ahead after a crash, and `verdict` then reports a rollback
 * on every unclean shutdown.
 */
export async function writeAnchorFile(
  file: string,
  counter: number,
  at: number,
  sealer: GuardSealer
): Promise<void> {
  const text = serializeGuard(counter, at, sealer)
  const tmp = `${file}.tmp`
  await fsp.writeFile(tmp, text, { encoding: 'utf8', mode: 0o600 })
  await fsp.rename(tmp, file)
}

/**
 * Belongs with deleting the vault: an anchor outliving its vault reports a
 * rollback that never happened against a fresh one, whose counter is at zero.
 */
export async function removeAnchorFile(file: string): Promise<void> {
  await fsp.rm(file, { force: true })
}

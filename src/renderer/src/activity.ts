// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Throttle for "the user is still here" reports; each re-arms the auto-lock
 * timer over IPC, so unthrottled it is one message per keystroke. Leading-edge,
 * not trailing: the first event after a quiet stretch is the moment the user
 * came back and must not wait for a timer.
 *
 * Only genuine user input may be reported. Never wire this to xterm's `onData`:
 * the emulator fires it for replies it owes the server, so a remote host could
 * hold the vault open with a cursor-position query on a timer.
 */
const ACTIVITY_INTERVAL_MS = 5_000

let lastReportedAt = Number.NEGATIVE_INFINITY

export function reportActivity(send: () => void): void {
  const now = Date.now()
  const since = now - lastReportedAt
  // `Date.now()` is wall clock: an NTP correction or a resumed VM snapshot
  // makes `since` negative, which is forever below the interval. Without the
  // `since >= 0` guard every report would be swallowed until the clock caught
  // up, and the vault would lock while the user is typing.
  if (since >= 0 && since < ACTIVITY_INTERVAL_MS) return
  lastReportedAt = now
  send()
}

/** Test seam and lock-time reset; the clock is module state. */
export function resetActivityThrottle(): void {
  lastReportedAt = Number.NEGATIVE_INFINITY
}

export { ACTIVITY_INTERVAL_MS }

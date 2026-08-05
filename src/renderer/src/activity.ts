// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Telling the main process the human is still here.
 *
 * Every report clears and re-arms the auto-lock timer over IPC. Unthrottled
 * that fired once per keystroke and dozens of times per scroll gesture — and
 * once per keystroke again from the terminal's own `onData`, so typing into a
 * session reported twice per character.
 *
 * Auto-lock is measured in minutes, so a report that is up to this many
 * milliseconds late changes nothing about when the vault locks. What it does
 * change is that a burst of input costs one message rather than hundreds.
 *
 * Leading-edge, not trailing: the first event after a quiet stretch is the one
 * that matters — it is the moment the human came back — and it must not wait
 * for a timer before the lock is deferred.
 */
const ACTIVITY_INTERVAL_MS = 5_000

let lastReportedAt = Number.NEGATIVE_INFINITY

export function reportActivity(send: () => void): void {
  const now = Date.now()
  const since = now - lastReportedAt
  // `Date.now()` is wall clock, not monotonic. A step backwards — NTP
  // correcting a drifted machine, a VM resuming from a snapshot, the user
  // changing the timezone — makes `since` negative, and a negative number is
  // forever below the interval. The throttle would then swallow every report
  // until the clock caught back up, and with nothing reaching the main process
  // the auto-lock timer is never re-armed: the vault locks while the user is
  // typing into it.
  //
  // Treating negative as "long enough ago" is the safe direction. The worst it
  // costs is one extra IPC message after a clock jump; the alternative costs
  // the user their session.
  if (since >= 0 && since < ACTIVITY_INTERVAL_MS) return
  lastReportedAt = now
  send()
}

/** Test seam and lock-time reset; the clock is module state. */
export function resetActivityThrottle(): void {
  lastReportedAt = Number.NEGATIVE_INFINITY
}

export { ACTIVITY_INTERVAL_MS }

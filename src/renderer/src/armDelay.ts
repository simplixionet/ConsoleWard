// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useState } from 'react'

/**
 * How long a freshly painted approval dialog refuses to act. A dialog can land
 * under a cursor aimed at something else — the window is raised for the first
 * request, and the next one renders the instant its predecessor is answered —
 * so this must stay long enough to break a click reflex.
 */
export const ARM_DELAY_MS = 400

/**
 * False until the component has actually been on screen for `delayMs`.
 *
 * Two animation frames, not one: the first callback still runs before this
 * commit reaches the screen, the second after it. Timing from mount would let
 * the delay expire while the dialog was invisible. A hidden window never gets
 * frames, so a dialog rendered behind the user's back stays unarmed —
 * intended; a plain setTimeout fallback would give that property away.
 */
export function useArmedAfterPaint(delayMs: number = ARM_DELAY_MS): boolean {
  const [armed, setArmed] = useState(false)

  useEffect(() => {
    let frame = 0
    let timer = 0
    frame = requestAnimationFrame(() => {
      frame = requestAnimationFrame(() => {
        timer = window.setTimeout(() => setArmed(true), delayMs)
      })
    })
    return () => {
      cancelAnimationFrame(frame)
      window.clearTimeout(timer)
    }
  }, [delayMs])

  return armed
}

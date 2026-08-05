// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useState } from 'react'

/**
 * How long a freshly painted approval dialog refuses to act.
 *
 * The window is raised for the first request of a batch, so a dialog can land
 * under a cursor that was aimed at something else entirely — and the next
 * request in the queue renders the instant the previous one is answered, under
 * a cursor that is still on the button. Long enough to break the reflex, short
 * enough that nobody notices they waited.
 */
export const ARM_DELAY_MS = 400

/**
 * False until the component has actually been on screen for `delayMs`.
 *
 * Two animation frames, not one: the first callback still runs before this
 * commit reaches the screen, the second runs after it. Starting the clock on
 * mount would let the delay expire while the dialog was invisible, which is
 * exactly the window a request arriving during a raise would slip through.
 *
 * A hidden or minimised window never gets its frames, so a dialog rendered
 * behind the user's back stays unarmed until the window is genuinely visible.
 * That is intended — do not add a plain setTimeout fallback, it would hand the
 * whole property back.
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

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useRef, useState, type RefObject } from 'react'

/**
 * Whether a scrollable box is hiding some of its content.
 *
 * `.command-box` is capped with `overflow-y: auto`, so anything past the cap
 * scrolls out of sight behind an easily missed scrollbar while the approve
 * button stays in the footer. A gate is only worth something if the human saw
 * every byte they are approving, so the dialogs say when they did not.
 *
 * Measured rather than guessed from a line or character count: the real
 * threshold depends on the font, the DPI and how the lines happen to wrap.
 *
 * `deps` are the values that change the content — remeasure when they do.
 */
export function useClipped(ref: RefObject<HTMLElement | null>, deps: unknown[]): boolean {
  const [clipped, setClipped] = useState(false)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    setClipped(el.scrollHeight > el.clientHeight + 1)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return clipped
}

/** Convenience for the common case: one box, one piece of content. */
export function useClippedBox<T extends HTMLElement>(
  content: unknown
): [RefObject<T | null>, boolean] {
  const ref = useRef<T>(null)
  return [ref, useClipped(ref, [content])]
}

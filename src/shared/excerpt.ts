// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/** Excerpt selection from terminal output, for the share dialog. */

/**
 * Rows offered by the "last N lines" button. Small enough that whatever lands in
 * the review step is short enough to actually be read, large enough that the
 * human does not fall back to selecting by hand every time.
 */
export const EXCERPT_LINES = 20

/**
 * Last `count` lines of text. Deliberately NOT `tailLines` from main/ansi.ts,
 * which looks like the same function and is not: that one caps a buffer and
 * counts the empty string after a trailing newline as one of its lines. Here a
 * trailing newline terminates the last line rather than starting a new one, so
 * twenty lines of terminal output are twenty lines and not nineteen plus a
 * blank. Merging the two would silently change one caller or the other.
 */
export function lastLines(text: string, count: number): string {
  // States the contract; not load-bearing — the tail below already returns ''.
  if (count <= 0 || text === '') return ''
  const body = text.endsWith('\n') ? text.slice(0, -1) : text
  const lines = body.split('\n')
  if (lines.length <= count) return body
  return lines.slice(lines.length - count).join('\n')
}

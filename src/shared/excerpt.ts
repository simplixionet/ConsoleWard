// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Výběr úryvku z výstupu terminálu pro sdílecí dialog.
 */

/**
 * Kolik řádků nabídne tlačítko „posledních N řádků".
 *
 * The number is a compromise between the two ways this button gets misused. Too
 * few and it never answers the model's question, so the human falls back to
 * selecting by hand every time and the shortcut is dead weight. Too many and it
 * is the old "send everything" button wearing a smaller number — the point of
 * the redesign is that whatever lands in the review step is short enough to
 * actually be read, and twenty lines is about the limit of that.
 */
export const EXCERPT_LINES = 20

/**
 * Posledních `count` řádků textu.
 *
 * Deliberately NOT `tailLines` from main/ansi.ts, which looks like the same
 * function and is not: that one caps a buffer (returns the input untouched when
 * it is already short, and counts the empty string after a trailing newline as
 * one of its lines). Here a trailing newline terminates the last line rather
 * than starting a new one, so asking for twenty lines of a buffer that ends the
 * way terminal output always ends gives twenty lines of text and not nineteen
 * plus a blank. Merging the two would silently change one caller or the other.
 */
export function lastLines(text: string, count: number): string {
  // Belt and braces, not load-bearing: with the guard removed the tail below
  // already returns '' for both cases, because slice() past the end of an array
  // yields an empty one. Deleting it breaks no test — it is here to state the
  // contract for anyone editing the tail, not because the tail depends on it.
  if (count <= 0 || text === '') return ''
  const body = text.endsWith('\n') ? text.slice(0, -1) : text
  const lines = body.split('\n')
  if (lines.length <= count) return body
  return lines.slice(lines.length - count).join('\n')
}

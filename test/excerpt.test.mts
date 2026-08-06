// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import { EXCERPT_LINES, lastLines } from '../src/shared/excerpt.ts'

describe('lastLines', () => {
  it('returns the last N lines', () => {
    assert.equal(lastLines('a\nb\nc\nd\ne', 3), 'c\nd\ne')
  })

  it('returns a shorter text in full', () => {
    assert.equal(lastLines('a\nb', 10), 'a\nb')
    assert.equal(lastLines('a single line', 20), 'a single line')
  })

  it('returns exactly N lines unchanged', () => {
    assert.equal(lastLines('a\nb\nc', 3), 'a\nb\nc')
  })

  /*
   * Why this is not main's tailLines: terminal output ends with a newline, so a
   * naive split leaves a trailing empty string that eats one of the N slots.
   */
  it('a trailing newline ends the last line, it does not begin a new one', () => {
    assert.equal(lastLines('a\nb\nc\n', 3), 'a\nb\nc')
    assert.equal(lastLines('a\nb\nc\nd\n', 2), 'c\nd')
    assert.equal(lastLines('a single line\n', 20), 'a single line')
  })

  it('only the final separator is dropped, blank lines inside stay', () => {
    assert.equal(lastLines('a\n\n\n', 5), 'a\n\n')
    assert.equal(lastLines('a\n\n\n', 2), '\n')
  })

  it('empty input and a lone newline both give an empty excerpt', () => {
    assert.equal(lastLines('', 20), '')
    assert.equal(lastLines('\n', 20), '')
  })

  it('a zero or negative count selects nothing', () => {
    assert.equal(lastLines('a\nb\nc', 0), '')
    assert.equal(lastLines('a\nb\nc', -1), '')
  })

  /*
   * A helper that quietly handed back more than it was asked for would route
   * around the one rule the review dialog rests on: nothing leaves without
   * someone choosing it.
   */
  it('never returns more than was asked for', () => {
    const text = Array.from({ length: 500 }, (_, i) => `line ${i}`).join('\n')
    for (const n of [1, 2, 20, 499, 500]) {
      assert.equal(lastLines(text, n).split('\n').length, n)
    }
  })

  it('EXCERPT_LINES stays within sane bounds', () => {
    assert.ok(EXCERPT_LINES >= 5 && EXCERPT_LINES <= 100)
  })
})

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import { EXCERPT_LINES, lastLines } from '../src/shared/excerpt.ts'

describe('lastLines', () => {
  it('vrátí posledních N řádků', () => {
    assert.equal(lastLines('a\nb\nc\nd\ne', 3), 'c\nd\ne')
  })

  it('kratší text vrátí celý', () => {
    assert.equal(lastLines('a\nb', 10), 'a\nb')
    assert.equal(lastLines('jediný řádek', 20), 'jediný řádek')
  })

  it('přesně N řádků vrátí beze změny', () => {
    assert.equal(lastLines('a\nb\nc', 3), 'a\nb\nc')
  })

  /*
   * The whole reason this is not main's tailLines. Terminal output ends with a
   * newline, so a naive split gives a trailing empty string that eats one of
   * the N slots and shows up in the review dialog as a blank final line.
   */
  it('koncový nový řádek ukončuje poslední řádek, nezakládá nový', () => {
    assert.equal(lastLines('a\nb\nc\n', 3), 'a\nb\nc')
    assert.equal(lastLines('a\nb\nc\nd\n', 2), 'c\nd')
    assert.equal(lastLines('jediný\n', 20), 'jediný')
  })

  it('zahodí se jen poslední oddělovač, prázdné řádky uvnitř zůstanou', () => {
    assert.equal(lastLines('a\n\n\n', 5), 'a\n\n')
    assert.equal(lastLines('a\n\n\n', 2), '\n')
  })

  it('prázdný vstup i samotný nový řádek dají prázdný výběr', () => {
    assert.equal(lastLines('', 20), '')
    assert.equal(lastLines('\n', 20), '')
  })

  it('nulový nebo záporný počet nevybere nic', () => {
    assert.equal(lastLines('a\nb\nc', 0), '')
    assert.equal(lastLines('a\nb\nc', -1), '')
  })

  /*
   * The dialog disables "continue" on an empty excerpt, so a helper that can
   * quietly hand back the whole buffer would route around the one rule the
   * redesign is built on: nothing leaves without someone choosing it.
   */
  it('nikdy nevrátí víc, než kolik bylo požádáno', () => {
    const text = Array.from({ length: 500 }, (_, i) => `line ${i}`).join('\n')
    for (const n of [1, 2, 20, 499, 500]) {
      assert.equal(lastLines(text, n).split('\n').length, n)
    }
  })

  it('EXCERPT_LINES je v rozumných mezích', () => {
    assert.ok(EXCERPT_LINES >= 5 && EXCERPT_LINES <= 100)
  })
})

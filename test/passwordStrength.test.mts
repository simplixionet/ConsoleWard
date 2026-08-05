// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The master-password strength estimate.
 *
 * The number is shown to a person, not used as a gate — the gate is the length
 * floor, which is a fact rather than a guess. So these tests pin the ORDERING
 * (this password must not rate above that one) rather than exact bit counts,
 * which would break on any tweak to the model without meaning anything.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import {
  estimatePasswordStrength as rate,
  MIN_PASSWORD_LENGTH
} from '../src/shared/passwordStrength.ts'

describe('estimatePasswordStrength', () => {
  test('anything under the floor is refused rather than rated', () => {
    // Rating a password the vault will refuse invites the user to argue with a
    // number instead of reading the requirement.
    const short = 'x'.repeat(MIN_PASSWORD_LENGTH - 1)
    assert.equal(rate(short).acceptable, false)
    assert.equal(rate(short).verdict, 'tooShort')
    assert.equal(rate(short).bits, 0, 'a refused password was still given a score')
  })

  test('the floor itself is accepted', () => {
    assert.equal(rate('x'.repeat(MIN_PASSWORD_LENGTH)).acceptable, true)
  })

  test('survives the inputs that are not passwords', () => {
    for (const bad of ['', null, undefined, 42, {}]) {
      const out = rate(bad as never)
      assert.equal(out.acceptable, false, `${JSON.stringify(bad)} was accepted`)
      assert.equal(typeof out.bits, 'number')
    }
  })

  test('a run of one character is not twelve characters of strength', () => {
    // What people type when told to make it longer. It has to cost something
    // here, or the meter rewards exactly the wrong instinct.
    assert.ok(
      rate('aaaaaaaaaaaaaaaa').bits < rate('kzqmwtbrxnvd').bits,
      'sixteen repeats outscored twelve unrelated letters'
    )
    assert.equal(rate('aaaaaaaaaaaaaaaa').verdict, 'weak')
  })

  test('a straight alphabetical or numeric walk is not strength either', () => {
    assert.ok(
      rate('abcdefghijklmnop').bits < rate('kzqmwtbrxnvd').bits,
      'the alphabet outscored twelve unrelated letters'
    )
    assert.ok(rate('0123456789012345').bits < rate('kzqmwtbrxnvd').bits, 'counting outscored it')
  })

  test('length beats punctuation, which is the advice the hint gives', () => {
    // The hint tells the user four or five unrelated words beat any amount of
    // punctuation. The meter has to agree with the hint, or one of them is
    // lying to the person reading both.
    const words = 'correct horse battery staple'
    const gnarly = 'P@ssw0rd!#$'.padEnd(MIN_PASSWORD_LENGTH, '%')
    assert.ok(
      rate(words).bits > rate(gnarly).bits,
      `the passphrase (${rate(words).bits} bits) did not beat the punctuation (${rate(gnarly).bits})`
    )
  })

  test('the verdicts are ordered and reachable', () => {
    assert.equal(rate('aaaaaaaaaaaaaaaa').verdict, 'weak')
    assert.equal(rate('kzqmwtbrxnvd').verdict, 'fair')
    assert.equal(rate('correct horse battery staple').verdict, 'strong')
  })

  test('more of the same password never scores lower', () => {
    // Monotonicity in length: a user adding a character must never watch the
    // meter go down, or they stop trusting it.
    let previous = 0
    let pw = 'kzqmwtbrxnvd'
    for (let i = 0; i < 12; i++) {
      const bits = rate(pw).bits
      assert.ok(bits >= previous, `adding a character lowered the score at length ${pw.length}`)
      previous = bits
      pw += String.fromCharCode(97 + ((i * 7) % 26))
    }
  })
})

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * How much a master password is actually worth.
 *
 * Deliberately not zxcvbn. That would be a good estimator and a megabyte of
 * dictionary in an installer whose whole pitch is that you can read what it
 * does — and this number is shown to a person, not used as a gate. The gate is
 * the length floor below, which is a fact rather than a guess.
 *
 * What this does estimate is the search space an attacker who knows the shape
 * of the password would face, which is the honest reading of "strength": the
 * character classes actually used, times the length, minus what obvious
 * structure gives back for free.
 *
 * It is shared because both ends need the same answer. The renderer draws the
 * meter, the main process enforces the floor, and a meter that says "strong"
 * over a password the vault then refuses is worse than no meter.
 */

/**
 * The shortest master password the vault will accept.
 *
 * Was eight, which at four random words is fine and at eight characters of
 * anything a human invented is not — scrypt at N = 2^17 buys roughly 160 ms per
 * guess, so eight lowercase letters is days on one machine and hours on a few.
 * Twelve is the point where even an all-lowercase password costs more than an
 * offline attacker is likely to spend on one vault, and it is short enough that
 * nobody reaches for a sticky note.
 *
 * Only `create`, `changePassword` and the new password set during recovery are
 * checked against it. Unlocking is not, so raising it never locks anyone out of
 * a vault they already have.
 */
export const MIN_PASSWORD_LENGTH = 12

export type PasswordVerdict = 'tooShort' | 'weak' | 'fair' | 'strong'

export interface PasswordStrength {
  /** Estimated bits of entropy, rounded down. Zero for anything under the floor. */
  bits: number
  verdict: PasswordVerdict
  /** True when the vault will accept it. Exactly `length >= MIN_PASSWORD_LENGTH`. */
  acceptable: boolean
}

/** Roughly how many symbols each class adds to the alphabet an attacker tries. */
const CLASSES: { re: RegExp; size: number }[] = [
  { re: /[a-z]/, size: 26 },
  { re: /[A-Z]/, size: 26 },
  { re: /[0-9]/, size: 10 },
  { re: /[^A-Za-z0-9]/, size: 33 }
]

/**
 * Length after collapsing the structure a guesser gets for free.
 *
 * `aaaaaaaaaaaa` is twelve characters and about as hard as one. `abcdefghijkl`
 * is twelve characters and about as hard as `abc`. Neither is exotic — both are
 * what people type when told to make it longer — so both have to cost something
 * here or the meter rewards exactly the wrong instinct.
 */
function effectiveLength(pw: string): number {
  let length = 0
  let previous = -1
  let run = 0
  for (const ch of pw) {
    const code = ch.codePointAt(0) ?? 0
    const step = code - previous
    // A run of the same character, or a straight ascending or descending walk.
    // Guarded on `previous`, not on `run`: `run` only grows once a pattern has
    // been seen, so testing it here would mean a pattern could never start.
    const patterned = previous >= 0 && (step === 0 || step === 1 || step === -1)
    // The first repetition still costs something; the tenth costs almost nothing.
    length += patterned ? 1 / (run + 1) : 1
    run = patterned ? run + 1 : 0
    previous = code
  }
  return length
}

export function estimatePasswordStrength(pw: string): PasswordStrength {
  const text = typeof pw === 'string' ? pw : ''
  if (text.length < MIN_PASSWORD_LENGTH) {
    return { bits: 0, verdict: 'tooShort', acceptable: false }
  }

  const alphabet = CLASSES.reduce((sum, c) => sum + (c.re.test(text) ? c.size : 0), 0)
  const distinct = new Set(text).size
  // The classes say what an attacker would have to try; the distinct count says
  // what was actually reached for. Twelve 'a's touch a 26-letter alphabet and
  // one symbol, and no class analysis should pretend otherwise — but a genuinely
  // random twelve-character string only touches twelve of the twenty-six either,
  // so clamping straight to `distinct` would punish it for being short. Doubling
  // splits the difference: it bites hard on `abab…` and barely at all on a
  // password that simply is not very long.
  const symbols = Math.max(2, Math.min(alphabet, distinct * 2))
  const bits = Math.floor(effectiveLength(text) * Math.log2(symbols))

  const verdict: PasswordVerdict = bits >= 70 ? 'strong' : bits >= 50 ? 'fair' : 'weak'
  return { bits, verdict, acceptable: true }
}

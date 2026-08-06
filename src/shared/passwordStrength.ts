// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * How much a master password is actually worth. Deliberately not zxcvbn: a
 * megabyte of dictionary for a number shown to a person, not used as a gate.
 *
 * Shared because both ends need the same answer — the renderer draws the meter,
 * the main process enforces the floor, and a meter that says "strong" over a
 * password the vault then refuses is worse than no meter.
 */

/**
 * The shortest master password the vault accepts. scrypt at N = 2^17 buys ~160
 * ms per guess, so eight human-invented characters fall in hours to days
 * offline; twelve costs more than an attacker is likely to spend on one vault.
 *
 * Only `create`, `changePassword` and recovery's new password are checked
 * against it — unlocking is not, so raising it locks nobody out of a vault they
 * already have.
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
 * Length after collapsing structure a guesser gets free: `aaaaaaaaaaaa` is about
 * as hard as one character, `abcdefghijkl` as hard as `abc`. Both are what people
 * type when told to make it longer, so both must cost something here.
 */
function effectiveLength(pw: string): number {
  let length = 0
  let previous = -1
  let run = 0
  for (const ch of pw) {
    const code = ch.codePointAt(0) ?? 0
    const step = code - previous
    // Guarded on `previous`, not on `run`: `run` only grows once a pattern has
    // been seen, so testing it here would mean a pattern could never start.
    const patterned = previous >= 0 && (step === 0 || step === 1 || step === -1)
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
  // Doubling `distinct` splits the difference: twelve 'a's read as a 26-letter
  // alphabet by class but reach one symbol, while a genuinely random twelve-char
  // string reaches only twelve — clamping to `distinct` would punish it for that.
  const symbols = Math.max(2, Math.min(alphabet, distinct * 2))
  const bits = Math.floor(effectiveLength(text) * Math.log2(symbols))

  const verdict: PasswordVerdict = bits >= 70 ? 'strong' : bits >= 50 ? 'fair' : 'weak'
  return { bits, verdict, acceptable: true }
}

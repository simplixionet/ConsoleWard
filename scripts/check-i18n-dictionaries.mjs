// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Checks the locale dictionaries on disk. Static counterpart to
 * `check-i18n-ui.mjs`: that one drives the built app, this one reads the data.
 *
 * Four checks:
 *   D1 — the locale array holds exactly the 8 shipping codes, and a
 *        dictionary file exists for each (SC-1).
 *   D2 — key parity, plural-aware (SC-3). NOT strict equality with English:
 *        Czech correctly carries two plural keys English does not have.
 *   D3 — every {{placeholder}} in the 61 security-critical keys survives
 *        translation intact (SC-4).
 *   D4 — informational review table of the security strings that carry a
 *        negation or a limiter. Feeds the human checkpoint. Never fails.
 *
 * Exit code is 1 when D1, D2 or D3 failed. D4 never affects it — a
 * length-ratio gate that cannot fail on real data would only be noise.
 */
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import path from 'node:path'

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url))
const LOCALES_DIR = path.join(PROJECT_ROOT, 'src/shared/locales')
const I18N_SOURCE = path.join(PROJECT_ROOT, 'src/shared/i18n.ts')

/** The shipping set, in the order the picker offers it (D-01). */
const SHIPPING = ['en', 'cs', 'de', 'es', 'fr', 'it', 'pt-BR', 'nl']

/** The only two pluralised keys in the dictionary. */
const PLURAL_KEYS = ['term.connCount', 'term.snipCount']

/** Namespaces where a weakened string is a security failure, not a typo. */
const SECURITY_NAMESPACES = ['hostkey.', 'mcp.', 'secret.', 'recovery.']

/** Words whose loss flips a warning's meaning. Checked on the English source. */
const LIMITERS =
  /\b(not|never|no|none|cannot|can't|don't|doesn't|won't|without|only)\b/i

function report(check, locale, ok, detail) {
  const loc = locale ? ` [${locale}]` : ''
  const extra = detail ? ` — ${detail}` : ''
  console.log(`${check}${loc}: ${ok ? 'PASS' : 'FAIL'}${extra}`)
}

function readDictionary(code) {
  const file = path.join(LOCALES_DIR, `${code}.json`)
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

/** Placeholder tokens as a sorted multiset, so a duplicate is not lost. */
function placeholders(text) {
  return [...String(text).matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort()
}

/**
 * Categories the language actually uses for integers. Derived from the
 * platform, never hand-rolled — Czech's one/few/other split is exactly what
 * hand-written ternaries get wrong.
 */
function integerCategories(code) {
  const rules = new Intl.PluralRules(code)
  const seen = new Set()
  for (let i = 0; i <= 1000; i++) seen.add(rules.select(i))
  return [...seen].sort()
}

function isPluralVariant(key) {
  return PLURAL_KEYS.some((base) => key.startsWith(`${base}_`))
}

/* ------------------------------------------------------------------ D1 */

function checkLocaleArray() {
  const source = fs.readFileSync(I18N_SOURCE, 'utf8')
  const block = source.match(/export const LOCALES[\s\S]*?\n\]/)
  if (!block) {
    report('D1', null, false, 'could not find the LOCALES array in src/shared/i18n.ts')
    return false
  }

  const codes = [...block[0].matchAll(/code:\s*'([^']+)'/g)].map((m) => m[1])
  let ok = true

  if (codes.join(',') !== SHIPPING.join(',')) {
    report('D1', null, false, `LOCALES holds [${codes.join(', ')}], expected [${SHIPPING.join(', ')}]`)
    ok = false
  }

  for (const code of codes) {
    if (!fs.existsSync(path.join(LOCALES_DIR, `${code}.json`))) {
      report('D1', code, false, `listed in LOCALES but ${code}.json does not exist`)
      ok = false
    }
  }

  if (ok) report('D1', null, true, `${codes.length} codes, a dictionary file for each`)
  return ok
}

/* ------------------------------------------------------------------ D2 */

function checkParity(dicts) {
  // The base set excludes plural variants — those are per-language by design.
  const base = Object.keys(dicts.en).filter((k) => !isPluralVariant(k))
  let ok = true

  console.log('')
  console.log('  code    total  missing  extra  plural-missing  categories')
  console.log('  ------  -----  -------  -----  --------------  ----------')

  for (const code of SHIPPING) {
    const keys = Object.keys(dicts[code])
    const missing = base.filter((k) => !keys.includes(k))
    const extra = keys.filter((k) => !base.includes(k) && !isPluralVariant(k))

    const categories = integerCategories(code)
    const needed = categories.flatMap((c) => PLURAL_KEYS.map((base) => `${base}_${c}`))
    const pluralMissing = needed.filter((k) => !keys.includes(k))

    if (missing.length || extra.length || pluralMissing.length) ok = false

    console.log(
      `  ${code.padEnd(6)}  ${String(keys.length).padStart(5)}  ` +
        `${String(missing.length).padStart(7)}  ${String(extra.length).padStart(5)}  ` +
        `${String(pluralMissing.length).padStart(14)}  ${categories.join('+')}`
    )

    for (const k of missing.slice(0, 5)) console.log(`          missing: ${k}`)
    for (const k of extra.slice(0, 5)) console.log(`          extra:   ${k}`)
    for (const k of pluralMissing) console.log(`          plural:  ${k}`)
  }

  console.log('')
  report('D2', null, ok, ok ? 'key parity holds in all 8 locales' : 'key parity broken')
  return ok
}

/* ------------------------------------------------------------------ D3 */

function securityKeys(en) {
  return Object.keys(en).filter((k) => SECURITY_NAMESPACES.some((ns) => k.startsWith(ns)))
}

function checkPlaceholders(dicts, keys) {
  let ok = true
  let withPlaceholders = 0

  for (const key of keys) {
    const want = placeholders(dicts.en[key])
    if (want.length) withPlaceholders++

    for (const code of SHIPPING) {
      if (code === 'en') continue
      const value = dicts[code][key]
      if (value === undefined) continue // D2 already reported it as missing
      const got = placeholders(value)
      if (got.join(',') !== want.join(',')) {
        report('D3', code, false, `${key}: expected {{${want.join('}} {{')}}}, got ${got.length ? `{{${got.join('}} {{')}}}` : 'none'}`)
        ok = false
      }
    }
  }

  if (ok) {
    report(
      'D3',
      null,
      true,
      `${keys.length} security-critical keys, ${withPlaceholders} carrying placeholders, intact in all 7 translations`
    )
  }
  return ok
}

/* ------------------------------------------------------------------ D4 */

function reviewTable(dicts, keys) {
  const flagged = keys.filter((k) => LIMITERS.test(dicts.en[k]))

  console.log('')
  console.log('D4 — security strings carrying a negation or a limiter (informational)')
  console.log(`     ${flagged.length} of ${keys.length} security-critical keys. Read these; no script can.`)
  console.log('     ratio = translated length / English length. Printed, not gated:')
  console.log('     the observed spread is too wide for any threshold to mean anything.')

  for (const key of flagged) {
    const english = dicts.en[key]
    console.log('')
    console.log(`  ${key}`)
    console.log(`    en     1.00  ${english}`)
    for (const code of SHIPPING) {
      if (code === 'en') continue
      const value = dicts[code][key] ?? '(missing)'
      const ratio = (String(value).length / english.length).toFixed(2)
      const same = value === english ? '  <- identical to English' : ''
      console.log(`    ${code.padEnd(6)} ${ratio}  ${value}${same}`)
    }
  }
  console.log('')
}

/* ----------------------------------------------------------------- main */

function main() {
  const dicts = {}
  for (const code of SHIPPING) {
    try {
      dicts[code] = readDictionary(code)
    } catch (err) {
      report('D1', code, false, `cannot read ${code}.json — ${err.message}`)
      process.exitCode = 1
      return
    }
  }

  const keys = securityKeys(dicts.en)

  console.log(`Source dictionary: ${Object.keys(dicts.en).length} keys, ${keys.length} security-critical.`)

  let ok = checkLocaleArray()
  ok = checkParity(dicts) && ok
  ok = checkPlaceholders(dicts, keys) && ok

  reviewTable(dicts, keys)

  console.log(ok ? 'RESULT: all checks passed' : 'RESULT: one or more checks failed')
  process.exitCode = ok ? 0 : 1
}

main()

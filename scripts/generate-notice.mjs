// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Builds NOTICE from the production dependency tree. GPL-3.0 requires the
 * licence texts of everything distributed with the binary to travel with it,
 * and electron-builder ships only the project's own LICENSE.
 *
 *   node scripts/generate-notice.mjs           # write the checked-in NOTICE
 *   node scripts/generate-notice.mjs --check   # fail if that file is out of date
 *   node scripts/generate-notice.mjs --dist    # write what THIS machine ships
 *
 * The two outputs differ on purpose. Optional packages (cpu-features,
 * buildcheck, nan) install only where a compiler is present, so the checked-in
 * file comes from the lock file alone with those skipped — the only way it is
 * byte-identical everywhere and can be checked. --dist reads the installed tree.
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const noticePath = path.join(root, 'NOTICE')

const LICENCE_FILES = [
  'LICENSE',
  'LICENSE.md',
  'LICENSE.txt',
  'LICENCE',
  'LICENCE.md',
  'LICENCE.txt',
  'License',
  'license',
  'COPYING',
  'COPYING.md'
]

/**
 * Every non-dev package in the resolved tree, from package-lock.json rather
 * than `npm ls`: node 24 on Windows will not spawn `npm.cmd` without a shell.
 * Optional packages are kept only for --dist — the checked-in file cannot
 * contain them and stay reproducible off this machine.
 */
function productionPackages({ includeOptional }) {
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'))
  const found = new Map()
  const skipped = new Set()

  for (const [key, info] of Object.entries(lock.packages ?? {})) {
    if (!key.startsWith('node_modules/') || info.dev) continue
    if (info.optional && !includeOptional) {
      skipped.add(key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length))
      continue
    }
    // Nested installs appear as `node_modules/a/node_modules/b`; the name is what follows the last one.
    const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length)
    const version = info.version ?? null

    // Keyed by name AND version, carrying the path the package actually lives
    // at. Keying by name alone reads the licence from the top-level directory,
    // which can be a different package under a different licence:
    // `cross-spawn/node_modules/isexe` is ISC, top-level `isexe` is BlueOak.
    const id = `${name}@${version ?? '?'}`
    if (!found.has(id)) found.set(id, { name, version, dir: key })
  }
  const packages = [...found.values()].sort((a, b) =>
    a.name === b.name ? (a.version < b.version ? -1 : 1) : a.name < b.name ? -1 : 1
  )
  return { packages, skipped: [...skipped].sort() }
}

function readPackage(installPath) {
  const dir = path.join(root, ...installPath.split('/'))
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'))
    for (const file of LICENCE_FILES) {
      const candidate = path.join(dir, file)
      if (fs.existsSync(candidate)) {
        return { meta, text: fs.readFileSync(candidate, 'utf8').trim(), file }
      }
    }
    return { meta, text: null, file: null }
  } catch {
    return null
  }
}

function licenceId(meta) {
  if (typeof meta.license === 'string') return meta.license
  if (meta.license && typeof meta.license === 'object') return meta.license.type ?? 'UNKNOWN'
  if (Array.isArray(meta.licenses)) return meta.licenses.map((l) => l.type ?? l).join(' OR ')
  return 'UNKNOWN'
}

function build({ includeOptional }) {
  const { packages, skipped } = productionPackages({ includeOptional })
  const sections = []
  const missing = []
  const counts = new Map()

  const absent = []

  for (const { name, version, dir } of packages) {
    const found = readPackage(dir)
    if (!found) {
      // Declared in the tree but not on disk, so not distributed and not ours
      // to reproduce. A build machine with a compiler ships optional native
      // packages this one does not, so the release build must regenerate.
      absent.push(name)
      continue
    }
    const id = licenceId(found.meta)
    counts.set(id, (counts.get(id) ?? 0) + 1)

    // A real gap, not a formatting problem: the obligation is to reproduce the
    // terms, and naming the SPDX id is not that.
    if (!found.text) missing.push(`${name}@${version ?? '?'} — declares ${id}, ships no text`)

    const heading = `${name}@${version ?? found.meta.version ?? '?'}`
    const homepage = found.meta.homepage ? `\n${found.meta.homepage}` : ''
    sections.push(
      [
        '-'.repeat(78),
        `${heading}`,
        `SPDX-License-Identifier: ${id}${homepage}`,
        '-'.repeat(78),
        '',
        found.text ?? `[No licence text shipped in the package. Declared licence: ${id}.]`,
        ''
      ].join('\n')
    )
  }

  const summary = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([id, n]) => `  ${String(n).padStart(3)}  ${id}`)
    .join('\n')

  /*
    Named, not silently dropped: this file is a checkable claim about what is
    inside, so the one category it does not cover must be visible in it.
  */
  const optionalNote = skipped.length
    ? [
        '',
        'Conditionally installed packages are NOT listed above: they build only',
        'where a toolchain is present, so a file that included them would depend',
        'on the machine that generated it and could not be checked. The installer',
        'ships a NOTICE regenerated with --dist on the build machine, which does',
        'reproduce the terms of whichever of these it actually installed:',
        ...skipped.map((name) => `  ${name}`)
      ]
    : []

  const header = [
    'THIRD-PARTY NOTICES',
    '',
    'ConsoleWard itself is licensed under GPL-3.0-or-later; see LICENSE.',
    '',
    'This file reproduces the licence terms of the third-party software',
    'distributed with the ConsoleWard binary. Every package below is either',
    'bundled into the application code by the renderer build or loaded from',
    'node_modules by the main process at runtime.',
    '',
    'Generated by scripts/generate-notice.mjs from the production dependency',
    'tree. Do not edit by hand — regenerate it.',
    '',
    `Packages: ${packages.length - absent.length}`,
    '',
    summary,
    ...optionalNote,
    '',
    'Electron, Chromium and Node.js are not reproduced here. electron-builder',
    'already places their terms beside the executable, as LICENSE.electron.txt',
    'and LICENSES.chromium.html — verified in the packaged output, not assumed.',
    '',
    ''
  ].join('\n')

  return {
    text: header + sections.join('\n'),
    missing,
    absent,
    count: packages.length - absent.length
  }
}

const check = process.argv.includes('--check')
/*
  --check must stay a pure function of the lock file: a gate whose expected
  value depends on the machine running it is not a gate. So --dist, the only
  form that reads optional packages off disk, is ignored when --check is set.
*/
const dist = process.argv.includes('--dist') && !check
const { text, missing, absent, count } = build({ includeOptional: dist })

if (check) {
  const current = fs.existsSync(noticePath) ? fs.readFileSync(noticePath, 'utf8') : ''
  // Line endings normalised: git rewrites them on checkout under
  // `core.autocrlf`, so a byte comparison fails on every Windows checkout.
  const same = current.replace(/\r\n/g, '\n') === text.replace(/\r\n/g, '\n')
  if (!same) {
    console.error('NOTICE is out of date. Run: node scripts/generate-notice.mjs')
    process.exit(1)
  }
  console.log(`NOTICE is current (${count} packages).`)
} else {
  fs.writeFileSync(noticePath, text, 'utf8')
  console.log(`NOTICE written: ${count} packages.`)
}

if (absent.length) {
  console.log('\nDeclared in the tree but not installed here, so not distributed:')
  for (const name of absent) console.log(`  ${name}`)
  console.log(
    '\nOnly --dist reads the installed tree, so this list is what THIS machine\n' +
      'would have shipped and did not. The checked-in NOTICE is unaffected.'
  )
}

if (missing.length) {
  console.warn('\nInstalled, but their terms could not be reproduced in full:')
  for (const m of missing) console.warn(`  ${m}`)
  console.warn('\nEach needs its licence text sourced by hand before release.')
  process.exitCode = 1
}

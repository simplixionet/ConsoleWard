// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Builds NOTICE from the production dependency tree.
 *
 * GPL-3.0 requires the licence texts of everything distributed alongside the
 * binary to travel with it. electron-builder does not do this: `build.files`
 * carries the project's own LICENSE and nothing else, so without this the
 * installer shipped 40-odd MIT and BSD notices' worth of code and none of their
 * terms.
 *
 * A script rather than a hand-written file because it has to stay true. A
 * dependency added six months from now changes the obligation, and a NOTICE
 * nobody regenerates is worse than none — it is a specific, checkable claim
 * about what is inside, and it would be wrong.
 *
 *   node scripts/generate-notice.mjs           # write the checked-in NOTICE
 *   node scripts/generate-notice.mjs --check   # fail if that file is out of date
 *   node scripts/generate-notice.mjs --dist    # write what THIS machine ships
 *
 * The --check form is what CI runs, so a forgotten regeneration is a red build
 * rather than a licensing problem discovered by someone else.
 *
 * Why there are two forms. Three production packages are `optional` in the lock
 * file — `cpu-features`, `buildcheck` and `nan` — and whether they install at
 * all depends on the machine: ssh2 asks for `cpu-features`, which needs a
 * compiler. So a developer laptop resolves 104 packages and a Windows CI runner
 * with MSVC resolves 106, from identical sources. A `--check` that read the
 * installed tree therefore compared two different questions and failed on every
 * runner that could build more than the committer's machine could, which is
 * what it did: CI has been red since the gate started running there.
 *
 * The checked-in file is built from the lock file alone, skipping everything
 * marked optional, so it is byte-identical everywhere and can be checked. The
 * shipped file is built with --dist from what is actually on disk, on the
 * machine that produces the installer, so it reproduces the terms of everything
 * that really goes out. Those are genuinely two different files and conflating
 * them is what broke.
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const noticePath = path.join(root, 'NOTICE')

/** Files a package might keep its licence text in, in the order to prefer them. */
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
 * Every non-dev package in the resolved tree, from package-lock.json.
 *
 * The lock file rather than `npm ls`: it is the resolved tree already, it needs
 * no subprocess, and node 24 on Windows refuses to spawn `npm.cmd` without a
 * shell — and routing arguments through a shell in a script CI runs is not a
 * trade worth making for a file read.
 *
 * `dev` is what decides what is production at all. `optional` decides only
 * whether a package can be counted on to be here: an optional dependency that
 * IS installed is distributed like any other, so --dist keeps it, but the
 * checked-in file cannot contain it and still be reproducible off this machine.
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
    // Nested installs appear as `node_modules/a/node_modules/b`; the package is
    // whatever follows the last `node_modules/`.
    const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length)
    const version = info.version ?? null

    // Keyed by name AND version, and carrying the path the package actually
    // lives at. Keying by name alone recorded the nested version and then read
    // the licence from the top-level directory, which is a different package:
    // `cross-spawn/node_modules/isexe` is 2.0.0 under ISC while the top-level
    // `isexe` is 3.1.5 under BlueOak-1.0.0, so NOTICE named one and reproduced
    // the terms of the other. Attributing the wrong licence to a shipped
    // package is the exact failure this file exists to prevent.
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

/** The SPDX id a package declares, however it chose to declare it. */
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
      // Declared somewhere in the tree but not on disk, so not distributed and
      // not ours to reproduce. Optional native dependencies land here: ssh2
      // asks for `cpu-features`, which needs a compiler. That means a build
      // machine that HAS one ships a package this one does not — which is
      // exactly why the release build must regenerate rather than reuse.
      absent.push(name)
      continue
    }
    const id = licenceId(found.meta)
    counts.set(id, (counts.get(id) ?? 0) + 1)

    // A package that declares a licence but ships no text is a real gap, not a
    // formatting problem: the obligation is to reproduce the terms, and naming
    // the SPDX id is not that.
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
    Named, not silently dropped. The whole value of this file is that it is a
    checkable claim about what is inside, so the one category it deliberately
    does not cover has to be visible in it — otherwise the omission is
    indistinguishable from a bug, which is how it would eventually be treated.
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
  --dist is the only form that reads optional packages off disk, and it is only
  ever run on the machine that produces the installer. Everything else — the
  checked-in file and the gate that guards it — is a pure function of the lock
  file, so it gives the same answer on a laptop and on a runner with a compiler.
  --check never accepts --dist: a gate whose expected value depends on the
  machine running it is not a gate.
*/
const dist = process.argv.includes('--dist') && !check
const { text, missing, absent, count } = build({ includeOptional: dist })

if (check) {
  const current = fs.existsSync(noticePath) ? fs.readFileSync(noticePath, 'utf8') : ''
  // Compared with line endings normalised. Git rewrites them on checkout under
  // `core.autocrlf`, which is the default on Windows, so a byte comparison here
  // would fail on every developer machine that had ever checked the file out —
  // a gate that is always red teaches people to ignore it.
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

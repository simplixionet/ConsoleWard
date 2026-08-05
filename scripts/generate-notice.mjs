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
 *   node scripts/generate-notice.mjs           # write NOTICE
 *   node scripts/generate-notice.mjs --check   # fail if NOTICE is out of date
 *
 * The --check form is what CI runs, so a forgotten regeneration is a red build
 * rather than a licensing problem discovered by someone else.
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
 * `dev` is what decides. `optional` is kept, because an optional dependency
 * that IS installed is distributed like any other.
 */
function productionPackages() {
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'))
  const found = new Map()

  for (const [key, info] of Object.entries(lock.packages ?? {})) {
    if (!key.startsWith('node_modules/') || info.dev) continue
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
  return [...found.values()].sort((a, b) =>
    a.name === b.name ? (a.version < b.version ? -1 : 1) : a.name < b.name ? -1 : 1
  )
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

function build() {
  const packages = productionPackages()
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

const { text, missing, absent, count } = build()
const check = process.argv.includes('--check')

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
    '\nOptional native dependencies land here. A machine that can build them\n' +
      'ships them, so the release build has to regenerate this file rather than\n' +
      'reuse one produced elsewhere.'
  )
}

if (missing.length) {
  console.warn('\nInstalled, but their terms could not be reproduced in full:')
  for (const m of missing) console.warn(`  ${m}`)
  console.warn('\nEach needs its licence text sourced by hand before release.')
  process.exitCode = 1
}

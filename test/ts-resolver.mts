// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Resolve hook that lets the tests import `src/` directly.
 *
 * The source is written for a bundler: relative imports carry no extension
 * (`from './i18n'`), which Rollup resolves happily and Node ESM rejects
 * outright. Rather than rewrite 31 files to suit the test runner, this appends
 * the extension during resolution only.
 *
 * The alternative — testing the bundled output in `out/` — was rejected: the
 * bundle is one file with no individual exports, so the units under test would
 * not be reachable. Testing the source is also the honest target; a test that
 * passes against a bundle can still miss a bug the bundler happened to hide.
 *
 * Test-only. Nothing in the shipped application loads this.
 */
import { existsSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

const CANDIDATES = ['.ts', '.tsx', '/index.ts', '.json']

/**
 * The locale dictionaries are imported as plain modules (`import en from
 * './en.json'`), which a bundler accepts and Node ESM does not without an
 * explicit `with { type: 'json' }`. Same class of problem as the missing
 * extensions: a bundler convention the runtime does not share.
 *
 * The attribute has to be returned *from* the hook — passing a modified context
 * into `next()` does nothing, because the loader validates against the
 * attributes the import statement actually carried.
 */
function asJson(result) {
  return { ...result, importAttributes: { ...result.importAttributes, type: 'json' } }
}

export async function resolve(specifier, context, next) {
  const isRelative = specifier.startsWith('./') || specifier.startsWith('../')
  const hasExtension = /\.[cm]?[jt]sx?$|\.json$/.test(specifier)

  if (isRelative && !hasExtension && context.parentURL?.startsWith('file:')) {
    const base = path.dirname(fileURLToPath(context.parentURL))
    const target = path.resolve(base, specifier)

    for (const ext of CANDIDATES) {
      const candidate = target + ext
      if (existsSync(candidate)) {
        const result = await next(pathToFileURL(candidate).href, context)
        return ext === '.json' ? asJson(result) : result
      }
    }
  }

  const result = await next(specifier, context)
  return result.url?.endsWith('.json') ? asJson(result) : result
}

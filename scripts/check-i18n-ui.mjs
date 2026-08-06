// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Drives the built app over the Chrome DevTools Protocol and proves every
 * locale the picker offers actually renders its own dictionary. Typecheck
 * cannot catch the likeliest bug here: a dynamic `import('./xx.json')` that
 * forgets `.default` is type-correct and fails at runtime as a silent fallback
 * to English, which only a gate reading the real DOM can see.
 *
 *   C1 — one JS chunk per non-English locale, none inlined into the entry asset.
 *   C2 — the language picker offers exactly 8 options.
 *   C3 — every option offered renders that locale's dictionary, not English.
 *   C4 — a locale in prefs.json renders on the unlock screen's first paint.
 *
 * `--only=<codes>` restricts C1 and C3 and skips C2 and C4, which only make
 * sense over the full shipping set.
 */
import { spawn } from 'node:child_process'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url))
const LOCALES_DIR = path.join(PROJECT_ROOT, 'src/shared/locales')
const RENDERER_OUT = path.join(PROJECT_ROOT, 'out/renderer')
const MAIN_ENTRY = path.join(PROJECT_ROOT, 'out/main/index.js')
const ELECTRON_BIN = path.join(PROJECT_ROOT, 'node_modules/electron/dist/electron.exe')
const CDP_PORT = 9347

const onlyArg = process.argv.find((a) => a.startsWith('--only='))
const ONLY = onlyArg ? onlyArg.slice('--only='.length).split(',').filter(Boolean) : null

function report(check, locale, ok, detail) {
  const loc = locale ? ` [${locale}]` : ''
  const extra = detail ? ` — ${detail}` : ''
  console.log(`${check}${loc}: ${ok ? 'PASS' : 'FAIL'}${extra}`)
}

function skip(check, locale, reason) {
  console.log(`${check}${locale ? ` [${locale}]` : ''}: SKIPPED — ${reason}`)
}

function loadDictionaries() {
  const files = fs.readdirSync(LOCALES_DIR).filter((f) => f.endsWith('.json'))
  const dicts = {}
  for (const file of files) {
    const code = file.slice(0, -'.json'.length)
    dicts[code] = JSON.parse(fs.readFileSync(path.join(LOCALES_DIR, file), 'utf8'))
  }
  return dicts
}

function longestAsciiRun(value) {
  const runs = String(value ?? '').match(/[\x20-\x7E]+/g) ?? []
  return runs.reduce((best, run) => (run.length > best.length ? run : best), '')
}

function findFilesNamed(root, name) {
  const found = []
  function walk(dir) {
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) walk(full)
      else if (entry.name === name) found.push(full)
    }
  }
  walk(root)
  return found
}

function mkTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix))
}

function launchApp(userData, port) {
  return spawn(
    ELECTRON_BIN,
    [MAIN_ENTRY, `--remote-debugging-port=${port}`, `--user-data-dir=${userData}`],
    { cwd: PROJECT_ROOT, stdio: ['ignore', 'pipe', 'pipe'] }
  )
}

function killChild(child) {
  if (!child || child.killed) return
  child.kill()
}

let rpcId = 0
function cdp(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const msgId = ++rpcId
    const onMessage = (event) => {
      const message = JSON.parse(event.data)
      if (message.id !== msgId) return
      ws.removeEventListener('message', onMessage)
      if (message.error) reject(new Error(JSON.stringify(message.error)))
      else resolve(message.result)
    }
    ws.addEventListener('message', onMessage)
    ws.send(JSON.stringify({ id: msgId, method, params }))
  })
}

async function ev(ws, expression) {
  const result = await cdp(ws, 'Runtime.evaluate', {
    expression,
    returnByValue: true,
    awaitPromise: true
  })
  if (result.exceptionDetails) {
    const text = result.exceptionDetails.text
    const description = result.exceptionDetails.exception?.description ?? ''
    throw new Error(`page evaluate failed: ${text} ${description}`)
  }
  return result.result.value
}

async function connectCdp(port) {
  let page = null
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()
      page = list.find((t) => t.type === 'page')
      if (page) break
    } catch {
      // debugger endpoint not ready yet
    }
    await sleep(400)
  }
  if (!page) throw new Error(`no page target on CDP port ${port} after 20s`)
  const ws = new WebSocket(page.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true })
    ws.addEventListener('error', reject, { once: true })
  })
  await cdp(ws, 'Runtime.enable')
  return ws
}

const BROWSER_HELPERS = `
window.__set = (el, value, proto) => {
  const setter = Object.getOwnPropertyDescriptor(proto.prototype, 'value').set
  setter.call(el, value)
  el.dispatchEvent(new Event(proto === window.HTMLSelectElement ? 'change' : 'input', { bubbles: true }))
}
'ok'`

async function createVaultAndReachMainUi(ws) {
  await ev(ws, BROWSER_HELPERS)
  await sleep(2200)

  await ev(ws, `(() => {
    const inputs = [...document.querySelectorAll('.unlock-card input[type=password]')]
    window.__set(inputs[0], 'ui-check-i18n-123', window.HTMLInputElement)
    window.__set(inputs[1], 'ui-check-i18n-123', window.HTMLInputElement)
    document.querySelector('.unlock-card button[type=submit]').click()
    return inputs.length
  })()`)
  await sleep(3500)

  const recoveryShown = await ev(ws, '!!document.querySelector(".recovery-key")')
  if (!recoveryShown) throw new Error('recovery key dialog did not appear after vault creation')

  await ev(ws, `(() => {
    document.querySelector('.modal-body input[type=checkbox]').click()
    document.querySelector('.modal-foot .btn.primary').click()
    return 'ok'
  })()`)
  await sleep(1500)

  const mainUiVisible = await ev(ws, '!!document.querySelector(".side-tab")')
  if (!mainUiVisible) {
    throw new Error('main UI did not appear after dismissing the recovery dialog')
  }
}

async function openSettings(ws) {
  await ev(ws, `[...document.querySelectorAll('.titlebar-actions .btn')][0].click()`)
  await sleep(700)
  const settingsOpen = await ev(ws, '!!document.querySelector(".modal .tabs")')
  if (!settingsOpen) throw new Error('settings dialog did not open')
}

async function readPickerCodes(ws) {
  return ev(ws, `[...document.querySelectorAll('.modal-body select option')].map((o) => o.value)`)
}

function checkC1(dicts, codes) {
  if (!fs.existsSync(RENDERER_OUT)) {
    report('C1', null, false, 'out/renderer is missing — run `npm run build` first')
    return false
  }
  const html = fs.readFileSync(path.join(RENDERER_OUT, 'index.html'), 'utf8')
  const scriptMatch = html.match(/<script[^>]+type="module"[^>]+src="([^"]+)"/)
  if (!scriptMatch) {
    report('C1', null, false, 'could not find the entry <script type="module"> tag')
    return false
  }
  const entryRel = scriptMatch[1].replace(/^\.\//, '')
  const entrySource = fs.readFileSync(path.join(RENDERER_OUT, entryRel), 'utf8')
  const assetsDir = path.join(RENDERER_OUT, path.dirname(entryRel))
  const assetFiles = fs.readdirSync(assetsDir).filter((f) => f.endsWith('.js'))
  const assetSources = new Map(
    assetFiles.map((f) => [f, fs.readFileSync(path.join(assetsDir, f), 'utf8')])
  )

  const nonEnglish = codes.filter((c) => c !== 'en' && dicts[c])
  const markers = new Map()
  for (const code of nonEnglish) {
    const marker = longestAsciiRun(dicts[code]['unlock.subCreate'])
    if (marker.length < 10) {
      throw new Error(`C1 abort: ${code} has no ASCII run >= 10 chars in unlock.subCreate`)
    }
    markers.set(code, marker)
  }
  const ownerByMarker = new Map()
  for (const [code, marker] of markers) {
    const owner = ownerByMarker.get(marker)
    if (owner) {
      throw new Error(`C1 abort: marker collision between ${owner} and ${code}: "${marker}"`)
    }
    ownerByMarker.set(marker, code)
  }

  let allOk = true
  for (const [code, marker] of markers) {
    const holders = assetFiles.filter((f) => assetSources.get(f).includes(marker))
    const inEntry = entrySource.includes(marker)
    const ok = holders.length === 1 && !inEntry
    let detail
    if (inEntry) detail = 'marker present in the entry asset — not code-split'
    else if (holders.length === 0) detail = 'marker not found in any emitted asset'
    else if (holders.length > 1) detail = `marker found in ${holders.length} assets`
    report('C1', code, ok, ok ? `split into ${holders[0]}` : detail)
    if (!ok) allOk = false
  }
  return allOk
}

function checkC2(pickerCodes) {
  const ok = pickerCodes.length === 8
  report('C2', null, ok, `picker offers ${pickerCodes.length} option(s)`)
  return ok
}

async function checkC3(ws, codes, dicts) {
  let allOk = true
  for (const code of codes) {
    const dict = dicts[code]
    if (!dict) {
      skip('C3', code, 'no dictionary file on disk')
      continue
    }
    const setExpr =
      `window.__set(document.querySelector('.modal-body select'), ` +
      `${JSON.stringify(code)}, window.HTMLSelectElement)`
    await ev(ws, setExpr)
    await sleep(1200)

    const heading = await ev(ws, `document.querySelector('.modal-head h2')?.textContent`)
    const firstTab = await ev(
      ws,
      `document.querySelector('.side-tab')?.firstChild?.textContent?.trim()`
    )
    const settingsBtn = await ev(
      ws,
      `document.querySelectorAll('.titlebar-actions .btn')[0]?.textContent?.trim()`
    )

    const expectHeading = dict['settings.title']
    const expectTab = dict['sidebar.connections']
    const expectBtn = dict['app.settings']

    const ok = heading === expectHeading && firstTab === expectTab && settingsBtn === expectBtn
    const detail = ok
      ? undefined
      : `heading="${heading}" (want "${expectHeading}"), tab="${firstTab}" (want "${expectTab}"), ` +
        `settingsBtn="${settingsBtn}" (want "${expectBtn}")`
    report('C3', code, ok, detail)
    if (!ok) allOk = false
  }
  return allOk
}

async function checkC4(dicts, userData1) {
  const expected = dicts.fr?.['unlock.titleCreate']
  if (!expected) {
    report('C4', 'fr', false, 'fr dictionary has no unlock.titleCreate key')
    return false
  }

  const prefsCandidates = findFilesNamed(userData1, 'prefs.json')
  if (prefsCandidates.length === 0) {
    report(
      'C4',
      'fr',
      false,
      `prefs.json not found anywhere under ${userData1} — searched recursively, found nothing`
    )
    return false
  }
  const relDir = path.relative(userData1, path.dirname(prefsCandidates[0]))

  const userData2 = mkTempDir('cw-check-i18n-c4-')
  const prefsDir2 = path.join(userData2, relDir)
  fs.mkdirSync(prefsDir2, { recursive: true })
  fs.writeFileSync(
    path.join(prefsDir2, 'prefs.json'),
    JSON.stringify({ locale: 'fr' }, null, 2),
    'utf8'
  )

  const child2 = launchApp(userData2, CDP_PORT)
  try {
    const ws2 = await connectCdp(CDP_PORT)
    await sleep(2200)
    const heading = await ev(ws2, `document.querySelector('.unlock-card h1')?.textContent`)
    const ok = heading === expected
    report('C4', 'fr', ok, ok ? undefined : `expected "${expected}", got "${heading}"`)
    return ok
  } finally {
    killChild(child2)
    await sleep(500)
    fs.rmSync(userData2, { recursive: true, force: true })
  }
}

async function main() {
  if (!fs.existsSync(ELECTRON_BIN)) {
    console.error(`FATAL: electron binary not found at ${ELECTRON_BIN}`)
    process.exitCode = 1
    return
  }
  if (!fs.existsSync(MAIN_ENTRY)) {
    console.error(`FATAL: ${MAIN_ENTRY} is missing — run \`npm run build\` first`)
    process.exitCode = 1
    return
  }

  const dicts = loadDictionaries()
  let overallOk = true

  try {
    const c1Codes = ONLY ?? Object.keys(dicts)
    overallOk = checkC1(dicts, c1Codes) && overallOk
  } catch (err) {
    console.error(`FATAL: ${err.message}`)
    process.exitCode = 1
    return
  }

  const userData1 = mkTempDir('cw-check-i18n-')
  let child1 = null

  try {
    child1 = launchApp(userData1, CDP_PORT)
    const ws1 = await connectCdp(CDP_PORT)
    await createVaultAndReachMainUi(ws1)
    await openSettings(ws1)
    const pickerCodes = await readPickerCodes(ws1)

    if (ONLY) {
      skip('C2', null, 'skipped with --only')
    } else {
      overallOk = checkC2(pickerCodes) && overallOk
    }

    const c3Codes = ONLY ?? pickerCodes
    overallOk = (await checkC3(ws1, c3Codes, dicts)) && overallOk

    killChild(child1)
    await sleep(500)
    child1 = null

    if (ONLY) {
      skip('C4', 'fr', 'skipped with --only')
    } else {
      overallOk = (await checkC4(dicts, userData1)) && overallOk
    }
  } catch (err) {
    console.error(`FATAL: ${err.stack ?? err.message}`)
    overallOk = false
  } finally {
    killChild(child1)
    fs.rmSync(userData1, { recursive: true, force: true })
  }

  console.log(overallOk ? 'RESULT: all checks passed' : 'RESULT: one or more checks failed')
  process.exitCode = overallOk ? 0 : 1
}

await main()

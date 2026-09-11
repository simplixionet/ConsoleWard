// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Captures the README screenshots from the real renderer.
 *
 * Loads the production renderer bundle with `mock-preload.js` in place of the
 * real bridge, walks it through the screens worth showing, and writes a PNG per
 * screen. What ends up in the repository is therefore the actual interface —
 * same components, same stylesheet — filled with machines that never existed.
 *
 * Committed rather than run once by hand because screenshots rot: a capture
 * taken today is a claim about the product, and the only way to keep that claim
 * true after a redesign is to be able to retake them in one command.
 *
 * Requires a build first, since it loads out/renderer.
 *
 *   npm run build && npm run screenshots
 */
const { app, BrowserWindow } = require('electron')
const fs = require('node:fs')
const path = require('node:path')

const ROOT = path.join(__dirname, '..', '..')
const PAGE = path.join(ROOT, 'out', 'renderer', 'index.html')
const OUT = path.join(ROOT, 'docs', 'screenshots')

/** The real window's size, so the captures show the layout users get. */
const WIDTH = 1360
const HEIGHT = 860

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function shoot(win, name) {
  /*
    Long enough for two things, not one. A repaint has to land between the state
    change and the grab, or the capture shows the previous screen — and the
    approval dialogs disable their confirm button for ARM_DELAY_MS after paint,
    so a quicker grab catches it greyed out and the screenshot reads as a broken
    control rather than an anti-click-through delay working as designed.
  */
  await wait(900)
  const image = await win.webContents.capturePage()
  const file = path.join(OUT, `${name}.png`)
  fs.writeFileSync(file, image.toPNG())
  const kb = Math.round(fs.statSync(file).size / 1024)
  console.log(`  ${name}.png  ${image.getSize().width}x${image.getSize().height}  ${kb} KB`)
}

/** Types into a controlled React input the way a user would. */
const TYPE_INTO = (selector, value) => `
  (() => {
    const el = document.querySelector(${JSON.stringify(selector)})
    if (!el) return 'missing: ' + ${JSON.stringify(selector)}
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set
    setter.call(el, ${JSON.stringify(value)})
    el.dispatchEvent(new Event('input', { bubbles: true }))
    return 'ok'
  })()
`

const CLICK = (selector) => `
  (() => {
    const el = document.querySelector(${JSON.stringify(selector)})
    if (!el) return 'missing: ' + ${JSON.stringify(selector)}
    el.click()
    return 'ok'
  })()
`

/** Clicks the first element whose trimmed text matches exactly. */
/** For a label that carries a count — "SSH keys (2)" — where the count is not the point. */
const CLICK_PREFIX = (selector, text) => `
  (() => {
    const all = [...document.querySelectorAll(${JSON.stringify(selector)})]
    const el = all.find((e) => e.textContent.trim().startsWith(${JSON.stringify(text)}))
    if (!el) return 'no ' + ${JSON.stringify(selector)} + ' starts with ' + ${JSON.stringify(text)} +
      ' — saw: ' + all.map((e) => e.textContent.trim()).join(' | ')
    el.click()
    return 'ok'
  })()
`

const CLICK_TEXT = (selector, text) => `
  (() => {
    const all = [...document.querySelectorAll(${JSON.stringify(selector)})]
    const el = all.find((e) => e.textContent.trim() === ${JSON.stringify(text)})
    if (!el) return 'no ' + ${JSON.stringify(selector)} + ' says ' + ${JSON.stringify(text)} +
      ' — saw: ' + all.map((e) => e.textContent.trim()).join(' | ')
    el.click()
    return 'ok'
  })()
`

async function run(win) {
  const js = (code) => win.webContents.executeJavaScript(code)
  const step = async (label, code) => {
    const result = await js(code)
    if (typeof result === 'string' && result !== 'ok') {
      throw new Error(`${label}: ${result}`)
    }
  }

  fs.mkdirSync(OUT, { recursive: true })
  console.log(`writing to ${path.relative(ROOT, OUT)}\n`)

  await wait(1200)
  await shoot(win, '01-unlock')

  await step('password', TYPE_INTO('input[type="password"]', 'correct horse battery staple'))
  await step('unlock', CLICK('button[type="submit"]'))
  await wait(900)

  // The session arrives the way it would over IPC, then the tab is opened.
  // Selecting it is a separate step because nothing selects a session for you:
  // sessions adopted from the main process appear as tabs and wait to be
  // clicked, so emitting the scrollback before the click would paint it into a
  // terminal that is not on screen.
  await js('window.api.__demo.emitSession()')
  await wait(500)
  await step('open the session', CLICK('.tabbar .tab-item'))
  await wait(500)
  await js('window.api.__demo.emitData()')
  await wait(700)
  await shoot(win, '02-sessions')

  await js('window.api.__demo.askCommand()')
  await shoot(win, '03-command-approval')

  // Deny it, so the share dialog below is not stacked behind the approval —
  // only one approval dialog is on screen at a time by design.
  // Deny it, so the share dialog below is not stacked behind the approval —
  // only one approval dialog is on screen at a time by design.
  await step('deny', CLICK_TEXT('.modal-foot .btn', 'Deny'))
  await wait(500)

  await js('window.api.__demo.askShare()')
  await shoot(win, '04-output-choose')

  // Second stage: the excerpt is shown for reading and editing, with anything
  // that looks like a credential highlighted. This is the screen worth showing
  // — the first one only proves there is no "send everything" button.
  await step('take the last lines', CLICK_TEXT('.modal-foot .btn', 'Last 20 lines'))
  await shoot(win, '05-output-review')

  await step('close share', CLICK_TEXT('.modal-foot .btn', 'Back'))
  await wait(300)
  await step('send nothing', CLICK_TEXT('.modal-foot .btn', 'Send nothing'))
  await wait(500)

  await step('settings', CLICK_TEXT('.titlebar-actions .btn', 'Settings'))
  await wait(700)
  await step('mcp tab', CLICK_TEXT('.tab', 'AI access'))
  await shoot(win, '06-mcp-gateway')

  // The per-client setup sits below the fold, and it is the part someone
  // actually needs to see: the config for the client that cannot speak HTTP
  // directly, filled in and ready to paste.
  await step('claude desktop', CLICK_TEXT('.client-tabs .tab', 'Claude Desktop'))
  await wait(300)
  await js(`
    (() => {
      const body = document.querySelector('.modal-body')
      if (body) body.scrollTop = body.scrollHeight
      return 'ok'
    })()
  `)
  await shoot(win, '07-connect-client')

  // The key library and the logs: the two things a reader has no other way to
  // picture, and the two that carry the most "is my private key safe" doubt.
  // Both show only public halves and invented metadata, as everything here does.
  await step('keys tab', CLICK_PREFIX('.tab', 'SSH keys'))
  await wait(400)
  await step('show a public key', CLICK_TEXT('.key-actions .btn', 'Public key'))
  await wait(200)
  await shoot(win, '08-key-library')

  await step('logs tab', CLICK_PREFIX('.tab', 'Logs'))
  await wait(400)
  await shoot(win, '09-session-logs')
}

app.whenReady().then(async () => {
  if (!fs.existsSync(PAGE)) {
    console.error(`No renderer build at ${PAGE}\nRun: npm run build`)
    app.exit(1)
    return
  }

  const win = new BrowserWindow({
    width: WIDTH,
    height: HEIGHT,
    show: true,
    backgroundColor: '#0e1116',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'mock-preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      // The real window runs sandboxed; this preload needs `require`, and the
      // page it loads is our own build with a bridge that reaches nothing.
      sandbox: false
    }
  })

  win.webContents.on('console-message', (_e, _level, message) => {
    if (/error/i.test(message)) console.error(`  renderer: ${message}`)
  })

  try {
    await win.loadFile(PAGE)
    await run(win)
    console.log('\ndone')
    app.exit(0)
  } catch (err) {
    console.error(`\nfailed: ${err.message}`)
    app.exit(1)
  }
})

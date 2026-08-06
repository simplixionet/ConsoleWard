// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Renders build/icon.svg to build/icon.ico with the Electron already in the
 * dependency tree — no image library, no native binary.
 *
 * Never shell out to `convert`: on Windows that name resolves to the system
 * FAT-to-NTFS filesystem utility, not ImageMagick.
 *
 * One offscreen BrowserWindow loads both SVGs at the largest size; the frame
 * arrives through the webContents `paint` event, because capturePage() on a
 * window that was never shown returns an empty bitmap. One window and one load
 * is deliberate — an offscreen window per size makes the second load reject
 * with ERR_FAILED. Smaller sizes come from NativeImage.resize().
 *
 * Run: npm run build:icon
 */
const { app, BrowserWindow } = require('electron')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const ROOT = path.join(__dirname, '..', '..')
const SVG_FULL = path.join(ROOT, 'build', 'icon.svg')
const SVG_SMALL = path.join(ROOT, 'build', 'icon-small.svg')
const OUT = path.join(ROOT, 'build', 'icon.ico')

// Below 48px the full mark's interior collapses, so those sizes come from the
// small variant with the prompt enlarged. The in-between sizes exist so Windows
// never has to scale one of ours.
const SIZES = [
  { px: 16, variant: 'small' },
  { px: 24, variant: 'small' },
  { px: 32, variant: 'small' },
  { px: 48, variant: 'full' },
  { px: 64, variant: 'full' },
  { px: 128, variant: 'full' },
  { px: 256, variant: 'full' }
]

const MASTER = 256

const PAINT_TIMEOUT_MS = 8000

function minify(svg) {
  return svg.replace(/<!--[\s\S]*?-->/g, '').replace(/\s+/g, ' ').trim()
}

/** Both variants side by side, so one render plus two crops produces both masters. */
function writePage(tmpDir, fullSvg, smallSvg) {
  const file = path.join(tmpDir, 'icon.html')
  const enc = (s) => Buffer.from(s, 'utf8').toString('base64')
  fs.writeFileSync(
    file,
    `<!doctype html><meta charset="utf-8">
<style>
  html,body{margin:0;padding:0;background:transparent;overflow:hidden}
  #sheet{display:flex;width:${MASTER * 2}px;height:${MASTER}px}
  img{display:block;width:${MASTER}px;height:${MASTER}px}
</style>
<div id="sheet">
  <img src="data:image/svg+xml;base64,${enc(fullSvg)}">
  <img src="data:image/svg+xml;base64,${enc(smallSvg)}">
</div>`,
    'utf8'
  )
  return file
}

/** Resolve on the first painted frame that actually has content in it. */
function renderSheet(file, width, height) {
  return new Promise((resolve, reject) => {
    const win = new BrowserWindow({
      width,
      height,
      show: false,
      frame: false,
      transparent: true,
      useContentSize: true,
      webPreferences: { offscreen: true, sandbox: true, contextIsolation: true }
    })

    let settled = false
    const finish = (err, image) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      win.destroy()
      err ? reject(err) : resolve(image)
    }

    const timer = setTimeout(
      () => finish(new Error(`no painted frame within ${PAINT_TIMEOUT_MS}ms`)),
      PAINT_TIMEOUT_MS
    )

    win.webContents.on('paint', (_event, _dirty, image) => {
      if (image.isEmpty()) return
      // A fully transparent frame encodes to a handful of bytes; the marks
      // cover most of the sheet, so anything that small is a blank paint.
      if (image.toPNG().length < 400) return
      finish(null, image)
    })

    win.webContents.on('did-fail-load', (_e, code, desc) =>
      finish(new Error(`load failed: ${desc} (${code})`))
    )

    win.loadFile(file).catch((err) => finish(err))
  })
}

/** ICO container. Width and height are one byte each, so 256 is encoded as 0. */
function buildIco(images) {
  const header = Buffer.alloc(6)
  header.writeUInt16LE(0, 0) // reserved
  header.writeUInt16LE(1, 2) // 1 = icon
  header.writeUInt16LE(images.length, 4)

  const directory = Buffer.alloc(16 * images.length)
  let offset = header.length + directory.length

  images.forEach(({ size, png }, i) => {
    const at = i * 16
    directory.writeUInt8(size >= 256 ? 0 : size, at + 0)
    directory.writeUInt8(size >= 256 ? 0 : size, at + 1)
    directory.writeUInt8(0, at + 2) // palette size, 0 for PNG
    directory.writeUInt8(0, at + 3) // reserved
    directory.writeUInt16LE(1, at + 4) // colour planes
    directory.writeUInt16LE(32, at + 6) // bits per pixel
    directory.writeUInt32LE(png.length, at + 8)
    directory.writeUInt32LE(offset, at + 12)
    offset += png.length
  })

  return Buffer.concat([header, directory, ...images.map((i) => i.png)])
}

app.disableHardwareAcceleration()

app.whenReady().then(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'consoleward-icon-'))
  try {
    const full = minify(fs.readFileSync(SVG_FULL, 'utf8'))
    const small = minify(fs.readFileSync(SVG_SMALL, 'utf8'))

    const sheet = await renderSheet(writePage(tmpDir, full, small), MASTER * 2, MASTER)

    const masters = {
      full: sheet.crop({ x: 0, y: 0, width: MASTER, height: MASTER }),
      small: sheet.crop({ x: MASTER, y: 0, width: MASTER, height: MASTER })
    }

    for (const [name, image] of Object.entries(masters)) {
      if (image.toPNG().length < 200) throw new Error(`${name} master cropped to a blank frame`)
    }

    const images = SIZES.map(({ px, variant }) => {
      const master = masters[variant]
      const image = px === MASTER ? master : master.resize({ width: px, height: px })
      const png = image.toPNG()
      if (png.length < 200) throw new Error(`resample produced a blank frame at ${px}px`)
      return { size: px, variant, png }
    })

    for (const { size, variant, png } of images) {
      console.log(
        `  ${String(size).padStart(3)}px  ${variant.padEnd(5)}  ${String(png.length).padStart(6)} bytes`
      )
    }

    fs.writeFileSync(OUT, buildIco(images))
    console.log(`\nicon.ico written: ${images.length} sizes, ${fs.statSync(OUT).size} bytes`)
    app.exit(0)
  } catch (err) {
    console.error(`FATAL: ${err.stack ?? err.message}`)
    app.exit(1)
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  }
})

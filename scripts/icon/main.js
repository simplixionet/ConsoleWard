/**
 * Renders build/icon.svg to build/icon.ico using the Electron already in the
 * dependency tree — no image library, no native binary, no ImageMagick.
 *
 * There is deliberately no `convert` call anywhere in here. On Windows
 * `convert` resolves to the system FAT-to-NTFS filesystem utility, not
 * ImageMagick, and a build script that shells out to it is pointed at a disk
 * tool while it thinks it is resizing a picture.
 *
 * How it works: one offscreen BrowserWindow loads a small HTML wrapper around
 * the SVG at the largest size. The frame arrives through the webContents
 * `paint` event as a NativeImage — offscreen rendering is the reliable path
 * here, because capturePage() on a window that was never shown returns an
 * empty bitmap. The smaller sizes come from NativeImage.resize().
 *
 * The ICO container is then assembled by hand: a 6-byte header, one 16-byte
 * directory entry per image, and the payloads. PNG payloads are legal inside
 * ICO from Vista onward, so the frames are embedded with no re-encoding.
 *
 * One window, one load — deliberately. Creating and destroying an offscreen
 * window per size fails: the first renders, the second reliably rejects its
 * load with ERR_FAILED. Rendering each size from the vector would be sharper
 * in principle, but a mark this simple survives the resample, and a build step
 * that works beats one that is theoretically crisper. If the 16px frame ever
 * stops reading, render that one size in its own process rather than
 * reintroducing the churn.
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

// 16 and 32 are what Windows actually shows in the taskbar and Explorer.
// 256 is the installer and the high-DPI Alt-Tab view. The rest fill the gaps
// so Windows never has to scale one of ours badly.
//
// Below 48px the full mark's interior collapses — verified by eye on the
// generated frames, not assumed — so those sizes come from the small variant
// with the prompt enlarged. Per-size artwork is what ICO is for.
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

/** Comments are for the reader of the SVG, not for the renderer. */
function minify(svg) {
  return svg.replace(/<!--[\s\S]*?-->/g, '').replace(/\s+/g, ' ').trim()
}

/**
 * Both variants on one page, side by side, so a single render produces both
 * masters. Two sequential windows do not work — see the header note — and one
 * page plus two crops sidesteps the problem entirely.
 */
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

/**
 * Resolve on the first painted frame. Offscreen windows emit `paint` with a
 * NativeImage; a frame whose bitmap is entirely transparent is not a frame we
 * want, so keep waiting for one with content.
 */
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
      // A fully transparent frame encodes to a handful of bytes. The marks
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

/**
 * ICO container. Width and height are one byte each, so 256 is encoded as 0 —
 * the format's way of saying "not 1..255".
 */
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

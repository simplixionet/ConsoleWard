// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Reads a ConsoleWard log without ConsoleWard.
 *
 * A record kept for the case where something went wrong is worth little if the
 * only program that can open it is the one that was there when it happened. So
 * this exists: plain Node, no dependencies, no part of the application.
 *
 *   node scripts/decrypt-log.mjs <file.cwlog> --key <base64 master key>
 *   node scripts/decrypt-log.mjs <file.cwlog> --key-file <path>
 *
 * The master key is the one in the vault, under `logKey`. ConsoleWard's own
 * export is the easier path and the one to reach for first; this is the escape
 * hatch, and it takes the key on the command line only because there is nowhere
 * else for it to come from.
 *
 * Deliberately a separate implementation of the same format rather than an
 * import of `logFormat.ts`: if the two ever disagree, the format documented in
 * docs/LOG-FORMAT.md is what a reader outside this repository would build, and
 * that is the promise worth testing.
 */

import { createDecipheriv, scryptSync } from 'node:crypto'
import { readFileSync } from 'node:fs'

const MAGIC = 'CWLOG'
const VERSION = 1
const KDF = { N: 1 << 17, r: 8, p: 1, keylen: 32 }
const MAXMEM = 320 * 1024 * 1024
const NONCE_BYTES = 12
const TAG_BYTES = 16
const LENGTH_BYTES = 4
const MAX_HEADER_BYTES = 64 * 1024
const FRAME_OVERHEAD = NONCE_BYTES + TAG_BYTES
const MAX_FRAME_PAYLOAD_BYTES = 1024 * 1024

function die(message) {
  process.stderr.write(`decrypt-log: ${message}\n`)
  process.exit(1)
}

function parseArgs(argv) {
  const out = { file: null, key: null }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--key') out.key = Buffer.from(argv[++i] ?? '', 'base64')
    else if (arg === '--key-file') out.key = Buffer.from(readFileSync(argv[++i] ?? '', 'utf8').trim(), 'base64')
    else if (arg === '--help' || arg === '-h') out.help = true
    else if (!out.file) out.file = arg
    else die(`unexpected argument: ${arg}`)
  }
  return out
}

const args = parseArgs(process.argv.slice(2))

if (args.help || !args.file) {
  process.stdout.write(
    'Usage: node scripts/decrypt-log.mjs <file.cwlog> --key <base64> | --key-file <path>\n' +
      '\nThe key is the vault field `logKey`. See docs/LOG-FORMAT.md.\n'
  )
  process.exit(args.help ? 0 : 1)
}

if (!args.key || args.key.length < 16) die('--key must be at least 16 bytes of base64')

const bytes = readFileSync(args.file)

// The header is one line of JSON in the clear, so a reader holding nothing but
// the file still knows which session it belongs to.
const lineEnd = bytes.subarray(0, MAX_HEADER_BYTES).indexOf(0x0a)
if (lineEnd === -1) die(`no header line in the first ${MAX_HEADER_BYTES} bytes`)

let header
try {
  header = JSON.parse(bytes.subarray(0, lineEnd).toString('utf8'))
} catch {
  die('the header line is not JSON')
}

if (header.magic !== MAGIC) die(`not a ConsoleWard log (magic ${JSON.stringify(header.magic)})`)
if (header.version !== VERSION) die(`format version ${header.version}, this tool reads ${VERSION}`)

/* The file key, wrapped by the master. Same shape the vault uses for its DEK. */
const wrap = header.wrappedKey ?? {}
const salt = Buffer.from(String(wrap.salt ?? ''), 'base64')
const kek = scryptSync(args.key, salt, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: MAXMEM })

let fileKey
try {
  const unwrap = createDecipheriv('aes-256-gcm', kek, Buffer.from(String(wrap.iv ?? ''), 'base64'))
  unwrap.setAuthTag(Buffer.from(String(wrap.tag ?? ''), 'base64'))
  fileKey = Buffer.concat([
    unwrap.update(Buffer.from(String(wrap.data ?? ''), 'base64')),
    unwrap.final()
  ])
} catch {
  die('the file key did not unwrap — wrong master key, or the header was edited')
}

/* The AAD binds each frame to its file and to its position in it. */
function frameAad(sessionId, index) {
  const id = Buffer.from(String(sessionId), 'utf8')
  const idLen = Buffer.alloc(4)
  idLen.writeUInt32BE(id.length)
  const version = Buffer.alloc(4)
  version.writeUInt32BE(VERSION)
  const at = Buffer.alloc(8)
  at.writeBigUInt64BE(BigInt(index))
  return Buffer.concat([Buffer.from('consoleward.log.aad.1', 'ascii'), version, idLen, id, at])
}

let at = lineEnd + 1
let index = 0
let truncated = false
const out = []

while (at < bytes.length) {
  if (at + LENGTH_BYTES > bytes.length) {
    // A partial length prefix is what a crash mid-write leaves behind. Normal,
    // not corruption — and the distinction matters to whoever is reading this
    // because something already went wrong.
    truncated = true
    break
  }
  const length = bytes.readUInt32BE(at)
  const bodyAt = at + LENGTH_BYTES

  // Before the short-read check, and the order is the point: a length this
  // format could never have written is damage, and taking it for a partial
  // write would file the rest of the file away as an ordinary crash. Both
  // bounds, not just the lower one — a huge length reads as a truncation too.
  if (length < FRAME_OVERHEAD || length > FRAME_OVERHEAD + MAX_FRAME_PAYLOAD_BYTES) {
    die(`frame ${index} declares ${length} bytes, which this format cannot write`)
  }

  // A frame cut short by a crash mid-append. Everything before it still stands.
  if (bodyAt + length > bytes.length) {
    truncated = true
    break
  }

  const nonce = bytes.subarray(bodyAt, bodyAt + NONCE_BYTES)
  const tag = bytes.subarray(bodyAt + length - TAG_BYTES, bodyAt + length)
  const ciphertext = bytes.subarray(bodyAt + NONCE_BYTES, bodyAt + length - TAG_BYTES)

  // The index lives only in the nonce, which is what makes a missing or
  // reordered frame visible at all.
  const seen = Number(nonce.readBigUInt64BE(NONCE_BYTES - 8))
  if (nonce.readUInt32BE(0) !== 0) die(`frame ${index} has a nonce outside the format's range`)
  if (seen !== index) die(`frame at position ${index} carries index ${seen} — a frame is missing or moved`)

  try {
    const decipher = createDecipheriv('aes-256-gcm', fileKey, nonce)
    decipher.setAAD(frameAad(header.sessionId, index))
    decipher.setAuthTag(tag)
    out.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]))
  } catch {
    die(`frame ${index} failed its tag — it was edited, or it came from another log`)
  }

  at = bodyAt + length
  index += 1
}

process.stderr.write(
  `decrypt-log: ${header.label || header.sessionId}, ${index} frames, ` +
    `written ${new Date(header.createdAt).toISOString()}\n`
)
if (truncated) {
  process.stderr.write(
    'decrypt-log: the file ends mid-frame, which is what a crash leaves. Everything above is intact.\n'
  )
}

process.stdout.write(Buffer.concat(out))

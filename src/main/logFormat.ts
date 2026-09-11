// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The on-disk format for session transcripts and AI audit logs. Append-only and
 * framed: a live session seals each chunk on its own and appends it, and never
 * goes back to rewrite what it already wrote.
 *
 * Line 1 is the header as JSON plus `\n`, in the clear, so a reader holding the
 * file and nothing else still knows which session it belongs to. Everything
 * after that line is frames:
 *
 *     [ u32be length ][ 12B nonce ][ ciphertext ][ 16B tag ]
 *
 * `length` counts the body after itself, nonce and tag included, so the file can
 * be walked without decrypting any of it.
 *
 * The nonce is the frame index as a 12-byte big-endian counter, not random
 * bytes. One key covers every frame of one file, and two frames sharing a nonce
 * under one GCM key hand out the keystream and the authentication key with it; a
 * counter removes that outcome rather than bounding its probability. It also
 * puts the index in the file, which is how `readLogFile` tells a frame that is
 * missing from one that is merely unreadable.
 *
 * What the format does NOT do, and what the documentation must not claim it
 * does:
 *
 * - **A clean cut at the end is invisible.** Frames stand alone and nothing
 *   records how many there should be, so dropping the last few looks exactly
 *   like a crash mid-write. `truncated` reports a *partial* frame, never an
 *   absent one. Catching that needs a count kept outside the file, the way
 *   `vaultGuard.ts` keeps the vault's.
 * - **`label` and `createdAt` are not bound.** Only `sessionId`, the format
 *   version and the frame index reach the AAD, so those two can be edited in
 *   place and every tag still verifies.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'

export const LOG_MAGIC = 'CWLOG'
export const LOG_FORMAT_VERSION = 1

/**
 * The same wrapping the vault uses (`makeWrap` in vault.ts), with the same cost.
 * The parameters are NOT written to the file: nothing read off disk gets to pick
 * how expensive the reader's key derivation is, which is the whole job of
 * `assertKdf` over there and a check this format therefore does not need.
 */
const KDF = { N: 1 << 17, r: 8, p: 1, keylen: 32 }

/** scrypt wants ~128 * N * r bytes, well over Node's 32 MB default. As vault.ts. */
const MAXMEM = 320 * 1024 * 1024

const FILE_KEY_BYTES = 32
const SALT_BYTES = 32
const IV_BYTES = 12
const TAG_BYTES = 16
const NONCE_BYTES = 12
const LENGTH_BYTES = 4

/** Everything in a frame body that is not payload. GCM does not expand the rest. */
const FRAME_OVERHEAD = NONCE_BYTES + TAG_BYTES

const NEWLINE = 0x0a

/**
 * The header is a few hundred bytes. This cap is what stops a reader scanning a
 * gigabyte of frames for a newline that was never written, and it is enforced on
 * the way out too — writing a header this reader would refuse is worse than
 * refusing to write it.
 */
export const MAX_HEADER_BYTES = 64 * 1024

/** Bound separately from the header: it is length-prefixed into EVERY frame's AAD. */
export const MAX_SESSION_ID_CHARS = 256

/** One frame is one chunk of terminal output, or one exchange with the model. */
export const MAX_FRAME_PAYLOAD_BYTES = 1024 * 1024

/**
 * The nonce field is 12 bytes wide, but the index filling it is a JS number, so
 * the safe-integer range is the real bound: past it `index + 1` stops advancing
 * and the next frame silently reuses a nonce.
 */
export const MAX_FRAME_INDEX = Number.MAX_SAFE_INTEGER

/** A master with no entropy is the one input scrypt cannot save us from. */
const MIN_MASTER_KEY_BYTES = 16

export interface LogHeader {
  magic: string
  version: number
  /** Session this belongs to. Also bound into every frame's AAD. */
  sessionId: string
  createdAt: number
  /** Human-readable, for a reader that only has the file. Not a secret. */
  label: string
  /** The file key, wrapped by the caller's master key. */
  wrappedKey: { salt: string; iv: string; data: string; tag: string }
}

export interface ReadResult {
  header: LogHeader
  frames: Buffer[]
  /** Set when the file ended mid-frame — normal after a crash, not corruption. */
  truncated: boolean
}

function fail(message: string): never {
  throw new Error(`logFormat: ${message}`)
}

/* --------------------------------------------------------------------- AAD */

/**
 * Domain prefix, as in vault.ts: without it some other format could produce the
 * same bytes and a tag would then authenticate a frame nobody meant. The
 * trailing number versions this *encoding* — reorder the fields, bump it.
 */
const AAD_MAGIC = Buffer.from('consoleward.log.aad.1', 'ascii')

/** `length || body`. The framing is the only thing stopping `ab|c` reading as `a|bc`. */
function lengthPrefixed(value: string): Buffer {
  const body = Buffer.from(value, 'utf8')
  const head = Buffer.alloc(4)
  head.writeUInt32BE(body.length)
  return Buffer.concat([head, body])
}

function u32(value: number): Buffer {
  const buf = Buffer.alloc(4)
  buf.writeUInt32BE(value)
  return buf
}

function u64(value: number): Buffer {
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(value))
  return buf
}

/**
 * Ties a frame to its file and to its place in it. A frame lifted out of another
 * log carries that log's `sessionId` and fails here even under the same file
 * key; a frame moved within this one no longer matches its index.
 */
function frameAad(version: number, sessionId: string, index: number): Buffer {
  return Buffer.concat([AAD_MAGIC, u32(version), lengthPrefixed(sessionId), u64(index)])
}

function nonceFor(index: number): Buffer {
  const nonce = Buffer.alloc(NONCE_BYTES)
  // The top four bytes stay zero because no JS number reaches them; that is
  // exactly the range `MAX_FRAME_INDEX` pins and `indexFromNonce` re-checks.
  nonce.writeBigUInt64BE(BigInt(index), NONCE_BYTES - 8)
  return nonce
}

/** The index this writer would have used for that nonce, or a refusal. */
function indexFromNonce(nonce: Buffer): number {
  const high = nonce.readUInt32BE(0)
  const low = nonce.readBigUInt64BE(4)
  if (high !== 0 || low > BigInt(MAX_FRAME_INDEX)) {
    fail('a frame nonce is outside the range this format can write')
  }
  return Number(low)
}

/* ------------------------------------------------------------ key wrapping */

/**
 * Synchronous because the exported API is, which costs one blocked event loop
 * per derivation — acceptable at one per file created or opened, and nowhere
 * near the path a session appends frames on. Opening logs in a loop is what
 * would make this need to move off the main thread.
 */
function deriveKek(masterKey: Buffer, salt: Buffer): Buffer {
  return scryptSync(masterKey, salt, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: MAXMEM })
}

function assertMasterKey(key: Buffer): void {
  // scrypt takes a zero-length password without complaint and derives a
  // perfectly usable key from it, so an unset master would encrypt, decrypt and
  // look like it worked.
  if (key.length < MIN_MASTER_KEY_BYTES) {
    fail(`master key must be at least ${MIN_MASTER_KEY_BYTES} bytes, got ${key.length}`)
  }
}

function wrapKey(fileKey: Buffer, masterKey: Buffer): LogHeader['wrappedKey'] {
  const salt = randomBytes(SALT_BYTES)
  const kek = deriveKek(masterKey, salt)
  try {
    const iv = randomBytes(IV_BYTES)
    const cipher = createCipheriv('aes-256-gcm', kek, iv)
    const data = Buffer.concat([cipher.update(fileKey), cipher.final()])
    return {
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      data: data.toString('base64'),
      tag: cipher.getAuthTag().toString('base64')
    }
  } finally {
    kek.fill(0)
  }
}

/**
 * Sizes are checked before any derivation: a header edited into nonsense should
 * cost a reader nothing, and `createDecipheriv` on a 3-byte IV throws something
 * no caller can act on.
 */
function assertWrappedKey(wrapped: unknown): void {
  const w = (wrapped ?? {}) as Record<string, unknown>
  for (const field of ['salt', 'iv', 'data', 'tag'] as const) {
    if (typeof w[field] !== 'string') fail(`header wrappedKey.${field} is missing`)
  }
  // Measured after decoding, never as string length: `Buffer.from` drops
  // characters it does not recognise, so only the decoded size means anything.
  const salt = Buffer.from(w.salt as string, 'base64').length
  const iv = Buffer.from(w.iv as string, 'base64').length
  const data = Buffer.from(w.data as string, 'base64').length
  const tag = Buffer.from(w.tag as string, 'base64').length
  if (salt < 16) fail('header wrappedKey.salt is too short')
  if (iv !== IV_BYTES) fail(`header wrappedKey.iv must be ${IV_BYTES} bytes`)
  if (tag !== TAG_BYTES) fail(`header wrappedKey.tag must be ${TAG_BYTES} bytes`)
  if (data !== FILE_KEY_BYTES) fail(`header wrappedKey.data must be ${FILE_KEY_BYTES} bytes`)
}

function unwrapKey(wrapped: LogHeader['wrappedKey'], masterKey: Buffer): Buffer {
  const kek = deriveKek(masterKey, Buffer.from(wrapped.salt, 'base64'))
  try {
    const decipher = createDecipheriv('aes-256-gcm', kek, Buffer.from(wrapped.iv, 'base64'))
    decipher.setAuthTag(Buffer.from(wrapped.tag, 'base64'))
    return Buffer.concat([decipher.update(Buffer.from(wrapped.data, 'base64')), decipher.final()])
  } catch {
    fail('cannot unwrap the file key: wrong master key, or the header was edited')
  } finally {
    kek.fill(0)
  }
}

/* ------------------------------------------------------------------ header */

/**
 * The fields a frame is sealed against. Checked on the way in as well as out:
 * `encodeFrame` puts them in the AAD, so a header the reader would reject must
 * not get as far as producing frames that nothing can ever open.
 */
function assertBinding(header: LogHeader): void {
  if (header.magic !== LOG_MAGIC) {
    fail(`not a ConsoleWard log: magic is ${JSON.stringify(String(header.magic))}`)
  }
  if (header.version !== LOG_FORMAT_VERSION) {
    fail(`unsupported log format version ${String(header.version)}`)
  }
  if (typeof header.sessionId !== 'string' || header.sessionId.length === 0) {
    fail('header sessionId is missing')
  }
  if (header.sessionId.length > MAX_SESSION_ID_CHARS) {
    fail(`header sessionId is longer than ${MAX_SESSION_ID_CHARS} characters`)
  }
}

function assertHeader(value: unknown): asserts value is LogHeader {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail('header is not an object')
  }
  const header = value as LogHeader
  assertBinding(header)
  if (typeof header.label !== 'string') fail('header label is missing')
  if (!Number.isSafeInteger(header.createdAt) || header.createdAt < 0) {
    fail('header createdAt is not a timestamp')
  }
  assertWrappedKey(header.wrappedKey)
}

function encodeHeaderLine(header: LogHeader): string {
  // JSON escapes control characters, so nothing a caller puts in `label` can
  // close the line early and pass the rest off as frames.
  const line = JSON.stringify(header)
  if (Buffer.byteLength(line, 'utf8') + 1 > MAX_HEADER_BYTES) {
    fail(`header is larger than the ${MAX_HEADER_BYTES} bytes a reader will look at`)
  }
  return line + '\n'
}

/* ------------------------------------------------------------------- write */

/**
 * A new log file. The key is per file, so one leaked file key costs one session
 * and the master is the only thing tying them together — and `rewrapLogHeader`
 * moves the file to a new master by rewriting line 1 alone.
 *
 * `headerLine` carries its own `\n`; write it and nothing else before the first
 * frame.
 */
export function createLogFile(opts: {
  sessionId: string
  label: string
  masterKey: Buffer
}): { header: LogHeader; fileKey: Buffer; headerLine: string } {
  assertMasterKey(opts.masterKey)

  const fileKey = randomBytes(FILE_KEY_BYTES)
  const header: LogHeader = {
    magic: LOG_MAGIC,
    version: LOG_FORMAT_VERSION,
    sessionId: opts.sessionId,
    createdAt: Date.now(),
    label: opts.label,
    wrappedKey: wrapKey(fileKey, opts.masterKey)
  }
  assertHeader(header)
  return { header, fileKey, headerLine: encodeHeaderLine(header) }
}

/** One frame. Returns the bytes to append. Pure — the caller owns the fd. */
export function encodeFrame(opts: {
  fileKey: Buffer
  header: LogHeader
  index: number
  payload: Buffer
}): Buffer {
  if (opts.fileKey.length !== FILE_KEY_BYTES) {
    fail(`file key must be ${FILE_KEY_BYTES} bytes, got ${opts.fileKey.length}`)
  }
  assertBinding(opts.header)
  if (!Number.isSafeInteger(opts.index) || opts.index < 0 || opts.index > MAX_FRAME_INDEX) {
    fail(`frame index ${String(opts.index)} is outside 0..${MAX_FRAME_INDEX}`)
  }
  if (opts.payload.length > MAX_FRAME_PAYLOAD_BYTES) {
    fail(`frame payload of ${opts.payload.length} bytes is over the ${MAX_FRAME_PAYLOAD_BYTES} cap`)
  }

  const nonce = nonceFor(opts.index)
  const cipher = createCipheriv('aes-256-gcm', opts.fileKey, nonce)
  cipher.setAAD(frameAad(opts.header.version, opts.header.sessionId, opts.index))
  const ciphertext = Buffer.concat([cipher.update(opts.payload), cipher.final()])
  const tag = cipher.getAuthTag()

  const body = NONCE_BYTES + ciphertext.length + TAG_BYTES
  const out = Buffer.alloc(LENGTH_BYTES + body)
  out.writeUInt32BE(body, 0)
  nonce.copy(out, LENGTH_BYTES)
  ciphertext.copy(out, LENGTH_BYTES + NONCE_BYTES)
  tag.copy(out, LENGTH_BYTES + NONCE_BYTES + ciphertext.length)
  return out
}

/**
 * Moves a log to a new master without touching a single frame — what keeps a
 * password change cheap. The frames are sealed under the file key and bound to
 * `sessionId` and the version, none of which this changes.
 */
export function rewrapLogHeader(opts: {
  header: LogHeader
  oldMasterKey: Buffer
  newMasterKey: Buffer
}): { header: LogHeader; headerLine: string } {
  assertHeader(opts.header)
  assertMasterKey(opts.oldMasterKey)
  assertMasterKey(opts.newMasterKey)

  const fileKey = unwrapKey(opts.header.wrappedKey, opts.oldMasterKey)
  try {
    const header: LogHeader = { ...opts.header, wrappedKey: wrapKey(fileKey, opts.newMasterKey) }
    return { header, headerLine: encodeHeaderLine(header) }
  } finally {
    fileKey.fill(0)
  }
}

/* -------------------------------------------------------------------- read */

export function readLogFile(bytes: Buffer, masterKey: Buffer): ReadResult {
  assertMasterKey(masterKey)

  const lineEnd = bytes.subarray(0, MAX_HEADER_BYTES).indexOf(NEWLINE)
  if (lineEnd === -1) fail(`no header line in the first ${MAX_HEADER_BYTES} bytes`)

  let parsed: unknown
  try {
    parsed = JSON.parse(bytes.subarray(0, lineEnd).toString('utf8'))
  } catch {
    fail('header line is not JSON')
  }
  assertHeader(parsed)
  const header = parsed

  const fileKey = unwrapKey(header.wrappedKey, masterKey)
  try {
    const { frames, truncated } = readFrames(bytes, lineEnd + 1, header, fileKey)
    return { header, frames, truncated }
  } finally {
    fileKey.fill(0)
  }
}

function readFrames(
  bytes: Buffer,
  start: number,
  header: LogHeader,
  fileKey: Buffer
): { frames: Buffer[]; truncated: boolean } {
  const frames: Buffer[] = []
  let offset = start
  let expected = 0

  while (offset < bytes.length) {
    if (bytes.length - offset < LENGTH_BYTES) return { frames, truncated: true }
    const length = bytes.readUInt32BE(offset)

    /*
     * Before the short-read check below, and that order is the point: a length
     * this writer could never have produced is damage, and taking it for a
     * partial write would file the rest of the file away as an ordinary crash.
     */
    if (length < FRAME_OVERHEAD || length > FRAME_OVERHEAD + MAX_FRAME_PAYLOAD_BYTES) {
      fail(`frame at byte ${offset} declares ${length} bytes, which this format cannot write`)
    }

    const body = offset + LENGTH_BYTES
    // A frame cut short by a crash mid-append. Everything before it still stands.
    if (bytes.length - body < length) return { frames, truncated: true }

    const nonce = bytes.subarray(body, body + NONCE_BYTES)
    const ciphertext = bytes.subarray(body + NONCE_BYTES, body + length - TAG_BYTES)
    const tag = bytes.subarray(body + length - TAG_BYTES, body + length)

    /*
     * The index is read off the nonce, so the AAD below always agrees with it
     * and a deleted or reordered frame would verify happily. This comparison is
     * the only thing that catches that — and it cannot catch frames cut off the
     * end, which is why the file needs an external count to be called
     * tamper-proof.
     */
    const index = indexFromNonce(nonce)
    if (index !== expected) {
      fail(`frame ${index} sits where frame ${expected} should: frames are missing or reordered`)
    }

    const decipher = createDecipheriv('aes-256-gcm', fileKey, nonce)
    decipher.setAAD(frameAad(header.version, header.sessionId, index))
    decipher.setAuthTag(tag)
    try {
      frames.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]))
    } catch {
      fail(`frame ${index} failed its tag: it was edited, or it belongs to another log`)
    }

    expected = index + 1
    offset = body + length
  }

  return { frames, truncated: false }
}

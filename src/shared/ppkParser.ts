// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Reads a PuTTY private key file, format version 3 only, and returns the key in
 * OpenSSH form so the rest of the application has one shape to handle.
 *
 * All of this runs on a file somebody sent the user, before anything about it
 * is known, so every length the file states is checked before it is used: the
 * text, the line count, each line, the two blob line counts, and above all the
 * Argon2 cost, which is the one field in a PPK that can ask the machine for
 * gigabytes. `Public-Lines: 999999999` has to cost nothing.
 *
 * The MAC is verified before any field of the private blob is believed. What it
 * cannot do is say why it failed: a v3 MAC key is derived from the passphrase,
 * so a wrong passphrase and an edited file end in the same mismatch.
 * `classifyMacFailure` separates them, and not by looking at the MAC.
 *
 * Despite living in shared/, this is main-process code — it needs node:crypto.
 * ssh2 is deliberately not imported: its `parseKey` only reads OpenSSH keys,
 * there is no writer to reuse, so the container is assembled here and the test
 * proves the result parses back.
 */

import { argon2Sync, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export interface ParsedPpk {
  /** OpenSSH PEM, decrypted. Never logged, never shown. */
  privateKey: string
  /** `ssh-ed25519 AAAA…` form, safe to display. */
  publicKey: string
  comment: string
  keyType: string
}

export type PpkErrorCode =
  | 'notPpk'
  | 'unsupportedVersion'
  | 'unsupportedCipher'
  | 'unsupportedKeyType'
  | 'malformed'
  | 'needPassphrase'
  | 'wrongPassphrase'
  | 'badMac'

/**
 * `code` is the contract. `message` is a note for whoever reads a stack trace:
 * English, and it never quotes the file, because the file is hostile text and
 * this message can end up in a log.
 */
export class PpkError extends Error {
  readonly code: PpkErrorCode

  constructor(code: PpkErrorCode, message: string) {
    super(message)
    this.name = 'PpkError'
    this.code = code
  }
}

function fail(code: PpkErrorCode, message: string): never {
  throw new PpkError(code, message)
}

/** A 16 kbit RSA key writes about 14 KiB; past this it is not a key file. */
const MAX_TEXT_CHARS = 128 * 1024
const MAX_LINES = 4096
/** PuTTY wraps base64 at 64 columns. The slack is for a long comment. */
const MAX_LINE_CHARS = 4096
const MAX_BLOB_LINES = 2048

/**
 * Argon2 cost, straight from the file, is an allocation instruction. PuTTYgen's
 * default is 8 MiB over roughly 13 passes; these ceilings leave room for
 * someone who turned the dial up and still refuse a file that asks for the
 * machine.
 *
 * The product matters as much as the parts: 1 GiB at 256 passes sits inside
 * both individual limits and would hold the process for minutes.
 * MAX_ARGON2_WORK is the bound that means anything, about a few seconds of one
 * core.
 */
const MAX_ARGON2_MEMORY_KIB = 1024 * 1024
const MAX_ARGON2_PASSES = 256
const MAX_ARGON2_PARALLELISM = 16
const MAX_ARGON2_WORK = 4 * 1024 * 1024

/** 32-byte AES key, 16-byte IV, 32-byte MAC key, in that order. */
const ARGON2_TAG_LENGTH = 80

/** Argon2 needs at least 8 bytes of salt; PuTTYgen writes 16. */
const MIN_SALT_BYTES = 8
const MAX_SALT_BYTES = 64

/** 8192-bit RSA. Bounds the mpints before they reach the OpenSSH encoder. */
const MAX_RSA_BYTES = 1024

const ED25519_BYTES = 32

const AES_BLOCK_BYTES = 16

type SupportedKeyType = 'ssh-ed25519' | 'ssh-rsa'

/** Fields after the type string: ed25519 has the point, RSA has e and n. */
const PUBLIC_FIELDS: Record<SupportedKeyType, number> = { 'ssh-ed25519': 1, 'ssh-rsa': 2 }

/** ed25519 has the private scalar, RSA has d, p, q and iqmp. */
const PRIVATE_FIELDS: Record<SupportedKeyType, number> = { 'ssh-ed25519': 1, 'ssh-rsa': 4 }

interface Cursor {
  i: number
}

/**
 * Reads one SSH string out of a blob without ever allocating on the strength of
 * a declared length. Returns null instead of throwing: the same reader runs
 * over a MAC-verified blob, where a failure means `malformed`, and over an
 * unverified one, where a failure is the evidence that the passphrase was wrong.
 */
function readSshString(buf: Buffer, cur: Cursor): Buffer | null {
  if (cur.i + 4 > buf.length) return null
  const len = buf.readUInt32BE(cur.i)
  // Subtraction rather than `i + 4 + len <= length`: len comes from the file
  // and reaches 2^32, and this side of the comparison cannot overflow.
  if (len > buf.length - cur.i - 4) return null
  const start = cur.i + 4
  cur.i = start + len
  return buf.subarray(start, cur.i)
}

function sshString(body: Buffer): Buffer {
  const out = Buffer.alloc(4 + body.length)
  out.writeUInt32BE(body.length, 0)
  body.copy(out, 4)
  return out
}

function sshText(text: string): Buffer {
  return sshString(Buffer.from(text, 'utf8'))
}

function sshUint32(value: number): Buffer {
  const out = Buffer.alloc(4)
  out.writeUInt32BE(value, 0)
  return out
}

/**
 * Canonical SSH mpint: no leading zero bytes, and a zero byte in front when the
 * top bit is set. The file is meant to hold them in this form already;
 * re-encoding means a key written by a sloppier tool still comes out as an
 * OpenSSH file OpenSSL will accept.
 */
function mpint(raw: Buffer): Buffer {
  let i = 0
  while (i < raw.length && raw[i] === 0) i++
  const body = raw.subarray(i)
  if (body.length === 0) return sshString(body)
  if ((body[0] & 0x80) !== 0) return sshString(Buffer.concat([Buffer.from([0]), body]))
  return sshString(body)
}

function lineOf(lines: string[], cur: Cursor): string {
  if (cur.i >= lines.length) fail('malformed', 'file ends before the key does')
  return lines[cur.i++]
}

/**
 * PuTTY writes `Name: value` and its reader skips whitespace after the colon.
 * One optional space is all this accepts: an empty comment is written as
 * `Comment: ` with the space still there, and no value in the format has
 * leading space worth preserving.
 */
function header(lines: string[], cur: Cursor, name: string): string {
  const line = lineOf(lines, cur)
  if (!line.startsWith(name + ':')) fail('malformed', `expected the ${name} header`)
  const value = line.slice(name.length + 1)
  return value.startsWith(' ') ? value.slice(1) : value
}

function decimal(raw: string, name: string): number {
  if (!/^\d{1,9}$/.test(raw)) fail('malformed', `${name} is not a plain decimal number`)
  return Number(raw)
}

function hex(raw: string, name: string, minBytes: number, maxBytes: number): Buffer {
  if (!/^(?:[0-9a-fA-F]{2}){1,512}$/.test(raw)) fail('malformed', `${name} is not hex`)
  const buf = Buffer.from(raw, 'hex')
  if (buf.length < minBytes || buf.length > maxBytes) {
    fail('malformed', `${name} is ${buf.length} bytes, expected ${minBytes} to ${maxBytes}`)
  }
  return buf
}

/**
 * `count` is attacker input naming an allocation, so it is range-checked and
 * then checked against the lines the file actually has before any are touched.
 * The base64 is validated rather than handed to Buffer.from, which drops what
 * it does not recognise and would turn a corrupted line into a short blob
 * instead of an error.
 */
function readBlob(lines: string[], cur: Cursor, name: string): Buffer {
  const count = decimal(header(lines, cur, name), name)
  if (count > MAX_BLOB_LINES) {
    fail('malformed', `${name} is ${count}, over the ${MAX_BLOB_LINES} cap`)
  }
  if (count > lines.length - cur.i) fail('malformed', `${name} claims more lines than the file has`)

  const parts: string[] = []
  for (let n = 0; n < count; n++) {
    const line = lines[cur.i++]
    if (!/^[A-Za-z0-9+/]{0,256}={0,2}$/.test(line)) {
      fail('malformed', `${name} holds a line that is not base64`)
    }
    parts.push(line)
  }

  const text = parts.join('')
  const blob = Buffer.from(text, 'base64')
  const unpadded = text.replace(/={0,2}$/, '')
  if (blob.toString('base64').replace(/={0,2}$/, '') !== unpadded) {
    fail('malformed', `${name} is not canonical base64`)
  }
  return blob
}

function supportedKeyType(name: string): SupportedKeyType {
  if (name === 'ssh-ed25519' || name === 'ssh-rsa') return name
  fail('unsupportedKeyType', 'the key type is not one this build reads')
}

function argon2Flavour(name: string): 'argon2d' | 'argon2i' | 'argon2id' {
  switch (name) {
    case 'Argon2d':
      return 'argon2d'
    case 'Argon2i':
      return 'argon2i'
    case 'Argon2id':
      return 'argon2id'
    default:
      fail('unsupportedCipher', 'Key-Derivation is not an Argon2 flavour')
  }
}

/**
 * The comment comes out of a file somebody sent the user and ends up in the
 * connection list. C0 and C1 bytes in it are escape sequences to a terminal and
 * invisible everywhere else, so they do not leave this module. The MAC is taken
 * over the comment as it was written, never over this.
 */
function displayComment(raw: string): string {
  return raw.replace(/\p{Cc}/gu, '')
}

function readFields(blob: Buffer, count: number, slack: number): Buffer[] | null {
  const cur: Cursor = { i: 0 }
  const fields: Buffer[] = []
  for (let n = 0; n < count; n++) {
    const field = readSshString(blob, cur)
    if (field === null) return null
    fields.push(field)
  }
  return blob.length - cur.i > slack ? null : fields
}

function shapeIsSane(keyType: SupportedKeyType, fields: Buffer[]): boolean {
  if (keyType === 'ssh-ed25519') return fields[0].length === ED25519_BYTES
  return fields.every((f) => f.length > 0 && f.length <= MAX_RSA_BYTES)
}

/**
 * PuTTY pads the private blob with random bytes up to the AES block size before
 * encrypting, so an encrypted file carries up to a block of trailing rubbish
 * that is inside the MAC and means nothing. An unencrypted blob is exact.
 */
function readPrivateFields(
  keyType: SupportedKeyType,
  blob: Buffer,
  encrypted: boolean
): Buffer[] | null {
  const fields = readFields(blob, PRIVATE_FIELDS[keyType], encrypted ? AES_BLOCK_BYTES : 0)
  if (fields === null) return null
  return shapeIsSane(keyType, fields) ? fields : null
}

/**
 * A v3 MAC key is derived from the passphrase, so a wrong passphrase and a file
 * edited behind the user's back both arrive here as one mismatch — PuTTY itself
 * reports them together. What separates them is whether AES produced something
 * shaped like a private blob: under a wrong key the output is noise, and noise
 * does not parse as length-prefixed fields whose sizes fit the key type. A blob
 * that still parses means the passphrase was right and the bytes under it
 * changed.
 *
 * The key is refused either way, so this is allowed to be a guess — all that
 * changes is whether the user is told to retype the passphrase or to distrust
 * the file. Nothing here looks at either MAC.
 */
function classifyMacFailure(
  keyType: SupportedKeyType,
  blob: Buffer,
  encrypted: boolean
): PpkErrorCode {
  if (!encrypted) return 'badMac'
  return readPrivateFields(keyType, blob, true) === null ? 'wrongPassphrase' : 'badMac'
}

function macOver(
  keyType: string,
  encryption: string,
  comment: string,
  publicBlob: Buffer,
  privateBlob: Buffer,
  macKey: Buffer
): Buffer {
  const data = Buffer.concat([
    sshText(keyType),
    sshText(encryption),
    sshText(comment),
    sshString(publicBlob),
    sshString(privateBlob)
  ])
  return createHmac('sha256', macKey).update(data).digest()
}

interface Argon2Spec {
  flavour: 'argon2d' | 'argon2i' | 'argon2id'
  memory: number
  passes: number
  parallelism: number
  salt: Buffer
}

function readArgon2(lines: string[], cur: Cursor): Argon2Spec {
  const flavour = argon2Flavour(header(lines, cur, 'Key-Derivation'))
  const memory = decimal(header(lines, cur, 'Argon2-Memory'), 'Argon2-Memory')
  const passes = decimal(header(lines, cur, 'Argon2-Passes'), 'Argon2-Passes')
  const parallelism = decimal(header(lines, cur, 'Argon2-Parallelism'), 'Argon2-Parallelism')
  const salt = hex(header(lines, cur, 'Argon2-Salt'), 'Argon2-Salt', MIN_SALT_BYTES, MAX_SALT_BYTES)

  if (memory < 8 || memory > MAX_ARGON2_MEMORY_KIB) fail('malformed', 'Argon2-Memory out of range')
  if (passes < 1 || passes > MAX_ARGON2_PASSES) fail('malformed', 'Argon2-Passes out of range')
  if (parallelism < 1 || parallelism > MAX_ARGON2_PARALLELISM) {
    fail('malformed', 'Argon2-Parallelism out of range')
  }
  // Argon2 requires this itself; checking here keeps it a PpkError.
  if (memory < 8 * parallelism) fail('malformed', 'Argon2-Memory is too small for the parallelism')
  if (memory * passes > MAX_ARGON2_WORK) fail('malformed', 'Argon2 cost is over the work budget')

  return { flavour, memory, passes, parallelism, salt }
}

function derive(spec: Argon2Spec, passphrase: string): Buffer {
  try {
    return argon2Sync(spec.flavour, {
      message: Buffer.from(passphrase, 'utf8'),
      nonce: spec.salt,
      parallelism: spec.parallelism,
      tagLength: ARGON2_TAG_LENGTH,
      memory: spec.memory,
      passes: spec.passes
    })
  } catch {
    // In range by our rules and still refused by Argon2. Treat it as the file's
    // fault rather than letting a raw crypto error out of the module.
    fail('malformed', 'the Argon2 parameters were rejected')
  }
}

const OPENSSH_MAGIC = Buffer.from('openssh-key-v1\0', 'utf8')

/** No cipher, so the private section pads to 8 bytes with 1, 2, 3, ... */
const OPENSSH_PAD_TO = 8

/**
 * The unencrypted OpenSSH container. `checkint` is written twice because that
 * is how the format detects a bad decryption; nothing here is encrypted, but
 * the field is not optional and a reader that checks it has to see a match.
 */
function openSshPrivateKey(publicBlob: Buffer, body: Buffer, comment: string): string {
  const check = randomBytes(4)
  const section = Buffer.concat([check, check, body, sshText(comment)])
  const padLength = (OPENSSH_PAD_TO - (section.length % OPENSSH_PAD_TO)) % OPENSSH_PAD_TO
  const padding = Buffer.alloc(padLength)
  for (let i = 0; i < padLength; i++) padding[i] = i + 1

  const file = Buffer.concat([
    OPENSSH_MAGIC,
    sshText('none'),
    sshText('none'),
    sshText(''),
    sshUint32(1),
    sshString(publicBlob),
    sshString(Buffer.concat([section, padding]))
  ])

  const base64 = file.toString('base64')
  const out: string[] = ['-----BEGIN OPENSSH PRIVATE KEY-----']
  for (let i = 0; i < base64.length; i += 70) out.push(base64.slice(i, i + 70))
  out.push('-----END OPENSSH PRIVATE KEY-----', '')
  return out.join('\n')
}

/**
 * PuTTY stores the ed25519 scalar little-endian and fixed-length, which is byte
 * for byte the seed OpenSSH stores. No conversion, but do not "fix" it into an
 * mpint either: the endianness is the whole reason it matches.
 */
function ed25519Output(point: Buffer, scalar: Buffer, comment: string): ParsedPpk {
  const publicBlob = Buffer.concat([sshText('ssh-ed25519'), sshString(point)])
  const body = Buffer.concat([
    sshText('ssh-ed25519'),
    sshString(point),
    sshString(Buffer.concat([scalar, point]))
  ])
  return {
    privateKey: openSshPrivateKey(publicBlob, body, comment),
    publicKey: `ssh-ed25519 ${publicBlob.toString('base64')}`,
    comment,
    keyType: 'ssh-ed25519'
  }
}

function rsaOutput(pub: Buffer[], priv: Buffer[], comment: string): ParsedPpk {
  const [e, n] = pub
  const [d, p, q, iqmp] = priv
  const publicBlob = Buffer.concat([sshText('ssh-rsa'), mpint(e), mpint(n)])
  // OpenSSH's order is n, e, d, iqmp, p, q, which is not the order PuTTY wrote
  // them in. Both mean q^-1 mod p by iqmp, so the values pass straight through.
  const body = Buffer.concat([
    sshText('ssh-rsa'),
    mpint(n),
    mpint(e),
    mpint(d),
    mpint(iqmp),
    mpint(p),
    mpint(q)
  ])
  return {
    privateKey: openSshPrivateKey(publicBlob, body, comment),
    publicKey: `ssh-rsa ${publicBlob.toString('base64')}`,
    comment,
    keyType: 'ssh-rsa'
  }
}

/** Throws PpkError with a stable `code` on anything malformed. */
export function parsePpk(text: string, passphrase?: string): ParsedPpk {
  if (text.length > MAX_TEXT_CHARS) fail('malformed', 'the file is too large to be a key')

  const lines = text.split(/\r?\n/)
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  if (lines.length === 0) fail('notPpk', 'the file is empty')
  if (lines.length > MAX_LINES) fail('malformed', 'the file has more lines than a key can')
  for (const line of lines) {
    if (line.length > MAX_LINE_CHARS) fail('malformed', 'the file has a line longer than a key can')
  }

  if (!lines[0].startsWith('PuTTY-User-Key-File-')) fail('notPpk', 'no PuTTY-User-Key-File header')
  const head = /^PuTTY-User-Key-File-(\d{1,3}): ([A-Za-z0-9@._-]{1,64})$/.exec(lines[0])
  if (head === null) fail('malformed', 'the PuTTY-User-Key-File header is unreadable')
  const version = Number(head[1])
  // v1 and v2 are rejected by number rather than read: current PuTTYgen writes
  // v3, and the editor tells the user to convert rather than trust our copy of
  // a format whose MAC is SHA-1.
  if (version !== 3) fail('unsupportedVersion', `PPK version ${version}, only version 3 is read`)
  const keyType = supportedKeyType(head[2])

  const cur: Cursor = { i: 1 }
  const encryption = header(lines, cur, 'Encryption')
  if (encryption !== 'none' && encryption !== 'aes256-cbc') {
    fail('unsupportedCipher', 'Encryption is neither none nor aes256-cbc')
  }
  const encrypted = encryption === 'aes256-cbc'
  const comment = header(lines, cur, 'Comment')
  const publicBlob = readBlob(lines, cur, 'Public-Lines')
  const argon2 = encrypted ? readArgon2(lines, cur) : null
  const storedPrivate = readBlob(lines, cur, 'Private-Lines')
  const storedMac = hex(header(lines, cur, 'Private-MAC'), 'Private-MAC', 32, 32)
  // Anything after Private-MAC is ignored, as PuTTY's own loader ignores it.

  const publicFields = readFields(publicBlob, PUBLIC_FIELDS[keyType] + 1, 0)
  if (publicFields === null) fail('malformed', 'the public blob does not parse')
  const [declaredType, ...pub] = publicFields
  if (declaredType.toString('utf8') !== keyType) {
    fail('malformed', 'the public blob disagrees with the header about the key type')
  }
  if (!shapeIsSane(keyType, pub)) fail('malformed', 'the public blob has a field of the wrong size')

  if (encrypted && (passphrase === undefined || passphrase.length === 0)) {
    fail('needPassphrase', 'the key is encrypted and no passphrase was given')
  }

  // Derived key material is wiped in the finally. The PEM this returns is a JS
  // string and cannot be; the wipe only drops the copies we do control.
  let derived: Buffer | null = null
  try {
    let privateBlob: Buffer = storedPrivate
    let macKey: Buffer = Buffer.alloc(0)

    if (argon2 !== null && passphrase !== undefined) {
      if (storedPrivate.length === 0 || storedPrivate.length % AES_BLOCK_BYTES !== 0) {
        fail('malformed', 'the encrypted private blob is not a whole number of AES blocks')
      }
      derived = derive(argon2, passphrase)
      const key = derived.subarray(0, 32)
      const iv = derived.subarray(32, 48)
      const decipher = createDecipheriv('aes-256-cbc', key, iv)
      // PPK pads with random bytes, not PKCS#7. Node must not try to strip it.
      decipher.setAutoPadding(false)
      privateBlob = Buffer.concat([decipher.update(storedPrivate), decipher.final()])
      macKey = derived.subarray(48, 80)
    }

    // An unencrypted v3 file is MACed under a key of zero length, not under
    // SHA-256 of the empty string — that is the natural guess, and it is what
    // PPK v2 does with SHA-1, and it produces a MAC PuTTY will not accept.
    // PuTTY's Appendix C: with no encryption "it has a zero-length key".
    const mac = macOver(keyType, encryption, comment, publicBlob, privateBlob, macKey)
    if (!timingSafeEqual(mac, storedMac)) {
      fail(classifyMacFailure(keyType, privateBlob, encrypted), 'the Private-MAC does not match')
    }

    const privateFields = readPrivateFields(keyType, privateBlob, encrypted)
    if (privateFields === null) fail('malformed', 'the private blob does not parse')

    const shown = displayComment(comment)
    return keyType === 'ssh-ed25519'
      ? ed25519Output(pub[0], privateFields[0], shown)
      : rsaOutput(pub, privateFields, shown)
  } finally {
    derived?.fill(0)
  }
}

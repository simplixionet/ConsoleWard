// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The PPK v3 reader, tested against files this suite writes itself. The writer
 * below is the point: a committed .ppk fixture proves the parser still agrees
 * with a blob nobody can read, while a writer lets every test say exactly which
 * byte it broke and why that byte matters.
 *
 * Two things carry the weight. Real key material goes in — node generates the
 * ed25519 and RSA keys — and the assertion is that the same key comes back out,
 * checked by handing the OpenSSH file to ssh2 and comparing JWKs. And every
 * refusal is asserted by `code`, because the import dialog decides what to tell
 * the user from the code and nothing else.
 *
 * What a self-written fixture cannot prove is that the format is right: writer
 * and parser share every assumption. Those came from PuTTY's own Appendix C
 * (the zero-length MAC key with no encryption, the 80-byte Argon2 split, the
 * MAC over the *padded* plaintext) and from its sshecc.c (the ed25519 scalar
 * stored little-endian), and each is cited where it is implemented. Anything
 * here that disagrees with a file real PuTTYgen writes is a bug in both files.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import {
  argon2Sync,
  createCipheriv,
  createHmac,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes
} from 'node:crypto'
// ssh2 is CommonJS, so its named exports are not reachable from an ESM test.
import ssh2 from 'ssh2'

const { parsePpk, PpkError } = await import('../src/shared/ppkParser.ts')
type PpkErrorCode = import('../src/shared/ppkParser.ts').PpkErrorCode
type ParsedPpk = import('../src/shared/ppkParser.ts').ParsedPpk

function sshString(body: Buffer): Buffer {
  const out = Buffer.alloc(4 + body.length)
  out.writeUInt32BE(body.length, 0)
  body.copy(out, 4)
  return out
}

function sshText(value: string): Buffer {
  return sshString(Buffer.from(value, 'utf8'))
}

function mpint(raw: Buffer): Buffer {
  let i = 0
  while (i < raw.length && raw[i] === 0) i++
  const body = raw.subarray(i)
  if (body.length > 0 && (body[0] & 0x80) !== 0) {
    return sshString(Buffer.concat([Buffer.from([0]), body]))
  }
  return sshString(body)
}

function jwkField(value: string | undefined, name: string): Buffer {
  assert.ok(value !== undefined, `the generated key has no ${name}; the fixture cannot be built`)
  return Buffer.from(value, 'base64url')
}

interface Material {
  keyType: string
  publicBlob: Buffer
  privateBlob: Buffer
  jwk: JsonWebKey
}

/**
 * PuTTY stores the ed25519 scalar little-endian and fixed length, which is the
 * same 32 bytes OpenSSH calls the seed and the same 32 bytes node puts at the
 * end of a PKCS#8 export. If that ever stops being true this fixture is what
 * says so.
 */
function ed25519Material(): Material {
  const pair = generateKeyPairSync('ed25519')
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' })
  const pkcs8 = pair.privateKey.export({ type: 'pkcs8', format: 'der' })
  const point = spki.subarray(spki.length - 32)
  const seed = pkcs8.subarray(pkcs8.length - 32)
  return {
    keyType: 'ssh-ed25519',
    publicBlob: Buffer.concat([sshText('ssh-ed25519'), sshString(point)]),
    privateBlob: sshString(seed),
    jwk: pair.privateKey.export({ format: 'jwk' })
  }
}

/** PuTTY's private order is d, p, q, iqmp, with iqmp meaning q^-1 mod p. */
function rsaMaterial(): Material {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = pair.privateKey.export({ format: 'jwk' })
  const n = jwkField(jwk.n, 'n')
  const e = jwkField(jwk.e, 'e')
  return {
    keyType: 'ssh-rsa',
    publicBlob: Buffer.concat([sshText('ssh-rsa'), mpint(e), mpint(n)]),
    privateBlob: Buffer.concat([
      mpint(jwkField(jwk.d, 'd')),
      mpint(jwkField(jwk.p, 'p')),
      mpint(jwkField(jwk.q, 'q')),
      mpint(jwkField(jwk.qi, 'qi'))
    ]),
    jwk
  }
}

const ED25519 = ed25519Material()
const RSA = rsaMaterial()

const PASSPHRASE = 'correct horse battery staple'

/** Cheap on purpose. PuTTYgen's defaults would put seconds into every test. */
const ARGON2 = { flavour: 'Argon2id', memory: 8192, passes: 2, parallelism: 1 }

interface PpkOptions {
  material?: Material
  version?: number
  keyType?: string
  encryption?: string
  comment?: string
  passphrase?: string
  argon2?: Partial<typeof ARGON2>
  salt?: Buffer
  /**
   * Flip the last byte of the stored private blob after the MAC is taken over
   * it. The last byte and not the first: in CBC that garbles only the final
   * block, which for these keys is padding and tail, so the blob still parses
   * and the parser has to reach for the MAC to notice.
   */
  tamperPrivate?: boolean
  /** Flip a byte of the public blob after the MAC is taken over it. */
  tamperPublic?: boolean
  /** Hex to write as Private-MAC instead of the real one. */
  mac?: string
}

function base64Lines(blob: Buffer): string[] {
  const text = blob.toString('base64')
  const out: string[] = []
  for (let i = 0; i < text.length; i += 64) out.push(text.slice(i, i + 64))
  return out
}

function argon2Flavour(name: string): 'argon2d' | 'argon2i' | 'argon2id' {
  if (name === 'Argon2d') return 'argon2d'
  if (name === 'Argon2i') return 'argon2i'
  return 'argon2id'
}

/**
 * Writes a PPK v3 the way PuTTY does: pad the private blob to the AES block
 * size with random bytes, MAC the *padded plaintext*, then encrypt. Getting
 * that order wrong is the classic way to write a file PuTTY cannot read, so the
 * writer doing it correctly is half of what the passing tests prove.
 */
function writePpk(options: PpkOptions = {}): string {
  const material = options.material ?? ED25519
  const version = options.version ?? 3
  const keyType = options.keyType ?? material.keyType
  const encryption = options.encryption ?? 'none'
  const comment = options.comment ?? 'consoleward test key'
  const salt = options.salt ?? Buffer.alloc(16, 0x5a)
  const argon2 = { ...ARGON2, ...options.argon2 }

  let publicBlob = material.publicBlob
  let plain = material.privateBlob
  let stored = plain
  let macKey = Buffer.alloc(0)
  const kdf: string[] = []

  if (encryption !== 'none') {
    const padding = (16 - (plain.length % 16)) % 16
    plain = Buffer.concat([plain, randomBytes(padding)])
    const derived = argon2Sync(argon2Flavour(argon2.flavour), {
      message: Buffer.from(options.passphrase ?? '', 'utf8'),
      nonce: salt,
      parallelism: argon2.parallelism,
      tagLength: 80,
      memory: argon2.memory,
      passes: argon2.passes
    })
    const cipher = createCipheriv('aes-256-cbc', derived.subarray(0, 32), derived.subarray(32, 48))
    cipher.setAutoPadding(false)
    stored = Buffer.concat([cipher.update(plain), cipher.final()])
    macKey = derived.subarray(48, 80)
    kdf.push(
      `Key-Derivation: ${argon2.flavour}`,
      `Argon2-Memory: ${argon2.memory}`,
      `Argon2-Passes: ${argon2.passes}`,
      `Argon2-Parallelism: ${argon2.parallelism}`,
      `Argon2-Salt: ${salt.toString('hex')}`
    )
  }

  const mac =
    options.mac ??
    createHmac('sha256', macKey)
      .update(
        Buffer.concat([
          sshText(keyType),
          sshText(encryption),
          sshText(comment),
          sshString(publicBlob),
          sshString(plain)
        ])
      )
      .digest('hex')

  if (options.tamperPrivate) {
    stored = Buffer.from(stored)
    stored[stored.length - 1] ^= 0xff
  }
  if (options.tamperPublic) {
    publicBlob = Buffer.from(publicBlob)
    publicBlob[publicBlob.length - 1] ^= 0xff
  }

  const publicLines = base64Lines(publicBlob)
  const privateLines = base64Lines(stored)
  return [
    `PuTTY-User-Key-File-${version}: ${keyType}`,
    `Encryption: ${encryption}`,
    `Comment: ${comment}`,
    `Public-Lines: ${publicLines.length}`,
    ...publicLines,
    ...kdf,
    `Private-Lines: ${privateLines.length}`,
    ...privateLines,
    `Private-MAC: ${mac}`,
    ''
  ].join('\n')
}

function replaceLine(file: string, prefix: string, replacement: string): string {
  const lines = file.split('\n')
  const at = lines.findIndex((line) => line.startsWith(prefix))
  assert.notEqual(at, -1, `the fixture has no ${prefix} line to replace`)
  lines[at] = replacement
  return lines.join('\n')
}

function expectRefused(what: string, code: PpkErrorCode, run: () => unknown): PpkError {
  try {
    run()
  } catch (err) {
    assert.ok(
      err instanceof PpkError,
      `${what} must be refused as a PpkError the dialog can read, not as ${String(err)}`
    )
    assert.equal(
      err.code,
      code,
      `${what} must be reported as "${code}" — it came back as "${err.code}", so the user is ` +
        'told the wrong thing about a file they need to act on'
    )
    return err
  }
  assert.fail(`${what} was accepted, and a key the parser cannot vouch for reached the vault`)
}

/**
 * The real check on the happy path: put the OpenSSH file through ssh2, take the
 * PEM it builds, and compare the key node reads back with the key that was
 * generated. Equal JWKs mean every component survived in the right slot — an
 * RSA p and q the wrong way round, or an ed25519 scalar byte-reversed, both
 * produce a file that still parses and still fails this.
 */
function assertSameKey(parsed: ParsedPpk, material: Material, what: string): void {
  const key = ssh2.utils.parseKey(parsed.privateKey)
  assert.ok(
    !(key instanceof Error),
    `${what}: ssh2 could not read the OpenSSH key we assembled (${String(key)}), so importing ` +
      'it would fail at connection time'
  )
  const restored = createPrivateKey(key.getPrivatePEM()).export({ format: 'jwk' })
  assert.deepEqual(
    restored,
    material.jwk,
    `${what}: the key that came out of the parser is not the key that went into the file`
  )
  assert.equal(
    parsed.publicKey,
    `${material.keyType} ${key.getPublicSSH().toString('base64')}`,
    `${what}: the advertised public key disagrees with the private key, so the user would put ` +
      'the wrong line in authorized_keys'
  )
}

describe('parsePpk, keys that should load', () => {
  test('an unencrypted ed25519 key round-trips into OpenSSH', () => {
    const parsed = parsePpk(writePpk())
    assert.equal(parsed.keyType, 'ssh-ed25519', 'the key type is what the import dialog shows')
    assert.equal(
      parsed.comment,
      'consoleward test key',
      'the comment is what names the key in the connection list'
    )
    assertSameKey(parsed, ED25519, 'unencrypted ed25519')
  })

  test('an encrypted ed25519 key loads with the right passphrase', () => {
    const file = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    assertSameKey(parsePpk(file, PASSPHRASE), ED25519, 'encrypted ed25519')
  })

  test('an unencrypted rsa key round-trips into OpenSSH', () => {
    const parsed = parsePpk(writePpk({ material: RSA }))
    assert.equal(parsed.keyType, 'ssh-rsa', 'the key type is what the import dialog shows')
    assertSameKey(parsed, RSA, 'unencrypted rsa')
  })

  test('an encrypted rsa key loads with the right passphrase', () => {
    const file = writePpk({ material: RSA, encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    assertSameKey(parsePpk(file, PASSPHRASE), RSA, 'encrypted rsa')
  })

  test('CRLF line endings load, because PuTTYgen on Windows writes them', () => {
    const file = writePpk().split('\n').join('\r\n')
    assertSameKey(parsePpk(file), ED25519, 'a CRLF file')
  })

  test('an empty comment loads, trailing space on the header and all', () => {
    const parsed = parsePpk(writePpk({ comment: '' }))
    assert.equal(parsed.comment, '', 'a key saved without a comment must still import')
  })

  test('a passphrase handed to an unencrypted key is ignored, not treated as a mismatch', () => {
    const parsed = parsePpk(writePpk(), PASSPHRASE)
    assert.equal(
      parsed.keyType,
      'ssh-ed25519',
      'a user who types a passphrase anyway must not be locked out of their own key'
    )
  })

  test('control characters are stripped from the comment but not from the MAC', () => {
    // The file verifies, which is only possible if the MAC ran over the comment
    // as written; the escape sequence is gone from what the UI will render.
    const parsed = parsePpk(writePpk({ comment: 'work\u001b[31mserver\u0007' }))
    assert.equal(
      parsed.comment,
      'work[31mserver',
      'a comment out of a file somebody sent must not carry an escape sequence into the UI'
    )
  })
})

describe('parsePpk, files that must be refused', () => {
  test('a PPK v2 file is refused by version, not read with a SHA-1 MAC', () => {
    expectRefused('a v2 key file', 'unsupportedVersion', () => parsePpk(writePpk({ version: 2 })))
  })

  test('a PPK v1 file is refused by version', () => {
    expectRefused('a v1 key file', 'unsupportedVersion', () => parsePpk(writePpk({ version: 1 })))
  })

  test('an OpenSSH key is not mistaken for a PPK', () => {
    const pem = [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB',
      '-----END OPENSSH PRIVATE KEY-----',
      ''
    ].join('\n')
    expectRefused('an OpenSSH private key', 'notPpk', () => parsePpk(pem))
  })

  test('an empty file is not a PPK', () => {
    expectRefused('an empty file', 'notPpk', () => parsePpk(''))
  })

  test('a truncated file is refused instead of read past its end', () => {
    const lines = writePpk({ material: RSA }).split('\n')
    const cut = lines.slice(0, lines.length - 4).join('\n')
    expectRefused('a file cut off mid key', 'malformed', () => parsePpk(cut))
  })

  test('Public-Lines larger than the file is refused before anything is read', () => {
    const file = replaceLine(writePpk(), 'Public-Lines:', 'Public-Lines: 999999999')
    expectRefused('Public-Lines: 999999999', 'malformed', () => parsePpk(file))
  })

  test('Private-Lines larger than the cap is refused', () => {
    const file = replaceLine(writePpk(), 'Private-Lines:', 'Private-Lines: 99999')
    expectRefused('Private-Lines: 99999', 'malformed', () => parsePpk(file))
  })

  test('a line count that is not a number is refused', () => {
    const file = replaceLine(writePpk(), 'Public-Lines:', 'Public-Lines: 0x10')
    expectRefused('a hexadecimal line count', 'malformed', () => parsePpk(file))
  })

  test('a tampered private blob is reported as a bad MAC, not as a bad passphrase', () => {
    expectRefused('an edited unencrypted key file', 'badMac', () =>
      parsePpk(writePpk({ tamperPrivate: true }))
    )
  })

  test('a tampered public blob is caught, because the MAC covers it too', () => {
    expectRefused('an edited public blob', 'badMac', () =>
      parsePpk(writePpk({ tamperPublic: true }))
    )
  })

  test('an edited comment is caught, because the MAC covers it too', () => {
    const file = replaceLine(writePpk(), 'Comment:', 'Comment: something else entirely')
    expectRefused('an edited comment', 'badMac', () => parsePpk(file))
  })

  test('the wrong passphrase is reported as a wrong passphrase', () => {
    const file = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    expectRefused('a mistyped passphrase', 'wrongPassphrase', () => parsePpk(file, 'not it'))
  })

  test('a forged MAC on an encrypted file is a bad MAC, not a bad passphrase', () => {
    // The passphrase is right, so AES yields a private blob that still parses.
    // That is the whole signal separating this from the test above it.
    const forged = '00'.repeat(32)
    const file = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE, mac: forged })
    expectRefused('an encrypted file with a forged MAC', 'badMac', () => parsePpk(file, PASSPHRASE))
  })

  test('a flipped byte inside an encrypted blob is a bad MAC, not a bad passphrase', () => {
    // A real edit this time, to the ciphertext, with the right passphrase in
    // hand. Telling the user to retype their passphrase here would be wrong.
    const file = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE, tamperPrivate: true })
    expectRefused('an edited encrypted key file', 'badMac', () => parsePpk(file, PASSPHRASE))
  })

  test('an encrypted file with no passphrase asks for one instead of failing the MAC', () => {
    const file = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    expectRefused('an encrypted key with no passphrase', 'needPassphrase', () => parsePpk(file))
  })

  test('an encrypted file with an empty passphrase asks for one', () => {
    const file = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    expectRefused('an encrypted key with an empty passphrase', 'needPassphrase', () =>
      parsePpk(file, '')
    )
  })

  test('an unsupported key type is named rather than half-parsed', () => {
    const file = writePpk({ keyType: 'ssh-dss' })
    expectRefused('a DSA key', 'unsupportedKeyType', () => parsePpk(file))
  })

  test('a certificate key type is refused rather than treated as its base type', () => {
    const file = writePpk({ keyType: 'ssh-rsa-cert-v01@openssh.com' })
    expectRefused('a certificate key', 'unsupportedKeyType', () => parsePpk(file))
  })

  test('a cipher other than aes256-cbc is refused', () => {
    const file = replaceLine(writePpk(), 'Encryption:', 'Encryption: aes128-cbc')
    expectRefused('an aes128-cbc key file', 'unsupportedCipher', () => parsePpk(file))
  })

  test('a key derivation other than Argon2 is refused', () => {
    const encrypted = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    const file = replaceLine(encrypted, 'Key-Derivation:', 'Key-Derivation: scrypt')
    expectRefused('a scrypt-derived key file', 'unsupportedCipher', () =>
      parsePpk(file, PASSPHRASE)
    )
  })

  test('a public blob whose type disagrees with the header is refused', () => {
    const file = writePpk({ material: RSA, keyType: 'ssh-ed25519' })
    expectRefused('a header claiming a type the blob does not', 'malformed', () => parsePpk(file))
  })

  test('a short Private-MAC is refused, not compared at the wrong length', () => {
    const file = replaceLine(writePpk(), 'Private-MAC:', `Private-MAC: ${'ab'.repeat(31)}`)
    expectRefused('a 31-byte MAC', 'malformed', () => parsePpk(file))
  })

  test('a Private-MAC that is not hex is refused', () => {
    const file = replaceLine(writePpk(), 'Private-MAC:', `Private-MAC: ${'zz'.repeat(32)}`)
    expectRefused('a non-hex MAC', 'malformed', () => parsePpk(file))
  })

  test('an encrypted blob that is not a whole number of AES blocks is refused', () => {
    const file = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    const lines = file.split('\n')
    const at = lines.findIndex((line) => line.startsWith('Private-Lines:'))
    lines[at + 1] = lines[at + 1].slice(0, 60)
    expectRefused('a private blob of partial blocks', 'malformed', () =>
      parsePpk(lines.join('\n'), PASSPHRASE)
    )
  })

  test('a base64 line with characters outside the alphabet is refused', () => {
    const file = writePpk()
    const lines = file.split('\n')
    const at = lines.findIndex((line) => line.startsWith('Public-Lines:'))
    lines[at + 1] = `${lines[at + 1].slice(0, -1)}!`
    expectRefused('a corrupted base64 line', 'malformed', () => parsePpk(lines.join('\n')))
  })

  test('a missing header is refused rather than skipped over', () => {
    const file = writePpk()
      .split('\n')
      .filter((line) => !line.startsWith('Encryption:'))
      .join('\n')
    expectRefused('a file with no Encryption header', 'malformed', () => parsePpk(file))
  })

  test('an oversized file is refused before it is parsed', () => {
    const file = `${writePpk()}\n${'A'.repeat(200 * 1024)}`
    expectRefused('a 200 KiB key file', 'malformed', () => parsePpk(file))
  })

  test('an absurdly long line is refused', () => {
    const file = replaceLine(writePpk(), 'Comment:', `Comment: ${'x'.repeat(5000)}`)
    expectRefused('a 5000 character comment', 'malformed', () => parsePpk(file))
  })
})

describe('parsePpk, cost stated by the file', () => {
  test('an Argon2-Memory of 4 GiB is refused without allocating it', () => {
    const encrypted = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    const file = replaceLine(encrypted, 'Argon2-Memory:', 'Argon2-Memory: 4194304')
    const started = process.hrtime.bigint()
    expectRefused('Argon2-Memory: 4194304', 'malformed', () => parsePpk(file, PASSPHRASE))
    const ms = Number(process.hrtime.bigint() - started) / 1e6
    assert.ok(
      ms < 1000,
      `the 4 GiB request took ${ms.toFixed(0)}ms, so it was handed to Argon2 rather than refused`
    )
  })

  test('a memory and pass count that are each legal but ruinous together are refused', () => {
    const encrypted = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    const file = replaceLine(
      replaceLine(encrypted, 'Argon2-Memory:', 'Argon2-Memory: 1048576'),
      'Argon2-Passes:',
      'Argon2-Passes: 256'
    )
    const started = process.hrtime.bigint()
    expectRefused('1 GiB over 256 passes', 'malformed', () => parsePpk(file, PASSPHRASE))
    const ms = Number(process.hrtime.bigint() - started) / 1e6
    assert.ok(ms < 1000, `the work budget check took ${ms.toFixed(0)}ms, so it ran the KDF first`)
  })

  test('an Argon2-Salt shorter than Argon2 accepts is refused, not passed through', () => {
    const encrypted = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    const file = replaceLine(encrypted, 'Argon2-Salt:', 'Argon2-Salt: 0011')
    expectRefused('a 2-byte salt', 'malformed', () => parsePpk(file, PASSPHRASE))
  })

  test('zero passes is refused rather than handed to the KDF', () => {
    const encrypted = writePpk({ encryption: 'aes256-cbc', passphrase: PASSPHRASE })
    const file = replaceLine(encrypted, 'Argon2-Passes:', 'Argon2-Passes: 0')
    expectRefused('Argon2-Passes: 0', 'malformed', () => parsePpk(file, PASSPHRASE))
  })

  test('Argon2i and Argon2d files load, since PuTTYgen can write either', () => {
    for (const flavour of ['Argon2i', 'Argon2d']) {
      const file = writePpk({
        encryption: 'aes256-cbc',
        passphrase: PASSPHRASE,
        argon2: { flavour }
      })
      assertSameKey(parsePpk(file, PASSPHRASE), ED25519, `an ${flavour} key file`)
    }
  })
})

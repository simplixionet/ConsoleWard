// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Vault crypto: envelope encryption, the recovery key, and DEK rotation.
 *
 * The vault is a module-level singleton that re-reads its directory from
 * Electron's `userData` on *every* file access, so pointing the stub at a mutable
 * variable gives each test its own vault; `fresh()` also locks the singleton, or
 * in-memory state leaks from one test into the next. Tests that splice wraps back
 * into the file on disk are taking the attacker's view.
 */

import { test, mock, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { randomBytes, scrypt, createCipheriv } from 'node:crypto'
import { promisify } from 'node:util'
import { MIN_PASSWORD_LENGTH } from '../src/shared/passwordStrength.ts'

let dir = ''
const madeDirs: string[] = []

mock.module('electron', { exports: { app: { getPath: () => dir } } })

const { vault, generateRecoveryKey, normalizeRecoveryKey, migrateLegacyProfile } = await import(
  '../src/main/vault.ts'
)

/* ----------------------------------------------------------------- helpers */

const PASSWORD = 'correct-horse-battery'
const OTHER_PASSWORD = 'staple-battery-horse'
const THIRD_PASSWORD = 'battery-staple-horse'

function fresh(): string {
  vault.lock()
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-vault-'))
  madeDirs.push(dir)
  return dir
}

const vaultPath = (): string => path.join(dir, 'vault.enc')
const backupPath = (): string => path.join(dir, 'vault.enc.bak')

interface OnDiskWrap {
  type: 'password' | 'recovery'
  kdf: { name: string; salt: string; N: number; r: number; p: number; keylen: number }
  iv: string
  tag: string
  wrapped: string
}

interface OnDiskVault {
  version: number
  cipher: string
  /** v3 only; absent in the v1 and v2 fixtures. */
  counter?: number
  iv: string
  tag: string
  data: string
  wraps: OnDiskWrap[]
}

const readVaultFile = (): OnDiskVault => JSON.parse(fs.readFileSync(vaultPath(), 'utf8'))

const writeVaultFile = (file: unknown): void =>
  fs.writeFileSync(vaultPath(), typeof file === 'string' ? file : JSON.stringify(file))

const wrapOfType = (file: OnDiskVault, type: 'password' | 'recovery'): OnDiskWrap => {
  const found = file.wraps.find((w) => w.type === type)
  assert.ok(found, `fixture is wrong: the file carries no ${type} wrap`)
  return found
}

/**
 * Asserts the call rejects with an AppError carrying `key`. Matching on the key
 * keeps the tests language-independent and pins down *which* failure happened —
 * several of these paths have more than one way to go wrong.
 */
async function rejectsWithKey(run: () => Promise<unknown>, key: string, note = ''): Promise<Error> {
  let caught: (Error & { key?: string }) | null = null
  try {
    await run()
  } catch (err) {
    caught = err as Error & { key?: string }
  }
  assert.ok(caught, `${note || 'call'}: expected rejection with ${key}, but it resolved`)
  const actual = caught.key ?? `${caught.name}: ${caught.message}`
  assert.equal(caught.key, key, `${note || 'call'}: expected ${key}, got ${actual}`)
  return caught
}

function throwsWithKey(run: () => unknown, key: string, note = ''): Error & { key?: string } {
  let caught: (Error & { key?: string }) | null = null
  try {
    run()
  } catch (err) {
    caught = err as Error & { key?: string }
  }
  assert.ok(caught, `${note || 'call'}: expected a throw of ${key}, but it returned`)
  const actual = caught.key ?? `${caught.name}: ${caught.message}`
  assert.equal(caught.key, key, `${note || 'call'}: expected ${key}, got ${actual}`)
  return caught
}

function sampleConnection(): Record<string, unknown> {
  return {
    id: 'conn-1',
    name: 'prod-db',
    host: '10.0.0.7',
    port: 2222,
    username: 'deploy',
    authKind: 'password',
    password: 'hunter2-the-real-secret',
    privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n',
    createdAt: 1700000000000,
    updatedAt: 1700000000001
  }
}

/**
 * Recognisable content, plus the `vault.enc.bak` the backup assertions need in
 * order to be able to fail: `persist()` only backs up an existing vault file.
 */
async function seed(): Promise<void> {
  await vault.mutate((data) => {
    data.connections.push(sampleConnection() as never)
    data.knownHosts.push({
      hostKey: '10.0.0.7:2222',
      keyType: 'ssh-ed25519',
      fingerprint: 'SHA256:abcdef',
      addedAt: 1700000000002
    })
    data.snippets.push({
      id: 'snip-1',
      title: 'restart',
      body: 'systemctl restart nginx',
      kind: 'command',
      createdAt: 1700000000003,
      updatedAt: 1700000000004
    })
    data.settings.autoLockMinutes = 3
    data.mcpToken = 'mcp-bearer-token'
  })
}

function assertSeeded(note: string): void {
  const data = vault.read()
  assert.equal(data.connections.length, 1, `${note}: the connection is gone`)
  assert.equal(
    data.connections[0].password,
    'hunter2-the-real-secret',
    `${note}: the stored connection password did not survive`
  )
  assert.equal(data.snippets[0].body, 'systemctl restart nginx', `${note}: the snippet is wrong`)
  assert.equal(data.knownHosts[0].fingerprint, 'SHA256:abcdef', `${note}: the known host is wrong`)
  assert.equal(data.settings.autoLockMinutes, 3, `${note}: the settings did not survive`)
  assert.equal(data.mcpToken, 'mcp-bearer-token', `${note}: the MCP token did not survive`)
}

const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number }
) => Promise<Buffer>

/**
 * A version-1 vault file built by hand: key derived straight from the password,
 * no DEK, no wraps. The migration off it runs exactly once, with no second try.
 */
async function writeLegacyVault(password: string, payload: unknown): Promise<void> {
  const salt = randomBytes(32)
  const params = { N: 1 << 17, r: 8, p: 1, keylen: 32 }
  const key = await scryptAsync(password, salt, params.keylen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 320 * 1024 * 1024
  })
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const data = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(payload), 'utf8')),
    cipher.final()
  ])
  fs.mkdirSync(dir, { recursive: true })
  writeVaultFile({
    version: 1,
    kdf: { name: 'scrypt', salt: salt.toString('base64'), ...params },
    cipher: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64')
  })
}

/**
 * A version-2 key wrap, written by hand: a fixture built from `vault.ts` would
 * only prove the code agrees with itself.
 */
async function makeV2Wrap(
  type: 'password' | 'recovery',
  secret: string,
  dek: Buffer
): Promise<OnDiskWrap> {
  const salt = randomBytes(32)
  const params = { N: 1 << 17, r: 8, p: 1, keylen: 32 }
  const kek = await scryptAsync(secret, salt, params.keylen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 320 * 1024 * 1024
  })
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', kek, iv)
  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()])
  return {
    type,
    kdf: { name: 'scrypt', salt: salt.toString('base64'), ...params },
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    wrapped: wrapped.toString('base64')
  }
}

/**
 * A version-2 vault file: one data key wrapped by both secrets, body sealed with
 * **no AAD** — the header floats free of the ciphertext, which is why v3 exists.
 * The upgrade runs once with no second attempt, so both wraps must survive it;
 * the recovery key exists only on paper.
 */
async function writeV2Vault(
  password: string,
  recoveryKey: string,
  payload: unknown
): Promise<void> {
  const dek = randomBytes(32)
  const wraps = [
    await makeV2Wrap('password', password, dek),
    await makeV2Wrap('recovery', normalizeRecoveryKey(recoveryKey), dek)
  ]
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', dek, iv)
  const data = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(payload), 'utf8')),
    cipher.final()
  ])
  fs.mkdirSync(dir, { recursive: true })
  writeVaultFile({
    version: 2,
    cipher: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64'),
    wraps
  })
}

// One real vault, reused as the base for every forged file in the KDF section:
// those tests need a genuine file to mutate and `create()` costs two scrypts.
let goodFile: OnDiskVault | null = null

async function baseVaultFile(): Promise<OnDiskVault> {
  if (!goodFile) {
    fresh()
    await vault.create(PASSWORD)
    goodFile = readVaultFile()
  }
  return goodFile
}

/**
 * Writes a fresh vault whose `type` wrap carries the patched `kdf`, leaving the
 * singleton locked. A `null` patch drops the `kdf` object entirely —
 * `JSON.stringify` omits an `undefined` value, the shape of a file that lost it.
 */
async function forgeKdf(
  type: 'password' | 'recovery',
  patch: Partial<OnDiskWrap['kdf']> | null
): Promise<void> {
  const base = await baseVaultFile()
  fresh()
  writeVaultFile({
    ...base,
    wraps: base.wraps.map((w) =>
      w.type === type ? { ...w, kdf: patch === null ? undefined : { ...w.kdf, ...patch } } : w
    )
  })
}

after(() => {
  vault.lock()
  for (const made of madeDirs) fs.rmSync(made, { recursive: true, force: true })
})

/* -------------------------------------------------------------- the basics */

test('a vault survives create → lock → unlock with every field intact', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  assert.equal(typeof recoveryKey, 'string', 'create() must hand back a recovery key')
  await seed()
  // Compared as JSON because that is what goes through the cipher: an own
  // property whose value is `undefined` is not a difference the vault preserves.
  const before = JSON.stringify(vault.read())

  vault.lock()
  assert.equal(vault.isUnlocked(), false, 'lock() left the vault unlocked')
  throwsWithKey(() => vault.read(), 'error.vaultLocked', 'read() while locked')
  await rejectsWithKey(() => vault.mutate((d) => d), 'error.vaultLocked', 'mutate() while locked')
  throwsWithKey(
    () => vault.requireUnlockedPublic(),
    'error.vaultLocked',
    'requireUnlockedPublic() let a locked vault through — the SSH handlers rely on it'
  )

  await vault.unlock(PASSWORD)
  assert.equal(vault.isUnlocked(), true, 'unlock() did not unlock')
  assertSeeded('after a lock/unlock round trip')
  assert.equal(JSON.stringify(vault.read()), before, 'the round trip changed the vault contents')
  assert.doesNotThrow(() => vault.requireUnlockedPublic(), 'unlocked vault refused the SSH gate')
})

test('the vault file on disk never contains the plaintext it was given', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const raw = fs.readFileSync(vaultPath(), 'utf8')
  for (const secret of ['hunter2-the-real-secret', 'mcp-bearer-token', 'systemctl restart nginx']) {
    assert.ok(!raw.includes(secret), `the vault file leaks ${secret} in the clear`)
  }
  assert.ok(!raw.includes(PASSWORD), 'the vault file leaks the master password')
})

test('create() refuses to overwrite an existing vault and leaves it readable', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()

  await rejectsWithKey(() => vault.create(OTHER_PASSWORD), 'error.vaultExists')

  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('after a refused create()')
})

test('create() rejects a password below the length floor and writes nothing', async () => {
  fresh()
  const short = 'x'.repeat(MIN_PASSWORD_LENGTH - 1)
  await rejectsWithKey(() => vault.create(short), 'error.passwordTooShort', 'one under the floor')
  assert.equal(vault.exists(), false, 'a rejected create() still left a vault file behind')
  await rejectsWithKey(() => vault.create(''), 'error.passwordTooShort', 'empty password')
  assert.equal(vault.exists(), false, 'an empty password still created a vault')

  await vault.create('y'.repeat(MIN_PASSWORD_LENGTH))
  assert.equal(vault.exists(), true, 'a password exactly at the floor was refused')
})

test('the floor is only checked where a password is chosen, never on unlock', async () => {
  // Raising it must not lock anyone out; unlock() never calls validatePassword.
  fresh()
  await vault.create('z'.repeat(MIN_PASSWORD_LENGTH))
  vault.lock()
  await vault.unlock('z'.repeat(MIN_PASSWORD_LENGTH))
  assert.equal(vault.isUnlocked(), true, 'unlock() started enforcing the floor')
})

test('unlock() rejects a wrong password without touching the vault file', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  vault.lock()
  const before = fs.readFileSync(vaultPath())

  await rejectsWithKey(() => vault.unlock('wrong-password-entirely'), 'error.wrongPassword')
  assert.equal(vault.isUnlocked(), false, 'a failed unlock left the vault unlocked')
  assert.deepEqual(fs.readFileSync(vaultPath()), before, 'a failed unlock rewrote the vault file')

  await vault.unlock(PASSWORD)
  assertSeeded('after a rejected unlock attempt')
})

test('unlock() reports a missing vault instead of inventing an empty one', async () => {
  fresh()
  assert.equal(vault.exists(), false, 'the fresh directory already holds a vault')
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultMissing')
  assert.equal(vault.isUnlocked(), false, 'a missing vault ended up unlocked')
})

/* ----------------------------------------------------- recovery key: shape */

test('generateRecoveryKey() returns six groups of five — 35 characters with the dashes', () => {
  for (let i = 0; i < 50; i++) {
    const key = generateRecoveryKey()
    assert.match(key, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){5}$/, `malformed recovery key: ${key}`)
    assert.equal(key.length, 35, `expected 35 characters including separators, got ${key.length}`)
    assert.equal(key.replace(/-/g, '').length, 30, 'the payload must be 30 alphabet characters')
  }
})

test('generateRecoveryKey() never emits the lookalike letters I, L, O or U', () => {
  for (let i = 0; i < 200; i++) {
    const key = generateRecoveryKey()
    assert.doesNotMatch(key, /[ILOU]/, `recovery key contains an ambiguous letter: ${key}`)
  }
})

test('generateRecoveryKey() draws on the whole 32 character alphabet', () => {
  // Catches a mask that truncates the alphabet (`& 15` not `& 31`), halving the
  // entropy without changing the shape.
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
  const seen = new Set<string>()
  for (let i = 0; i < 300; i++) {
    for (const ch of generateRecoveryKey().replace(/-/g, '')) seen.add(ch)
  }
  for (const ch of alphabet) {
    assert.ok(seen.has(ch), `the character ${ch} never appeared in 9000 draws`)
  }
  assert.equal(seen.size, alphabet.length, `unexpected characters: ${[...seen].join('')}`)
})

test('generateRecoveryKey() does not hand out the same key twice', () => {
  const keys = new Set<string>()
  for (let i = 0; i < 200; i++) keys.add(generateRecoveryKey())
  assert.equal(keys.size, 200, 'generateRecoveryKey() repeated itself')
})

/* --------------------------------------------- recovery key: normalisation */

test('normalizeRecoveryKey() folds case, separators and the 0/O and 1/I/L lookalikes', () => {
  const canonical = '0123456789ABCDEFGHJKMNPQRSTVWX'
  assert.equal(canonical.length, 30, 'the fixture itself is the wrong length')

  assert.equal(normalizeRecoveryKey(canonical), canonical, 'a canonical key was altered')
  assert.equal(normalizeRecoveryKey(canonical.toLowerCase()), canonical, 'case was not folded')
  assert.equal(
    normalizeRecoveryKey(canonical.match(/.{1,5}/g)!.join('-')),
    canonical,
    'dashes were not stripped'
  )
  assert.equal(
    normalizeRecoveryKey(`  ${canonical.match(/.{1,5}/g)!.join(' ')}\n`),
    canonical,
    'spaces and surrounding whitespace were not stripped'
  )
  assert.equal(
    normalizeRecoveryKey(canonical.replace(/0/g, 'O').replace(/1/g, 'I')),
    canonical,
    'the O→0 and I→1 substitutions did not happen'
  )
  assert.equal(
    normalizeRecoveryKey(canonical.replace(/0/g, 'o').replace(/1/g, 'l')),
    canonical,
    'the lowercase o→0 and l→1 substitutions did not happen'
  )
})

test('normalizeRecoveryKey() rejects a key of the wrong length and says how long it was', () => {
  const short = '0123456789ABCDEFGHJKMNPQRSTVW'
  assert.equal(short.length, 29, 'the fixture itself is the wrong length')
  const err = throwsWithKey(() => normalizeRecoveryKey(short), 'error.recoveryLength', '29 chars')
  assert.match(err.message, /29/, 'the error does not tell the user how many characters they typed')
  throwsWithKey(
    () => normalizeRecoveryKey('0123456789ABCDEFGHJKMNPQRSTVWXY'),
    'error.recoveryLength',
    '31 characters'
  )
  throwsWithKey(() => normalizeRecoveryKey(''), 'error.recoveryLength', 'an empty key')
})

test('normalizeRecoveryKey() rejects characters outside the alphabet', () => {
  // U is excluded from the alphabet and, unlike O and I, is not remapped.
  const err = throwsWithKey(
    () => normalizeRecoveryKey('U123456789ABCDEFGHJKMNPQRSTVWX'),
    'error.recoveryChar',
    'the letter U'
  )
  assert.match(err.message, /U/, 'the error does not name the offending character')
})

test('a sloppily typed recovery key still unlocks the vault', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()
  vault.lock()

  const mangled = recoveryKey.toLowerCase().replace(/-/g, ' ').replace(/0/g, 'o').replace(/1/g, 'l')
  const sloppy = ` ${mangled} `
  assert.notEqual(sloppy.trim(), recoveryKey, 'the fixture did not actually mangle the key')

  const replacement = await vault.unlockWithRecovery(sloppy, OTHER_PASSWORD)
  assert.match(replacement, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){5}$/, 'the replacement key is malformed')
  assertSeeded('after unlocking with a sloppily typed key')
})

/* ------------------------------------------------------- password recovery */

test('unlockWithRecovery() opens the vault, sets a new password and rotates', async () => {
  fresh()
  const firstKey = await vault.create(PASSWORD)
  await seed()
  const before = readVaultFile()
  vault.lock()

  assert.ok(fs.existsSync(backupPath()), 'precondition: a backup exists before the recovery')

  const secondKey = await vault.unlockWithRecovery(firstKey, OTHER_PASSWORD)
  assertSeeded('after a recovery unlock')
  assert.notEqual(secondKey, firstKey, 'unlockWithRecovery() returned the key just used')
  assert.match(secondKey, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){5}$/, 'the returned key is malformed')
  assert.equal(
    fs.existsSync(backupPath()),
    false,
    'the backup survived the recovery — it still holds a wrap the used key opens'
  )

  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.wrongPassword', 'the replaced password')
  await vault.unlock(OTHER_PASSWORD)
  assertSeeded('unlocking with the password set during recovery')

  // The used key must be dead, and not merely because a newer wrap sits in front
  // of it: spliced back in as the only recovery wrap it must still fail.
  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(firstKey, THIRD_PASSWORD),
    'error.wrongRecoveryKey'
  )
  const spliced = readVaultFile()
  spliced.wraps = spliced.wraps
    .filter((w) => w.type !== 'recovery')
    .concat([wrapOfType(before, 'recovery')])
  writeVaultFile(spliced)
  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(firstKey, THIRD_PASSWORD),
    'error.decryptFailed',
    'the pre-recovery wrap still opened the current data key'
  )
})

test('unlockWithRecovery() rejects a wrong key and leaves the real one working', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()
  vault.lock()

  const wrong = generateRecoveryKey()
  assert.notEqual(wrong, recoveryKey, 'the fixture drew the same key twice')
  await rejectsWithKey(
    () => vault.unlockWithRecovery(wrong, OTHER_PASSWORD),
    'error.wrongRecoveryKey'
  )
  assert.equal(vault.isUnlocked(), false, 'a rejected recovery left the vault unlocked')

  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(typeof replacement, 'string', 'the real key stopped working after a wrong guess')
  assertSeeded('after a rejected recovery attempt')
})

test('unlockWithRecovery() rejects a short new password without consuming the key', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()
  vault.lock()

  await rejectsWithKey(
    () => vault.unlockWithRecovery(recoveryKey, 'short'),
    'error.passwordTooShort'
  )
  assert.equal(vault.isUnlocked(), false, 'the rejected recovery left the vault unlocked')

  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(typeof replacement, 'string', 'the recovery key was burned by a rejected attempt')
  assertSeeded('after a recovery rejected for a short password')

  vault.lock()
  await vault.unlock(OTHER_PASSWORD)
  assertSeeded('the password set by the successful recovery')
})

test('unlockWithRecovery() reports noRecoverySet on a vault that never had one', async () => {
  fresh()
  await vault.create(PASSWORD)
  await vault.removeRecoveryKey(PASSWORD)
  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(generateRecoveryKey(), OTHER_PASSWORD),
    'error.noRecoverySet'
  )
})

/* ------------------------------------------------------------ key rotation */

test('changePassword() revokes the old password and the old recovery key together', async () => {
  fresh()
  const firstKey = await vault.create(PASSWORD)
  await seed()
  const before = readVaultFile()
  assert.ok(fs.existsSync(backupPath()), 'precondition: a backup exists before the rotation')

  const secondKey = await vault.changePassword(PASSWORD, OTHER_PASSWORD)
  assert.ok(secondKey, 'changePassword() returned no replacement key for a vault that had one')
  assert.notEqual(secondKey, firstKey, 'changePassword() handed back the old recovery key')
  assert.equal(
    fs.existsSync(backupPath()),
    false,
    'the backup survived the rotation — it still holds wraps the revoked secrets open'
  )

  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.wrongPassword', 'the old password')
  await rejectsWithKey(
    () => vault.unlockWithRecovery(firstKey, THIRD_PASSWORD),
    'error.wrongRecoveryKey',
    'the old recovery key'
  )

  await vault.unlock(OTHER_PASSWORD)
  assertSeeded('after changePassword()')

  vault.lock()
  const thirdKey = await vault.unlockWithRecovery(secondKey!, THIRD_PASSWORD)
  assert.notEqual(thirdKey, secondKey, 'the recovery unlock did not rotate again')
  assertSeeded('unlocking with the key changePassword() returned')
})

test('a password wrap captured before changePassword() is dead afterwards', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const before = readVaultFile()

  await vault.changePassword(PASSWORD, OTHER_PASSWORD)
  await vault.mutate((data) => {
    data.settings.scrollback = 12345
  })

  // The attacker holds the old wrap and the old password; spliced into the current
  // file it yields the *old* data key, which changePassword() must have retired.
  const spliced = readVaultFile()
  spliced.wraps = spliced.wraps
    .filter((w) => w.type !== 'password')
    .concat([wrapOfType(before, 'password')])
  writeVaultFile(spliced)
  vault.lock()

  await rejectsWithKey(
    () => vault.unlock(PASSWORD),
    'error.decryptFailed',
    'the pre-rotation password wrap still opened the current data key'
  )
  assert.equal(vault.isUnlocked(), false, 'the vault ended up unlocked by a revoked wrap')
})

test('changePassword() returns null when the vault has no recovery key', async () => {
  fresh()
  await vault.create(PASSWORD)
  await vault.removeRecoveryKey(PASSWORD)
  await seed()

  const replacement = await vault.changePassword(PASSWORD, OTHER_PASSWORD)
  assert.equal(replacement, null, 'changePassword() invented a recovery key the vault never had')
  assert.equal(await vault.hasRecoveryOnDisk(), false, 'a recovery wrap reappeared on disk')

  vault.lock()
  await vault.unlock(OTHER_PASSWORD)
  assertSeeded('after changing the password on a recovery-less vault')
})

test('changePassword() rejects a wrong old password and leaves both secrets working', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()

  await rejectsWithKey(
    () => vault.changePassword('not-the-old-password', OTHER_PASSWORD),
    'error.wrongOldPassword'
  )
  assert.equal(vault.isUnlocked(), true, 'the rejected change locked the vault')
  assertSeeded('after a rejected changePassword()')

  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('the old password after a rejected changePassword()')
  vault.lock()
  const replacement = await vault.unlockWithRecovery(recoveryKey, THIRD_PASSWORD)
  assert.equal(typeof replacement, 'string', 'a rejected changePassword() burned the recovery key')
})

test('changePassword() rejects a short new password and leaves both secrets working', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()

  await rejectsWithKey(() => vault.changePassword(PASSWORD, 'short'), 'error.passwordTooShort')
  assertSeeded('after a changePassword() rejected for a short password')

  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('the old password after a short new password was refused')
  vault.lock()
  const replacement = await vault.unlockWithRecovery(recoveryKey, THIRD_PASSWORD)
  assert.equal(typeof replacement, 'string', 'a refused short password burned the recovery key')
})

test('regenerateRecoveryKey() revokes the previous key, wrap and backup', async () => {
  fresh()
  const firstKey = await vault.create(PASSWORD)
  await seed()
  const before = readVaultFile()
  assert.ok(fs.existsSync(backupPath()), 'precondition: a backup exists before the rotation')

  const secondKey = await vault.regenerateRecoveryKey(PASSWORD)
  assert.notEqual(secondKey, firstKey, 'regenerateRecoveryKey() returned the key it replaced')
  assert.match(secondKey, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){5}$/, 'the returned key is malformed')
  assert.equal(
    fs.existsSync(backupPath()),
    false,
    'the backup survived — it still holds a wrap the revoked key opens'
  )
  assertSeeded('after regenerateRecoveryKey()')

  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('the unchanged password after regenerateRecoveryKey()')

  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(firstKey, OTHER_PASSWORD),
    'error.wrongRecoveryKey',
    'the revoked recovery key'
  )

  const spliced = readVaultFile()
  spliced.wraps = spliced.wraps
    .filter((w) => w.type !== 'recovery')
    .concat([wrapOfType(before, 'recovery')])
  writeVaultFile(spliced)
  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(firstKey, OTHER_PASSWORD),
    'error.decryptFailed',
    'the revoked wrap still opened the current data key'
  )
})

test('regenerateRecoveryKey() rejects a wrong password and keeps the current key', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()
  const before = readVaultFile()

  await rejectsWithKey(() => vault.regenerateRecoveryKey('not-the-password'), 'error.wrongPassword')
  assert.equal(vault.isUnlocked(), true, 'the rejected call locked the vault')
  assert.deepEqual(
    readVaultFile().wraps.map((w) => w.wrapped),
    before.wraps.map((w) => w.wrapped),
    'a rejected regenerateRecoveryKey() rewrote the wraps anyway'
  )
  assertSeeded('after a rejected regenerateRecoveryKey()')

  vault.lock()
  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(typeof replacement, 'string', 'the current recovery key stopped working')
})

test('regenerateRecoveryKey() rejects an empty password instead of skipping it', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  await rejectsWithKey(() => vault.regenerateRecoveryKey(''), 'error.wrongPassword')
  assertSeeded('after regenerateRecoveryKey() with an empty password')
})

test('removeRecoveryKey() revokes the removed key and keeps the password working', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()
  const before = readVaultFile()
  assert.ok(fs.existsSync(backupPath()), 'precondition: a backup exists before the rotation')
  assert.equal(vault.hasRecoveryKey(), true, 'precondition: the vault has a recovery key')

  await vault.removeRecoveryKey(PASSWORD)
  assert.equal(vault.hasRecoveryKey(), false, 'removeRecoveryKey() left a recovery wrap in memory')
  assert.equal(await vault.hasRecoveryOnDisk(), false, 'a recovery wrap is still on disk')
  assert.equal(
    fs.existsSync(backupPath()),
    false,
    'the backup survived — it still holds a wrap the removed key opens'
  )

  // Removing recovery must never remove the way in.
  const onDisk = readVaultFile()
  assert.equal(onDisk.wraps.length, 1, 'the file should be left with exactly one wrap')
  assert.equal(onDisk.wraps[0].type, 'password', 'the surviving wrap is not the password wrap')

  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('after removeRecoveryKey()')

  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD),
    'error.noRecoverySet',
    'the removed recovery key'
  )

  const spliced = readVaultFile()
  spliced.wraps = [...spliced.wraps, wrapOfType(before, 'recovery')]
  writeVaultFile(spliced)
  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD),
    'error.decryptFailed',
    'the removed wrap still opened the current data key'
  )
})

test('removeRecoveryKey() rejects a wrong password and leaves recovery working', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()

  await rejectsWithKey(() => vault.removeRecoveryKey('not-the-password'), 'error.wrongPassword')
  assert.equal(vault.hasRecoveryKey(), true, 'a rejected removal dropped the recovery wrap anyway')
  assert.equal(await vault.hasRecoveryOnDisk(), true, 'a rejected removal rewrote the file')
  assertSeeded('after a rejected removeRecoveryKey()')

  vault.lock()
  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(typeof replacement, 'string', 'the recovery key stopped working')
})

test('rotation operations refuse to run while the vault is locked', async () => {
  fresh()
  await vault.create(PASSWORD)
  vault.lock()

  await rejectsWithKey(
    () => vault.changePassword(PASSWORD, OTHER_PASSWORD),
    'error.vaultLocked',
    'changePassword() while locked'
  )
  await rejectsWithKey(
    () => vault.regenerateRecoveryKey(PASSWORD),
    'error.vaultLocked',
    'regenerateRecoveryKey() while locked'
  )
  await rejectsWithKey(
    () => vault.removeRecoveryKey(PASSWORD),
    'error.vaultLocked',
    'removeRecoveryKey() while locked'
  )
})

test('a rotation that cannot be written back leaves the old secrets working', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  await seed()

  // Occupying the temp path makes the atomic write fail. The vault must roll
  // back rather than keep a data key in memory that no longer matches the file.
  fs.mkdirSync(vaultPath() + '.tmp')
  await assert.rejects(
    () => vault.changePassword(PASSWORD, OTHER_PASSWORD),
    'a blocked write reported success'
  )
  fs.rmSync(vaultPath() + '.tmp', { recursive: true, force: true })

  assert.equal(vault.isUnlocked(), true, 'the failed rotation locked the user out')
  assertSeeded('after a rotation that failed to write')

  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('the old password after a rotation that failed to write')
  vault.lock()
  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(typeof replacement, 'string', 'a failed rotation burned the recovery key')
})

test('a mutation that cannot be written back does not survive in memory', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const before = vault.read().knownHosts.length

  // ssh.verifyHostKey() records trust through mutate(), so a failed write left in
  // memory would have the app trusting a host key the file on disk does not.
  fs.mkdirSync(vaultPath() + '.tmp')
  await assert.rejects(
    () =>
      vault.mutate((data) => {
        data.knownHosts.push({
          hostKey: 'AAAAB3NzaC1yc2EAAAA-forged',
          keyType: 'ssh-rsa',
          fingerprint: 'SHA256:forged',
          addedAt: 1
        })
      }),
    'a blocked write reported success'
  )
  fs.rmSync(vaultPath() + '.tmp', { recursive: true, force: true })

  assert.equal(
    vault.read().knownHosts.length,
    before,
    'the failed mutation stayed in memory, so the app trusts a key the file does not'
  )

  await vault.mutate((data) => {
    data.settings.scrollback = 1234
  })
  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(vault.read().knownHosts.length, before, 'the discarded change was written later')
  assert.equal(vault.read().settings.scrollback, 1234, 'the following write did not stick')
})

test('a failed write during create or v1 migration does not leave the vault open', async () => {
  // isUnlocked() is what requireUnlockedPublic() gates SSH and MCP on: an error
  // to the renderer while the main process holds an open vault is no lock at all.
  fresh()
  fs.mkdirSync(vaultPath() + '.tmp')
  await assert.rejects(() => vault.create(PASSWORD), 'a blocked create reported success')
  assert.equal(vault.isUnlocked(), false, 'a failed create left the vault unlocked')
  assert.equal(vault.exists(), false, 'a failed create left a vault file behind')
  fs.rmSync(vaultPath() + '.tmp', { recursive: true, force: true })

  fresh()
  await writeLegacyVault(PASSWORD, { connections: [sampleConnection()] })
  fs.mkdirSync(vaultPath() + '.tmp')
  await assert.rejects(() => vault.unlock(PASSWORD), 'a blocked v1 migration reported success')
  assert.equal(vault.isUnlocked(), false, 'a failed v1 migration left the vault unlocked')
  assert.equal(readVaultFile().version, 1, 'the v1 file was half-migrated')
  fs.rmSync(vaultPath() + '.tmp', { recursive: true, force: true })

  await vault.unlock(PASSWORD)
  assert.equal(readVaultFile().version, 4, 'the migration no longer runs after a failed write')
  assert.equal(vault.read().connections.length, 1, 'the legacy data was lost')
})

test('concurrent wrong passwords are serialised, not run side by side', async () => {
  // A sleep is not a throttle: fired together, every call reads the same
  // failedUnlocks, sleeps once and reaches scrypt at the same moment.
  fresh()
  await vault.create(PASSWORD)
  vault.lock()
  await vault.unlock(PASSWORD)
  vault.lock()

  const started = Date.now()
  const results = await Promise.allSettled(
    Array.from({ length: 4 }, (_, i) => vault.unlock(`wrong-${i}`))
  )
  const spent = Date.now() - started

  assert.ok(
    results.every((r) => r.status === 'rejected'),
    'a wrong password was accepted'
  )
  // Four serialised attempts cost four derivations; side by side, roughly one.
  assert.ok(spent > 900, `four concurrent guesses took only ${spent} ms`)
})

test('a migration does not leave the old-format vault lying next to the new one', async () => {
  // The .bak persist() takes before every write holds the OLD format with the SAME
  // secrets: for v2, a copy with no AAD and no counter -- a ready-made rollback.
  fresh()
  await writeV2Vault(PASSWORD, generateRecoveryKey(), { connections: [sampleConnection()] })
  await vault.unlock(PASSWORD)

  assert.equal(readVaultFile().version, 4, 'precondition: the migration ran')
  assert.equal(
    fs.existsSync(backupPath()),
    false,
    'the pre-migration v2 copy is still on disk beside the v3 file'
  )

  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(vault.read().connections.length, 1, 'dropping the backup cost us the data')
})

test('an ordinary write still keeps its backup', async () => {
  // Only a migration drops the .bak; it is the safety net for an interrupted write.
  fresh()
  await vault.create(PASSWORD)
  await vault.mutate((data) => {
    data.settings.scrollback = 1111
  })
  assert.equal(fs.existsSync(backupPath()), true, 'an ordinary write lost its safety net')
})

test('wrong passwords get slower, and a lock does not clear the penalty', async () => {
  fresh()
  await vault.create(PASSWORD)

  // lock() deliberately does not reset the counter; only a success clears it.
  vault.lock()
  await vault.unlock(PASSWORD)
  vault.lock()

  // The first attempt is not penalised, or an honest user pays on arrival.
  const firstAt = Date.now()
  await rejectsWithKey(() => vault.unlock('wrong-one'), 'error.wrongPassword')
  const first = Date.now() - firstAt

  const secondAt = Date.now()
  await rejectsWithKey(() => vault.unlock('wrong-two'), 'error.wrongPassword')
  const second = Date.now() - secondAt

  assert.ok(
    second > first + 100,
    `a repeated wrong password cost ${second} ms against ${first} ms for the first`
  )

  // Locking must not reset the throttle, or it is one script away from nothing.
  vault.lock()
  const afterLockAt = Date.now()
  await rejectsWithKey(() => vault.unlock('wrong-three'), 'error.wrongPassword')
  const afterLock = Date.now() - afterLockAt
  assert.ok(afterLock > first + 100, `locking reset the throttle: ${afterLock} ms`)

  await vault.unlock(PASSWORD)
  assert.equal(vault.isUnlocked(), true, 'the throttle refused a correct password')
  vault.lock()
  const cleanAt = Date.now()
  await vault.unlock(PASSWORD)
  assert.ok(Date.now() - cleanAt < first + 500, 'a success did not clear the penalty')
})

test('locking before a queued write runs refuses the write outright', async () => {
  // `mutate` queues, so a synchronous `lock()` always beats the job body, which
  // re-checks and refuses. NOT covered: `lock()` landing INSIDE writeSealed's
  // awaits, after its own guard passed — that is what the `dek === null` re-check
  // before `this.data = draft` exists for, without which a just-locked instance
  // gets its decrypted VaultData reattached.
  fresh()
  await vault.create(PASSWORD)
  await seed()

  const writing = vault.mutate((data) => {
    data.settings.scrollback = 3333
  })
  vault.lock()
  await assert.rejects(() => writing, 'a mutation queued before a lock reported success')
  assert.equal(vault.isUnlocked(), false, 'the refused write reopened a locked vault')

  await vault.unlock(PASSWORD)
  assert.notEqual(vault.read().settings.scrollback, 3333, 'a refused write reached the disk')
  assertSeeded('after a write refused by a lock')
})

test('a mutation whose callback throws leaves the data untouched', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()

  await assert.rejects(
    () =>
      vault.mutate((data) => {
        data.settings.scrollback = 777
        throw new Error('half way through')
      }),
    /half way through/
  )

  assert.notEqual(vault.read().settings.scrollback, 777, 'a half-finished edit stayed live')
  assertSeeded('after a callback that threw')
})

test('concurrent mutations do not lose one another', async () => {
  fresh()
  await vault.create(PASSWORD)

  // Without the write queue both callbacks clone the same state and one is lost.
  await Promise.all([
    vault.mutate((data) => {
      data.settings.fontSize = 20
    }),
    vault.mutate((data) => {
      data.settings.scrollback = 4242
    })
  ])

  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(vault.read().settings.fontSize, 20, 'the first concurrent write was lost')
  assert.equal(vault.read().settings.scrollback, 4242, 'the second concurrent write was lost')
})

/* ------------------------------------------------------- v1 → v3 migration */

test('a v1 vault migrates to the current format on unlock and keeps its data', async () => {
  fresh()
  await writeLegacyVault(PASSWORD, {
    connections: [sampleConnection()],
    knownHosts: [],
    snippets: [],
    settings: { autoLockMinutes: 7, fontSize: 18 },
    mcpToken: 'legacy-mcp-token'
  })

  await vault.unlock(PASSWORD)
  const migrated = vault.read()
  assert.equal(
    migrated.connections[0].password,
    'hunter2-the-real-secret',
    'the legacy connection secret did not survive the migration'
  )
  assert.equal(migrated.settings.autoLockMinutes, 7, 'legacy settings were lost')
  assert.equal(migrated.mcpToken, 'legacy-mcp-token', 'the legacy MCP token was lost')

  const onDisk = readVaultFile()
  assert.equal(onDisk.version, 4, 'the file was not rewritten in the current format')
  assert.ok(
    Number.isSafeInteger(onDisk.counter) && onDisk.counter! >= 1,
    `the migrated file carries no usable counter: ${onDisk.counter}`
  )
  assert.deepEqual(
    onDisk.wraps.map((w) => w.type),
    ['password'],
    'the migrated file should carry exactly one password wrap'
  )

  // The migration runs once and cannot be retried, so the file has to reopen.
  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(
    vault.read().connections[0].password,
    'hunter2-the-real-secret',
    'the migrated vault could not be reopened with the same password'
  )

  await vault.mutate((data) => {
    data.settings.scrollback = 999
  })
  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(vault.read().settings.scrollback, 999, 'writes to the migrated vault did not stick')
})

test('migration fills in the collections a v1 payload never had', async () => {
  fresh()
  await writeLegacyVault(PASSWORD, { connections: [sampleConnection()] })

  await vault.unlock(PASSWORD)
  const data = vault.read()
  assert.deepEqual(data.knownHosts, [], 'knownHosts was not filled in')
  assert.deepEqual(data.snippets, [], 'snippets was not filled in')
  assert.equal(typeof data.settings.autoLockMinutes, 'number', 'settings were not filled in')
  assert.equal(data.settings.mcpPort, 7345, 'the settings defaults are missing')
})

test('a migrated v1 vault has no recovery key until one is asked for', async () => {
  fresh()
  await writeLegacyVault(PASSWORD, { connections: [] })
  await vault.unlock(PASSWORD)

  assert.equal(vault.hasRecoveryKey(), false, 'the migration invented a recovery key')
  assert.equal(await vault.hasRecoveryOnDisk(), false, 'the migrated file claims a recovery wrap')

  const recoveryKey = await vault.regenerateRecoveryKey(PASSWORD)
  assert.equal(vault.hasRecoveryKey(), true, 'the migrated vault refused to take a recovery key')
  vault.lock()
  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(typeof replacement, 'string', 'the new key did not open the migrated vault')
})

test('a v1 vault opened with the wrong password is left exactly as it was', async () => {
  fresh()
  await writeLegacyVault(PASSWORD, { connections: [sampleConnection()] })
  const before = fs.readFileSync(vaultPath())

  await rejectsWithKey(() => vault.unlock('not-the-legacy-password'), 'error.wrongPassword')
  assert.equal(vault.isUnlocked(), false, 'a failed legacy unlock left the vault unlocked')
  assert.deepEqual(fs.readFileSync(vaultPath()), before, 'a failed legacy unlock rewrote the file')
  assert.equal(readVaultFile().version, 1, 'a failed legacy unlock half-migrated the file')

  await vault.unlock(PASSWORD)
  assert.equal(readVaultFile().version, 4, 'the migration no longer runs after a wrong guess')
  assert.equal(vault.read().connections.length, 1, 'the legacy data was lost')
})

test('unlockWithRecovery() on a v1 vault says so and leaves the file untouched', async () => {
  fresh()
  await writeLegacyVault(PASSWORD, { connections: [sampleConnection()] })
  const before = fs.readFileSync(vaultPath())

  await rejectsWithKey(
    () => vault.unlockWithRecovery(generateRecoveryKey(), OTHER_PASSWORD),
    'error.legacyNoRecovery'
  )
  assert.deepEqual(fs.readFileSync(vaultPath()), before, 'the legacy file was rewritten')
  assert.equal(readVaultFile().version, 1, 'the legacy file was migrated by a failed recovery')

  await vault.unlock(PASSWORD)
  assert.equal(vault.read().connections.length, 1, 'the legacy data was lost')
})

/* ------------------------------------------------------- v2 → v3 migration */

test('a v2 vault migrates on unlock, keeping its data and both secrets', async () => {
  fresh()
  const recoveryKey = generateRecoveryKey()
  await writeV2Vault(PASSWORD, recoveryKey, {
    connections: [sampleConnection()],
    knownHosts: [],
    snippets: [],
    settings: { autoLockMinutes: 11 },
    mcpToken: 'v2-mcp-token'
  })

  await vault.unlock(PASSWORD)
  assert.equal(
    vault.read().connections[0].password,
    'hunter2-the-real-secret',
    'the v2 connection secret did not survive the migration'
  )
  assert.equal(vault.read().settings.autoLockMinutes, 11, 'v2 settings were lost')
  assert.equal(vault.read().mcpToken, 'v2-mcp-token', 'the v2 MCP token was lost')

  const onDisk = readVaultFile()
  assert.equal(onDisk.version, 4, 'unlocking a v2 vault did not rewrite it in the current format')
  assert.ok(
    Number.isSafeInteger(onDisk.counter) && onDisk.counter! >= 1,
    `the migrated file carries no usable counter: ${onDisk.counter}`
  )
  assert.deepEqual(
    onDisk.wraps.map((w) => w.type).sort(),
    ['password', 'recovery'],
    'the migration dropped a wrap'
  )

  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(
    vault.read().connections[0].password,
    'hunter2-the-real-secret',
    'the migrated vault could not be reopened with the same password'
  )

  // The recovery key is carried across verbatim: it cannot be rebuilt from the
  // file, so rotating the DEK here would kill the only string the user has.
  vault.lock()
  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.match(replacement, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){5}$/, 'the replacement key is malformed')
  assert.equal(
    vault.read().connections[0].password,
    'hunter2-the-real-secret',
    'recovering into the migrated vault lost the data'
  )
})

test('the file a v2 migration leaves behind is header-protected like any other v3', async () => {
  fresh()
  await writeV2Vault(PASSWORD, generateRecoveryKey(), { connections: [sampleConnection()] })
  await vault.unlock(PASSWORD)
  vault.lock()

  // A migration writing v3 in the header but sealing without AAD protects nothing.
  const migrated = readVaultFile()
  writeVaultFile({ ...migrated, wraps: migrated.wraps.filter((w) => w.type === 'password') })
  await rejectsWithKey(
    () => vault.unlock(PASSWORD),
    'error.decryptFailed',
    'the migrated file accepted a stripped wrap list'
  )
})

test('a v2 vault opened with the wrong password is left in the v2 format', async () => {
  fresh()
  await writeV2Vault(PASSWORD, generateRecoveryKey(), { connections: [sampleConnection()] })
  const before = fs.readFileSync(vaultPath())

  await rejectsWithKey(() => vault.unlock('not-the-v2-password'), 'error.wrongPassword')
  assert.equal(vault.isUnlocked(), false, 'a failed v2 unlock left the vault unlocked')
  assert.deepEqual(fs.readFileSync(vaultPath()), before, 'a failed v2 unlock rewrote the file')
  assert.equal(readVaultFile().version, 2, 'a failed v2 unlock half-migrated the file')

  await vault.unlock(PASSWORD)
  assert.equal(readVaultFile().version, 4, 'the migration no longer runs after a wrong guess')
  assert.equal(vault.read().connections.length, 1, 'the v2 data was lost')
})

test('unlockWithRecovery() on a v2 vault migrates it and rotates', async () => {
  fresh()
  const recoveryKey = generateRecoveryKey()
  await writeV2Vault(PASSWORD, recoveryKey, { connections: [sampleConnection()] })

  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.notEqual(replacement, recoveryKey, 'the recovery unlock handed back the key just used')
  assert.equal(readVaultFile().version, 4, 'the recovery unlock left the file at v2')
  assert.equal(vault.read().connections.length, 1, 'the v2 data was lost')

  vault.lock()
  await vault.unlock(OTHER_PASSWORD)
  assert.equal(vault.read().connections.length, 1, 'the migrated vault did not reopen')
})

/* ----------------------------------------------------------- damaged files */

test('unlock() reports a damaged file instead of crashing on invalid JSON', async () => {
  fresh()
  fs.mkdirSync(dir, { recursive: true })
  writeVaultFile('this is not JSON at all')
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'garbage')

  fresh()
  writeVaultFile('')
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'empty file')
})

test('unlock() reports a damaged file instead of crashing on a truncated one', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const raw = fs.readFileSync(vaultPath(), 'utf8')
  writeVaultFile(raw.slice(0, Math.floor(raw.length / 2)))
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt')
  assert.equal(vault.isUnlocked(), false, 'a truncated file ended up unlocked')
})

test('unlock() refuses a version or cipher it does not understand', async () => {
  fresh()
  await vault.create(PASSWORD)
  const good = readVaultFile()

  writeVaultFile({ ...good, version: 5 })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultUnsupported', 'a future version')

  writeVaultFile({ ...good, cipher: 'aes-128-cbc' })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultUnsupported', 'a foreign cipher')

  writeVaultFile({ ...good, version: undefined })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultUnsupported', 'no version field')

  writeVaultFile(good)
  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(vault.isUnlocked(), true, 'the untouched file stopped opening')
})

test('unlock() detects tampering with the encrypted body and stays locked', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const file = readVaultFile()

  // Flip one ciphertext bit with the wraps intact: only the GCM tag catches it.
  const body = Buffer.from(file.data, 'base64')
  body[0] ^= 0x01
  writeVaultFile({ ...file, data: body.toString('base64') })
  vault.lock()

  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.decryptFailed')
  assert.equal(vault.isUnlocked(), false, 'a tampered vault ended up unlocked')
  throwsWithKey(() => vault.read(), 'error.vaultLocked', 'a tampered vault was readable')
})

test('unlock() detects tampering with a key wrap', async () => {
  fresh()
  await vault.create(PASSWORD)
  const file = readVaultFile()
  const wrapped = Buffer.from(wrapOfType(file, 'password').wrapped, 'base64')
  wrapped[0] ^= 0x01
  file.wraps = file.wraps.map((w) =>
    w.type === 'password' ? { ...w, wrapped: wrapped.toString('base64') } : w
  )
  writeVaultFile(file)
  vault.lock()

  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.wrongPassword')
  assert.equal(vault.isUnlocked(), false, 'a tampered wrap ended up unlocking the vault')
})

test('unlock() reports a missing password wrap instead of opening anyway', async () => {
  fresh()
  await vault.create(PASSWORD)
  const file = readVaultFile()

  writeVaultFile({ ...file, wraps: [] })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.noPasswordSet', 'an empty wraps array')

  writeVaultFile({ ...file, wraps: file.wraps.filter((w) => w.type === 'recovery') })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.noPasswordSet', 'a recovery-only file')
})

/**
 * `readFile()` must reject a non-array `wraps` with `error.vaultCorrupt`. Without
 * that check the field reaches `wraps.find(...)` and a merely damaged file puts a
 * raw TypeError on the unlock screen.
 */
test('unlock() reports a damaged file when the wraps array is missing', async () => {
  fresh()
  await vault.create(PASSWORD)
  const file = readVaultFile()

  writeVaultFile({ version: 2, cipher: file.cipher, iv: file.iv, tag: file.tag, data: file.data })
  vault.lock()
  const err = await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'no wraps')
  assert.notEqual(err.name, 'TypeError', 'a damaged file crashed instead of reporting an error')

  writeVaultFile({ ...file, wraps: null })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'a null wraps field')
})

/* ---------------------------------------------------------- KDF parameters */

test('unlock() refuses a wrap whose KDF is not scrypt', async () => {
  // `deriveKek` never reads `name`, so without this check the field is decorative.
  await forgeKdf('password', { name: 'argon2id' })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'name = argon2id')
  assert.equal(vault.isUnlocked(), false, 'a foreign KDF name still opened the vault')
})

test('unlock() refuses a wrap whose N is below the floor', async () => {
  await forgeKdf('password', { N: 1024 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'N = 1024')
  await forgeKdf('password', { N: 2 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'N = 2')
})

test('unlock() refuses an N over the memory ceiling or off the power of two', async () => {
  // Unchecked, both reach scrypt as a RangeError reported back as a wrong password.
  await forgeKdf('password', { N: 1 << 19 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'N = 1 << 19')
  await forgeKdf('password', { N: 131073 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'N = 131073')
})

test('unlock() refuses a wrap whose r is not 8', async () => {
  await forgeKdf('password', { r: 4 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'r = 4')
})

test('unlock() refuses a p other than 1 without ever running the KDF', async () => {
  // `maxmem` accepts p up to 196606 at our N and r, which would tie up a libuv
  // thread for hours with every `fsp.*` call behind it. The fixture uses 64 so an
  // unguarded build fails instead of hanging; the time bound proves p was checked.
  await forgeKdf('password', { p: 64 })
  const started = Date.now()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'p = 64')
  const spent = Date.now() - started
  assert.ok(spent < 2000, `the rejection took ${spent} ms — the KDF ran before the check`)
})

test('unlock() refuses a keylen other than 32', async () => {
  // `maxmem` does not bound keylen at all: unguarded it allocates before AES objects.
  await forgeKdf('password', { keylen: 64 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'keylen = 64')
  await forgeKdf('password', { keylen: 50_000_000 })
  const started = Date.now()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'keylen = 50 MB')
  const spent = Date.now() - started
  assert.ok(spent < 2000, `the rejection took ${spent} ms — the KDF ran before the check`)
})

test('unlock() refuses a salt shorter than sixteen bytes', async () => {
  // The salt is stored base64, so the floor applies to the decoded bytes.
  await forgeKdf('password', { salt: randomBytes(8).toString('base64') })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'an 8 byte salt')
  await forgeKdf('password', { salt: '' })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'an empty salt')

  // The floor is 16, not whatever makeWrap writes today: 15 out, 16 through.
  await forgeKdf('password', { salt: randomBytes(15).toString('base64') })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'a 15 byte salt')
  await forgeKdf('password', { salt: randomBytes(16).toString('base64') })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.wrongPassword', 'a 16 byte salt')
})

test('unlock() refuses a wrap carrying no kdf object at all', async () => {
  // Unguarded, `wrap.kdf.salt` throws a TypeError reported as a wrong password.
  await forgeKdf('password', null)
  const err = await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'no kdf')
  assert.notEqual(err.name, 'TypeError', 'a wrap with no kdf crashed instead of reporting')
})

test('unlock() validates the recovery wrap too, not only the one it opens', async () => {
  // The check belongs to reading the file, not to opening a wrap: a hostile
  // recovery wrap lies dormant until someone recovers, carried forward untouched.
  await forgeKdf('recovery', { p: 64 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'hostile recovery wrap')
})

test('a v1 vault with hostile KDF parameters is refused before deriving', async () => {
  // `unlockLegacy` calls `deriveKek(…, file.kdf)` outside the wrap path, with its
  // `Buffer.from(file.kdf.salt, …)` outside any try: unguarded it throws a raw
  // TypeError for a missing kdf and runs the attacker's p for a present one.
  fresh()
  await writeLegacyVault(PASSWORD, { connections: [sampleConnection()] })
  const legacy = JSON.parse(fs.readFileSync(vaultPath(), 'utf8')) as { kdf: OnDiskWrap['kdf'] }

  writeVaultFile({ ...legacy, kdf: { ...legacy.kdf, p: 64 } })
  const started = Date.now()
  const err = await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'v1 p = 64')
  assert.notEqual(err.name, 'TypeError', 'a damaged v1 file crashed instead of reporting')
  const spent = Date.now() - started
  assert.ok(spent < 2000, `the v1 path spent ${spent} ms deriving before it checked`)

  writeVaultFile({ ...legacy, kdf: undefined })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', 'v1 with no kdf')

  // The untouched legacy file must still migrate; the floor cannot lock out v1.
  writeVaultFile(legacy)
  await vault.unlock(PASSWORD)
  assert.equal(readVaultFile().version, 4, 'the KDF check blocked the v1 migration')
  assert.equal(vault.read().connections.length, 1, 'the legacy data was lost')
})

test('the KDF check leaves a genuine file alone and leaves room to raise N', async () => {
  // A validator that refused everything would satisfy every test above.
  const base = await baseVaultFile()
  fresh()
  writeVaultFile(base)
  await vault.unlock(PASSWORD)
  assert.equal(vault.isUnlocked(), true, 'the KDF check refused a file the vault wrote itself')

  // N = 1 << 18 must fail on the GCM tag, not on the parameters: the ceiling has
  // to leave room to raise the cost without existing vaults reading as corrupt.
  await forgeKdf('password', { N: 1 << 18 })
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.wrongPassword', 'N = 1 << 18')
})

/* ----------------------------------------------- authenticated header (v3) */

test('a new vault is written in the current format with a counter in the header', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()

  const file = readVaultFile()
  assert.equal(file.version, 4, 'create() did not write the current format')
  assert.ok(Number.isSafeInteger(file.counter), `the header counter is not whole: ${file.counter}`)
  assert.ok(file.counter! >= 1, 'the header counter never advanced past zero')

  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('after a v3 round trip')
})

test('every write advances the header counter, and reopening resumes from it', async () => {
  fresh()
  await vault.create(PASSWORD)
  const first = readVaultFile().counter!
  await seed()
  const second = readVaultFile().counter!
  assert.ok(second > first, `the counter did not advance on a write: ${first} then ${second}`)

  // A counter that restarted at 1 after every unlock would make old files new.
  vault.lock()
  await vault.unlock(PASSWORD)
  await vault.mutate((data) => {
    data.settings.scrollback = 4321
  })
  const third = readVaultFile().counter!
  assert.ok(third > second, `the counter restarted after a lock/unlock: ${second} then ${third}`)
})

test('removing a wrap from a finished v3 file makes the body undecryptable', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const file = readVaultFile()
  assert.equal(file.wraps.length, 2, 'precondition: the file has a password and a recovery wrap')

  // Strip the recovery wrap only. Without AAD the password still yields the data
  // key and the body's tag still verifies, so the file opens minus its escape hatch.
  writeVaultFile({ ...file, wraps: file.wraps.filter((w) => w.type === 'password') })
  vault.lock()
  await rejectsWithKey(
    () => vault.unlock(PASSWORD),
    'error.decryptFailed',
    'a v3 file with the recovery wrap stripped still opened'
  )
  assert.equal(vault.isUnlocked(), false, 'a header-tampered vault ended up unlocked')

  // Writing the file back verbatim must restore it, or the rejection proves nothing.
  writeVaultFile(file)
  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('after the untouched file was written back')
})

test('adding a wrap to a finished v3 file makes the body undecryptable', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const file = readVaultFile()

  // The added wrap is a copy of an existing one: same key, same body, bigger header.
  writeVaultFile({ ...file, wraps: [...file.wraps, wrapOfType(file, 'password')] })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.decryptFailed', 'an added wrap')
})

test('reordering the wraps of a finished v3 file makes the body undecryptable', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const file = readVaultFile()
  assert.equal(file.wraps[0].type, 'password', 'precondition: the password wrap is written first')

  // `find()` still locates the password wrap, so the data key is unchanged. Wrap
  // order is part of the AAD on purpose: sorting them would let this edit through.
  writeVaultFile({ ...file, wraps: [...file.wraps].reverse() })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.decryptFailed', 'reordered wraps')
})

test('changing version in a finished v3 file makes it fail instead of opening', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const file = readVaultFile()

  writeVaultFile({ ...file, version: 5 })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultUnsupported', 'version 4')

  // Claiming v2 asks for the AAD-free path; that is why `version` is in the AAD.
  writeVaultFile({ ...file, version: 2 })
  vault.lock()
  await rejectsWithKey(
    () => vault.unlock(PASSWORD),
    'error.decryptFailed',
    'a v3 file relabelled as v2 skipped the AAD and opened'
  )
  assert.equal(vault.isUnlocked(), false, 'a downgraded vault ended up unlocked')
})

test('rewinding or advancing the header counter makes the body undecryptable', async () => {
  fresh()
  await vault.create(PASSWORD)
  await seed()
  const file = readVaultFile()
  assert.ok(file.counter! >= 2, 'precondition: the counter has advanced at least twice')

  // The counter must not be editable, or the rollback check has nothing to trust.
  writeVaultFile({ ...file, counter: file.counter! - 1 })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.decryptFailed', 'a rewound counter')

  writeVaultFile({ ...file, counter: file.counter! + 1000 })
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.decryptFailed', 'an advanced counter')
})

test('a v3 header that cannot be encoded is reported as damaged, not crashed', async () => {
  fresh()
  await vault.create(PASSWORD)
  const file = readVaultFile()

  // Unguarded, the AAD encoder throws a raw RangeError or TypeError out of unlock().
  const kdfOf = (patch: Record<string, unknown>): unknown => ({
    ...file,
    wraps: file.wraps.map((w) => ({ ...w, kdf: { ...w.kdf, ...patch } }))
  })
  const cases: Array<[string, unknown]> = [
    ['a counter that is not a number', { ...file, counter: 'seven' }],
    ['a negative counter', { ...file, counter: -1 }],
    ['a fractional counter', { ...file, counter: 1.5 }],
    ['a missing counter', { ...file, counter: undefined }],
    ['an out-of-range scrypt N', kdfOf({ N: 1e40 })],
    ['a negative scrypt r', kdfOf({ r: -8 })],
    ['a null salt', kdfOf({ salt: null })],
    ['a numeric wrap type', { ...file, wraps: file.wraps.map((w) => ({ ...w, type: 7 })) }],
    ['a null wrap', { ...file, wraps: [...file.wraps, null] }]
  ]
  for (const [label, broken] of cases) {
    writeVaultFile(broken)
    vault.lock()
    const err = await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.vaultCorrupt', label)
    assert.notEqual(err.name, 'RangeError', `${label} crashed instead of reporting an error`)
    assert.notEqual(err.name, 'TypeError', `${label} crashed instead of reporting an error`)
  }
})

/* --------------------------------------------------------- rollback anchor */

const guardPath = (): string => path.join(dir, 'vault.guard')

test('vault.guard appears beside the vault and holds the last write', async () => {
  fresh()
  await vault.create(PASSWORD)

  assert.ok(fs.existsSync(guardPath()), 'the anchor must appear the moment the vault is created')

  const before = readVaultFile().counter
  await vault.mutate((d) => d.connections.push(sampleConnection()))
  const after = readVaultFile().counter

  assert.ok(after! > before!, 'a write must advance the counter')
  // The anchor tracks the counter, not the clock; with no keyring it is plain text.
  const anchor = JSON.parse(
    Buffer.from(JSON.parse(fs.readFileSync(guardPath(), 'utf8')).payload, 'base64').toString('utf8')
  )
  assert.equal(anchor.counter, after, 'the anchor must match the file after a write')
})

test('an ordinary unlock reports no rollback', async () => {
  fresh()
  await vault.create(PASSWORD)
  await vault.mutate((d) => d.connections.push(sampleConnection()))
  vault.lock()

  await vault.unlock(PASSWORD)
  assert.deepEqual(vault.rollback, { kind: 'ok' })
})

// An attacker who can only write files swaps yesterday's vault.enc back in: every
// tag in it verifies, because it really was ours. Only the anchor outside notices.
test('an older copy planted underneath is caught', async () => {
  fresh()
  await vault.create(PASSWORD)
  const stale = fs.readFileSync(vaultPath())
  const staleCounter = readVaultFile().counter!

  for (let i = 0; i < 3; i++) {
    await vault.mutate((d) => d.connections.push(sampleConnection()))
  }
  const freshCounter = readVaultFile().counter!
  assert.ok(freshCounter > staleCounter)

  vault.lock()
  fs.writeFileSync(vaultPath(), stale)
  await vault.unlock(PASSWORD)

  assert.equal(vault.rollback.kind, 'rollback')
  assert.deepEqual(
    vault.rollback.kind === 'rollback'
      ? { expected: vault.rollback.expected, found: vault.rollback.found }
      : null,
    { expected: freshCounter, found: staleCounter }
  )
})

test('a deleted anchor reports nothing — it has nothing to compare against', async () => {
  fresh()
  await vault.create(PASSWORD)
  const stale = fs.readFileSync(vaultPath())
  await vault.mutate((d) => d.connections.push(sampleConnection()))

  vault.lock()
  fs.writeFileSync(vaultPath(), stale)
  fs.rmSync(guardPath())

  await vault.unlock(PASSWORD)
  assert.deepEqual(vault.rollback, { kind: 'unknown' }, 'with no anchor it must not guess')
})

test('locking throws the verdict away', async () => {
  fresh()
  await vault.create(PASSWORD)
  const stale = fs.readFileSync(vaultPath())
  await vault.mutate((d) => d.connections.push(sampleConnection()))
  vault.lock()
  fs.writeFileSync(vaultPath(), stale)
  await vault.unlock(PASSWORD)
  assert.equal(vault.rollback.kind, 'rollback')

  vault.lock()
  assert.deepEqual(vault.rollback, { kind: 'unknown' }, 'the warning must not survive a lock')
})

// Recovery is a route in too, and someone recovering into a planted older file is
// who most needs telling.
test('a recovery-key unlock spots a rolled-back file too', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  const stale = fs.readFileSync(vaultPath())

  await vault.mutate((d) => d.connections.push(sampleConnection()))
  vault.lock()
  fs.writeFileSync(vaultPath(), stale)

  await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(vault.rollback.kind, 'rollback')
})

// The vault write has already landed by the time the anchor is touched, so a
// failure here must not be reported as a failed write -- the caller would undo
// in-memory state over something that actually succeeded.
test('an anchor that cannot be written does not fail the vault write', async () => {
  fresh()
  await vault.create(PASSWORD)

  fs.rmSync(guardPath())
  fs.mkdirSync(guardPath())

  await vault.mutate((d) => d.connections.push(sampleConnection()))

  assert.equal(vault.read().connections.length, 1, 'the change must go through without an anchor')
  assert.ok(readVaultFile().counter! >= 2, 'the vault itself must still be written')
})

// Deleting vault.enc and leaving vault.guard behind is something a person can do,
// and the transplanted vault would then be judged against a counter that was never
// its own. The anchor belongs to the file, not to the directory.
test('a profile migration drops an anchor that belonged to another vault', async () => {
  fresh()
  await vault.create(PASSWORD)
  for (let i = 0; i < 3; i++) {
    await vault.mutate((d) => d.connections.push(sampleConnection()))
  }
  const highCounter = readVaultFile().counter!
  assert.ok(highCounter >= 4)
  vault.lock()

  // The old profile as a sibling: `dir` is .../cw-vault-xxx, so 'putty-ui' is next.
  const legacyDir = path.join(path.dirname(dir), 'putty-ui')
  fs.mkdirSync(legacyDir, { recursive: true })
  madeDirs.push(legacyDir)
  fs.copyFileSync(vaultPath(), path.join(legacyDir, 'vault.enc'))

  fs.rmSync(vaultPath())
  assert.ok(fs.existsSync(guardPath()), 'precondition: the anchor is still here')

  const from = await migrateLegacyProfile(['putty-ui'])
  assert.equal(from, legacyDir, 'the migration must have happened')
  assert.ok(!fs.existsSync(guardPath()), 'a foreign anchor must not survive the migration')

  await vault.unlock(PASSWORD)
  assert.deepEqual(vault.rollback, { kind: 'unknown' }, 'a migrated vault must not be accused')
})

test('a failed reseal during recovery does not leave the vault open', async () => {
  // `adopt()` makes isUnlocked() true before the reseal, so a reseal that then
  // fails leaves the renderer on the lock screen while SSH and MCP -- both gated
  // on isUnlocked() -- see an open vault with no auto-lock behind it.
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  vault.lock()

  fs.mkdirSync(vaultPath() + '.tmp')
  await assert.rejects(
    () => vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD),
    'a blocked recovery reported success'
  )
  assert.equal(vault.isUnlocked(), false, 'a failed recovery left the vault unlocked')
  fs.rmSync(vaultPath() + '.tmp', { recursive: true, force: true })

  await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(vault.isUnlocked(), true, 'the one chance at recovery was burned')
})

test('recovery hands back a new key, because the rotation retires the one just used', async () => {
  // Recovery rotates the DEK, so the key just used stops working: a caller that
  // does not show what comes back leaves the user with no way in.
  fresh()
  const first = await vault.create(PASSWORD)
  vault.lock()

  const second = await vault.unlockWithRecovery(first, OTHER_PASSWORD)
  assert.notEqual(second, first, 'recovery must return a key other than the one just used')
  assert.match(second, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){5}$/, 'and a usable one, not an empty string')

  vault.lock()
  await assert.rejects(
    () => vault.unlockWithRecovery(first, THIRD_PASSWORD),
    'the old key must stop working after the rotation'
  )
  vault.lock()
  await vault.unlockWithRecovery(second, THIRD_PASSWORD)
  assert.equal(vault.isUnlocked(), true, 'the new key must work')
})

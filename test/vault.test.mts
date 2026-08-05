// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Trezor — obálkové šifrování, obnovovací klíč a rotace datového klíče.
 *
 * Vault crypto: envelope encryption, the recovery key, and DEK rotation.
 *
 * The vault is a module-level singleton that reads its directory from
 * Electron's `userData` path on *every* file access, so pointing the stub at a
 * mutable variable is enough to give each test its own vault. `fresh()` also
 * locks the singleton, otherwise in-memory state from the previous test would
 * leak into the next one and make assertions pass for the wrong reason.
 *
 * Several tests deliberately reach into the vault file on disk. That is not
 * testing the implementation for its own sake — it is the attacker's view.
 * The whole point of DEK rotation is that a wrap captured before a revocation
 * is worthless afterwards, and the only way to assert that is to splice the
 * revoked wrap back in and confirm it no longer yields readable content.
 */

import { test, mock, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { randomBytes, scrypt, createCipheriv } from 'node:crypto'
import { promisify } from 'node:util'

let dir = ''
const madeDirs: string[] = []

mock.module('electron', { exports: { app: { getPath: () => dir } } })

const { vault, generateRecoveryKey, normalizeRecoveryKey } = await import('../src/main/vault.ts')

/* ------------------------------------------------------------------ nářadí */

const PASSWORD = 'correct-horse-battery'
const OTHER_PASSWORD = 'staple-battery-horse'
const THIRD_PASSWORD = 'battery-staple-horse'

/** Fresh directory + locked singleton, so no two tests share a vault. */
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
 * Asserts the call rejects with an AppError carrying `key`.
 *
 * Matching on the key rather than the message keeps the tests independent of
 * the display language, and pins down *which* failure happened — several of
 * these paths have more than one way to go wrong and only one of them proves
 * the security property.
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

/** The synchronous twin of `rejectsWithKey`, for `read()` and the key parsers. */
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
 * Puts recognisable content in the vault. The `mutate` also produces a
 * `vault.enc.bak`, which the backup assertions need in order to be able to
 * fail — `persist()` only makes a backup when a vault file is already there,
 * so straight after `create()` there is nothing to destroy.
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

/** The recognisable content, as it must read back after any round trip. */
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
 * Builds a version-1 vault file by hand — key derived straight from the
 * password, no DEK, no wraps. This is the format on the disk of anyone who
 * installed an early build; the migration runs exactly once on their machine
 * and there is no second attempt if it goes wrong.
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

after(() => {
  vault.lock()
  for (const made of madeDirs) fs.rmSync(made, { recursive: true, force: true })
})

/* -------------------------------------------------------- základní provoz */

test('a vault survives create → lock → unlock with every field intact', async () => {
  fresh()
  const recoveryKey = await vault.create(PASSWORD)
  assert.equal(typeof recoveryKey, 'string', 'create() must hand back a recovery key')
  await seed()
  // Compared as JSON because that is what actually goes through the cipher;
  // an own property whose value is `undefined` is not a difference the vault
  // could ever preserve.
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

test('create() rejects a password below the eight character floor and writes nothing', async () => {
  fresh()
  await rejectsWithKey(() => vault.create('7chars!'), 'error.passwordTooShort', 'seven characters')
  assert.equal(vault.exists(), false, 'a rejected create() still left a vault file behind')
  await rejectsWithKey(() => vault.create(''), 'error.passwordTooShort', 'empty password')
  assert.equal(vault.exists(), false, 'an empty password still created a vault')

  // Eight is the documented floor, so eight must be accepted.
  await vault.create('8charact')
  assert.equal(vault.exists(), true, 'an eight character password was refused')
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

/* ---------------------------------------------------- obnovovací klíč: tvar */

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
  // Catches a mask that quietly truncates the alphabet (`& 15` instead of
  // `& 31`), which would halve the entropy without changing the shape.
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

/* --------------------------------------------- obnovovací klíč: normalizace */

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

/* ------------------------------------------------------------ obnova hesla */

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

  // The new password is the one that works now; the old one is gone.
  vault.lock()
  await rejectsWithKey(() => vault.unlock(PASSWORD), 'error.wrongPassword', 'the replaced password')
  await vault.unlock(OTHER_PASSWORD)
  assertSeeded('unlocking with the password set during recovery')

  // The used key must be dead, and not merely because a newer wrap sits in
  // front of it: splicing it back in as the only recovery wrap must still fail.
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

  // Nothing may have rotated, so the very same key must still work.
  const replacement = await vault.unlockWithRecovery(recoveryKey, OTHER_PASSWORD)
  assert.equal(typeof replacement, 'string', 'the recovery key was burned by a rejected attempt')
  assertSeeded('after a recovery rejected for a short password')

  // And the original password must be untouched too.
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

/* ---------------------------------------------------------- rotace klíčů */

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

  // The returned key is the user's only remaining escape hatch. If it does not
  // work, the caller has shown them a useless string.
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

  // The attacker holds the old wrap and the old password. Splicing the wrap
  // into the current file hands them the *old* data key — which must no longer
  // decrypt anything, because changePassword() reseals under a new one.
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

  // The password is unchanged by this operation.
  vault.lock()
  await vault.unlock(PASSWORD)
  assertSeeded('the unchanged password after regenerateRecoveryKey()')

  vault.lock()
  await rejectsWithKey(
    () => vault.unlockWithRecovery(firstKey, OTHER_PASSWORD),
    'error.wrongRecoveryKey',
    'the revoked recovery key'
  )

  // Splice the revoked wrap back in as the only recovery wrap. Before the DEK
  // started rotating this succeeded, and the .bak on disk made it reachable.
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

  // Put the removed wrap back: it must no longer yield a usable data key.
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

/* ------------------------------------------------------- migrace v1 → v2 */

test('a v1 vault migrates to v2 on unlock and keeps its data', async () => {
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
  assert.equal(onDisk.version, 2, 'the file was not rewritten in the v2 format')
  assert.deepEqual(
    onDisk.wraps.map((w) => w.type),
    ['password'],
    'the migrated file should carry exactly one password wrap'
  )

  // The migration runs once and can never be retried, so the migrated file has
  // to be openable on the next launch — that is the part that cannot be undone.
  vault.lock()
  await vault.unlock(PASSWORD)
  assert.equal(
    vault.read().connections[0].password,
    'hunter2-the-real-secret',
    'the migrated vault could not be reopened with the same password'
  )

  // And it must keep behaving like a v2 vault from then on.
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

  // The one chance at migration must still be there.
  await vault.unlock(PASSWORD)
  assert.equal(readVaultFile().version, 2, 'the migration no longer runs after a wrong guess')
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

/* -------------------------------------------------- poškozené soubory */

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

  writeVaultFile({ ...good, version: 3 })
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

  // Flip one bit of the ciphertext, leaving the wraps intact: the password
  // still opens the data key, so only the GCM tag stands between the user and
  // silently altered content.
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
 * KNOWN FAILURE — a bug in `vault.ts`, not in this test.
 *
 * `readFile()` checks `version` and `cipher` but never checks that `wraps` is
 * an array, so a v2 file that lost the field throws
 * `TypeError: Cannot read properties of undefined (reading 'find')` out of
 * `unlock()` instead of a translated error. The user sees a raw stack trace on
 * the unlock screen for a vault that is merely damaged. `hasRecoveryOnDisk()`
 * already guards this with `Array.isArray(file.wraps)`; `readFile()` should do
 * the same and raise `error.vaultCorrupt`.
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

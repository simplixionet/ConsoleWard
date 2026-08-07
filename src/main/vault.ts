// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Encrypted vault, envelope encryption. A random 32-byte data key (DEK)
 * encrypts the contents and is stored once per unlock secret, wrapped under
 * scrypt(secret, salt), so a password change or a recovery only rewraps it.
 *
 * File: { version: 3, cipher, counter, iv, tag, data, wraps: [...] }. The
 * header is readable but not freely editable — `version`, `cipher`, `counter`
 * and every wrap field go into GCM as AAD (see `headerAad`), so swapping,
 * removing or splicing wraps breaks the tag on the body. `counter` rises with
 * every write, but a whole older copy carries a valid, lower one, so the last
 * seen value lives out of band in `vault.guard` (see `vaultGuard.ts`).
 *
 * v1 (key straight from the password, no DEK) and v2 (no header binding) are
 * read and migrated to v3 on unlock.
 */

import { app } from 'electron'
import { randomBytes, randomUUID, scrypt, createCipheriv, createDecipheriv } from 'node:crypto'
import { promisify } from 'node:util'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import type { Connection, KnownHost, Settings, Snippet } from '../shared/types'
import { MIN_PASSWORD_LENGTH } from '../shared/passwordStrength'
import { appError } from './i18n'
import { DEFAULT_SETTINGS } from './settings'
import {
  readAnchorFile,
  removeAnchorFile,
  verdict as guardVerdict,
  writeAnchorFile,
  type GuardSealer,
  type GuardVerdict
} from './vaultGuard'

const scryptAsync = promisify(scrypt) as (
  password: string | Buffer,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number }
) => Promise<Buffer>

const KDF_PARAMS = { N: 1 << 17, r: 8, p: 1, keylen: 32 }
// scrypt needs ~128 * N * r bytes; Node's default 32 MB ceiling is too low for ours.
const MAXMEM = 320 * 1024 * 1024

/**
 * What `assertKdf` accepts. Deliberately **not** derived from `KDF_PARAMS`:
 * raising the cost for new vaults must not lock anyone out of one sealed under
 * the old cost, so this records what was written and may only widen. `maxN` is
 * the largest N that fits in `MAXMEM` (128 * r * (N + p + 2)); raise both.
 */
const KDF_ACCEPTED = { minN: 1 << 17, maxN: 1 << 18, r: 8, p: 1, keylen: 32, minSaltBytes: 16 }

const VAULT_VERSION = 3 as const

/** Penalty after the first wrong password, doubling with each further one. */
const UNLOCK_BASE_DELAY_MS = 250

const UNLOCK_MAX_DELAY_MS = 5_000

type WrapType = 'password' | 'recovery'

interface KdfSpec {
  name: 'scrypt'
  salt: string
  N: number
  r: number
  p: number
  keylen: number
}

interface KeyWrap {
  type: WrapType
  kdf: KdfSpec
  iv: string
  tag: string
  wrapped: string
}

interface VaultFileV1 {
  version: 1
  kdf: KdfSpec
  cipher: 'aes-256-gcm'
  iv: string
  tag: string
  data: string
}

interface VaultFileV2 {
  version: 2
  cipher: 'aes-256-gcm'
  iv: string
  tag: string
  data: string
  wraps: KeyWrap[]
}

interface VaultFileV3 {
  version: 3
  cipher: 'aes-256-gcm'
  /** Rises with every write. AAD protects it; `vaultGuard` compares it. */
  counter: number
  iv: string
  tag: string
  data: string
  wraps: KeyWrap[]
}

export interface VaultData {
  connections: Connection[]
  knownHosts: KnownHost[]
  snippets: Snippet[]
  settings: Settings
  /** Bearer token for the local MCP server. */
  mcpToken?: string
  /** Encrypted along with the rest of the vault; reserved for phase 2. */
  aiApiKey?: string
}

function emptyData(): VaultData {
  return { connections: [], knownHosts: [], snippets: [], settings: { ...DEFAULT_SETTINGS } }
}

/** Fills in missing collections — vaults from earlier versions may not have them. */
function normalizeData(parsed: Partial<VaultData>): VaultData {
  return {
    connections: parsed.connections ?? [],
    knownHosts: parsed.knownHosts ?? [],
    snippets: parsed.snippets ?? [],
    settings: { ...DEFAULT_SETTINGS, ...(parsed.settings ?? {}) },
    mcpToken: parsed.mcpToken,
    aiApiKey: parsed.aiApiKey
  }
}

/* ----------------------------------------------------------- recovery key */

/** Crockford Base32 – no I, L, O or U, so hand transcription cannot slip. 150 bits. */
const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const RECOVERY_LENGTH = 30
const RECOVERY_GROUP = 5

export function generateRecoveryKey(): string {
  const bytes = randomBytes(RECOVERY_LENGTH)
  let raw = ''
  // 256 = 8 × 32, so masking down to 5 bits stays uniform (no modulo bias).
  for (let i = 0; i < RECOVERY_LENGTH; i++) raw += RECOVERY_ALPHABET[bytes[i] & 31]
  return raw.match(new RegExp(`.{1,${RECOVERY_GROUP}}`, 'g'))!.join('-')
}

/** Canonicalises a key: upper case, no separators, O→0 and I/L→1. */
export function normalizeRecoveryKey(input: string): string {
  const cleaned = String(input ?? '')
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')

  if (cleaned.length !== RECOVERY_LENGTH) {
    throw appError('error.recoveryLength', {
      length: RECOVERY_LENGTH,
      actual: cleaned.length
    })
  }
  for (const ch of cleaned) {
    if (!RECOVERY_ALPHABET.includes(ch)) {
      throw appError('error.recoveryChar', { char: ch })
    }
  }
  return cleaned
}

/* ----------------------------------------------------------- DEK wrapping */

/**
 * Rejects KDF parameters this application did not write. `deriveKek` feeds N,
 * r, p and keylen from the file straight into scrypt, so whoever can write
 * `vault.enc` picks the cost, and `maxmem` bounds neither `keylen` nor `p`
 * usefully — it still admits `p = 196606`, hours of a libuv threadpool thread
 * per unlock. Must run before any key is derived. Not in `openWrap`, because
 * `unlockLegacy` bypasses that and every caller of it rewrites throws into
 * "wrong password", blaming the user for a malformed file.
 */
function assertKdf(kdf: unknown): void {
  const k = (kdf ?? {}) as Record<string, unknown>
  const { name, salt, N, r, p, keylen } = k
  const bad =
    name !== 'scrypt' ||
    typeof salt !== 'string' ||
    typeof N !== 'number' ||
    !Number.isInteger(N) ||
    N < KDF_ACCEPTED.minN ||
    N > KDF_ACCEPTED.maxN ||
    (N & (N - 1)) !== 0 ||
    r !== KDF_ACCEPTED.r ||
    p !== KDF_ACCEPTED.p ||
    keylen !== KDF_ACCEPTED.keylen ||
    // The field is base64, so the string length says nothing about the entropy.
    Buffer.from(salt, 'base64').length < KDF_ACCEPTED.minSaltBytes
  if (bad) throw appError('error.vaultCorrupt')
}

async function deriveKek(secret: string, salt: Buffer, kdf?: KdfSpec): Promise<Buffer> {
  const params = kdf ?? { ...KDF_PARAMS, name: 'scrypt' as const, salt: '' }
  return scryptAsync(secret, salt, params.keylen ?? KDF_PARAMS.keylen, {
    N: params.N ?? KDF_PARAMS.N,
    r: params.r ?? KDF_PARAMS.r,
    p: params.p ?? KDF_PARAMS.p,
    maxmem: MAXMEM
  })
}

async function makeWrap(type: WrapType, secret: string, dek: Buffer): Promise<KeyWrap> {
  const salt = randomBytes(32)
  const kek = await deriveKek(secret, salt)
  try {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', kek, iv)
    const wrapped = Buffer.concat([cipher.update(dek), cipher.final()])
    return {
      type,
      kdf: {
        name: 'scrypt',
        salt: salt.toString('base64'),
        N: KDF_PARAMS.N,
        r: KDF_PARAMS.r,
        p: KDF_PARAMS.p,
        keylen: KDF_PARAMS.keylen
      },
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      wrapped: wrapped.toString('base64')
    }
  } finally {
    kek.fill(0)
  }
}

/** Unwraps the DEK. Throws if the secret is wrong — the GCM tag decides. */
async function openWrap(wrap: KeyWrap, secret: string): Promise<Buffer> {
  const salt = Buffer.from(wrap.kdf.salt, 'base64')
  const kek = await deriveKek(secret, salt, wrap.kdf)
  try {
    const decipher = createDecipheriv('aes-256-gcm', kek, Buffer.from(wrap.iv, 'base64'))
    decipher.setAuthTag(Buffer.from(wrap.tag, 'base64'))
    return Buffer.concat([
      decipher.update(Buffer.from(wrap.wrapped, 'base64')),
      decipher.final()
    ])
  } finally {
    kek.fill(0)
  }
}

/* --------------------------------------------- authenticated header (AAD) */

/**
 * Domain prefix: without it another format could produce the same bytes and the
 * tag would authenticate a header nobody intended. The trailing number versions
 * the *encoding*, not the file — change the field order, change it too.
 */
const AAD_MAGIC = Buffer.from('consoleward.vault.aad.1', 'ascii')

/** `length || body`. The framing is the only thing stopping `ab|c` reading as `a|bc`. */
function frame(value: string): Buffer {
  const body = Buffer.from(value, 'utf8')
  const header = Buffer.alloc(4)
  header.writeUInt32BE(body.length)
  return Buffer.concat([header, body])
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
 * Canonical header form, bound to the body through `setAAD()`. Covers
 * `version`, `cipher`, `counter` and **every** field of **every** wrap, in file
 * order; GCM already covers the body's `iv`, `tag` and `data`.
 *
 * Not `JSON.stringify`: key order is the writer's choice, so a reformatted file
 * would yield different AAD and stop opening. Here the field order is fixed,
 * every variable-length run is length-prefixed and the wrap count precedes the
 * wraps, so no two distinct headers share the same bytes. Wraps get no AAD of
 * their own — it would be circular, and rebuilding a recovery wrap would need
 * the plaintext recovery key, which is stored nowhere.
 */
function headerAad(header: {
  version: number
  cipher: string
  counter: number
  wraps: KeyWrap[]
}): Buffer {
  const parts: Buffer[] = [
    AAD_MAGIC,
    u32(header.version),
    frame(header.cipher),
    u64(header.counter),
    u32(header.wraps.length)
  ]
  for (const w of header.wraps) {
    parts.push(
      frame(w.type),
      frame(w.kdf.name),
      frame(w.kdf.salt),
      u32(w.kdf.N),
      u32(w.kdf.r),
      u32(w.kdf.p),
      u32(w.kdf.keylen),
      frame(w.iv),
      frame(w.tag),
      frame(w.wrapped)
    )
  }
  return Buffer.concat(parts)
}

/**
 * Verifies a v3 header can be encoded into AAD at all (`assertKdf` covers the
 * KDF fields earlier). Without it, `writeBigUInt64BE(BigInt(1.5))` or
 * `Buffer.from(null)` drops a raw RangeError on the unlock screen instead of a
 * translated message.
 */
function assertHeaderShape(file: VaultFileV3): void {
  if (!Number.isSafeInteger(file.counter) || file.counter < 0) {
    throw appError('error.vaultCorrupt')
  }
  for (const w of file.wraps) {
    const ok =
      typeof w?.type === 'string' &&
      typeof w.iv === 'string' &&
      typeof w.tag === 'string' &&
      typeof w.wrapped === 'string'
    if (!ok) throw appError('error.vaultCorrupt')
  }
}

/* ------------------------------------------------------------------ vault */

/**
 * The state on a machine with no platform keychain. `seal` and `open` throw on
 * purpose: returning the input unchanged would make the anchor look sealed when
 * it is not. Unavailability is reported through `available()`, never silently.
 */
const NO_SEALER: GuardSealer = {
  available: () => false,
  seal: () => {
    throw new Error('vault: no guard sealer installed')
  },
  open: () => {
    throw new Error('vault: no guard sealer installed')
  }
}

class Vault {
  private dek: Buffer | null = null
  private wraps: KeyWrap[] = []
  private data: VaultData | null = null
  /** Last write number seen or written. Zero means none yet. */
  private counter = 0
  /** Tail of the write queue; see `enqueueWrite`. */
  private writes: Promise<unknown> = Promise.resolve()
  /** Consecutive failed unlock attempts; see `awaitUnlockSlot`. */
  private failedUnlocks = 0
  /** Tail of the unlock attempt queue; see `awaitUnlockSlot`. */
  private unlocks: Promise<unknown> = Promise.resolve()

  /**
   * Installed by `index.ts`: importing `safeStorage` here would break tests that
   * stub only `app` out of Electron. The "none" default is also Linux without a
   * keyring — the anchor is then written in the clear and says so.
   */
  private sealer: GuardSealer = NO_SEALER

  /** Verdict from the last anchor. Meaningful only after unlock; `lock()` clears it. */
  private guard: GuardVerdict = { kind: 'unknown' }

  get filePath(): string {
    return path.join(app.getPath('userData'), 'vault.enc')
  }

  private get backupPath(): string {
    return this.filePath + '.bak'
  }

  /** The anchor is a sibling of the vault, not a suffix — a profile copy takes both. */
  private get guardPath(): string {
    return path.join(app.getPath('userData'), 'vault.guard')
  }

  installGuardSealer(sealer: GuardSealer): void {
    this.sealer = sealer
  }

  /**
   * `unknown` until an unlock succeeds — judging a file that could not be
   * decrypted would mean warning on every password typo.
   */
  get rollback(): GuardVerdict {
    return this.guard
  }

  exists(): boolean {
    return fs.existsSync(this.filePath)
  }

  isUnlocked(): boolean {
    return this.dek !== null && this.data !== null
  }

  hasRecoveryKey(): boolean {
    return this.wraps.some((w) => w.type === 'recovery')
  }

  /** Reads it out of the file header, so it works on a locked vault too. */
  async hasRecoveryOnDisk(): Promise<boolean> {
    if (!this.exists()) return false
    try {
      const file = JSON.parse(await fsp.readFile(this.filePath, 'utf8')) as
        | VaultFileV2
        | VaultFileV3
      return Array.isArray(file.wraps) && file.wraps.some((w) => w.type === 'recovery')
    } catch {
      return false
    }
  }

  /** Returns the recovery key generated for the new vault. */
  async create(masterPassword: string): Promise<string> {
    if (this.exists()) throw appError('error.vaultExists')
    validatePassword(masterPassword)

    const dek = randomBytes(32)
    const recoveryKey = generateRecoveryKey()

    this.dek = dek
    this.data = emptyData()
    this.counter = 0
    /*
     * A new vault: an anchor from a previous one at this path would report a
     * rollback after every delete-and-recreate. `persist` overwrites it below.
     */
    this.guard = { kind: 'unknown' }
    this.wraps = [
      await makeWrap('password', masterPassword, dek),
      await makeWrap('recovery', normalizeRecoveryKey(recoveryKey), dek)
    ]
    // The assignments above already made `isUnlocked()` true, so a failed write
    // would leave the main process holding an open vault behind an error screen,
    // and the caller would never receive the recovery key for it.
    try {
      await this.persist(this.data!)
    } catch (err) {
      this.lock()
      throw err
    }
    return recoveryKey
  }

  async unlock(masterPassword: string): Promise<void> {
    return this.enqueueUnlock(() => this.attemptUnlock(masterPassword))
  }

  private async attemptUnlock(masterPassword: string): Promise<void> {
    await this.awaitUnlockSlot()
    const file = await this.readFile()

    if (file.version === 1) {
      await this.unlockLegacy(file, masterPassword)
      return
    }

    const wrap = file.wraps.find((w) => w.type === 'password')
    if (!wrap) throw appError('error.noPasswordSet')

    let dek: Buffer
    try {
      dek = await openWrap(wrap, masterPassword)
    } catch {
      this.failedUnlocks += 1
      throw appError('error.wrongPassword')
    }
    this.failedUnlocks = 0
    this.adopt(file, dek)
    /*
     * Before the migration below, or its own write overwrites the verdict. Zero
     * for v2 is correct, not a fallback: the anchor first appears with a v3
     * write, so a v2 file next to an anchor is the descent being looked for.
     */
    this.guard = await this.readAnchor(this.counter)

    // v2 → v3: only the body changes, resealed with AAD over the header. The DEK
    // and wraps stay, because rebuilding the recovery wrap would need the
    // plaintext recovery key, which is stored nowhere. A failed write must lock —
    // `adopt()` has already set `dek`, `wraps` and `data`, so `isUnlocked()`
    // would stay true behind the lock screen, and SSH and MCP both hang on it.
    if (file.version === 2) {
      try {
        await this.persist(this.data!)
      } catch (err) {
        this.lock()
        throw err
      }
      await this.dropBackupAfterMigration()
    }
  }

  /** Unlocks with the recovery key and sets a new master password in one step. */
  async unlockWithRecovery(recoveryKey: string, newPassword: string): Promise<string> {
    const normalized = normalizeRecoveryKey(recoveryKey)
    validatePassword(newPassword)

    const file = await this.readFile()
    if (file.version === 1) {
      throw appError('error.legacyNoRecovery')
    }

    const wrap = file.wraps.find((w) => w.type === 'recovery')
    if (!wrap) throw appError('error.noRecoverySet')

    let dek: Buffer
    try {
      dek = await openWrap(wrap, normalized)
    } catch {
      throw appError('error.wrongRecoveryKey')
    }

    this.adopt(file, dek)
    /*
     * Before `reseal` below, and required: recovery would otherwise be the one
     * way into the vault that skips the anchor.
     */
    this.guard = await this.readAnchor(this.counter)
    validatePassword(newPassword)

    // Recovery answers compromise, so it rotates the DEK: the key just used dies.
    const freshRecoveryKey = generateRecoveryKey()
    /*
     * As in `create()`: `adopt()` already made `isUnlocked()` true, so a failed
     * `reseal` leaves an open vault behind the lock screen, un-auto-locked.
     */
    try {
      await this.reseal([
        { type: 'password', secret: newPassword },
        { type: 'recovery', secret: normalizeRecoveryKey(freshRecoveryKey) }
      ])
    } catch (err) {
      this.lock()
      throw err
    }
    return freshRecoveryKey
  }

  lock(): void {
    this.dek?.fill(0)
    this.dek = null
    this.data = null
    this.wraps = []
    this.counter = 0
    // Belongs to the file that was open; otherwise a warning about the previous
    // vault would light up after unlocking a different one.
    this.guard = { kind: 'unknown' }
  }

  /**
   * Changes the master password and **rotates the data key**. Returns a new
   * recovery key if the vault had one — rotation forces that, since rebuilding
   * the old recovery wrap would need the plaintext recovery key. The caller
   * **must** show it to the user; discarding it silently costs them the only way
   * back from a forgotten password.
   */
  async changePassword(oldPw: string, newPw: string): Promise<string | null> {
    this.requireUnlocked()
    const wrap = this.wraps.find((w) => w.type === 'password')
    if (!wrap) throw appError('error.noPasswordSet')

    try {
      const check = await openWrap(wrap, oldPw)
      check.fill(0)
    } catch {
      throw appError('error.wrongOldPassword')
    }

    validatePassword(newPw)

    const hadRecovery = this.wraps.some((w) => w.type === 'recovery')
    const recoveryKey = hadRecovery ? generateRecoveryKey() : null

    const secrets: Array<{ type: KeyWrap['type']; secret: string }> = [
      { type: 'password', secret: newPw }
    ]
    if (recoveryKey) {
      secrets.push({ type: 'recovery', secret: normalizeRecoveryKey(recoveryKey) })
    }

    await this.reseal(secrets)
    return recoveryKey
  }

  /** Issues a new recovery key. `reseal` rotates the DEK, so the old one stops working. */
  async regenerateRecoveryKey(password: string): Promise<string> {
    this.requireUnlocked()
    const wrap = this.wraps.find((w) => w.type === 'password')
    if (!wrap) throw appError('error.noPasswordSet')

    // Required, and not only because the rotation needs it to build the new
    // password wrap: without a check, two minutes at an unlocked session yields
    // a 150-bit key that opens the vault forever and can be copied out.
    try {
      const check = await openWrap(wrap, password)
      check.fill(0)
    } catch {
      throw appError('error.wrongPassword')
    }

    const recoveryKey = generateRecoveryKey()
    await this.reseal([
      { type: 'password', secret: password },
      { type: 'recovery', secret: normalizeRecoveryKey(recoveryKey) }
    ])
    return recoveryKey
  }

  /** Removes the recovery option, rotating the DEK so the revoked key really dies. */
  async removeRecoveryKey(password: string): Promise<void> {
    this.requireUnlocked()
    const wrap = this.wraps.find((w) => w.type === 'password')
    // Unreachable today: every path to an unlocked vault installs a password
    // wrap. Kept as an invariant assertion — if that ever changes, this is a
    // translated message rather than a TypeError in the middle of a rotation.
    if (!wrap) throw appError('error.lastUnlockMethod')

    try {
      const check = await openWrap(wrap, password)
      check.fill(0)
    } catch {
      throw appError('error.wrongPassword')
    }

    await this.reseal([{ type: 'password', secret: password }])
  }

  read(): VaultData {
    this.requireUnlocked()
    return this.data!
  }

  /**
   * Applies a change to the data and stores it. The change runs on a **copy**
   * and only lands in `this.data` after the write succeeds, so a failed write
   * never leaves memory holding state that is not on disk — the bug that let
   * `verifyHostKey` report an error and still trust the fingerprint for the rest
   * of the run.
   */
  async mutate<T>(fn: (data: VaultData) => T): Promise<T> {
    this.requireUnlocked()
    return this.enqueueWrite(async () => {
      // Again: the vault can be locked between queueing and running.
      this.requireUnlocked()
      const draft = structuredClone(this.data!)
      const result = fn(draft)
      await this.writeSealed(draft)
      // `writeSealed` awaits four filesystem calls and `lock()` is synchronous,
      // so a lock can land mid-write. This does NOT reopen the vault (`dek` is
      // still null); it reattaches the decrypted `VaultData`, and dropping that
      // object is half of what `lock()` is for. Disk is correct either way, so
      // there is nothing to roll back — only a state not to restore.
      if (this.dek === null) throw appError('error.vaultLocked')
      this.data = draft
      return result
    })
  }

  /**
   * One unlock attempt at a time, whatever the caller does. The delay alone is
   * not a throttle: `ipcMain.handle` runs handlers concurrently, so parallel
   * calls read the same `failedUnlocks`, sleep together and reach scrypt
   * together — many guesses for the price of one. Serialising the WHOLE attempt
   * (wait, derivation, counter update) is what makes the penalty compound.
   * Errors are swallowed into the tail so one rejection cannot stall the queue.
   */
  private enqueueUnlock<T>(attempt: () => Promise<T>): Promise<T> {
    const done = this.unlocks.then(attempt, attempt)
    this.unlocks = done.then(
      () => undefined,
      () => undefined
    )
    return done
  }

  /**
   * Waits out the penalty earned by previous wrong passwords. scrypt alone only
   * bounds guessing at the IPC channel to roughly six a second, and that channel
   * is reachable from the lock screen with no secret at all. Deliberately in
   * memory, not in the file: a persisted count would let an attacker lock the
   * owner out by editing it. Resets on success — and `lock()` deliberately does
   * NOT reset it, or the way past the throttle would be to lock and retry.
   */
  private async awaitUnlockSlot(): Promise<void> {
    if (this.failedUnlocks === 0) return
    const delay = Math.min(UNLOCK_MAX_DELAY_MS, UNLOCK_BASE_DELAY_MS * 2 ** (this.failedUnlocks - 1))
    await new Promise((resolve) => setTimeout(resolve, delay))
  }

  /* ------------------------------------------------------------ internals */

  private async readFile(): Promise<VaultFileV1 | VaultFileV2 | VaultFileV3> {
    if (!this.exists()) throw appError('error.vaultMissing')
    const raw = await fsp.readFile(this.filePath, 'utf8')
    let file: VaultFileV1 | VaultFileV2 | VaultFileV3
    try {
      file = JSON.parse(raw)
    } catch {
      throw appError('error.vaultCorrupt')
    }
    if (
      file.cipher !== 'aes-256-gcm' ||
      (file.version !== 1 && file.version !== 2 && file.version !== 3)
    ) {
      throw appError('error.vaultUnsupported')
    }
    // Without this a corrupt file reaches `wraps.find(...)` and puts a raw
    // TypeError on the unlock screen. An empty array is legitimate.
    if (file.version !== 1 && !Array.isArray((file as VaultFileV2 | VaultFileV3).wraps)) {
      throw appError('error.vaultCorrupt')
    }
    // The one place where file bytes become KDF parameters, and the last moment
    // before a key is derived from them. Wraps in memory came from `makeWrap()`
    // or from here, which is why `openWrap()` does not repeat the check.
    if (file.version === 1) {
      assertKdf(file.kdf)
    } else {
      for (const wrap of file.wraps) assertKdf(wrap?.kdf)
    }
    // The v3 header goes into AAD, so anything unencodable must not get past here.
    if (file.version === 3) assertHeaderShape(file)
    return file
  }

  /**
   * Decrypts the body with the DEK and takes the state into memory. In v3 the
   * AAD binding makes any header edit fail the tag; v2 has none and cannot,
   * which is why `version` is itself in the AAD — rewriting a v3 header to
   * `version: 2` to skip AAD ends in `error.decryptFailed`.
   */
  private adopt(file: VaultFileV2 | VaultFileV3, dek: Buffer): void {
    let plaintext: string
    try {
      const decipher = createDecipheriv('aes-256-gcm', dek, Buffer.from(file.iv, 'base64'))
      if (file.version === 3) decipher.setAAD(headerAad(file))
      decipher.setAuthTag(Buffer.from(file.tag, 'base64'))
      plaintext = Buffer.concat([
        decipher.update(Buffer.from(file.data, 'base64')),
        decipher.final()
      ]).toString('utf8')
    } catch {
      dek.fill(0)
      throw appError('error.decryptFailed')
    }

    this.dek = dek
    this.wraps = file.wraps
    // v2 has no counter; there is nothing to continue from until the first v3 write.
    this.counter = file.version === 3 ? file.counter : 0
    this.data = normalizeData(JSON.parse(plaintext) as Partial<VaultData>)
  }

  private async unlockLegacy(file: VaultFileV1, masterPassword: string): Promise<void> {
    const salt = Buffer.from(file.kdf.salt, 'base64')
    const key = await deriveKek(masterPassword, salt, file.kdf)

    let plaintext: string
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(file.iv, 'base64'))
      decipher.setAuthTag(Buffer.from(file.tag, 'base64'))
      plaintext = Buffer.concat([
        decipher.update(Buffer.from(file.data, 'base64')),
        decipher.final()
      ]).toString('utf8')
    } catch {
      // Counted here too, or v1 gets no throttle at all: it only migrates on a
      // SUCCESSFUL unlock, so it stays v1 for as long as somebody is guessing.
      // `unlock` increments on the v2/v3 path and this branch returns first.
      this.failedUnlocks += 1
      throw appError('error.wrongPassword')
    } finally {
      key.fill(0)
    }

    this.failedUnlocks = 0
    this.dek = randomBytes(32)
    this.data = normalizeData(JSON.parse(plaintext) as Partial<VaultData>)
    this.counter = 0
    // As with v2: an anchor next to a v1 file means a descent, not an antique.
    // Before `persist` below, because that overwrites the anchor.
    this.guard = await this.readAnchor(0)
    this.wraps = [await makeWrap('password', masterPassword, this.dek)]
    // As in the v2 branch: without this a v1 user on a read-only profile gets an
    // error, the lock screen, and an unlocked vault behind it.
    try {
      await this.persist(this.data!)
    } catch (err) {
      this.lock()
      throw err
    }
    await this.dropBackupAfterMigration()
  }

  private requireUnlocked(): void {
    if (!this.isUnlocked()) throw appError('error.vaultLocked')
  }

  /**
   * For the SSH IPC handlers — sessions live in the main process, so without
   * this a locked app keeps writing to the remote shell.
   */
  requireUnlockedPublic(): void {
    this.requireUnlocked()
  }

  /**
   * Reseals the vault under a **new** data key. This is what makes revocation
   * real: swapping a wrap alone leaves `.bak` holding a copy the old secret
   * opens, yielding the same DEK that decrypts every *future* version too.
   *
   * 1. **Nothing is assigned to the instance until every wrap is built**, or a
   *    failed scrypt leaves a vault with no password wrap and the next write
   *    commits that to disk.
   * 2. **A failed `persist()` rolls the state back**, or the DEK in memory stops
   *    matching the file on disk.
   */
  private async reseal(secrets: Array<{ type: KeyWrap['type']; secret: string }>): Promise<void> {
    if (!secrets.some((s) => s.type === 'password')) {
      throw appError('error.noUnlockMethod')
    }

    const newDek = randomBytes(32)
    let built: KeyWrap[]
    try {
      built = []
      for (const s of secrets) built.push(await makeWrap(s.type, s.secret, newDek))
    } catch (err) {
      newDek.fill(0)
      throw err
    }

    const prevDek = this.dek
    const prevWraps = this.wraps
    this.dek = newDek
    this.wraps = built

    try {
      await this.persist(this.data!)
    } catch (err) {
      this.dek = prevDek
      this.wraps = prevWraps
      newDek.fill(0)
      throw err
    }

    prevDek?.fill(0)
    await this.destroyBackup()
  }

  /**
   * `unlink` alone is not enough: the content stays on disk until something
   * overwrites it, and after a rotation `.bak` holds the old wrap and contents.
   * The overwrite proves nothing on a wear-levelling SSD or a copy-on-write
   * filesystem, but it beats leaving the file lying there.
   */
  private async destroyBackup(): Promise<void> {
    try {
      const stat = await fsp.stat(this.backupPath)
      await fsp.writeFile(this.backupPath, randomBytes(stat.size))
      await fsp.rm(this.backupPath, { force: true })
    } catch {
      // No backup, or something else holds it. The rotation does not fail over this.
    }
  }

  /**
   * Drops the pre-migration backup, but only after reading the new file back and
   * decrypting it. `.bak` otherwise keeps the vault in the OLD format under the
   * SAME secrets — for v2, a copy with no AAD and no counter, a ready-made
   * target for the rollback the guard exists to detect. Verifying first keeps the
   * safety net at the one moment a format change needs it; on failure it stays.
   */
  private async dropBackupAfterMigration(): Promise<void> {
    try {
      const written = await this.readFile()
      if (written.version !== VAULT_VERSION || !this.dek) return
      const decipher = createDecipheriv('aes-256-gcm', this.dek, Buffer.from(written.iv, 'base64'))
      decipher.setAAD(headerAad(written))
      decipher.setAuthTag(Buffer.from(written.tag, 'base64'))
      Buffer.concat([decipher.update(Buffer.from(written.data, 'base64')), decipher.final()])
    } catch {
      return
    }
    await this.destroyBackup()
  }

  /**
   * Queues a write behind all previous ones, however they ended. One file, one
   * `.tmp`, one counter: concurrent writes clobber `.tmp` and produce two bodies
   * with the same number, and `mutate()` would clone both drafts from the same
   * state, so the second would discard the first.
   */
  private enqueueWrite<T>(job: () => Promise<T>): Promise<T> {
    const done = this.writes.then(job, job)
    // Swallowed only here so it cannot stall the queue; the caller gets it in `done`.
    this.writes = done.then(
      () => undefined,
      () => undefined
    )
    return done
  }

  /** Writes outside `mutate()` — creation, migration, reseal. */
  private async persist(data: VaultData): Promise<void> {
    return this.enqueueWrite(() => this.writeSealed(data))
  }

  /** Seals `data` and swaps it in atomically. Called **only from the write queue**. */
  private async writeSealed(data: VaultData): Promise<void> {
    if (!this.dek) throw appError('error.vaultLocked')
    if (this.wraps.length === 0) throw appError('error.noUnlockMethod')

    // AAD only protects the counter here; `recordAnchor` stores it after the rename.
    const counter = this.counter + 1
    if (!Number.isSafeInteger(counter)) throw appError('error.vaultCorrupt')

    const iv = randomBytes(12)
    const aad = headerAad({
      version: VAULT_VERSION,
      cipher: 'aes-256-gcm',
      counter,
      wraps: this.wraps
    })
    const cipher = createCipheriv('aes-256-gcm', this.dek, iv)
    cipher.setAAD(aad)
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(data), 'utf8')),
      cipher.final()
    ])

    const file: VaultFileV3 = {
      version: VAULT_VERSION,
      cipher: 'aes-256-gcm',
      counter,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: ciphertext.toString('base64'),
      wraps: this.wraps
    }

    await fsp.mkdir(path.dirname(this.filePath), { recursive: true })
    // So an interrupted write cannot destroy the previous version.
    if (fs.existsSync(this.filePath)) {
      await fsp.copyFile(this.filePath, this.backupPath).catch(() => {})
    }
    const tmp = this.filePath + '.tmp'
    await fsp.writeFile(tmp, JSON.stringify(file), { encoding: 'utf8', mode: 0o600 })
    await fsp.rename(tmp, this.filePath)
    // Only after a successful rename, or memory would claim a higher number than
    // the file holds and the next write would leave a gap in the sequence.
    this.counter = counter
    await this.recordAnchor(counter)
  }

  /**
   * Compares the anchor with the counter from the header. Missing and unreadable
   * both give `unknown`, so neither warns. An unreadable anchor is overwritten by
   * the next write: whoever can corrupt it can delete it, so refusing to write
   * would only turn one corruption into permanently disabled detection.
   */
  private async readAnchor(fileCounter: number): Promise<GuardVerdict> {
    const read = await readAnchorFile(this.guardPath, this.sealer)
    if (read.kind === 'ok') return guardVerdict(read.anchor, fileCounter)
    if (read.kind === 'unreadable') {
      console.warn('vault: rollback anchor is unreadable:', read.reason)
    }
    return { kind: 'unknown' }
  }

  /**
   * **Only after a successful `rename`, never before.** An anchor written first
   * would claim the file is older than it is after every unclean shutdown, and a
   * warning that cries wolf gets clicked away blind.
   *
   * Failures are swallowed: the vault is **already written**, so throwing would
   * have the caller roll back over something that succeeded. Detection then
   * silently stops on an unwritable profile, hence the log line.
   */
  private async recordAnchor(counter: number): Promise<void> {
    try {
      await writeAnchorFile(this.guardPath, counter, Date.now(), this.sealer)
    } catch (err) {
      console.warn('vault: could not update the rollback anchor:', (err as Error).message)
    }
  }
}

/**
 * Length only — the strength estimate next to it drives the meter, not a gate.
 * Never reached from `unlock`, so raising the floor cannot lock anyone out of a
 * vault they already have.
 */
function validatePassword(pw: string): void {
  if (typeof pw !== 'string' || pw.length < MIN_PASSWORD_LENGTH) {
    throw appError('error.passwordTooShort', { length: MIN_PASSWORD_LENGTH })
  }
}

/**
 * Brings the vault over from the profile directory of an earlier app name:
 * Electron derives that path from `productName`, so a rename otherwise looks
 * like losing every saved connection. Copies rather than moves.
 */
export async function migrateLegacyProfile(legacyNames: string[]): Promise<string | null> {
  if (vault.exists()) return null

  const currentDir = path.dirname(vault.filePath)
  const parent = path.dirname(currentDir)

  for (const name of legacyNames) {
    const legacyDir = path.join(parent, name)
    const legacyVault = path.join(legacyDir, 'vault.enc')
    if (legacyDir === currentDir || !fs.existsSync(legacyVault)) continue

    await fsp.mkdir(currentDir, { recursive: true })
    await fsp.copyFile(legacyVault, vault.filePath)
    const legacyBackup = legacyVault + '.bak'
    if (fs.existsSync(legacyBackup)) {
      await fsp.copyFile(legacyBackup, vault.filePath + '.bak').catch(() => {})
    }
    /*
     * The anchor belongs to the file, not the directory: deleting a vault and
     * leaving `vault.guard` behind would make the freshly copied file report a
     * rollback against a counter that was never its own.
     */
    await removeAnchorFile(path.join(currentDir, 'vault.guard')).catch(() => {})
    return legacyDir
  }
  return null
}

export function newId(): string {
  return randomUUID()
}

export const vault = new Vault()

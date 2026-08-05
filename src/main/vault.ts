// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Šifrovaný trezor s obálkovým šifrováním (envelope encryption).
 *
 * Obsah trezoru šifruje náhodný **datový klíč (DEK)**, 32 B z CSPRNG.
 * Ten je v souboru uložený vícekrát – pokaždé zabalený jiným klíčem:
 *
 *   wrap[password] = AES-GCM(DEK, scrypt(hlavní heslo, salt₁))
 *   wrap[recovery] = AES-GCM(DEK, scrypt(obnovovací klíč, salt₂))
 *
 * Odemknout jde kterýmkoli z nich. Díky tomu:
 *  - změna hesla i obnova jen přebalí DEK, obsah se nešifruje znovu
 *  - zapomenuté heslo lze resetovat obnovovacím klíčem
 *
 * Formát souboru (JSON, čitelná hlavička + zašifrovaný obsah):
 *   { version: 2, cipher, iv, tag, data, wraps: [...] }
 *
 * Verze 1 (klíč odvozený přímo z hesla) se při odemčení automaticky převede na verzi 2.
 */

import { app } from 'electron'
import { randomBytes, randomUUID, scrypt, createCipheriv, createDecipheriv } from 'node:crypto'
import { promisify } from 'node:util'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import type { Connection, KnownHost, Settings, Snippet } from '../shared/types'
import { appError } from './i18n'

const scryptAsync = promisify(scrypt) as (
  password: string | Buffer,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number }
) => Promise<Buffer>

const KDF_PARAMS = { N: 1 << 17, r: 8, p: 1, keylen: 32 }
// scrypt potřebuje ~128 * N * r bajtů; Node má výchozí strop 32 MB, zvedáme ho.
const MAXMEM = 320 * 1024 * 1024

/**
 * What `assertKdf` accepts out of a vault file.
 *
 * Deliberately **not** derived from `KDF_PARAMS`. Raising the cost of new
 * vaults must never lock anyone out of a vault sealed under the old cost, so
 * this is the record of what has actually been written, and it only widens.
 * Every version of this project wrote `N = 1 << 17, r = 8, p = 1, keylen = 32`
 * and a 32-byte salt, so the historical set is a single point today.
 *
 * `maxN` is the largest N that fits in `MAXMEM` (128 * r * (N + p + 2)) — raise
 * the two together, or newly written vaults start reading as corrupt.
 */
const KDF_ACCEPTED = { minN: 1 << 17, maxN: 1 << 18, r: 8, p: 1, keylen: 32, minSaltBytes: 16 }

type WrapType = 'password' | 'recovery'

interface KdfSpec {
  name: 'scrypt'
  salt: string
  N: number
  r: number
  p: number
  keylen: number
}

/** Datový klíč zabalený jedním přihlašovacím tajemstvím. */
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

export interface VaultData {
  connections: Connection[]
  knownHosts: KnownHost[]
  snippets: Snippet[]
  settings: Settings
  /** Bearer token pro lokální MCP server. */
  mcpToken?: string
  /** Šifrovaný spolu se zbytkem trezoru; rezervováno pro 2. fázi. */
  aiApiKey?: string
}

export const DEFAULT_SETTINGS: Settings = {
  autoLockMinutes: 15,
  disconnectOnLock: true,
  fontSize: 14,
  scrollback: 5000,
  mcpEnabled: false,
  mcpPort: 7345,
  aiModel: 'claude-opus-5',
  aiEffort: 'high'
}

function emptyData(): VaultData {
  return { connections: [], knownHosts: [], snippets: [], settings: { ...DEFAULT_SETTINGS } }
}

/** Doplní chybějící kolekce – trezory z dřívějších verzí je nemusí mít. */
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

/* ------------------------------------------------------- obnovovací klíč */

/**
 * Crockford Base32 – bez písmen I, L, O a U, aby nešlo splést znaky
 * při ručním přepisu. 30 znaků = 150 bitů entropie.
 */
const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const RECOVERY_LENGTH = 30
const RECOVERY_GROUP = 5

/** Vygeneruje nový obnovovací klíč ve tvaru `XXXXX-XXXXX-…` (6 skupin). */
export function generateRecoveryKey(): string {
  const bytes = randomBytes(RECOVERY_LENGTH)
  let raw = ''
  // 256 = 8 × 32, takže maskování na 5 bitů je rovnoměrné (bez zkreslení).
  for (let i = 0; i < RECOVERY_LENGTH; i++) raw += RECOVERY_ALPHABET[bytes[i] & 31]
  return raw.match(new RegExp(`.{1,${RECOVERY_GROUP}}`, 'g'))!.join('-')
}

/** Sjednotí zápis klíče: velká písmena, bez oddělovačů, záměny O/0 a I/L/1. */
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

/* ------------------------------------------------------------- balení DEK */

/**
 * Rejects KDF parameters that this application did not write.
 *
 * `deriveKek` feeds N, r, p and keylen from the file straight into scrypt, so
 * whoever can write `vault.enc` picks the cost. `maxmem` is a far weaker guard
 * than it looks: it bounds 128 * r * (N + p + 2), which at our N and r still
 * admits `p = 196606`. Measured at ~146 ms per unit of p, that is about eight
 * hours of one libuv threadpool thread for a single unlock, and the pool has
 * four — every `fsp.*` call in the application queues behind them. `keylen` is
 * not bounded by `maxmem` at all: `keylen: 1_000_000_000` is accepted and
 * allocates a gigabyte. And nothing sets a floor, so N could read 1024.
 *
 * Checked here rather than in `openWrap` because `unlockLegacy` reaches
 * `deriveKek` without passing through it, and because all five `openWrap`
 * callers wrap it in a `catch {}` that rewrites every throw into "wrong
 * password" — the user would be blamed for a file that is malformed.
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

/** Rozbalí DEK. Vyhodí výjimku, pokud tajemství nesedí (ověřuje GCM tag). */
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

/* -------------------------------------------------------------- trezor */

class Vault {
  private dek: Buffer | null = null
  private wraps: KeyWrap[] = []
  private data: VaultData | null = null

  get filePath(): string {
    return path.join(app.getPath('userData'), 'vault.enc')
  }

  private get backupPath(): string {
    return this.filePath + '.bak'
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

  /**
   * Zjistí z hlavičky souboru, jestli je nastavený obnovovací klíč.
   * Funguje i se zamčeným trezorem – hlavička není šifrovaná.
   */
  async hasRecoveryOnDisk(): Promise<boolean> {
    if (!this.exists()) return false
    try {
      const file = JSON.parse(await fsp.readFile(this.filePath, 'utf8')) as VaultFileV2
      return Array.isArray(file.wraps) && file.wraps.some((w) => w.type === 'recovery')
    } catch {
      return false
    }
  }

  /** Založí nový trezor a rovnou vygeneruje obnovovací klíč, který vrátí. */
  async create(masterPassword: string): Promise<string> {
    if (this.exists()) throw appError('error.vaultExists')
    validatePassword(masterPassword)

    const dek = randomBytes(32)
    const recoveryKey = generateRecoveryKey()

    this.dek = dek
    this.data = emptyData()
    this.wraps = [
      await makeWrap('password', masterPassword, dek),
      await makeWrap('recovery', normalizeRecoveryKey(recoveryKey), dek)
    ]
    await this.persist()
    return recoveryKey
  }

  async unlock(masterPassword: string): Promise<void> {
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
      throw appError('error.wrongPassword')
    }
    this.adopt(file, dek)
  }

  /**
   * Odemkne obnovovacím klíčem a rovnou nastaví nové hlavní heslo.
   * Bez nastavení nového hesla by trezor zůstal přístupný jen přes obnovu.
   */
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
    validatePassword(newPassword)

    // Obnova je ze své podstaty reakce na kompromitaci nebo ztrátu, takže
    // rotuje DEK. Použitý obnovovací klíč tím přestane platit — kdo by ho měl,
    // po tomhle už dovnitř nevidí — a uživatel dostane nový.
    const freshRecoveryKey = generateRecoveryKey()
    await this.reseal([
      { type: 'password', secret: newPassword },
      { type: 'recovery', secret: normalizeRecoveryKey(freshRecoveryKey) }
    ])
    return freshRecoveryKey
  }

  lock(): void {
    this.dek?.fill(0)
    this.dek = null
    this.data = null
    this.wraps = []
  }

  /**
   * Změní hlavní heslo a **rotuje datový klíč**.
   *
   * Vrací nový obnovovací klíč, pokud trezor nějaký měl. To je nevyhnutelný
   * důsledek rotace: starý obnovovací wrap by se musel postavit pod novým DEK,
   * a k tomu je potřeba obnovovací klíč v plaintextu — ten se ale nikde
   * neukládá, což je celý smysl jeho návrhu. Buď tedy rotace, nebo tichá
   * nemožnost odvolání; volba padla na rotaci.
   *
   * Volající **musí** vrácený klíč uživateli zobrazit. Zahození návratové
   * hodnoty znamená, že uživatel přijde o jedinou záchranu pro zapomenuté
   * heslo, aniž by se to dozvěděl.
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

  /**
   * Vygeneruje nový obnovovací klíč a nahradí jím starý wrap.
   *
   * POZOR — starý klíč tím **nepřestává platit**. Datový klíč (DEK) se
   * nerotuje, a `persist()` před každým zápisem zkopíruje současný
   * `vault.enc` do `vault.enc.bak`. Ten `.bak` tedy obsahuje wrap otevřený
   * starým klíčem, ten wrap vydá tentýž DEK, a ten DEK dešifruje i všechny
   * *budoucí* verze trezoru. Totéž platí pro `changePassword` a
   * `removeRecoveryKey`.
   *
   * Předchozí znění tohoto komentáře tvrdilo, že starý klíč okamžitě přestane
   * platit. Nebyla to pravda a nikdo si toho nevšiml, protože komentář zněl
   * jako záruka. Skutečná revokace vyžaduje rotaci DEK a přešifrování obsahu.
   */
  async regenerateRecoveryKey(password: string): Promise<string> {
    this.requireUnlocked()
    const wrap = this.wraps.find((w) => w.type === 'password')
    if (!wrap) throw appError('error.noPasswordSet')

    // Heslo je tu povinné ze dvou důvodů. Jednak ho rotace DEK potřebuje, aby
    // šel postavit nový wrap. Jednak bez něj stačily dvě minuty u odemčené
    // relace na vygenerování 150bitového klíče, který trezor otevírá navždy a
    // jde zkopírovat do schránky nebo do souboru — `changePassword` staré heslo
    // vyžadoval, tahle operace ne, a přitom je stejně mocná.
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

  /**
   * Zruší možnost obnovy. Pak už zapomenuté heslo znamená ztrátu dat.
   *
   * Rotuje DEK, takže odvolaný klíč skutečně přestane platit — dřív zůstal
   * použitelný přes `.bak` navždy.
   */
  async removeRecoveryKey(password: string): Promise<void> {
    this.requireUnlocked()
    const wrap = this.wraps.find((w) => w.type === 'password')
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

  /** Provede změnu nad daty a uloží je. */
  async mutate<T>(fn: (data: VaultData) => T): Promise<T> {
    this.requireUnlocked()
    const result = fn(this.data!)
    await this.persist()
    return result
  }

  /* ------------------------------------------------------------ vnitřní */

  private async readFile(): Promise<VaultFileV1 | VaultFileV2> {
    if (!this.exists()) throw appError('error.vaultMissing')
    const raw = await fsp.readFile(this.filePath, 'utf8')
    let file: VaultFileV1 | VaultFileV2
    try {
      file = JSON.parse(raw)
    } catch {
      throw appError('error.vaultCorrupt')
    }
    if (file.cipher !== 'aes-256-gcm' || (file.version !== 1 && file.version !== 2)) {
      throw appError('error.vaultUnsupported')
    }
    // Verze 2 stojí na seznamu wrapů. Bez téhle kontroly se poškozený soubor
    // dostal až k `file.wraps.find(...)` a uživateli se na odemykací obrazovce
    // ukázal syrový `TypeError` místo přeložené hlášky. `hasRecoveryOnDisk()`
    // tuhle situaci hlídalo, `readFile()` ne — vypadá to na opomenutí, ne na
    // rozhodnutí. Prázdné pole je legitimní a řeší se dál jako chybějící heslo.
    if (file.version === 2 && !Array.isArray((file as VaultFileV2).wraps)) {
      throw appError('error.vaultCorrupt')
    }
    // The one place where file bytes become KDF parameters, so the one place
    // that has to check them — before a key is derived from them, which is the
    // only moment at which checking still helps. Wraps held in memory come only
    // from `makeWrap()` or from a file that passed through here, which is why
    // `openWrap()` does not repeat the check.
    if (file.version === 1) {
      assertKdf(file.kdf)
    } else {
      for (const wrap of file.wraps) assertKdf(wrap?.kdf)
    }
    return file
  }

  /** Dešifruje obsah pomocí DEK a převezme stav do paměti. */
  private adopt(file: VaultFileV2, dek: Buffer): void {
    let plaintext: string
    try {
      const decipher = createDecipheriv('aes-256-gcm', dek, Buffer.from(file.iv, 'base64'))
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
    this.data = normalizeData(JSON.parse(plaintext) as Partial<VaultData>)
  }

  /** Trezor verze 1: klíč byl odvozený přímo z hesla. Po odemčení převedeme na v2. */
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
      throw appError('error.wrongPassword')
    } finally {
      key.fill(0)
    }

    this.dek = randomBytes(32)
    this.data = normalizeData(JSON.parse(plaintext) as Partial<VaultData>)
    this.wraps = [await makeWrap('password', masterPassword, this.dek)]
    await this.persist()
  }

  private requireUnlocked(): void {
    if (!this.isUnlocked()) throw appError('error.vaultLocked')
  }

  /**
   * Totéž jako `requireUnlocked`, ale volatelné zvenčí.
   *
   * Existuje pro IPC handlery SSH. Zámek musí platit i pro ně — jinak zamčená
   * aplikace pořád píše do vzdáleného shellu, protože relace žijí v hlavním
   * procesu nezávisle na tom, co si o nich myslí renderer.
   */
  requireUnlockedPublic(): void {
    this.requireUnlocked()
  }

  /**
   * Přepečetí trezor pod **novým** datovým klíčem.
   *
   * Tohle je jádro skutečné revokace. Dřív každá „revokační" operace jen
   * vyměnila wrap a nechala DEK být — jenže `persist()` před každým zápisem
   * kopíruje trezor do `.bak`, takže vedle souboru zůstal wrap otevřený starým
   * tajemstvím, který vydal tentýž DEK, kterým šlo dešifrovat i všechny
   * *budoucí* verze. Odvolání kl��če tedy neodvolalo nic.
   *
   * Teď se vygeneruje nový DEK, všechny wrapy se postaví pod ním, `persist()`
   * obsah přešifruje a záloha se přepíše náhodnými daty a smaže. Starý wrap ani
   * starý DEK nikde nezůstanou.
   *
   * Dva invarianty, na kterých to stojí:
   *
   * 1. **Nic se nepřiřadí do instance, dokud nejsou hotové všechny wrapy.**
   *    Dřív se seznam nejdřív profiltroval a teprve pak se čekalo na
   *    `makeWrap()`; když scrypt selhal, zůstal trezor bez hesla a další
   *    nesouvisející zápis to potvrdil na disk. Hlavní heslo bylo mrtvé při
   *    příštím spuštění.
   * 2. **Při selhání `persist()` se stav vrátí zpět.** Jinak by DEK v paměti
   *    přestal odpovídat souboru na disku.
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
      await this.persist()
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
   * Přepíše zálohu náhodnými daty a smaže ji.
   *
   * Samotné `unlink` nestačí: obsah zůstane na disku, dokud ho něco nepřepíše,
   * a `.bak` po rotaci drží starý wrap i starý obsah. Přepis nedává záruku na
   * SSD s wear levellingem ani na copy-on-write souborovém systému — je to
   * zlepšení, ne důkaz — ale je výrazně lepší než ponechat soubor ležet.
   */
  private async destroyBackup(): Promise<void> {
    try {
      const stat = await fsp.stat(this.backupPath)
      await fsp.writeFile(this.backupPath, randomBytes(stat.size))
      await fsp.rm(this.backupPath, { force: true })
    } catch {
      // Záloha neexistuje, nebo ji drží něco jiného. Rotace tím neselhává.
    }
  }

  private async persist(): Promise<void> {
    if (!this.dek || !this.data) throw appError('error.vaultLocked')
    if (this.wraps.length === 0) throw appError('error.noUnlockMethod')

    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', this.dek, iv)
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(this.data), 'utf8')),
      cipher.final()
    ])

    const file: VaultFileV2 = {
      version: 2,
      cipher: 'aes-256-gcm',
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: ciphertext.toString('base64'),
      wraps: this.wraps
    }

    await fsp.mkdir(path.dirname(this.filePath), { recursive: true })
    // Záloha předchozí verze, aby přerušený zápis nezničil data.
    if (fs.existsSync(this.filePath)) {
      await fsp.copyFile(this.filePath, this.backupPath).catch(() => {})
    }
    const tmp = this.filePath + '.tmp'
    await fsp.writeFile(tmp, JSON.stringify(file), { encoding: 'utf8', mode: 0o600 })
    await fsp.rename(tmp, this.filePath)
  }
}

function validatePassword(pw: string): void {
  if (typeof pw !== 'string' || pw.length < 8) {
    throw appError('error.passwordTooShort')
  }
}

/**
 * Přenese trezor ze složky profilu pod dřívějším názvem aplikace.
 *
 * Electron odvozuje cestu k profilu z `productName`, takže přejmenování
 * projektu jinak vypadá jako ztráta všech uložených připojení. Kopírujeme
 * (nemažeme), aby šlo v případě potíží sáhnout po originálu.
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
    return legacyDir
  }
  return null
}

export function newId(): string {
  return randomUUID()
}

export const vault = new Vault()

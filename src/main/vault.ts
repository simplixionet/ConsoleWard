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
 *   { version: 3, cipher, counter, iv, tag, data, wraps: [...] }
 *
 * Hlavička je čitelná, ale ne volně měnitelná: `version`, `cipher`, `counter`
 * a všechna pole všech wrapů jdou do GCM jako AAD (viz `headerAad`). Kdo do
 * souboru zapíše, tím pádem nemůže vyndat password wrap, podstrčit cizí
 * recovery wrap ani splácnout wrapy ze starší kopie — tag na těle přestane
 * sedět a trezor se neotevře.
 *
 * `counter` roste s každým zápisem. Tady ho AAD jen chrání před přepsáním;
 * porovnání proti dřív viděné hodnotě, kterým se pozná vrácení celé staré
 * kopie souboru, tu **není** — je to samostatný krok (C6).
 *
 * Starší formáty se při odemčení převedou na verzi 3:
 *   verze 1 – klíč odvozený přímo z hesla, bez DEK a bez wrapů
 *   verze 2 – DEK a wrapy jako dnes, ale hlavička nesvázaná s tělem
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

/** Aktuální formát souboru. Verze 1 a 2 se umí přečíst a při odemčení převést sem. */
const VAULT_VERSION = 3 as const

/**
 * Penalty after the first wrong password, doubling with each further one.
 *
 * Small enough that a human who mistyped once notices nothing — scrypt already
 * costs longer than this — and large enough that it compounds fast.
 */
const UNLOCK_BASE_DELAY_MS = 250

/**
 * Ceiling on that penalty.
 *
 * Five seconds is an obstacle to a script and a nuisance to a person, which is
 * the right way round: someone who genuinely forgot their password has the
 * recovery key, and someone guessing has to spend five seconds per attempt for
 * as long as they keep going.
 */
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

interface VaultFileV3 {
  version: 3
  cipher: 'aes-256-gcm'
  /** Roste s každým zápisem. Chrání ho AAD; porovnávat ho bude až C6. */
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
  /** Bearer token pro lokální MCP server. */
  mcpToken?: string
  /** Šifrovaný spolu se zbytkem trezoru; rezervováno pro 2. fázi. */
  aiApiKey?: string
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

/* --------------------------------------------- autentizovaná hlavička (AAD) */

/**
 * Doménová předpona serializace.
 *
 * Bez ní by stačilo, aby nějaký jiný formát náhodou vyprodukoval tytéž bajty,
 * a tag by ověřil hlavičku, kterou nikdo nezamýšlel. Číslo na konci je verze
 * *kódování*, ne verze souboru — kdyby se pořadí polí někdy měnilo, změní se
 * i tahle konstanta.
 */
const AAD_MAGIC = Buffer.from('consoleward.vault.aad.1', 'ascii')

/** `délka || obsah`. Rámování je jediné, co brání záměně `ab|c` za `a|bc`. */
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
 * Kanonická podoba hlavičky, kterou přes `setAAD()` svážeme s tělem.
 *
 * Pokrývá `version`, `cipher`, `counter` a **všechna** pole **všech** wrapů
 * v tom pořadí, v jakém leží v souboru. Nepokrývá `iv`, `tag` a `data` těla:
 * `tag` je výstup právě počítané operace, `iv` vstupuje do GCM zvlášť a jeho
 * záměna rozbije tag sama o sobě, a `data` autentizuje GCM z definice.
 *
 * Proč ne `JSON.stringify`: pořadí klíčů v souboru si diktuje ten, kdo ho
 * napsal, takže dva soubory se stejným významem by daly různé AAD a trezor by
 * se po ručním přeformátování neotevřel. Tady je pořadí polí pevné a každý
 * proměnlivě dlouhý úsek nese svou délku před sebou; počet wrapů je zapsaný
 * před nimi. Díky tomu neexistují dvě různé hlavičky se stejnými bajty.
 *
 * Wrapy vlastní AAD nedostávají. Bylo by to kruhové — tag wrapu je součástí
 * téhle serializace — a hlavně by to zabilo migraci z v2: obnovovací wrap se dá
 * postavit znovu jen s obnovovacím klíčem v plaintextu, který nikde není.
 * Vazba tělo → všechna pole wrapů je ta, na které záleží.
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
 * Ověří, že hlavička v3 jde vůbec zakódovat do AAD.
 *
 * KDF parametry řeší `assertKdf`, který běží dřív a je přísnější, než by tady
 * dávalo smysl. Zbývá čítač a ta pole wrapu, která jdou do `headerAad()` jako
 * rámované řetězce — bez téhle kontroly by `writeBigUInt64BE(BigInt(1.5))` nebo
 * `Buffer.from(null)` shodily odemykací obrazovku syrovým RangeError/TypeError
 * místo přeložené hlášky.
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

/* -------------------------------------------------------------- trezor */

/**
 * Pečetidlo, které nic neumí — stav stroje bez platformního trezoru hesel.
 *
 * `seal` a `open` vyhazují schválně: kdyby vracely vstup beze změny, kotva by
 * se tvářila jako zapečetěná, aniž by byla. Nedostupnost se hlásí přes
 * `available()`, ne mlčky.
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
  /** Poslední číslo zápisu, které jsme viděli nebo zapsali. Nula = zatím žádné. */
  private counter = 0
  /** Konec fronty zápisů; viz `enqueueWrite`. */
  private writes: Promise<unknown> = Promise.resolve()
  /** Kolik pokusů o odemčení po sobě selhalo; viz `awaitUnlockSlot`. */
  private failedUnlocks = 0
  /** Konec fronty pokusů o odemčení; viz `awaitUnlockSlot`. */
  private unlocks: Promise<unknown> = Promise.resolve()

  /**
   * Pečetidlo kotvy. Instaluje ho `index.ts`, protože `safeStorage` se sem
   * importovat nesmí: testovací soubory stubují z Electronu jen `app` a
   * chybějící pojmenovaný export je shodí už při načtení, ne v jednom testu.
   *
   * Výchozí „žádné" je zároveň to, co běží na Linuxu bez keyringu — kotva se
   * pak zapisuje jako prostý text a přizná to.
   */
  private sealer: GuardSealer = NO_SEALER

  /** Verdikt z poslední kotvy. Platí až po odemčení; `lock()` ho ruší. */
  private guard: GuardVerdict = { kind: 'unknown' }

  get filePath(): string {
    return path.join(app.getPath('userData'), 'vault.enc')
  }

  private get backupPath(): string {
    return this.filePath + '.bak'
  }

  /** Kotva je sourozenec trezoru, ne jeho přípona – kopie profilu vezme obojí. */
  private get guardPath(): string {
    return path.join(app.getPath('userData'), 'vault.guard')
  }

  installGuardSealer(sealer: GuardSealer): void {
    this.sealer = sealer
  }

  /**
   * Co kotva říká o souboru, který je právě otevřený.
   *
   * `unknown`, dokud se neodemklo — hlavička je sice čitelná i bez hesla, ale
   * tvrdit něco o souboru, který se ani nepovedlo rozšifrovat, by znamenalo
   * varovat u každého překlepu v hesle.
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

  /**
   * Zjistí z hlavičky souboru, jestli je nastavený obnovovací klíč.
   * Funguje i se zamčeným trezorem – hlavička není šifrovaná.
   */
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

  /** Založí nový trezor a rovnou vygeneruje obnovovací klíč, který vrátí. */
  async create(masterPassword: string): Promise<string> {
    if (this.exists()) throw appError('error.vaultExists')
    validatePassword(masterPassword)

    const dek = randomBytes(32)
    const recoveryKey = generateRecoveryKey()

    this.dek = dek
    this.data = emptyData()
    this.counter = 0
    /*
     * Zakládá se nový trezor, takže kotva po tom předchozím na stejné cestě je
     * bezpředmětná — porovnávat proti ní by hlásilo vrácení souboru pokaždé,
     * když si někdo trezor smaže a založí znovu. `persist` níž ji stejně
     * přepíše; tohle jen říká, že se o ní vědomě nesoudí.
     */
    this.guard = { kind: 'unknown' }
    this.wraps = [
      await makeWrap('password', masterPassword, dek),
      await makeWrap('recovery', normalizeRecoveryKey(recoveryKey), dek)
    ]
    // Same guard as the v2 migration in `unlock`, and for the same reason: the
    // three assignments above already made `isUnlocked()` true, so a failed
    // write would report an error to the renderer while leaving the main
    // process holding an open vault that `requireUnlockedPublic()` waves
    // through. Worse here than there — the file does not exist at all, so the
    // caller never receives the recovery key, and any later `mutate()` that
    // succeeded would materialise a vault whose recovery wrap opens with a key
    // nobody was ever shown.
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
     * Před migrací níž, jinak si verdikt přepíše její vlastní zápis.
     *
     * Nula pro v2 není náhradní hodnota, ale správná odpověď: kotva vznikne až
     * prvním v3 zápisem, takže v2 soubor vedle kotvy je sestup na starší
     * formát — přesně to vrácení, které se hledá.
     */
    this.guard = await this.readAnchor(this.counter)

    // Migrace v2 → v3. Přepsat soubor jde až teď, kdy je DEK v ruce. DEK ani
    // wrapy se nemění: obnovovací wrap by šlo postavit znovu jen s obnovovacím
    // klíčem v plaintextu, který se nikde neukládá, takže rotace by uživateli
    // tiše zabila klíč, který má opsaný na papíře. Mění se jen tělo — nově
    // zapečetěné s AAD nad hlavičkou.
    //
    // Když zápis selže (profil jen pro čtení, plný disk), je nutné se zamknout.
    // `adopt()` už nastavil `dek`, `wraps` i `data`, takže bez tohohle by
    // `unlock()` volajícímu ohlásil chybu, renderer zůstal na zamykací
    // obrazovce — a `vault.isUnlocked()` by v hlavním procesu bylo `true`,
    // což je přesně ten predikát, na kterém visí SSH i MCP.
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
    /*
     * I obnova obnovovacím klíčem musí verdikt zjistit, a to PŘED `reseal`
     * níž. Kdo se zotavuje do podstrčeného staršího souboru, je ten, kdo se to
     * potřebuje dozvědět nejvíc — a bez tohohle by to byla jediná cesta do
     * trezoru, která kotvu přeskočí.
     */
    this.guard = await this.readAnchor(this.counter)
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
    this.counter = 0
    // Verdikt patří k otevřenému souboru. Nechat ho tu by znamenalo, že po
    // zamčení a odemčení jiného trezoru svítí varování o tom předchozím.
    this.guard = { kind: 'unknown' }
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
    // Unreachable today, and kept anyway. Every path to an unlocked vault
    // installs a password wrap — `create` writes one, `unlock` refuses a file
    // without one (`error.noPasswordSet`), `unlockLegacy` builds one, and
    // `reseal` rejects a secret list that has none — so no public API can
    // produce the state this guards against. It stays because it is an
    // invariant assertion, not a user-facing error: the day one of those four
    // paths changes, this is a translated message rather than a TypeError
    // thrown out of `openWrap(undefined, …)` in the middle of a rotation.
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
   * Provede změnu nad daty a uloží je.
   *
   * Změna se dělá nad **kopií**. Do `this.data` se překlopí až po úspěšném
   * zápisu, takže selhání zápisu (plný disk, profil jen pro čtení, obsazená
   * `.tmp`) nenechá v paměti stav, který na disku není. Dřív se měnil živý
   * objekt a zápis přišel po něm: `conn:save` ohlásil rendereru chybu, ale
   * připojení v paměti zůstalo a první další úspěšný zápis ho tiše uložil.
   * Nejhůř to dopadalo u `verifyHostKey`: uživatel dostal chybu, otisk se
   * neuložil — a přesto ho zbytek běhu aplikace považoval za důvěryhodný.
   *
   * `structuredClone` stačí — `VaultData` je čisté JSON (řetězce, čísla,
   * booleany, pole). Kopie stojí zlomek toho, co zápis hned za ní.
   *
   * Vedlejší efekt, který stojí za to mít: když `fn` uprostřed vyhodí výjimku,
   * rozdělaná změna zmizí s kopií. Předtím zůstala v živých datech.
   */
  async mutate<T>(fn: (data: VaultData) => T): Promise<T> {
    this.requireUnlocked()
    return this.enqueueWrite(async () => {
      // Znovu: mezi zařazením a během fronty se trezor mohl zamknout.
      this.requireUnlocked()
      const draft = structuredClone(this.data!)
      const result = fn(draft)
      await this.writeSealed(draft)
      // And once more, because `writeSealed` awaits four filesystem calls and
      // `lock()` is synchronous: an auto-lock, or the user locking by hand, can
      // land in the middle of the write.
      //
      // This does NOT reopen the vault — `isUnlocked()` also tests `dek`, which
      // `lock()` nulls and nothing here restores. What it did was reattach the
      // decrypted `VaultData` to the instance, and dropping that object is half
      // of what `lock()` is for: every stored password, private key and
      // passphrase stayed resident afterwards, in a process that had been told
      // to forget them.
      //
      // The bytes on disk are right either way — the write finished — so there
      // is nothing to roll back here, only a state not to restore.
      if (this.dek === null) throw appError('error.vaultLocked')
      this.data = draft
      return result
    })
  }

  /**
   * Waits out the penalty earned by previous wrong passwords.
   *
   * scrypt at N = 2^17 already costs ~160 ms, which bounds an online guess at
   * roughly six a second — enough against a person typing, useless against
   * anything scripted against the IPC channel, and that channel is reachable
   * from the lock screen without any secret at all.
   *
   * The delay is exponential in the number of consecutive failures and capped,
   * so a human who mistypes twice waits a quarter of a second while a run of a
   * thousand guesses waits `UNLOCK_MAX_DELAY_MS` for every one of them. It is
   * deliberately in memory and not in the file: this raises the cost of guessing
   * at a running app, which is what a lock screen is for. Someone who can copy
   * `vault.enc` attacks it offline where no counter of ours applies, and
   * persisting the count would hand them a way to lock the owner out by editing
   * it.
   *
   * The counter resets on success, and `lock()` deliberately does NOT reset it —
   * otherwise the way past the throttle would be to lock and try again.
   */
  /**
   * One unlock attempt at a time, whatever the caller does.
   *
   * The delay alone is not a throttle. Fifty concurrent calls read the same
   * `failedUnlocks`, sleep the same interval simultaneously, and reach scrypt
   * together — fifty guesses for the price of one delay, and the counter only
   * rises once because each of them read it before any of them failed. Nothing
   * upstream imposes order: `ipcMain.handle` runs handlers concurrently and the
   * lock screen can issue as many calls as it likes.
   *
   * Serialising the WHOLE attempt — the wait, the derivation and the counter
   * update — is what makes the penalty compound. Errors are swallowed into the
   * tail so one rejection cannot stall the queue; the caller still receives its
   * own rejection.
   */
  private enqueueUnlock<T>(attempt: () => Promise<T>): Promise<T> {
    const done = this.unlocks.then(attempt, attempt)
    this.unlocks = done.then(
      () => undefined,
      () => undefined
    )
    return done
  }

  private async awaitUnlockSlot(): Promise<void> {
    if (this.failedUnlocks === 0) return
    const delay = Math.min(UNLOCK_MAX_DELAY_MS, UNLOCK_BASE_DELAY_MS * 2 ** (this.failedUnlocks - 1))
    await new Promise((resolve) => setTimeout(resolve, delay))
  }

  /* ------------------------------------------------------------ vnitřní */

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
    // Verze 2 stojí na seznamu wrapů. Bez téhle kontroly se poškozený soubor
    // dostal až k `file.wraps.find(...)` a uživateli se na odemykací obrazovce
    // ukázal syrový `TypeError` místo přeložené hlášky. `hasRecoveryOnDisk()`
    // tuhle situaci hlídalo, `readFile()` ne — vypadá to na opomenutí, ne na
    // rozhodnutí. Prázdné pole je legitimní a řeší se dál jako chybějící heslo.
    if (file.version !== 1 && !Array.isArray((file as VaultFileV2 | VaultFileV3).wraps)) {
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
    // Hlavička v3 jde do AAD, takže co nejde zakódovat, se sem nesmí dostat.
    if (file.version === 3) assertHeaderShape(file)
    return file
  }

  /**
   * Dešifruje obsah pomocí DEK a převezme stav do paměti.
   *
   * U v3 je hlavička svázaná s tělem přes AAD, takže vyndaný wrap, přidaný wrap,
   * přeházené pořadí i posunutý čítač skončí selháním tagu. U v2 žádné AAD není
   * a být nemůže — soubor vznikl bez něj. Právě proto je `version` součástí AAD:
   * přepsat v3 hlavičku na `version: 2` a doufat, že se AAD přeskočí, končí
   * `error.decryptFailed`.
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
    // v2 čítač nemá; navazovat je na čem až od prvního v3 zápisu.
    this.counter = file.version === 3 ? file.counter : 0
    this.data = normalizeData(JSON.parse(plaintext) as Partial<VaultData>)
  }

  /** Trezor verze 1: klíč byl odvozený přímo z hesla. Po odemčení převedeme na v3. */
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
      // Counted here too, or a v1 vault — the format an early-build user still
      // has, and the one that only migrates on a SUCCESSFUL unlock, so it stays
      // v1 for exactly as long as somebody is guessing at it — gets no throttle
      // at all. `unlock` increments on the v2/v3 path; this branch returns
      // before reaching it.
      this.failedUnlocks += 1
      throw appError('error.wrongPassword')
    } finally {
      key.fill(0)
    }

    this.failedUnlocks = 0
    this.dek = randomBytes(32)
    this.data = normalizeData(JSON.parse(plaintext) as Partial<VaultData>)
    this.counter = 0
    // Stejně jako u v2: kotva vedle souboru ve formátu v1 znamená sestup, ne
    // starožitnost. Před `persist` níž, protože ten kotvu přepíše.
    this.guard = await this.readAnchor(0)
    this.wraps = [await makeWrap('password', masterPassword, this.dek)]
    // The v1 half of the guard the v2 branch of `unlock` already has. Without
    // it a v1 user on a read-only or full profile directory gets an error, the
    // lock screen, and an unlocked vault behind it.
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

  /**
   * Drops the pre-migration backup, but only once the new file has been read
   * back and decrypted.
   *
   * A migration leaves `.bak` holding the vault in the OLD format with the SAME
   * secrets, and nothing ever removed it. For v1 that is a copy whose key came
   * straight from the password; for v2 it is a copy with no AAD and no counter,
   * which is a ready-made target for exactly the rollback C6 exists to detect.
   * Leaving either lying next to the vault for good is worse than the risk of
   * dropping it.
   *
   * But dropping it blind would remove the safety net at the one moment a
   * format change most needs one. So the new file is opened again from disk and
   * its body decrypted with the data key already in memory — no password, no
   * scrypt, just the AES-GCM pass. If that succeeds the old copy is provably
   * redundant. If anything at all goes wrong the backup stays, because a
   * needless `.bak` costs nothing next to a vault nobody can open.
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
   * Zařadí zápis za všechny předchozí, ať dopadly jakkoli.
   *
   * Trezor je jeden soubor, jedna cesta `.tmp` a jeden čítač. Dva zápisy naráz
   * si `.tmp` přepíšou pod rukama a vyrobí dvě různá těla se stejným číslem.
   * A `mutate()` by bez fronty vzal obě kopie ze stejného výchozího stavu,
   * takže druhý zápis by ten první zahodil.
   */
  private enqueueWrite<T>(job: () => Promise<T>): Promise<T> {
    const done = this.writes.then(job, job)
    // Chyba se polyká jen tady, aby nezastavila frontu; volající ji dostane v `done`.
    this.writes = done.then(
      () => undefined,
      () => undefined
    )
    return done
  }

  /** Zápis mimo `mutate()` — zakládání, migrace, přepečetění. */
  private async persist(data: VaultData): Promise<void> {
    return this.enqueueWrite(() => this.writeSealed(data))
  }

  /**
   * Zapečetí `data` a atomicky je vymění za současný soubor.
   *
   * Volá se **jen zevnitř fronty zápisů** (`persist`, `mutate`). Nikdy přímo.
   */
  private async writeSealed(data: VaultData): Promise<void> {
    if (!this.dek) throw appError('error.vaultLocked')
    if (this.wraps.length === 0) throw appError('error.noUnlockMethod')

    // Čítač roste s každým zápisem. Tady ho jen chrání AAD; porovnat ho s dřív
    // viděnou hodnotou, a tím poznat vrácení staré kopie souboru, je C6.
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
    // Záloha předchozí verze, aby přerušený zápis nezničil data.
    if (fs.existsSync(this.filePath)) {
      await fsp.copyFile(this.filePath, this.backupPath).catch(() => {})
    }
    const tmp = this.filePath + '.tmp'
    await fsp.writeFile(tmp, JSON.stringify(file), { encoding: 'utf8', mode: 0o600 })
    await fsp.rename(tmp, this.filePath)
    // Až po úspěšném přejmenování. Jinak by paměť tvrdila vyšší číslo, než jaké
    // je v souboru, a příští zápis by v řadě udělal díru.
    this.counter = counter
    await this.recordAnchor(counter)
  }

  /**
   * Posune kotvu na právě zapsané číslo.
   *
   * **Až po úspěšném `rename`, nikdy před ním.** Kotva napřed by po každém
   * nečistém vypnutí tvrdila, že soubor je starší, než má být, a varování,
   * které křičí na nevinné, se za týden odklikává poslepu.
   *
   * Selhání se polyká. Trezor je v tu chvíli **už zapsaný** — vyhodit chybu by
   * volajícímu řeklo, že zápis neprošel, a ten by na to reagoval (vrátil změnu
   * v paměti, ukázal chybu) kvůli něčemu, co se povedlo. Cena je, že na
   * profilu, kam nejde psát, detekce tiše nefunguje; proto ta zpráva do logu,
   * ať to jde aspoň zpětně poznat.
   */
  /**
   * Přečte kotvu a porovná ji s číslem z hlavičky.
   *
   * Chybějící i nečitelná kotva dají `unknown`, tedy žádné varování. Rozdíl
   * mezi nimi tu **nezakládá jiné chování** — je v logu a v tom, že parser
   * nelže o tom, co na disku je.
   *
   * A nečitelná kotva se příštím zápisem přepíše. Zní to jako díra (poškoď
   * kotvu a detekce se resetuje), ale kdo umí kotvu poškodit, umí ji hlavně
   * smazat, takže odmítnutí zápisu nic nezachrání — jen by z jednoho poškození
   * udělalo trvale vypnutou detekci, kterou už nic neopraví. Sebeuzdravení je
   * z těch dvou možností ta lepší.
   */
  private async readAnchor(fileCounter: number): Promise<GuardVerdict> {
    const read = await readAnchorFile(this.guardPath, this.sealer)
    if (read.kind === 'ok') return guardVerdict(read.anchor, fileCounter)
    if (read.kind === 'unreadable') {
      console.warn('vault: rollback anchor is unreadable:', read.reason)
    }
    return { kind: 'unknown' }
  }

  private async recordAnchor(counter: number): Promise<void> {
    try {
      await writeAnchorFile(this.guardPath, counter, Date.now(), this.sealer)
    } catch (err) {
      console.warn('vault: could not update the rollback anchor:', (err as Error).message)
    }
  }
}

/**
 * The floor a new master password has to clear.
 *
 * Only length, and only here — the strength estimate next to it is for the
 * meter the user sees, not for a gate. A gate built on a guess refuses
 * passwords that are fine and lets through ones that are not, and the person
 * being refused has no way to argue with it.
 *
 * Reached from `create`, `changePassword` and the new password set during
 * recovery. Never from `unlock`, so raising the floor cannot lock anyone out of
 * a vault they already have.
 */
function validatePassword(pw: string): void {
  if (typeof pw !== 'string' || pw.length < MIN_PASSWORD_LENGTH) {
    throw appError('error.passwordTooShort', { length: MIN_PASSWORD_LENGTH })
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

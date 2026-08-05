// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Kotva proti vrácení staré `vault.enc`.
 *
 * Hlavička v3 nese `counter`, který roste s každým zápisem a chrání ho AAD,
 * takže ho nejde zfalšovat. Jenže číslo chráněné uvnitř souboru neřekne nic
 * o tom, že někdo podstrčil **celý starší soubor** — ten má svůj čítač taky
 * platný, jen menší. Poslední viděnou hodnotu je proto potřeba držet jinde:
 * v `vault.guard` vedle trezoru.
 *
 * **Co to umí a co ne.** Zapečetění přes `safeStorage` brání tomu, aby někdo,
 * kdo umí jen *zapisovat soubory* — synchronizační klient, obnovená záloha,
 * sdílená složka s rozbitými právy, offline obraz disku — kotvu podvrhl. Proti
 * kódu běžícímu pod tímtéž uživatelem nezmůže nic: DPAPI i Keychain mu rády
 * zašifrují cokoliv, a hlavně může `vault.guard` prostě smazat. Detekce tedy
 * chytá **nehody a nedbalé útočníky**, ne cílený útok z téhož účtu. Musí to tak
 * být napsané i v SECURITY.md — kotva, která slibuje víc, než umí, je horší než
 * žádná.
 *
 * Modul je **bez závislosti na Electronu**: pečetidlo se předává zvenčí. Jinak
 * by `safeStorage` v importu shodilo testovací soubory, které stubují jen `app`
 * — a shodilo by je při importu, ne v jednom testu.
 */

import { constants as fsConstants } from 'node:fs'
import fsp from 'node:fs/promises'

/** Verze formátu `vault.guard`. Neznámou verzi nečteme, ale ani nepřepisujeme naslepo. */
export const GUARD_VERSION = 1 as const

/**
 * Strop pro čtení kotvy.
 *
 * Kotva má pár set bajtů. Limit je tu proto, že soubor leží v adresáři, do
 * kterého může psát i něco jiného, a načíst odtud gigabajt při odemykání by byl
 * laciný způsob, jak aplikaci položit.
 */
export const GUARD_MAX_BYTES = 64 * 1024

// Windows nemá O_NONBLOCK a přímý odkaz by z celého příznakového slova udělal
// NaN. Stejný důvod jako v textFile.ts.
const O_NONBLOCK = (fsConstants as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0

/**
 * Zapečetění kotvy platformním trezorem hesel.
 *
 * `available()` je false na Linuxu bez keyringu (a u backendu `basic_text`,
 * který jen předstírá, že šifruje).
 */
export interface GuardSealer {
  available(): boolean
  seal(plain: string): Buffer
  open(blob: Buffer): string
}

export interface Anchor {
  /** Poslední čítač, který jsme u tohoto trezoru viděli. */
  counter: number
  /** Kdy se kotva zapsala (ms od epochy) – jde do textu varování. */
  at: number
  /** Byla kotva zapečetěná, nebo je to jen prostý text bez keyringu? */
  protected: boolean
}

export type GuardRead =
  | { kind: 'ok'; anchor: Anchor }
  /** Kotva ještě neexistuje – první spuštění, nebo ji někdo smazal. */
  | { kind: 'absent' }
  /** Kotva existuje, ale nedá se přečíst. Nikdy to netiš jako 'absent'. */
  | { kind: 'unreadable'; reason: string }

export type GuardVerdict =
  /** Soubor je stejně starý nebo novější než kotva. */
  | { kind: 'ok' }
  /** Není s čím porovnávat. */
  | { kind: 'unknown' }
  /** Soubor na disku je STARŠÍ než ten, který jsme naposledy viděli. */
  | { kind: 'rollback'; expected: number; found: number; at: number }

/**
 * Porovná čítač z hlavičky s kotvou.
 *
 * Pravidlo je jednosměrné schválně. `found > expected` **není** poplach: kotva
 * se zapisuje až po úspěšném zápisu trezoru, takže pád mezi těmi dvěma kroky
 * nechá kotvu o jedno pozadu, a to je normální stav, ne útok. Kdyby se pořadí
 * obrátilo, tenhle běžný pád by hlásil vrácení souboru pokaždé — a varování,
 * které křičí na nevinné, se za týden odklikává poslepu.
 */
export function verdict(anchor: Anchor | null, fileCounter: number): GuardVerdict {
  if (anchor === null) return { kind: 'unknown' }
  if (!Number.isSafeInteger(fileCounter) || fileCounter < 0) return { kind: 'unknown' }
  if (fileCounter >= anchor.counter) return { kind: 'ok' }
  return { kind: 'rollback', expected: anchor.counter, found: fileCounter, at: anchor.at }
}

/** Serializuje kotvu do obsahu `vault.guard`. */
export function serializeGuard(counter: number, at: number, sealer: GuardSealer): string {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new Error('vaultGuard: counter must be a non-negative safe integer')
  }
  if (!Number.isSafeInteger(at) || at < 0) {
    throw new Error('vaultGuard: timestamp must be a non-negative safe integer')
  }

  const body = JSON.stringify({ counter, at })
  const isProtected = sealer.available()
  /*
   * Bez keyringu se kotva zapíše jako prostý text, ne že se nezapíše.
   * Odmítnout ji znamená vypnout detekci celé jedné platformě, a i nechráněná
   * kotva chytí každé nechtěné vrácení souboru. Nesmí se ale tvářit jako
   * ochrana — proto to `protected` v souboru a proto to stojí v SECURITY.md.
   */
  const payload = isProtected
    ? sealer.seal(body).toString('base64')
    : Buffer.from(body, 'utf8').toString('base64')

  return JSON.stringify({ version: GUARD_VERSION, protected: isProtected, payload }, null, 2)
}

/** Přečte obsah `vault.guard`. Nikdy nevyhazuje – chyba je návratová hodnota. */
export function parseGuard(raw: string, sealer: GuardSealer): GuardRead {
  let outer: unknown
  try {
    outer = JSON.parse(raw)
  } catch {
    return { kind: 'unreadable', reason: 'not JSON' }
  }
  if (typeof outer !== 'object' || outer === null || Array.isArray(outer)) {
    return { kind: 'unreadable', reason: 'not an object' }
  }

  const file = outer as Record<string, unknown>
  /*
   * Novější verzi nečteme a volající ji nesmí přepsat. Přepsat kotvu, které
   * nerozumíme, je přesně to snížení ochrany, kvůli kterému tenhle soubor je:
   * stačilo by ji podvrhnout jako `version: 999` a detekce zmizí potichu.
   */
  if (file.version !== GUARD_VERSION) {
    return { kind: 'unreadable', reason: `unsupported version ${String(file.version)}` }
  }
  if (typeof file.protected !== 'boolean') {
    return { kind: 'unreadable', reason: 'protected flag missing' }
  }
  if (typeof file.payload !== 'string') {
    return { kind: 'unreadable', reason: 'payload missing' }
  }

  const blob = Buffer.from(file.payload, 'base64')
  if (blob.length === 0) return { kind: 'unreadable', reason: 'payload empty' }

  let body: string
  if (file.protected) {
    if (!sealer.available()) {
      // Chráněná kotva na stroji bez keyringu: nevíme, ne že je špatně.
      return { kind: 'unreadable', reason: 'sealed anchor, no keyring available' }
    }
    try {
      body = sealer.open(blob)
    } catch {
      return { kind: 'unreadable', reason: 'cannot decrypt' }
    }
  } else {
    body = blob.toString('utf8')
  }

  let inner: unknown
  try {
    inner = JSON.parse(body)
  } catch {
    return { kind: 'unreadable', reason: 'payload not JSON' }
  }
  if (typeof inner !== 'object' || inner === null || Array.isArray(inner)) {
    return { kind: 'unreadable', reason: 'payload not an object' }
  }

  const data = inner as Record<string, unknown>
  if (typeof data.counter !== 'number' || !Number.isSafeInteger(data.counter) || data.counter < 0) {
    return { kind: 'unreadable', reason: 'counter invalid' }
  }
  if (typeof data.at !== 'number' || !Number.isSafeInteger(data.at) || data.at < 0) {
    return { kind: 'unreadable', reason: 'timestamp invalid' }
  }

  return {
    kind: 'ok',
    anchor: { counter: data.counter, at: data.at, protected: file.protected }
  }
}

/* ------------------------------------------------------------ práce se souborem */

/**
 * Přečte `vault.guard`.
 *
 * Chybějící soubor je `absent`, cokoliv jiného `unreadable` — mezi „kotva tu
 * není" a „kotva tu je, ale nerozumím jí" se **nesmí** míchat. Volající první
 * případ přepisuje a druhý ne; kdyby splynuly, stačí kotvu poškodit a detekce
 * se sama vypne.
 *
 * Otevírá se dřív, než se ptá: `fstat` na otevřeném deskriptoru odpoví
 * `isFile() === false` i na pojmenovanou rouru, kterou `stat` nad cestou hlásí
 * jako soubor. Ta by jinak prošla limitem a čtení by se zaseklo na vlákně,
 * které nejde zrušit — přesně při odemykání.
 */
export async function readAnchorFile(file: string, sealer: GuardSealer): Promise<GuardRead> {
  let handle: fsp.FileHandle
  try {
    handle = await fsp.open(file, fsConstants.O_RDONLY | O_NONBLOCK)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'unreadable', reason: `cannot open: ${(err as Error).message}` }
  }

  try {
    const stat = await handle.stat()
    if (!stat.isFile()) return { kind: 'unreadable', reason: 'not a regular file' }
    if (stat.size > GUARD_MAX_BYTES) return { kind: 'unreadable', reason: 'too large' }

    const buf = Buffer.alloc(GUARD_MAX_BYTES + 1)
    let filled = 0
    while (filled < buf.length) {
      const { bytesRead } = await handle.read(buf, filled, buf.length - filled, filled)
      if (bytesRead === 0) break
      filled += bytesRead
    }
    if (filled > GUARD_MAX_BYTES) return { kind: 'unreadable', reason: 'too large' }

    return parseGuard(buf.subarray(0, filled).toString('utf8'), sealer)
  } catch (err) {
    return { kind: 'unreadable', reason: `cannot read: ${(err as Error).message}` }
  } finally {
    await handle.close().catch(() => {})
  }
}

/**
 * Zapíše kotvu.
 *
 * Přes dočasný soubor a `rename`, aby přerušený zápis nenechal na disku
 * useknutou kotvu — tu by příští start četl jako `unreadable` a detekce by
 * tiše zmizela kvůli výpadku proudu.
 *
 * **Volá se až po úspěšném zápisu trezoru, nikdy před ním.** Opačné pořadí
 * nechá po pádu kotvu napřed a `verdict` pak hlásí vrácení souboru při každém
 * nečistém vypnutí.
 */
export async function writeAnchorFile(
  file: string,
  counter: number,
  at: number,
  sealer: GuardSealer
): Promise<void> {
  const text = serializeGuard(counter, at, sealer)
  const tmp = `${file}.tmp`
  await fsp.writeFile(tmp, text, { encoding: 'utf8', mode: 0o600 })
  await fsp.rename(tmp, file)
}

/**
 * Smaže kotvu. Chybějící soubor není chyba.
 *
 * Patří k mazání trezoru: kotva, která přežije svůj trezor, ohlásí u nově
 * založeného (čítač zpátky na nule) vrácení souboru, které se nestalo.
 */
export async function removeAnchorFile(file: string): Promise<void> {
  await fsp.rm(file, { force: true })
}

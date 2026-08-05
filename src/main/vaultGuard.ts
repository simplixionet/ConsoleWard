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

/** Verze formátu `vault.guard`. Neznámou verzi nečteme, ale ani nepřepisujeme naslepo. */
export const GUARD_VERSION = 1 as const

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

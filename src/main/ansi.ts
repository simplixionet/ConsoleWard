// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Převod surového výstupu terminálu na čitelný text.
 *
 * Buffer relace obsahuje escape sekvence pro barvy, pozici kurzoru a titulek
 * okna. Bez očištění by dialog i model dostaly guláš, takže filtr musí běžet
 * dřív, než text kdokoli uvidí.
 *
 * Řídicí znaky zapisujeme přes fromCharCode – syrové bajty ve zdrojáku jsou
 * neviditelné a snadno se poškodí.
 */

const ESC = String.fromCharCode(0x1b)
const BEL = String.fromCharCode(0x07)
const BACKSPACE = String.fromCharCode(0x08)

/** OSC: ESC ] … BEL nebo ESC \ (typicky titulek okna) */
const OSC = new RegExp(`${ESC}\\][\\s\\S]*?(?:${BEL}|${ESC}\\\\)`, 'g')
/** CSI: ESC [ parametry … koncový znak (barvy, pozice kurzoru) */
const CSI = new RegExp(`${ESC}\\[[0-9;:?<>=]*[ -/]*[@-~]`, 'g')
/** Ostatní dvouznakové escape sekvence */
const ESC_SHORT = new RegExp(`${ESC}[@-Z\\\\-_]`, 'g')
/** Zbylé řídicí znaky kromě \n (0x0A) a \t (0x09) */
const CONTROL = new RegExp('[\u0000-\u0008\u000B-\u001F\u007F]', 'g')

export function cleanTerminalText(raw: string): string {
  let text = raw.replace(OSC, '').replace(CSI, '').replace(ESC_SHORT, '')

  text = text.replace(/\r\n/g, '\n')

  // Samotné \r vrací kurzor na začátek řádku – bereme poslední přepis.
  if (text.includes('\r')) {
    text = text
      .split('\n')
      .map((line) => {
        if (!line.includes('\r')) return line
        const parts = line.split('\r')
        return parts[parts.length - 1]
      })
      .join('\n')
  }

  // Backspace maže předchozí znak; jeden průchod pokryje běžné případy.
  if (text.includes(BACKSPACE)) {
    text = text.replace(new RegExp(`[^\\n]${BACKSPACE}`, 'g'), '')
  }

  return text.replace(CONTROL, '')
}

/** Ponechá posledních `maxLines` řádků (0 = bez omezení). */
export function tailLines(text: string, maxLines: number): string {
  if (!maxLines || maxLines <= 0) return text
  const lines = text.split('\n')
  return lines.length <= maxLines ? text : lines.slice(-maxLines).join('\n')
}

/**
 * Zviditelní řídicí znaky v příkazu, který schvaluješ – aby se v něm nedal
 * schovat skrytý řádek navíc.
 */
export function visualizeControlChars(text: string): string {
  return (
    text
      .replace(new RegExp(ESC, 'g'), '␛')
      .replace(/\n/g, '␊\n')
      .replace(/\r/g, '␍')
      .replace(/\t/g, '→')
      .replace(new RegExp('[\u0000-\u0008\u000B-\u001F\u007F]', 'g'), '␦')
      // C1 controls. They arrive as single code points from UTF-8 sources and
      // were passing through untouched, unlike their C0 equivalents above.
      .replace(/[\u0080-\u009F]/g, '␦')
      // Bidi controls: RTL/LTR overrides, embeddings, isolates and the pop
      // markers. These do not print — they reorder. Left invisible, a command
      // can render as one thing and execute as another, which is exactly what
      // this dialog exists to prevent. `unicode-bidi: plaintext` on the box
      // handles the rendering; marking them makes the tampering visible rather
      // than merely neutralised.
      .replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g, '␤')
      // Zero-width and invisible formatting: ZWSP, ZWNJ, ZWJ, word joiner,
      // invisible operators, BOM/ZWNBSP and the Mongolian vowel separator.
      // An invisible character in a command is only ever there to mislead a
      // reader — the shell does not need it.
      .replace(/[\u200B-\u200D\u2060-\u2064\uFEFF\u180E]/g, '␣')
      // Unicode tag characters. Deprecated, invisible everywhere, and a known
      // channel for smuggling text past human review.
      .replace(/[\u{E0000}-\u{E007F}]/gu, '␦')
  )
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Terminal escape handling. `src/main/ansi.ts` is the last filter between a
 * remote host's bytes and the text a human reads before approving a command.
 * Both failure directions are tested equally: too little cleaning lets remote
 * text reach the reader disguised as trustworthy output, too much mangles
 * ordinary output and teaches the user to stop reading the dialog at all.
 *
 * Control characters are written as escapes on purpose — raw bytes in a source
 * file are invisible and do not survive editors reliably.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

import { cleanTerminalText, tailLines, visualizeControlChars } from '../src/main/ansi.ts'

const ESC = ''
const BEL = ''
const BS = ''
/** String Terminator, the two-character form: ESC \ */
const ST = `${ESC}\\`
/** Single-byte C1 CSI introducer. */
const CSI1 = ''

const MARK_CTRL = '␦'
const MARK_BIDI = '␤'
const MARK_INVISIBLE = '␣'

/** Names the code point in an assertion message. */
const u = (ch: string): string =>
  `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`

/** Bidi controls: overrides, embeddings, isolates and the marks. */
const BIDI = [
  '‪', '‫', '‬', '‭', '‮',
  '⁦', '⁧', '⁨', '⁩',
  '‎', '‏', '؜'
]

/** Zero-width joiners, invisible operators, BOM, Mongolian vowel separator. */
const INVISIBLE = [
  '​', '‌', '‍',
  '⁠', '⁡', '⁢', '⁣', '⁤',
  '﻿', '᠎'
]

describe('cleanTerminalText: ordinary output survives', () => {
  test('plain text passes through untouched', () => {
    const text = 'total 24\ndrwxr-xr-x  3 root root 4096 Jan  1 00:00 .\n'
    assert.equal(cleanTerminalText(text), text)
  })

  test('tabs and newlines are preserved', () => {
    assert.equal(cleanTerminalText('a\tb\nc'), 'a\tb\nc')
  })

  test('unicode text is untouched', () => {
    const text = 'příliš žluťoučký kůň — 日本語'
    assert.equal(cleanTerminalText(text), text)
  })

  test('an empty string stays empty', () => {
    assert.equal(cleanTerminalText(''), '')
  })
})

describe('cleanTerminalText: OSC sequences', () => {
  test('removes a BEL-terminated OSC whole', () => {
    assert.equal(cleanTerminalText(`before${ESC}]0;window title${BEL}after`), 'beforeafter')
  })

  test('removes an ST-terminated OSC whole', () => {
    assert.equal(cleanTerminalText(`before${ESC}]0;window title${ST}after`), 'beforeafter')
  })

  test('an unterminated OSC does not leak its payload', () => {
    // Falling through to the two-character rule would display the payload as
    // ordinary output: a remote host writing into the approval dialog.
    const out = cleanTerminalText(`${ESC}]0;root@host:~# rm -rf /`)
    assert.equal(out, '')
    assert.ok(!out.includes('rm -rf'))
  })

  test('an unterminated OSC does not swallow a preceding valid sequence', () => {
    assert.equal(cleanTerminalText(`ok${ESC}]0;t${BEL}fine${ESC}]leak`), 'okfine')
  })
})

describe('cleanTerminalText: DCS / APC / PM / SOS string sequences', () => {
  const introducers: [string, string][] = [
    ['DCS', 'P'],
    ['APC', '_'],
    ['PM', '^'],
    ['SOS', 'X']
  ]

  for (const [name, intro] of introducers) {
    test(`${name} payload is removed, not displayed`, () => {
      const out = cleanTerminalText(`ok${ESC}${intro}root@host:~# rm -rf /${ST}done`)
      assert.equal(out, 'okdone')
      assert.ok(!out.includes('rm -rf'))
    })

    test(`an unterminated ${name} does not leak its payload`, () => {
      assert.equal(cleanTerminalText(`ok${ESC}${intro}secret payload`), 'ok')
    })
  }

  test('a DCS payload cannot forge an extra line of output', () => {
    const forged = `real${ESC}P\nverification passed${ST}\nend`
    const out = cleanTerminalText(forged)
    assert.ok(!out.includes('verification passed'))
    assert.equal(out, 'real\nend')
  })
})

describe('cleanTerminalText: CSI sequences', () => {
  test('removes colour codes', () => {
    assert.equal(cleanTerminalText(`${ESC}[31mred${ESC}[0m`), 'red')
  })

  test('removes cursor positioning', () => {
    assert.equal(cleanTerminalText(`${ESC}[2J${ESC}[Hclear`), 'clear')
  })

  test('removes private-mode sequences', () => {
    assert.equal(cleanTerminalText(`${ESC}[?25la${ESC}[?25h`), 'a')
  })

  test('removes sequences with intermediate bytes', () => {
    assert.equal(cleanTerminalText(`${ESC}[1 qtext`), 'text')
  })

  test('removes the single-byte C1 CSI form', () => {
    // U+009B is CSI in one byte, handled separately from the ESC [ form.
    assert.equal(cleanTerminalText(`a${CSI1}31mb`), 'ab')
  })

  test('an incomplete CSI loses its ESC and its introducer', () => {
    const out = cleanTerminalText(`${ESC}[31`)
    assert.ok(!out.includes(ESC))
    assert.ok(!out.includes('['))
  })
})

describe('cleanTerminalText: two-character and charset escapes', () => {
  test('removes ESC M, ESC D and ESC E whole', () => {
    assert.equal(cleanTerminalText(`a${ESC}Mb${ESC}Dc${ESC}Ed`), 'abcd')
  })

  test('removes a stray ST whole', () => {
    assert.equal(cleanTerminalText(`a${ST}b`), 'ab')
  })

  test('removes a lone trailing ESC', () => {
    assert.equal(cleanTerminalText(`text${ESC}`), 'text')
  })

  test('cursor save and restore leave no stray digit', () => {
    // ESC 7 / ESC 8 pour out of vim, less and anything ncurses. Stripping the
    // ESC alone leaves the digit behind, reading as output the host never sent.
    assert.equal(cleanTerminalText(`a${ESC}7b${ESC}8c`), 'abc')
  })

  test('keypad mode escapes leave no stray symbol', () => {
    assert.equal(cleanTerminalText(`a${ESC}=b${ESC}>c`), 'abc')
  })

  test('charset designation is removed whole, including its third byte', () => {
    assert.equal(cleanTerminalText(`a${ESC}(Bb${ESC})0c`), 'abc')
  })
})

describe('cleanTerminalText: carriage return handling', () => {
  test('CRLF becomes LF', () => {
    assert.equal(cleanTerminalText('a\r\nb'), 'a\nb')
  })

  test('a bare CR keeps only the final overwrite', () => {
    assert.equal(cleanTerminalText('  0%\r 50%\r100%'), '100%')
  })

  test('a line ending in a lone CR keeps its text', () => {
    // On a real terminal CR only moves the cursor, so the text stays on screen.
    // Dropping the line would let one byte hide it from the reviewer.
    assert.equal(cleanTerminalText('important warning\r'), 'important warning')
  })

  test('trailing CRs do not eat ordinary progress output', () => {
    assert.equal(cleanTerminalText('  0%\r100%\r'), '100%')
  })

  test('CR handling is per line', () => {
    assert.equal(cleanTerminalText('a\rb\nc\rd'), 'b\nd')
  })

  test('a line that is only a CR collapses to empty', () => {
    assert.equal(cleanTerminalText('\r'), '')
  })
})

describe('cleanTerminalText: backspace', () => {
  test('a backspace removes the preceding character', () => {
    assert.equal(cleanTerminalText(`ab${BS}c`), 'ac')
  })

  test('a backspace does not eat across a newline', () => {
    assert.equal(cleanTerminalText(`a\n${BS}b`), 'a\nb')
  })
})

describe('cleanTerminalText: control and invisible characters', () => {
  test('C0 controls are stripped, tab and newline survive', () => {
    for (let code = 0x00; code <= 0x1f; code++) {
      if (code === 0x09 || code === 0x0a) continue
      const ch = String.fromCharCode(code)
      assert.ok(!cleanTerminalText(`a${ch}b`).includes(ch), `${u(ch)} survived`)
    }
  })

  test('DEL is stripped', () => {
    assert.equal(cleanTerminalText('ab'), 'ab')
  })

  test('C1 controls are stripped', () => {
    // Nothing downstream catches a leak here: the visualizer only ever sees
    // commands, never output.
    for (let code = 0x80; code <= 0x9f; code++) {
      const ch = String.fromCharCode(code)
      assert.ok(!cleanTerminalText(`a${ch}b`).includes(ch), `${u(ch)} survived`)
    }
  })

  test('bidi overrides and isolates are stripped', () => {
    for (const ch of BIDI) {
      assert.equal(cleanTerminalText(`a${ch}b`), 'ab', `${u(ch)} survived`)
    }
  })

  test('zero-width and invisible formatting is stripped', () => {
    for (const ch of INVISIBLE) {
      assert.equal(cleanTerminalText(`a${ch}b`), 'ab', `${u(ch)} survived`)
    }
  })

  test('unicode tag characters are stripped', () => {
    assert.equal(cleanTerminalText('ls\u{e0041}\u{e0042}'), 'ls')
  })

  test('printable ASCII is never touched', () => {
    for (let code = 0x20; code <= 0x7e; code++) {
      const ch = String.fromCharCode(code)
      assert.equal(cleanTerminalText(ch), ch, `${u(ch)} was altered`)
    }
  })
})

describe('tailLines', () => {
  test('returns the last n lines', () => {
    assert.equal(tailLines('a\nb\nc\nd', 2), 'c\nd')
  })

  test('returns everything when there are fewer lines than the limit', () => {
    assert.equal(tailLines('a\nb', 5), 'a\nb')
  })

  test('returns everything at exactly the limit', () => {
    assert.equal(tailLines('a\nb\nc', 3), 'a\nb\nc')
  })

  test('zero and negative mean no limit', () => {
    assert.equal(tailLines('a\nb\nc', 0), 'a\nb\nc')
    assert.equal(tailLines('a\nb\nc', -1), 'a\nb\nc')
  })

  test('handles an empty string', () => {
    assert.equal(tailLines('', 3), '')
  })
})

describe('visualizeControlChars', () => {
  test('an ordinary command is returned unchanged', () => {
    assert.equal(visualizeControlChars('ls -la /var/log'), 'ls -la /var/log')
  })

  test('marks ESC, CR and tab, and keeps the newline visible', () => {
    assert.equal(visualizeControlChars(ESC), '␛')
    assert.equal(visualizeControlChars('\r'), '␍')
    assert.equal(visualizeControlChars('\t'), '→')
    assert.equal(visualizeControlChars('\n'), '␊\n')
  })

  test('a CR-hidden second command is made visible but still readable', () => {
    const out = visualizeControlChars('ls -la\rrm -rf ~')
    assert.ok(out.includes('␍'))
    assert.ok(out.includes('rm -rf ~'), 'the hidden command must remain readable')
  })

  test('marks every C0 control and DEL', () => {
    for (let code = 0x00; code <= 0x1f; code++) {
      if (code === 0x09 || code === 0x0a || code === 0x0d || code === 0x1b) continue
      const ch = String.fromCharCode(code)
      assert.equal(visualizeControlChars(ch), MARK_CTRL, `${u(ch)} not marked`)
    }
    assert.equal(visualizeControlChars(''), MARK_CTRL)
  })

  test('marks every C1 control', () => {
    for (let code = 0x80; code <= 0x9f; code++) {
      const ch = String.fromCharCode(code)
      assert.equal(visualizeControlChars(ch), MARK_CTRL, `${u(ch)} not marked`)
    }
  })

  test('marks bidi overrides — the Trojan Source vector', () => {
    for (const ch of BIDI) {
      assert.equal(visualizeControlChars(ch), MARK_BIDI, `${u(ch)} not marked`)
    }
  })

  test('marks zero-width and invisible formatting', () => {
    for (const ch of INVISIBLE) {
      assert.equal(visualizeControlChars(ch), MARK_INVISIBLE, `${u(ch)} not marked`)
    }
  })

  test('marks unicode tag characters', () => {
    assert.equal(visualizeControlChars('\u{e0041}'), MARK_CTRL)
    assert.equal(visualizeControlChars('ls\u{e0041}\u{e0042}'), `ls${MARK_CTRL}${MARK_CTRL}`)
  })

  test('a bidi-reordered command is visibly marked', () => {
    const trojan = 'rm ‮ gnp. ‭ evil'
    const out = visualizeControlChars(trojan)
    assert.ok(out.includes(MARK_BIDI))
    assert.ok(!out.includes('‮'))
  })

  test('printable ASCII is never marked', () => {
    for (let code = 0x20; code <= 0x7e; code++) {
      const ch = String.fromCharCode(code)
      assert.equal(visualizeControlChars(ch), ch, `${u(ch)} was altered`)
    }
  })
})

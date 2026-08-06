// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import {
  forget,
  registerSelection,
  terminalSelection,
  type SelectionSource
} from '../src/renderer/src/terminalBus.ts'

function fakeSource(text: string): SelectionSource {
  return {
    read: () => text,
    subscribe: () => () => {},
    clear: () => {}
  }
}

describe('registr výběru z terminálu', () => {
  it('vrátí, co bylo zaregistrováno', () => {
    const source = fakeSource('ahoj')
    const off = registerSelection('s1', source)
    assert.equal(terminalSelection('s1'), source)
    assert.equal(terminalSelection('s1')?.read(), 'ahoj')
    off()
  })

  it('neznámá relace nemá výběr', () => {
    assert.equal(terminalSelection('neexistuje'), null)
  })

  /*
   * The share dialog offers "select in the console" only when this returns
   * something, so session teardown must clear this registry and not just the
   * data sinks — otherwise the button comes back pointing at a disposed xterm.
   */
  it('forget zahodí i výběr, ne jen sinky', () => {
    registerSelection('s2', fakeSource('x'))
    assert.notEqual(terminalSelection('s2'), null)
    forget('s2')
    assert.equal(terminalSelection('s2'), null)
  })

  /*
   * React can mount the replacement before the old component's cleanup runs, so
   * unregistering by key alone drops the terminal that is actually on screen and
   * silently kills console selection for a live session.
   */
  it('odhlášení staré instance nesmí smazat novou', () => {
    const older = fakeSource('starý')
    const newer = fakeSource('nový')
    const offOlder = registerSelection('s3', older)
    const offNewer = registerSelection('s3', newer)

    offOlder()

    assert.equal(terminalSelection('s3'), newer, 'nová instance musí přežít')
    offNewer()
    assert.equal(terminalSelection('s3'), null)
  })

  it('odhlášení je idempotentní', () => {
    const source = fakeSource('x')
    const off = registerSelection('s4', source)
    off()
    off()
    assert.equal(terminalSelection('s4'), null)
  })

  it('relace se navzájem nemíchají', () => {
    const a = fakeSource('a')
    const b = fakeSource('b')
    registerSelection('s5a', a)
    registerSelection('s5b', b)
    assert.equal(terminalSelection('s5a')?.read(), 'a')
    assert.equal(terminalSelection('s5b')?.read(), 'b')
    forget('s5a')
    assert.equal(terminalSelection('s5a'), null)
    assert.equal(terminalSelection('s5b')?.read(), 'b')
    forget('s5b')
  })
})

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The activity throttle behind auto-lock.
 *
 * A renderer file, but the logic is a pure function over `Date.now()` and a
 * callback, so it needs no DOM — which is the only reason it can be tested at
 * all. The rest of the renderer has no harness.
 *
 * What is at stake: every report re-arms the auto-lock timer in the main
 * process. Report too often and typing costs hundreds of IPC messages; report
 * too rarely — or not at all — and the vault locks with the user's hands on the
 * keyboard.
 */

import { describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'

const { reportActivity, resetActivityThrottle, ACTIVITY_INTERVAL_MS } = await import(
  '../src/renderer/src/activity.ts'
)

/** Counts the reports that actually reached the main process. */
function spy(): { sent: () => number; send: () => void } {
  let n = 0
  return { sent: () => n, send: () => n++ }
}

describe('reportActivity', () => {
  test('the first report after a quiet stretch goes straight through', (t) => {
    // Leading edge: the first event after a pause is the moment the human came
    // back, and it must not wait for a timer before the lock is deferred.
    mock.timers.enable({ apis: ['Date'] })
    t.after(() => mock.timers.reset())
    resetActivityThrottle()
    const s = spy()

    reportActivity(s.send)
    assert.equal(s.sent(), 1, 'the first report was swallowed')
  })

  test('a burst of typing costs one message, not one per keystroke', (t) => {
    mock.timers.enable({ apis: ['Date'] })
    t.after(() => mock.timers.reset())
    resetActivityThrottle()
    const s = spy()

    for (let i = 0; i < 200; i++) reportActivity(s.send)
    assert.equal(s.sent(), 1, `a 200-key burst sent ${s.sent()} messages`)
  })

  test('reports resume once the interval has passed', (t) => {
    mock.timers.enable({ apis: ['Date'] })
    t.after(() => mock.timers.reset())
    resetActivityThrottle()
    const s = spy()

    reportActivity(s.send)
    mock.timers.tick(ACTIVITY_INTERVAL_MS - 1)
    reportActivity(s.send)
    assert.equal(s.sent(), 1, 'the throttle let a report through early')

    mock.timers.tick(1)
    reportActivity(s.send)
    assert.equal(s.sent(), 2, 'the throttle never opened again')
  })

  test('a clock step backwards does not wedge it shut', (t) => {
    // Date.now() is wall clock, not monotonic. NTP correcting a drifted
    // machine, a VM resuming from a snapshot or a timezone change all step it
    // backwards, and a negative elapsed time is forever below the interval --
    // so the throttle swallowed every report until the clock caught up. With
    // nothing reaching the main process the auto-lock timer is never re-armed,
    // and the vault locks while the user is typing into it.
    // `setTime` refuses a negative epoch, so the fixture starts far enough in
    // for a backwards hour to stay positive.
    const start = 4 * 60 * 60 * 1000
    mock.timers.enable({ apis: ['Date'], now: start })
    t.after(() => mock.timers.reset())
    resetActivityThrottle()
    const s = spy()

    reportActivity(s.send)
    assert.equal(s.sent(), 1, 'fixture: the first report should go through')

    // The clock jumps back an hour, then the user keeps typing.
    mock.timers.setTime(start - 60 * 60 * 1000)
    reportActivity(s.send)
    assert.equal(s.sent(), 2, 'a backwards clock step silenced the throttle')

    // And it still throttles afterwards rather than reporting every keystroke.
    reportActivity(s.send)
    assert.equal(s.sent(), 2, 'the throttle stopped throttling after the jump')
  })

  test('resetting it lets the next report through immediately', (t) => {
    // Called when the vault locks: the keypress that brings the user back must
    // reach the main process rather than landing inside a window that started
    // before they walked away.
    mock.timers.enable({ apis: ['Date'] })
    t.after(() => mock.timers.reset())
    resetActivityThrottle()
    const s = spy()

    reportActivity(s.send)
    reportActivity(s.send)
    assert.equal(s.sent(), 1, 'fixture: the second report should be throttled')

    resetActivityThrottle()
    reportActivity(s.send)
    assert.equal(s.sent(), 2, 'a reset did not open the throttle')
  })
})

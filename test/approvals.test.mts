// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The MCP approval gate: the cap, the window raise, and the timeout.
 *
 * Unlike vault.test.mts and ssh.test.mts this file needs no `mock.module`.
 * `src/main/approvals.ts` has no runtime imports at all, which is the reason
 * the queue was moved out of `src/main/index.ts`: that file exports nothing
 * and calls `app.requestSingleInstanceLock()` at module scope, so none of this
 * was reachable from a test while it lived there.
 *
 * NOT covered here, and it cannot be: the 400 ms arm delay on the dialog
 * buttons (`src/renderer/src/armDelay.ts`). It needs a DOM, a React renderer
 * and real animation frames, none of which this harness has. See the manual
 * check at the bottom of this file.
 */

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import type { CommandApproval, ShareRequest } from '../src/shared/types.ts'
import {
  ApprovalQueue,
  APPROVAL_TIMEOUT_MS,
  FOCUS_QUIET_MS,
  MAX_PENDING_APPROVALS,
  isQueueFull
} from '../src/main/approvals.ts'

/* ------------------------------------------------------------------ nářadí */

let seq = 0

function command(): CommandApproval {
  seq += 1
  return {
    id: `cmd-${seq}`,
    sessionId: 'sess-1',
    sessionName: 'prod-db',
    command: 'uptime',
    commandVisualized: 'uptime',
    reason: 'checking the load'
  }
}

function share(origin: ShareRequest['origin'] = 'read_terminal'): ShareRequest {
  seq += 1
  return {
    id: `share-${seq}`,
    sessionId: 'sess-1',
    sessionName: 'prod-db',
    reason: 'reading the deploy log',
    origin,
    text: 'nothing secret here'
  }
}

/** Records what the queue asked the window to do, in order. */
function spyHost() {
  const sentCommands: CommandApproval[] = []
  const sentShares: ShareRequest[] = []
  let raises = 0
  return {
    sentCommands,
    sentShares,
    raises: () => raises,
    host: {
      sendCommand: (req: CommandApproval) => {
        sentCommands.push(req)
      },
      sendShare: (req: ShareRequest) => {
        sentShares.push(req)
      },
      raiseWindow: () => {
        raises += 1
      }
    }
  }
}

/** A bound queue plus its spy — no test wants one without the other. */
function fresh() {
  const spy = spyHost()
  const queue = new ApprovalQueue()
  queue.bind(spy.host)
  return { queue, spy }
}

/* --------------------------------------------------------------- strop */

test('the request past the cap is refused and leaves no record behind', async () => {
  const { queue, spy } = fresh()

  const pending = []
  for (let i = 0; i < MAX_PENDING_APPROVALS; i++) pending.push(queue.askCommand(command()))
  assert.equal(queue.size(), MAX_PENDING_APPROVALS, 'the queue refused its own allowance')

  const refused = command()
  await assert.rejects(
    () => queue.askCommand(refused),
    isQueueFull,
    'the request past the cap was accepted'
  )

  assert.equal(queue.size(), MAX_PENDING_APPROVALS, 'the refused request took a slot anyway')
  assert.equal(
    spy.sentCommands.length,
    MAX_PENDING_APPROVALS,
    'the refused request was still sent to the window'
  )
  assert.ok(
    !spy.sentCommands.some((r) => r.id === refused.id),
    'the refused request reached the renderer as a dialog'
  )

  queue.rejectAll()
  for (const p of pending) {
    assert.deepEqual(await p, { approved: false, autoShare: false })
  }
  assert.equal(queue.size(), 0, 'rejectAll() left records behind')
})

test('the share that completes an approved command is exempt from the cap', async () => {
  const { queue, spy } = fresh()

  const pending = []
  for (let i = 0; i < MAX_PENDING_APPROVALS; i++) pending.push(queue.askCommand(command()))

  // A read_terminal share is a fresh demand on the human, so it is refused.
  await assert.rejects(
    () => queue.askShare(share('read_terminal')),
    isQueueFull,
    'a full queue accepted a new read_terminal share'
  )

  // The output of a command they already approved is not: their click bought
  // that slot, and dropping it would waste an approval already given.
  const followUp = share('command_output')
  pending.push(queue.askShare(followUp))
  assert.equal(queue.size(), MAX_PENDING_APPROVALS + 1, 'the follow-up share was refused')
  assert.equal(spy.sentShares.length, 1, 'the follow-up share never reached the window')
  assert.equal(spy.sentShares[0].id, followUp.id, 'the wrong share was delivered')

  queue.rejectAll()
  await Promise.all(pending)
})

/* ---------------------------------------------------------------- fokus */

test('the window is raised once for a batch, not once per request', async () => {
  const { queue, spy } = fresh()

  const pending = [
    queue.askCommand(command()),
    queue.askCommand(command()),
    queue.askShare(share())
  ]
  assert.equal(queue.size(), 3, 'the three rapid requests were not all queued')
  assert.equal(spy.raises(), 1, `one batch raised the window ${spy.raises()} times`)

  queue.rejectAll()
  await Promise.all(pending)
})

test('a raise needs an empty queue and a quiet window, not just an empty queue', async (t) => {
  mock.timers.enable({ apis: ['setTimeout', 'Date'] })
  t.after(() => mock.timers.reset())
  const { queue, spy } = fresh()

  const first = command()
  const firstAnswer = queue.askCommand(first)
  assert.equal(spy.raises(), 1, 'the first request of a batch did not raise the window')

  queue.answerCommand(first.id, false, false)
  await firstAnswer
  assert.equal(queue.size(), 0, 'answering did not empty the queue')

  // Emptying the queue is the human clicking Deny. A client that fires again
  // straight away must not get a second flashFrame out of that same click.
  mock.timers.tick(FOCUS_QUIET_MS - 1)
  const second = command()
  const secondAnswer = queue.askCommand(second)
  assert.equal(spy.raises(), 1, 'the window was raised again inside the quiet window')

  queue.answerCommand(second.id, false, false)
  await secondAnswer
  mock.timers.tick(FOCUS_QUIET_MS)
  const third = queue.askCommand(command())
  assert.equal(spy.raises(), 2, 'the window never raised again after the quiet window passed')

  queue.rejectAll()
  await third
})

/* -------------------------------------------------------------- účetnictví */

test('a timed-out request denies the call and hands its slot back', async (t) => {
  mock.timers.enable({ apis: ['setTimeout', 'Date'] })
  t.after(() => mock.timers.reset())
  const { queue } = fresh()

  const answer = queue.askCommand(command())
  mock.timers.tick(APPROVAL_TIMEOUT_MS - 1)
  assert.equal(queue.size(), 1, 'the record vanished before the timeout was up')

  mock.timers.tick(1)
  assert.deepEqual(await answer, { approved: false, autoShare: false }, 'the timeout approved')
  assert.equal(queue.size(), 0, 'the timed-out record kept its slot')

  // The cap must not be a one-way ratchet: a slot freed by the timer is usable.
  const next = queue.askCommand(command())
  assert.equal(queue.size(), 1, 'a slot freed by the timeout stayed occupied')
  queue.rejectAll()
  await next
})

test('answering the same id twice resolves once and frees exactly one slot', async () => {
  const { queue } = fresh()

  const req = command()
  const answer = queue.askCommand(req)
  const other = queue.askCommand(command())

  queue.answerCommand(req.id, true, false)
  queue.answerCommand(req.id, false, false)
  assert.deepEqual(await answer, { approved: true, autoShare: false }, 'the second answer won')
  assert.equal(queue.size(), 1, 'a repeated answer freed a slot that was not its own')

  queue.answerCommand('never-issued', true, true)
  assert.equal(queue.size(), 1, 'an unknown id changed the queue')

  queue.rejectAll()
  await other
})

/*
 * Manual check for the renderer half (`useArmedAfterPaint`, 400 ms):
 *
 *  1. `npm run dev`, unlock, connect a session, enable MCP.
 *  2. Drive run_command from a client. When the dialog appears, "Run the
 *     command" must be visibly dimmed (`.btn:disabled`, opacity 0.45) and must
 *     not respond to a click or to Enter for the first ~400 ms.
 *  3. Deny it and immediately fire a second run_command: the second dialog
 *     must arrive unarmed too, so a double-click on Deny cannot approve it.
 *  4. Minimise the window while a dialog is up, restore it: the button must be
 *     unarmed again for 400 ms after it becomes visible.
 */


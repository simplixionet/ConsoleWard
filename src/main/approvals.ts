// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The approval queue between the MCP tools and the window.
 *
 * It owns the cap and the window raise as well as the records, because both
 * decisions are functions of the queue's size: `mcp.ts` cannot see it, and
 * while this lived in `index.ts` nothing could reach it — that file exports
 * nothing and calls `app.requestSingleInstanceLock()` at module scope. Nothing
 * here imports Electron, and that is the point: the gate is the part that has
 * to be tested.
 */

import type { CommandApproval, ShareRequest } from '../shared/types'

export interface CommandAnswer {
  approved: boolean
  autoShare: boolean
}

export interface ShareAnswer {
  shared: boolean
  text: string
}

/** The window half of the queue; `index.ts` supplies the Electron calls. */
export interface ApprovalHost {
  sendCommand: (req: CommandApproval) => void
  sendShare: (req: ShareRequest) => void
  /** Restore, show, focus and — on Windows — flash the frame. */
  raiseWindow: () => void
}

/**
 * The queue is the human's attention, not a buffer. Three is roughly what a
 * person can hold at once; past that a client is talking over itself, and the
 * honest answer is to refuse rather than to store the request, arm a timer for
 * it and yank the window forward on its behalf.
 */
export const MAX_PENDING_APPROVALS = 3

/** No answer within five minutes: deny, rather than leave the call hanging. */
export const APPROVAL_TIMEOUT_MS = 5 * 60_000

/**
 * A batch is one raise per stretch of pending work, plus this much quiet after
 * it drains. Without the tail a client raises the window again the instant the
 * human answers the last dialog — on Windows that is `flashFrame` in a loop,
 * driven by the human's own clicks.
 */
export const FOCUS_QUIET_MS = 5_000

/** Refusal by the cap. `mcp.ts` turns this into a tool error for the model. */
export class ApprovalQueueFullError extends Error {
  constructor() {
    super(`Too many approvals are already pending (limit ${MAX_PENDING_APPROVALS}).`)
    this.name = 'ApprovalQueueFullError'
  }
}

/** Matches on the name, so it survives a bundler that duplicates the class. */
export function isQueueFull(err: unknown): boolean {
  return err instanceof Error && err.name === 'ApprovalQueueFullError'
}

interface Pending<T> {
  resolve: (value: T) => void
  timer: NodeJS.Timeout
}

export class ApprovalQueue {
  private host: ApprovalHost | null = null
  private commands = new Map<string, Pending<CommandAnswer>>()
  private shares = new Map<string, Pending<ShareAnswer>>()
  /**
   * -Infinity, not 0: a clock reading 0 — a fake one in a test, or a machine
   * whose time has not been set yet — would otherwise swallow the very first
   * raise, and the first raise is the one that matters.
   */
  private lastRaiseAt = Number.NEGATIVE_INFINITY

  bind(host: ApprovalHost): void {
    this.host = host
  }

  size(): number {
    return this.commands.size + this.shares.size
  }

  async askCommand(req: CommandApproval): Promise<CommandAnswer> {
    this.admit()
    const raise = this.shouldRaise()
    return new Promise<CommandAnswer>((resolve) => {
      const timer = setTimeout(() => {
        if (this.commands.delete(req.id)) resolve({ approved: false, autoShare: false })
      }, APPROVAL_TIMEOUT_MS)
      this.commands.set(req.id, { resolve, timer })
      this.host?.sendCommand(req)
      if (raise) this.raise()
    })
  }

  async askShare(req: ShareRequest): Promise<ShareAnswer> {
    // The output half of a run_command the human already approved and which has
    // already run. Their click bought this slot, so refusing it here would
    // throw away an approval they already gave — and would hand a client a way
    // to silence an answer by flooding the queue while the command executes.
    if (req.origin !== 'command_output') this.admit()
    // A forced dialog is the one case where the human was explicitly promised
    // no dialog at all. It jumps the quiet window — otherwise it can sit behind
    // the terminal until the five-minute timer denies it on their behalf, and
    // they never learn a credential was about to be sent.
    const raise = req.autoShareOverridden === true || this.shouldRaise()
    return new Promise<ShareAnswer>((resolve) => {
      const timer = setTimeout(() => {
        if (this.shares.delete(req.id)) resolve({ shared: false, text: '' })
      }, APPROVAL_TIMEOUT_MS)
      this.shares.set(req.id, { resolve, timer })
      this.host?.sendShare(req)
      if (raise) this.raise()
    })
  }

  answerCommand(id: string, approved: boolean, autoShare: boolean): void {
    const pending = this.commands.get(id)
    if (!pending) return
    this.commands.delete(id)
    clearTimeout(pending.timer)
    pending.resolve({ approved: Boolean(approved), autoShare: Boolean(autoShare) })
  }

  answerShare(id: string, shared: boolean, text: string): void {
    const pending = this.shares.get(id)
    if (!pending) return
    this.shares.delete(id)
    clearTimeout(pending.timer)
    pending.resolve({ shared: Boolean(shared), text: shared ? String(text ?? '') : '' })
  }

  rejectAll(): void {
    for (const [, p] of this.commands) {
      clearTimeout(p.timer)
      p.resolve({ approved: false, autoShare: false })
    }
    this.commands.clear()
    for (const [, p] of this.shares) {
      clearTimeout(p.timer)
      p.resolve({ shared: false, text: '' })
    }
    this.shares.clear()
    // Lock and quit end the batch. Whatever arrives afterwards is a new one and
    // may raise the window again — the user comes back to an app showing nothing.
    this.lastRaiseAt = Number.NEGATIVE_INFINITY
  }

  /** Refuses before anything is stored, so a rejected request leaves no trace. */
  private admit(): void {
    if (this.size() >= MAX_PENDING_APPROVALS) throw new ApprovalQueueFullError()
  }

  /**
   * Read before the record is inserted, so the new request does not count
   * itself. `Date.now()` is not monotonic, so a clock that jumps can move this
   * either way: backwards suppresses a raise, forwards ends the quiet window
   * early and allows one. Both are harmless at the scale of a single window
   * raise. `performance.now()` would be monotonic but node's MockTimers cannot
   * advance it, which would make the quiet window untestable.
   */
  private shouldRaise(): boolean {
    if (this.size() > 0) return false
    return Date.now() - this.lastRaiseAt >= FOCUS_QUIET_MS
  }

  private raise(): void {
    this.lastRaiseAt = Date.now()
    this.host?.raiseWindow()
  }
}

export const approvals = new ApprovalQueue()

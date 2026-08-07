// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The approval queue between the MCP tools and the window. It owns the cap and
 * the window raise because both decisions are functions of the queue's size.
 * Nothing here imports Electron, deliberately: the gate has to be testable.
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

/** `index.ts` supplies the Electron calls. */
export interface ApprovalHost {
  sendCommand: (req: CommandApproval) => void
  sendShare: (req: ShareRequest) => void
  /** Restore, show, focus and — on Windows — flash the frame. */
  raiseWindow: () => void
}

/**
 * The queue is the human's attention, not a buffer. Past three, refusing is more
 * honest than storing the request, arming a timer and raising the window for it.
 */
export const MAX_PENDING_APPROVALS = 3

/**
 * No answer within this long: deny, rather than leave the call hanging.
 *
 * Fifteen minutes, not the five it was. Five is enough to answer a dialog you
 * were already looking at, and not enough for what these dialogs actually ask:
 * read a command you did not write, or scroll through terminal output, decide
 * what part of it a model may see, and edit it down. Someone doing that
 * carefully was being denied mid-edit, and the denial reads to the model as a
 * refusal rather than as a clock running out.
 *
 * Fifteen also matches the default auto-lock, which is the real ceiling: a lock
 * runs `rejectAll()`, so an approval can never outlive the vault it belongs to
 * however high this goes. Setting it far past the lock would only invent a
 * timeout nobody ever reaches.
 *
 * Waiting no longer costs a client its call — the MCP transport streams and
 * keeps the connection warm, see the transport comment in mcp.ts — so this is
 * now bounded by the human, not by whichever timeout expires first.
 */
export const APPROVAL_TIMEOUT_MS = 15 * 60_000

/**
 * Quiet tail after the queue drains. Without it a client raises the window again
 * the instant the human answers — `flashFrame` in a loop driven by their clicks.
 */
export const FOCUS_QUIET_MS = 5_000

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
  /** -Infinity, not 0: a zero clock would swallow the first raise, the one that matters. */
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
    // Exempt from the cap: the human already approved the command that produced
    // this output. Refusing here would also let a client silence an answer by
    // flooding the queue while the command runs.
    if (req.origin !== 'command_output') this.admit()
    // A forced dialog jumps the quiet window: the human was promised no dialog,
    // so one left behind the terminal would time out into a denial unseen.
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
    // Lock and quit end the batch, so the next request may raise the window again.
    this.lastRaiseAt = Number.NEGATIVE_INFINITY
  }

  /** Refuses before anything is stored, so a rejected request leaves no trace. */
  private admit(): void {
    if (this.size() >= MAX_PENDING_APPROVALS) throw new ApprovalQueueFullError()
  }

  /**
   * Must be read before the record is inserted, or the new request counts itself
   * and never raises. `Date.now()` because node's MockTimers cannot advance
   * `performance.now()`; a clock jump costs at most one window raise.
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

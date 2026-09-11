// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The record of what the AI did, one encrypted file per session.
 *
 * This is the half that makes unattended mode a trade rather than a leap. In
 * that mode the echo into the terminal is the only other trace a command ran,
 * and it dies with the tab — so if one thing here is load-bearing, it is that
 * every path through `mcp.ts` reaches this file, including the ones where
 * nobody was asked.
 *
 * Events are JSON, one per frame. Bodies are included: the log is ciphertext
 * under a key in the vault, which is what makes recording the real output
 * defensible rather than a second copy of everything in the clear.
 */

import type { LogWriter } from './logs'
import { logs } from './logs'
import { vault } from './vault'

export type AiEvent =
  /** The model asked for something and a human was shown it. */
  | { kind: 'proposed'; command: string; reason: string; flagged?: string }
  | { kind: 'approved'; command: string; autoShare: boolean }
  | { kind: 'denied'; command: string; flagged?: string }
  /** Unattended mode: it ran with nobody asked. The reason this log exists. */
  | { kind: 'unattended'; command: string; reason: string }
  | { kind: 'ran'; command: string; exitCode: number | null; output: string }
  | { kind: 'shared'; origin: string; chars: number; edited: boolean }
  | { kind: 'withheld'; origin: string; reason: string }
  | { kind: 'readTerminal'; reason: string; chars: number }
  | { kind: 'savedCommand'; title: string; body: string; approved: boolean }
  /** Content included: a file that landed unattended is the record's whole point. */
  | { kind: 'uploaded'; path: string; bytes: number; content: string; unattended: boolean }
  | { kind: 'uploadDenied'; path: string; bytes: number }

interface OpenLog {
  writer: LogWriter
  /** Set while `open` is in flight, so two events at once do not create two files. */
  opening: Promise<LogWriter> | null
}

class AiLog {
  private open = new Map<string, OpenLog>()

  /**
   * Records one event. Never throws and never rejects: an audit trail that can
   * fail a tool call turns logging into a reason commands stop working, and the
   * mode this log exists for is the one where nobody is watching for that.
   */
  async record(sessionId: string, sessionName: string, event: AiEvent): Promise<void> {
    try {
      if (!logs.configured) return
      if (vault.read().settings.aiLog === false) return
      const writer = await this.writerFor(sessionId, sessionName)
      writer.append(JSON.stringify({ at: new Date().toISOString(), ...event }) + '\n')
    } catch (err) {
      console.warn('ai log: event not recorded', err)
    }
  }

  private async writerFor(sessionId: string, sessionName: string): Promise<LogWriter> {
    const existing = this.open.get(sessionId)
    if (existing?.opening) return existing.opening
    if (existing) return existing.writer

    const opening = logs.open('ai', sessionId, sessionName)
    this.open.set(sessionId, { writer: null as unknown as LogWriter, opening })
    try {
      const writer = await opening
      this.open.set(sessionId, { writer, opening: null })
      return writer
    } catch (err) {
      // Dropped rather than cached: the next event tries again, which matters
      // when the failure was a locked vault during the first call.
      this.open.delete(sessionId)
      throw err
    }
  }

  async close(sessionId: string): Promise<void> {
    const entry = this.open.get(sessionId)
    if (!entry) return
    this.open.delete(sessionId)
    try {
      const writer = entry.opening ? await entry.opening : entry.writer
      await writer.close()
    } catch (err) {
      console.warn('ai log: close failed', err)
    }
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.open.keys()].map((id) => this.close(id)))
  }
}

export const aiLog = new AiLog()

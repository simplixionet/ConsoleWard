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
  /**
   * `unattended` carries what `approved` cannot. In unattended mode the bridge
   * returns `approved: true` after writing with nobody asked, so without this
   * the one record of an unreviewed write into the command library reads
   * exactly like one a human clicked through — and that library is run later,
   * out of context, which is the whole reason the mark on it is load-bearing.
   */
  | { kind: 'savedCommand'; title: string; body: string; approved: boolean; unattended: boolean }
  /** Content included: a file that landed unattended is the record's whole point. */
  | { kind: 'uploaded'; path: string; bytes: number; content: string; unattended: boolean }
  | { kind: 'uploadDenied'; path: string; bytes: number }
  /**
   * SFTP opens with truncate, so a write that fails part way has already
   * emptied the destination. An upload that left no entry at all was the one
   * case where the log went quiet exactly when it mattered.
   */
  | { kind: 'uploadFailed'; path: string; bytes: number; error: string }

interface OpenLog {
  writer: LogWriter
  /** Set while `open` is in flight, so two events at once do not create two files. */
  opening: Promise<LogWriter> | null
}

class AiLog {
  private open = new Map<string, OpenLog>()
  /**
   * Sessions whose log has been closed. Without this a stray event after the
   * close — a share dialog answered as the connection dropped — calls
   * `logs.open` again and creates a second file for a session that has ended,
   * under a map entry no close path will ever reach.
   *
   * One short string per session per run of the application, so it is bounded
   * by how many sessions a person opens before quitting.
   */
  private finished = new Set<string>()

  /**
   * Records one event. Never throws and never rejects: an audit trail that can
   * fail a tool call turns logging into a reason commands stop working, and the
   * mode this log exists for is the one where nobody is watching for that.
   */
  async record(sessionId: string, sessionName: string, event: AiEvent): Promise<void> {
    try {
      if (!logs.configured) return
      if (this.finished.has(sessionId)) return
      if (vault.read().settings.aiLog === false) return
      const writer = await this.writerFor(sessionId, sessionName)
      writer.append(JSON.stringify({ at: new Date().toISOString(), ...event }) + '\n')
      /*
        Flushed per event, unlike a transcript.

        A transcript is buffered because it is thousands of small chunks a
        second and the frame overhead would dwarf the content. An AI log is a
        handful of events an hour, and every one of them is the record of a
        decision — including, in unattended mode, decisions nobody was asked
        about. The buffer's timer is unref'd, so a quit inside 750 ms would drop
        exactly those. One append per event is the cost of the log being worth
        having, and `run_command` already tells the reader it recorded before it
        ran.
      */
      await writer.flush()
    } catch (err) {
      console.warn('ai log: event not recorded', err)
    }
  }

  private async writerFor(sessionId: string, sessionName: string): Promise<LogWriter> {
    const existing = this.open.get(sessionId)
    if (existing?.opening) return existing.opening
    if (existing) return existing.writer

    const opening = logs.open('ai', sessionId, sessionName)
    const entry: OpenLog = { writer: null as unknown as LogWriter, opening }
    this.open.set(sessionId, entry)
    try {
      const writer = await opening
      // Only if this entry is still the live one. A session closing while the
      // file was being created already took it out of the map and closed the
      // writer; re-adding it here would leave a closed writer behind for a
      // session that has ended, and nothing would ever remove it.
      if (this.open.get(sessionId) === entry) this.open.set(sessionId, { writer, opening: null })
      else await writer.close()
      return writer
    } catch (err) {
      // Dropped rather than cached: the next event tries again, which matters
      // when the failure was a locked vault during the first call.
      if (this.open.get(sessionId) === entry) this.open.delete(sessionId)
      throw err
    }
  }

  async close(sessionId: string): Promise<void> {
    this.finished.add(sessionId)
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

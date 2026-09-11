// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Session transcripts and the AI audit log, on disk, encrypted.
 *
 * The format lives in `logFormat.ts`; this file is the part that owns files,
 * keys and limits. Three rules shape it:
 *
 * 1. **A file key is resolved once, when the log opens.** Sessions outlive a
 *    vault lock whenever `disconnectOnLock` is off, so the write path may never
 *    touch the vault — and caching the master instead would keep a key that
 *    opens every log alive inside a locked process.
 * 2. **A cap is announced, never silent.** Hitting a limit writes a frame
 *    saying so and rolls to a new file. A security record that stops without
 *    saying it stopped is worse than none.
 * 3. **No vault string becomes a path.** Files are named by UUID and the
 *    readable label lives in the header, which is why `..\\..\\Startup\\x` as a
 *    connection name is not a question this file has to answer.
 */

import { randomBytes, randomUUID } from 'node:crypto'
import fsp from 'node:fs/promises'
import path from 'node:path'
import type { LogFileInfo, LogKind } from '../shared/types'
import { appError } from './i18n'
import {
  LOG_MAGIC,
  MAX_FRAME_PAYLOAD_BYTES,
  createLogFile,
  encodeFrame,
  readLogFile,
  type LogHeader
} from './logFormat'
import { vault } from './vault'

const EXTENSION = '.cwlog'

/** As the vault: on Windows this is close to decorative, and the contents are ciphertext anyway. */
const FILE_MODE = 0o600

/**
 * A cap the user cannot raise past this, whatever the settings dialog offers.
 * The dialog's own range is narrower; this is the floor under a hand-edited
 * vault, so a settings file cannot ask for a 4 GB transcript.
 */
const MAX_FILE_BYTES_LIMIT = 512 * 1024 * 1024

/** Terminal output arrives in small chunks; one frame per chunk would be mostly overhead. */
const FLUSH_MS = 750

/** Below this a partial write is cheaper than the frame it would save. */
const FLUSH_BYTES = 32 * 1024

export interface LogLimits {
  maxFileBytes: number
  maxTotalBytes: number
}

/**
 * One open log. Appends are buffered and sealed on a timer, so a chatty session
 * does not turn every keystroke echo into its own frame.
 */
export class LogWriter {
  private pending: string[] = []
  private pendingBytes = 0
  private timer: NodeJS.Timeout | null = null
  private index = 0
  private bytesWritten = 0
  private closed = false
  /** Appends are serialised through this: the format is append-only and ordered. */
  private queue: Promise<void> = Promise.resolve()

  private readonly store: LogStore
  private file: { filePath: string; header: LogHeader; fileKey: Buffer }
  private readonly limits: LogLimits
  private readonly kind: LogKind
  private part: number

  // Assigned field by field rather than as constructor parameter properties:
  // the test runner strips types without transforming, and that syntax needs a
  // transform, so a parameter property here stops the whole suite from loading.
  constructor(
    store: LogStore,
    file: { filePath: string; header: LogHeader; fileKey: Buffer },
    limits: LogLimits,
    kind: LogKind,
    part: number
  ) {
    this.store = store
    this.file = file
    this.limits = limits
    this.kind = kind
    this.part = part
  }

  get id(): string {
    return path.basename(this.file.filePath, EXTENSION)
  }

  /** Fire and forget: a failing log must never take a live session down with it. */
  append(text: string): void {
    if (this.closed || !text) return
    this.pending.push(text)
    this.pendingBytes += Buffer.byteLength(text)
    if (this.pendingBytes >= FLUSH_BYTES) {
      void this.flush()
      return
    }
    if (this.timer === null) {
      this.timer = setTimeout(() => void this.flush(), FLUSH_MS)
      // The flush timer must not be the reason the application stays alive.
      this.timer.unref?.()
    }
  }

  async flush(): Promise<void> {
    if (this.timer !== null) {
      clearTimeout(this.timer)
      this.timer = null
    }
    if (this.pending.length === 0) return
    const payload = this.pending.join('')
    this.pending = []
    this.pendingBytes = 0
    await this.write(payload)
  }

  async close(): Promise<void> {
    if (this.closed) return
    await this.flush()
    this.closed = true
  }

  private write(payload: string): Promise<void> {
    this.queue = this.queue.then(async () => {
      try {
        for (const chunk of splitPayload(payload)) await this.writeFrame(chunk)
      } catch (err) {
        // Logged and swallowed: the alternative is an unhandled rejection that
        // kills the process holding the user's live SSH sessions.
        console.warn('logs: append failed', err)
      }
    })
    return this.queue
  }

  private async writeFrame(payload: Buffer): Promise<void> {
    const frame = encodeFrame({
      fileKey: this.file.fileKey,
      header: this.file.header,
      index: this.index,
      payload
    })

    if (this.bytesWritten + frame.length > this.limits.maxFileBytes) {
      await this.rollOver()
      return this.writeFrame(payload)
    }

    await fsp.appendFile(this.file.filePath, frame, { mode: FILE_MODE })
    this.index += 1
    this.bytesWritten += frame.length
  }

  /**
   * Starts a new file rather than renaming one with an open handle, and says so
   * in both: the old file ends with a note and the new one starts with it, so a
   * reader holding either half knows the other exists.
   */
  private async rollOver(): Promise<void> {
    const next = this.part + 1
    const notice = Buffer.from(`\n[consoleward] size limit reached — continues in part ${next}\n`)
    const tail = encodeFrame({
      fileKey: this.file.fileKey,
      header: this.file.header,
      index: this.index,
      payload: notice
    })
    await fsp.appendFile(this.file.filePath, tail, { mode: FILE_MODE })

    this.file = await this.store.createFile(this.kind, this.file.header.sessionId, baseLabel(this.file.header.label), next)
    this.part = next
    this.index = 0
    this.bytesWritten = (await fsp.stat(this.file.filePath)).size

    const head = Buffer.from(`[consoleward] continued from part ${next - 1}\n`)
    await this.writeFrame(head)
  }
}

class LogStore {
  private directory: string | null = null
  private limits: LogLimits = { maxFileBytes: 16 * 1024 * 1024, maxTotalBytes: 512 * 1024 * 1024 }

  setDirectory(dir: string): void {
    this.directory = dir
  }

  /** False before startup has picked a directory — nothing can be logged yet. */
  get configured(): boolean {
    return this.directory !== null
  }

  setLimits(limits: Partial<LogLimits>): void {
    this.limits = {
      maxFileBytes: Math.min(
        MAX_FILE_BYTES_LIMIT,
        Math.max(64 * 1024, limits.maxFileBytes ?? this.limits.maxFileBytes)
      ),
      maxTotalBytes: Math.max(1024 * 1024, limits.maxTotalBytes ?? this.limits.maxTotalBytes)
    }
  }

  get dir(): string {
    if (!this.directory) throw appError('error.unexpected')
    return this.directory
  }

  /**
   * Opens a log. The vault must be unlocked here and only here — everything
   * after this point works from the file key held in the returned writer.
   */
  async open(kind: LogKind, sessionId: string, label: string): Promise<LogWriter> {
    await this.enforceTotalCap()
    const file = await this.createFile(kind, sessionId, label, 1)
    return new LogWriter(this, file, this.limits, kind, 1)
  }

  /** Also used by a roll-over, which is why it is not private. */
  async createFile(
    kind: LogKind,
    sessionId: string,
    label: string,
    part: number
  ): Promise<{ filePath: string; header: LogHeader; fileKey: Buffer }> {
    const master = await this.masterKey()
    const created = createLogFile({
      sessionId,
      label: part > 1 ? `${label} (${part})` : label,
      masterKey: master
    })
    // Never from the label: a vault string that reached a path component would
    // be the one input in this file that could escape the log directory.
    const filePath = path.join(this.dir, `${kind}-${randomUUID()}${EXTENSION}`)
    await fsp.mkdir(this.dir, { recursive: true })
    await fsp.writeFile(filePath, created.headerLine, { mode: FILE_MODE, flag: 'wx' })
    return { filePath, header: created.header, fileKey: created.fileKey }
  }

  async list(): Promise<LogFileInfo[]> {
    let names: string[]
    try {
      names = await fsp.readdir(this.dir)
    } catch {
      return []
    }

    const out: LogFileInfo[] = []
    for (const name of names) {
      if (!name.endsWith(EXTENSION)) continue
      const info = await this.describe(name)
      if (info) out.push(info)
    }
    return out.sort((a, b) => b.createdAt - a.createdAt)
  }

  /** Header line only — a listing must not read a gigabyte of frames. */
  private async describe(name: string): Promise<LogFileInfo | null> {
    const filePath = path.join(this.dir, name)
    let handle: fsp.FileHandle | null = null
    try {
      const stat = await fsp.stat(filePath)
      handle = await fsp.open(filePath, 'r')
      const head = Buffer.alloc(Math.min(64 * 1024, stat.size))
      await handle.read(head, 0, head.length, 0)
      const nl = head.indexOf(0x0a)
      if (nl < 0) return null
      const header = JSON.parse(head.subarray(0, nl).toString('utf8')) as LogHeader
      if (header.magic !== LOG_MAGIC) return null
      return {
        id: path.basename(name, EXTENSION),
        kind: name.startsWith('ai-') ? 'ai' : 'transcript',
        sessionId: String(header.sessionId ?? ''),
        label: String(header.label ?? ''),
        createdAt: Number(header.createdAt) || stat.mtimeMs,
        bytes: stat.size
      }
    } catch {
      // A half-written or hand-edited file is skipped, not fatal: the listing
      // exists so the user can find and delete exactly such a thing.
      return null
    } finally {
      await handle?.close()
    }
  }

  /**
   * Decrypts a whole log. This is where plaintext gets created, so the warning
   * belongs on the action that calls it and not on the switch that started the
   * logging.
   */
  async decrypt(id: string): Promise<{ info: LogFileInfo; text: string; truncated: boolean }> {
    const info = await this.describe(`${id}${EXTENSION}`)
    if (!info) throw appError('error.logNotFound')
    const bytes = await fsp.readFile(this.filePathFor(id))
    const result = readLogFile(bytes, await this.masterKey())
    return {
      info,
      text: result.frames.map((f) => f.toString('utf8')).join(''),
      truncated: result.truncated
    }
  }

  async remove(id: string): Promise<void> {
    await fsp.rm(this.filePathFor(id), { force: true })
  }

  async purge(): Promise<number> {
    const files = await this.list()
    for (const file of files) await this.remove(file.id)
    return files.length
  }

  async totalBytes(): Promise<number> {
    return (await this.list()).reduce((sum, f) => sum + f.bytes, 0)
  }

  /** A path built from an id that came back through IPC, so it is checked rather than trusted. */
  private filePathFor(id: string): string {
    if (!/^(ai|transcript)-[0-9a-f-]{36}$/.test(id)) throw appError('error.logNotFound')
    return path.join(this.dir, `${id}${EXTENSION}`)
  }

  /**
   * Oldest first, until the directory is back under the cap. Deleting rather
   * than refusing to log is the lesser harm: the alternative is a machine that
   * fills its disk and then stops recording anyway, with no warning either way.
   */
  private async enforceTotalCap(): Promise<void> {
    const files = await this.list()
    let total = files.reduce((sum, f) => sum + f.bytes, 0)
    if (total <= this.limits.maxTotalBytes) return

    for (const file of [...files].reverse()) {
      if (total <= this.limits.maxTotalBytes) break
      await this.remove(file.id)
      total -= file.bytes
      console.warn(`logs: removed ${file.id} to stay under the total size limit`)
    }
  }

  /**
   * The master that wraps every file key. Generated once and kept in the vault
   * beside `mcpToken`, so it is protected exactly as well as everything else.
   */
  private async masterKey(): Promise<Buffer> {
    const existing = vault.read().logKey
    if (existing) return Buffer.from(existing, 'base64')
    const fresh = randomBytes(32)
    await vault.mutate((data) => {
      // Re-read inside the write: two sessions opening at once would otherwise
      // each generate a key and the second would orphan the first one's logs.
      if (!data.logKey) data.logKey = fresh.toString('base64')
    })
    const stored = vault.read().logKey
    // Never fall back to `fresh`: a key that was not persisted encrypts a log
    // nothing can ever open again, which is worse than not writing one.
    if (!stored) throw appError('error.logKeyMissing')
    return Buffer.from(stored, 'base64')
  }
}

export const logs = new LogStore()

/** A frame holds at most `MAX_FRAME_PAYLOAD_BYTES`; a burst of output can exceed it. */
function splitPayload(text: string): Buffer[] {
  const buffer = Buffer.from(text, 'utf8')
  if (buffer.length <= MAX_FRAME_PAYLOAD_BYTES) return [buffer]
  const out: Buffer[] = []
  for (let at = 0; at < buffer.length; at += MAX_FRAME_PAYLOAD_BYTES) {
    out.push(buffer.subarray(at, at + MAX_FRAME_PAYLOAD_BYTES))
  }
  return out
}

/** Strips the ` (2)` a roll-over added, so part 3 does not become `name (2) (3)`. */
function baseLabel(label: string): string {
  return label.replace(/ \(\d{1,4}\)$/, '')
}

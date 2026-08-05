// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Reading the file a human picked in the open dialog.
 *
 * The path comes from the OS picker, never from the renderer, so this is not a
 * remote attack surface — it is what happens when the person at the keyboard
 * points the picker at something that is not an ordinary file.
 *
 * `fsp.stat()` cannot tell those apart. A POSIX FIFO reports `size: 0`, and on
 * Windows a named pipe reports `size: 0` **and** `isFile() === true` — measured
 * on node 24, Windows 11. Both walk through a size limit, and the `readFile`
 * that follows never returns: the read sits on a libuv threadpool thread and
 * cannot be cancelled, so the promise behind the dialog never settles, and four
 * of them exhaust the default pool of four. After that every `fsp.*` call in
 * the application and every `crypto.scrypt` the vault needs to unlock queue
 * behind them forever.
 *
 * So the file is opened first and asked afterwards: `fstat` on the open handle
 * answers `isFile() === false` for the same named pipe that path-`stat` called a
 * file. The handle is also what closes the gap between the check and the read —
 * they are now one file description rather than one path resolved twice.
 *
 * `O_NONBLOCK` is what keeps the open itself from blocking on POSIX, where
 * `open(fifo, O_RDONLY)` waits for a writer. It is a no-op for regular files
 * there, and node does not define it on Windows, where the open returns anyway
 * and only the read blocks.
 *
 * Symlinks are followed on purpose. `~/.ssh/id_ed25519` is a symlink on plenty
 * of machines, so `lstat` or `O_NOFOLLOW` would reject exactly the file this
 * dialog exists to load. Following it and then asking about the target is both
 * safe and correct: a symlink to a FIFO fails the `isFile()` check.
 */

import { constants as fsConstants } from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { appError } from './i18n'

/** A private key is a few kilobytes. A megabyte is already generous. */
export const TEXT_FILE_MAX_BYTES = 1024 * 1024

// Read defensively: node defines only the flags the platform has, and on
// Windows `O_NONBLOCK` is absent — referencing it directly yields `undefined`
// and turns the whole flag word into NaN.
const O_NONBLOCK = (fsConstants as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0

export async function readSmallTextFile(
  file: string,
  maxBytes: number = TEXT_FILE_MAX_BYTES
): Promise<{ name: string; content: string }> {
  const handle = await fsp.open(file, fsConstants.O_RDONLY | O_NONBLOCK)
  try {
    const stat = await handle.stat()
    if (!stat.isFile()) throw appError('error.notRegularFile')
    if (stat.size > maxBytes) throw appError('error.fileTooLarge')

    // One byte more than the limit, so a file that grew between the fstat and
    // the read is refused rather than silently cut in half — a size from `stat`
    // is a statement about the past. A single `read()` may come back short on a
    // network share, hence the loop.
    const buf = Buffer.alloc(maxBytes + 1)
    let filled = 0
    while (filled < buf.length) {
      const { bytesRead } = await handle.read(buf, filled, buf.length - filled, filled)
      if (bytesRead === 0) break
      filled += bytesRead
    }
    if (filled > maxBytes) throw appError('error.fileTooLarge')

    return { name: path.basename(file), content: buf.subarray(0, filled).toString('utf8') }
  } finally {
    // A failed close on a read-only handle says nothing the caller can act on,
    // and must not replace the error that brought us here.
    await handle.close().catch(() => {})
  }
}

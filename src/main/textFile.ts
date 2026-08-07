// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Reads the file a human picked in the open dialog. The path comes from the OS
 * picker, so the threat is a picker aimed at something that is not a file.
 *
 * Open first, ask afterwards — never `fsp.stat()` on the path. A Windows named
 * pipe reports `size: 0` and `isFile() === true` to path-`stat`, walks through
 * any size limit, and the read that follows never returns: it sits on an
 * uncancellable libuv threadpool thread, and four exhaust the default pool,
 * after which every `fsp.*` call and the `crypto.scrypt` that unlocks the vault
 * queue behind them forever. `fstat` on the handle answers `isFile() === false`
 * for that pipe, and closes the check-to-read gap as well.
 *
 * `O_NONBLOCK` stops the open itself blocking on POSIX, where
 * `open(fifo, O_RDONLY)` waits for a writer; a no-op for regular files. Symlinks
 * are followed on purpose — `~/.ssh/id_ed25519` is often one — and safely, since
 * a symlink to a FIFO still fails the `isFile()` check.
 */

import { constants as fsConstants } from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import { appError } from './i18n'

/** A private key is a few kilobytes. A megabyte is already generous. */
export const TEXT_FILE_MAX_BYTES = 1024 * 1024

// Read defensively: `O_NONBLOCK` is absent on Windows, and referencing it
// directly yields `undefined`, turning the whole flag word into NaN.
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

    // One byte more than the limit, so a file that grew since the fstat is
    // refused rather than silently cut in half. A single `read()` may come back
    // short on a network share, hence the loop.
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
    // A failed close on a read-only handle must not replace the error that
    // brought us here.
    await handle.close().catch(() => {})
  }
}

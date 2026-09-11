// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The encrypted log format, tested as a format rather than as a module: what a
 * reader must accept, what it must refuse, and which of the two a crash leaves
 * behind. A transcript that silently loses a frame, or one that cries corruption
 * every time the machine lost power, is worthless as evidence either way.
 *
 * The fixtures are built once at the top. Wrapping the file key costs a full
 * scrypt at the vault's parameters, so every test that only reads works from a
 * copy of the same bytes.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import type { LogHeader } from '../src/main/logFormat.ts'

const {
  LOG_FORMAT_VERSION,
  LOG_MAGIC,
  MAX_FRAME_INDEX,
  MAX_FRAME_PAYLOAD_BYTES,
  MAX_HEADER_BYTES,
  MAX_SESSION_ID_CHARS,
  createLogFile,
  encodeFrame,
  readLogFile,
  rewrapLogHeader
} = await import('../src/main/logFormat.ts')

const MASTER = Buffer.alloc(32, 0x5a)
const OTHER_MASTER = Buffer.alloc(32, 0xa5)

const SESSION_ID = '7f3c1d92-4a0b-4e77-9a21-6c5e8b0d1f44'
const LABEL = 'web01 — nginx restart'

const NEWLINE = 0x0a
const LENGTH_BYTES = 4
const NONCE_BYTES = 12
const TAG_BYTES = 16
const FRAME_OVERHEAD = NONCE_BYTES + TAG_BYTES

/** The empty entry is deliberate: a heartbeat frame carries no payload at all. */
const TRANSCRIPT = [
  'stan@web01:~$ systemctl restart nginx\r\n',
  '',
  'stan@web01:~$ tail -n1 /var/log/nginx/error.log\r\n',
  '2026-08-04 21:13:02 [warn] 812#812: conflicting server name "web01"\r\n'
]

interface Log {
  header: LogHeader
  fileKey: Buffer
  headerLine: string
  frames: Buffer[]
  bytes: Buffer
}

function buildLog(
  payloads: string[],
  opts: { sessionId?: string; label?: string; masterKey?: Buffer } = {}
): Log {
  const created = createLogFile({
    sessionId: opts.sessionId ?? SESSION_ID,
    label: opts.label ?? LABEL,
    masterKey: opts.masterKey ?? MASTER
  })
  const frames = payloads.map((payload, index) =>
    encodeFrame({
      fileKey: created.fileKey,
      header: created.header,
      index,
      payload: Buffer.from(payload, 'utf8')
    })
  )
  return { ...created, frames, bytes: concat(created.headerLine, frames) }
}

function concat(headerLine: string, frames: Buffer[]): Buffer {
  return Buffer.concat([Buffer.from(headerLine, 'utf8'), ...frames])
}

/** Rebuilds the file with the frames in a different order, or with some missing. */
function withFrames(log: Log, frames: Buffer[]): Buffer {
  return concat(log.headerLine, frames)
}

/** Edits line 1 in place, the way anyone with write access to the file could. */
function withHeader(log: Log, edit: (header: Record<string, unknown>) => void): Buffer {
  const header = JSON.parse(log.headerLine) as Record<string, unknown>
  edit(header)
  return concat(JSON.stringify(header) + '\n', log.frames)
}

function flipBit(bytes: Buffer, at: number): Buffer {
  const copy = Buffer.from(bytes)
  copy[at] ^= 0x01
  return copy
}

function u32be(value: number): Buffer {
  const buf = Buffer.alloc(4)
  buf.writeUInt32BE(value)
  return buf
}

function text(log: { frames: Buffer[] }): string[] {
  return log.frames.map((f) => f.toString('utf8'))
}

const LOG = buildLog(TRANSCRIPT)
const HEADER_BYTES = Buffer.byteLength(LOG.headerLine, 'utf8')

describe('round trip', () => {
  test('every frame comes back byte for byte, in order', () => {
    const result = readLogFile(LOG.bytes, MASTER)
    assert.deepEqual(text(result), TRANSCRIPT, 'the transcript read back is not the one written')
    assert.equal(result.truncated, false, 'a whole file must not be reported as cut short')
  })

  test('the header survives the round trip unchanged', () => {
    assert.deepEqual(
      readLogFile(LOG.bytes, MASTER).header,
      LOG.header,
      'the caller needs the header it wrote back, wrapped key included, to rewrap it later'
    )
  })

  test('a log with no frames yet reads as an empty transcript, not as damage', () => {
    // What every new session looks like between opening the file and the first
    // byte of output.
    const result = readLogFile(Buffer.from(LOG.headerLine, 'utf8'), MASTER)
    assert.deepEqual(result.frames, [], 'a header-only file has no frames')
    assert.equal(result.truncated, false, 'nothing was cut off: nothing was written yet')
  })

  test('a reader holding only the file can still say whose log it is', () => {
    // The whole reason line 1 is in the clear.
    const line = LOG.bytes.subarray(0, LOG.bytes.indexOf(NEWLINE)).toString('utf8')
    const header = JSON.parse(line) as LogHeader
    assert.equal(header.magic, LOG_MAGIC)
    assert.equal(header.version, LOG_FORMAT_VERSION)
    assert.equal(header.sessionId, SESSION_ID, 'the session id must be legible without a key')
    assert.equal(header.label, LABEL, 'so must the label — that is what it is for')
  })

  test('and nothing of the transcript itself', () => {
    for (const line of TRANSCRIPT) {
      if (line.length === 0) continue
      assert.equal(
        LOG.bytes.includes(Buffer.from(line, 'utf8')),
        false,
        `${JSON.stringify(line)} is sitting in the file in the clear`
      )
    }
  })

  test('a payload at the size cap survives the reader that must accept it', () => {
    // The fencepost that matters: if the writer's cap and the reader's bound
    // disagree by one byte, the largest legal frame is written and never read.
    const payload = Buffer.alloc(MAX_FRAME_PAYLOAD_BYTES, 0x41)
    const frame = encodeFrame({
      fileKey: LOG.fileKey,
      header: LOG.header,
      index: 0,
      payload
    })
    const result = readLogFile(withFrames(LOG, [frame]), MASTER)
    assert.equal(result.frames.length, 1, 'the largest frame the writer allows was refused on read')
    assert.equal(result.frames[0].length, payload.length)
  })
})

describe('the AAD binds a frame to its file and its place in it', () => {
  test('a frame from another log is refused even under the same file key', () => {
    // Same key on purpose. If only a different key were caught, the binding
    // would be doing nothing and the session id would be free to lie.
    const foreign: LogHeader = { ...LOG.header, sessionId: 'a-different-session' }
    const spliced = encodeFrame({
      fileKey: LOG.fileKey,
      header: foreign,
      index: 2,
      payload: Buffer.from('stan@web01:~$ echo nothing happened\r\n', 'utf8')
    })
    const bytes = withFrames(LOG, [LOG.frames[0], LOG.frames[1], spliced, LOG.frames[3]])
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /frame 2 failed its tag/,
      'a frame lifted from another session was accepted into this transcript'
    )
  })

  test('two frames swapped are refused', () => {
    const bytes = withFrames(LOG, [LOG.frames[0], LOG.frames[2], LOG.frames[1], LOG.frames[3]])
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /frame 2 sits where frame 1 should/,
      'reordering the transcript would let a command be blamed on the wrong output'
    )
  })

  test('a frame replayed further down the file is refused', () => {
    const bytes = withFrames(LOG, [LOG.frames[0], LOG.frames[1], LOG.frames[1], LOG.frames[3]])
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /frame 1 sits where frame 2 should/,
      'a frame copied over the one that followed it would erase that one silently'
    )
  })

  test('a gap in the indices is refused', () => {
    const bytes = withFrames(LOG, [LOG.frames[0], LOG.frames[1], LOG.frames[3]])
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /frame 3 sits where frame 2 should/,
      'cutting one frame out of the middle is exactly what this check exists for'
    )
  })

  test('editing the session id in the header breaks every frame', () => {
    const bytes = withHeader(LOG, (header) => {
      header.sessionId = '00000000-0000-4000-8000-000000000000'
    })
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /frame 0 failed its tag/,
      'a whole transcript could be re-attributed to another session by editing one string'
    )
  })

  test('KNOWN LIMIT: the label is outside the AAD, so it can be rewritten at will', () => {
    // Pinned, not endorsed. `label` and `createdAt` carry no tag; whoever can
    // write the file can relabel it. The module doc says so and so does this.
    const bytes = withHeader(LOG, (header) => {
      header.label = 'routine maintenance'
      header.createdAt = 0
    })
    const result = readLogFile(bytes, MASTER)
    assert.equal(result.header.label, 'routine maintenance')
    assert.deepEqual(text(result), TRANSCRIPT, 'only sessionId and the version are bound')
  })
})

describe('a crash and an edit are told apart', () => {
  test('a frame cut off mid-write reads as truncated, not as corruption', () => {
    const bytes = LOG.bytes.subarray(0, LOG.bytes.length - 5)
    const result = readLogFile(bytes, MASTER)
    assert.equal(result.truncated, true, 'the reader must say the file ended mid-frame')
    assert.deepEqual(
      text(result),
      TRANSCRIPT.slice(0, 3),
      'everything written before the crash must still be readable'
    )
  })

  test('a length field cut in half reads as truncated too', () => {
    // The smallest partial append there is: two bytes of a four-byte length.
    const bytes = Buffer.concat([LOG.bytes, Buffer.from([0x00, 0x00])])
    const result = readLogFile(bytes, MASTER)
    assert.equal(result.truncated, true, 'a half-written length is a crash, not damage')
    assert.deepEqual(text(result), TRANSCRIPT, 'and it costs none of the frames before it')
  })

  test('KNOWN LIMIT: a clean cut on a frame boundary is invisible', () => {
    // Nothing in the file records how many frames there should be, so dropping
    // the last two is indistinguishable from never having written them. This is
    // the property that stops the format being called tamper-proof; detecting it
    // needs a count kept outside the file, as vaultGuard.ts keeps the vault's.
    const bytes = withFrames(LOG, [LOG.frames[0], LOG.frames[1]])
    const result = readLogFile(bytes, MASTER)
    assert.equal(result.truncated, false, 'there is no partial frame here to notice')
    assert.deepEqual(text(result), TRANSCRIPT.slice(0, 2))
  })

  test('a flipped bit in a tag is refused', () => {
    const bytes = flipBit(LOG.bytes, HEADER_BYTES + LOG.frames[0].length - 1)
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /frame 0 failed its tag/,
      'a damaged tag must stop the read, never be passed off as the transcript'
    )
  })

  test('a flipped bit in a ciphertext is refused', () => {
    const bytes = flipBit(LOG.bytes, HEADER_BYTES + LENGTH_BYTES + NONCE_BYTES)
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /frame 0 failed its tag/,
      'GCM must catch an edited payload, not decrypt it into plausible output'
    )
  })

  test('a length no writer could have produced is damage, not a short read', () => {
    // Both halves matter. A length under the overhead cannot describe a frame at
    // all, and a length over the cap must be refused BEFORE the short-read check
    // or the rest of the file gets filed away as an ordinary crash.
    const tooSmall = Buffer.concat([u32be(FRAME_OVERHEAD - 1), Buffer.alloc(64)])
    assert.throws(
      () => readLogFile(concat(LOG.headerLine, [tooSmall]), MASTER),
      /declares 27 bytes/,
      'a frame shorter than its own nonce and tag was accepted'
    )

    const tooLarge = u32be(FRAME_OVERHEAD + MAX_FRAME_PAYLOAD_BYTES + 1)
    assert.throws(
      () => readLogFile(concat(LOG.headerLine, [tooLarge]), MASTER),
      /which this format cannot write/,
      'an impossible length was reported as a crash instead of as damage'
    )
  })

  test('a nonce outside the writable range is refused', () => {
    // The top four bytes of the counter are unreachable from a JS number, so a
    // frame claiming one was hand-built. Refused before it can be decrypted.
    const frame = Buffer.from(LOG.frames[0])
    frame.writeUInt32BE(1, LENGTH_BYTES)
    assert.throws(
      () => readLogFile(withFrames(LOG, [frame]), MASTER),
      /outside the range this format can write/,
      'a nonce this writer cannot reach must not be read back as an index'
    )
  })
})

describe('keys', () => {
  test('the wrong master is refused, and says which half is wrong', () => {
    assert.throws(
      () => readLogFile(LOG.bytes, OTHER_MASTER),
      /cannot unwrap the file key/,
      'the wrapped key is the gate; a wrong master must fail there and say so'
    )
  })

  test('the file key is per file, and so is everything that wraps it', () => {
    // Same master, same session id, same payload, same index: everything a
    // careless implementation might reuse.
    const a = buildLog(['deploy\r\n'], { sessionId: 'shared-session' })
    const b = buildLog(['deploy\r\n'], { sessionId: 'shared-session' })

    assert.notEqual(
      a.fileKey.toString('hex'),
      b.fileKey.toString('hex'),
      'two logs under one master must not share a file key'
    )
    assert.notEqual(
      a.header.wrappedKey.salt,
      b.header.wrappedKey.salt,
      'a shared salt is a shared KEK, and one scrypt run then opens both files'
    )

    const nonceOf = (frame: Buffer): string =>
      frame.subarray(LENGTH_BYTES, LENGTH_BYTES + NONCE_BYTES).toString('hex')
    assert.equal(
      nonceOf(a.frames[0]),
      nonceOf(b.frames[0]),
      'precondition: both files start at counter zero, as a counter must'
    )
    assert.notEqual(
      a.frames[0].toString('hex'),
      b.frames[0].toString('hex'),
      'identical nonces under a shared key is the one outcome the per-file key exists to prevent'
    )
    assert.throws(
      () => readLogFile(withFrames(a, [b.frames[0]]), MASTER),
      /frame 0 failed its tag/,
      "a frame must not open under another file's key"
    )
  })

  test('rotating the master rewrites line 1 and not one frame', () => {
    const rotated = rewrapLogHeader({
      header: LOG.header,
      oldMasterKey: MASTER,
      newMasterKey: OTHER_MASTER
    })
    assert.deepEqual(
      { ...rotated.header, wrappedKey: LOG.header.wrappedKey },
      LOG.header,
      'a rotation must change the wrapped key and nothing else in the header'
    )
    assert.notEqual(
      rotated.header.wrappedKey.data,
      LOG.header.wrappedKey.data,
      'the wrapped key did not actually change'
    )

    const bytes = concat(rotated.headerLine, LOG.frames)
    assert.deepEqual(
      text(readLogFile(bytes, OTHER_MASTER)),
      TRANSCRIPT,
      'the untouched frames must still open under the new master'
    )
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /cannot unwrap the file key/,
      'the old master must stop working, or the rotation revoked nothing'
    )
  })

  test('a master short enough to be an accident is refused', () => {
    // scrypt derives a perfectly usable key from an empty buffer, so an unset
    // master would encrypt, decrypt, and look like it worked.
    for (const key of [Buffer.alloc(0), Buffer.alloc(8)]) {
      assert.throws(
        () => createLogFile({ sessionId: SESSION_ID, label: LABEL, masterKey: key }),
        /master key must be at least/,
        `a ${key.length}-byte master key was accepted`
      )
      assert.throws(() => readLogFile(LOG.bytes, key), /master key must be at least/)
    }
  })
})

describe('the nonce is a counter, and stays one', () => {
  test('every frame index lands in the nonce as a big-endian counter', () => {
    const count = 4096
    const seen = new Set<string>()
    for (let index = 0; index < count; index++) {
      const frame = encodeFrame({
        fileKey: LOG.fileKey,
        header: LOG.header,
        index,
        payload: Buffer.alloc(0)
      })
      const nonce = frame.subarray(LENGTH_BYTES, LENGTH_BYTES + NONCE_BYTES)
      assert.equal(nonce.length, NONCE_BYTES, 'GCM nonces here are 12 bytes, always')
      assert.equal(nonce.readUInt32BE(0), 0, 'the high bytes of the counter must stay zero')
      assert.equal(
        Number(nonce.readBigUInt64BE(4)),
        index,
        'the nonce must be the index itself, or the reader cannot recover it'
      )
      seen.add(nonce.toString('hex'))
    }
    assert.equal(
      seen.size,
      count,
      'a repeated nonce under one key is the one failure GCM does not survive'
    )
  })

  test('an index past the counter range is refused rather than wrapped', () => {
    // Past MAX_SAFE_INTEGER, index + 1 stops advancing and the next frame
    // silently reuses the previous nonce.
    for (const index of [-1, 1.5, NaN, MAX_FRAME_INDEX + 1, Number.MAX_VALUE]) {
      assert.throws(
        () =>
          encodeFrame({
            fileKey: LOG.fileKey,
            header: LOG.header,
            index,
            payload: Buffer.alloc(0)
          }),
        /frame index .{0,32} is outside/,
        `index ${index} was accepted`
      )
    }
  })

  test('the last index the counter can hold still encodes', () => {
    // Guards the check above against being tightened into refusing everything.
    const frame = encodeFrame({
      fileKey: LOG.fileKey,
      header: LOG.header,
      index: MAX_FRAME_INDEX,
      payload: Buffer.alloc(0)
    })
    const nonce = frame.subarray(LENGTH_BYTES, LENGTH_BYTES + NONCE_BYTES)
    assert.equal(Number(nonce.readBigUInt64BE(4)), MAX_FRAME_INDEX)
  })
})

describe('everything the reader trusts from the file is bounded', () => {
  test('a file with no newline is refused instead of being scanned whole', () => {
    // An unbounded search for line 1 is a free way to make the reader walk a
    // gigabyte of frames before admitting there is no header.
    const bytes = Buffer.alloc(MAX_HEADER_BYTES * 2, 0x7b)
    assert.throws(
      () => readLogFile(bytes, MASTER),
      /no header line in the first/,
      'the header search must give up at the cap'
    )
  })

  test('a header this reader could not read back is refused on the way out', () => {
    assert.throws(
      () =>
        createLogFile({
          sessionId: SESSION_ID,
          label: 'x'.repeat(MAX_HEADER_BYTES),
          masterKey: MASTER
        }),
      /larger than/,
      'writing a log our own reader refuses is worse than refusing to open it'
    )
  })

  test('a session id is required, and bounded because every frame carries it', () => {
    assert.throws(
      () => createLogFile({ sessionId: '', label: LABEL, masterKey: MASTER }),
      /sessionId is missing/,
      'a log that belongs to no session binds its frames to nothing'
    )
    assert.throws(
      () =>
        createLogFile({
          sessionId: 'x'.repeat(MAX_SESSION_ID_CHARS + 1),
          label: LABEL,
          masterKey: MASTER
        }),
      /sessionId is longer than/,
      'the session id is length-prefixed into every single frame'
    )
  })

  test('a payload over the cap is refused', () => {
    assert.throws(
      () =>
        encodeFrame({
          fileKey: LOG.fileKey,
          header: LOG.header,
          index: 0,
          payload: Buffer.alloc(MAX_FRAME_PAYLOAD_BYTES + 1)
        }),
      /over the/,
      'the writer must not produce a frame its own reader would call damage'
    )
  })

  test('a file key that is not an AES-256 key is refused', () => {
    assert.throws(
      () =>
        encodeFrame({
          fileKey: Buffer.alloc(16),
          header: LOG.header,
          index: 0,
          payload: Buffer.alloc(0)
        }),
      /file key must be 32 bytes/,
      'a short key must be named, not left to a raw OpenSSL error'
    )
  })

  test('a header line that is not JSON is refused', () => {
    assert.throws(
      () => readLogFile(concat('not json at all\n', LOG.frames), MASTER),
      /header line is not JSON/
    )
  })

  test('a bad magic and a future version are both refused, each by name', () => {
    assert.throws(
      () => readLogFile(withHeader(LOG, (h) => void (h.magic = 'CWLOGX')), MASTER),
      /not a ConsoleWard log/,
      'some other framed file must not be read as a transcript'
    )
    assert.throws(
      () => readLogFile(withHeader(LOG, (h) => void (h.version = LOG_FORMAT_VERSION + 1)), MASTER),
      /unsupported log format version 2/,
      'a file from a newer ConsoleWard must be refused, not half-read'
    )
  })

  test('a wrapped key of the wrong shape is refused before any derivation', () => {
    // scrypt at these parameters costs a fifth of a second; a header edited into
    // nonsense must not buy that, and createDecipheriv on a 4-byte iv throws
    // something no caller can act on.
    const short = (bytes: number): string => Buffer.alloc(bytes).toString('base64')
    const cases: Array<[string, (w: Record<string, string>) => void, RegExp]> = [
      ['iv', (w) => void (w.iv = short(4)), /wrappedKey.iv must be 12/],
      ['tag', (w) => void (w.tag = short(8)), /wrappedKey.tag must be 16/],
      ['data', (w) => void (w.data = short(8)), /wrappedKey.data must be 32/],
      ['salt', (w) => void (w.salt = short(4)), /wrappedKey.salt is too short/],
      ['tag missing', (w) => void delete w.tag, /wrappedKey.tag is missing/]
    ]
    for (const [name, edit, expected] of cases) {
      const bytes = withHeader(LOG, (header) => {
        edit(header.wrappedKey as Record<string, string>)
      })
      assert.throws(() => readLogFile(bytes, MASTER), expected, `a bad ${name} was accepted`)
    }
  })

  test('a createdAt that is not a timestamp is refused', () => {
    assert.throws(
      () => readLogFile(withHeader(LOG, (h) => void (h.createdAt = 'yesterday')), MASTER),
      /createdAt is not a timestamp/
    )
  })
})

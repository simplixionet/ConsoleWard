# The `.cwlog` format

ConsoleWard writes session transcripts and AI audit logs to
`%APPDATA%\ConsoleWard\logs\*.cwlog`, encrypted. This document describes the
format well enough to write a reader from scratch, because a record kept for the
case where something went wrong is worth little if the only program that can
open it is the one that was there when it happened.

`scripts/decrypt-log.mjs` in this repository is exactly that — a reader written
from this document rather than from the writer's source, in plain Node with no
dependencies. `test/decryptLog.test.mts` runs it against real files the
application produced, which is what keeps this page honest.

**Version 1.** The version is in the header and a reader must refuse anything
higher rather than guess.

---

## Getting a log open, the easy way

Settings → Logs → Export writes a decrypted copy wherever you point it. That is
the path to reach for first. Everything below is for the case where ConsoleWard
will not start.

```bash
node scripts/decrypt-log.mjs transcript-<uuid>.cwlog --key <base64 master key> > session.txt
```

The master key is the `logKey` field inside the vault, base64 of 32 random
bytes. Getting it out means opening the vault, which means the password — there
is no way to read a log without it, and that is the point.

---

## Layout

```
line 1   {"magic":"CWLOG","version":1,…}\n      plaintext JSON, one line
frame    [u32be length][12B nonce][ciphertext][16B tag]
frame    …
```

`length` counts the whole body after itself — nonce, ciphertext and tag — so the
file can be walked without decrypting any of it. The minimum body is 28 bytes.

### The header

```json
{
  "magic": "CWLOG",
  "version": 1,
  "sessionId": "4f1c…",
  "createdAt": 1757620000000,
  "label": "web01",
  "wrappedKey": { "salt": "…", "iv": "…", "data": "…", "tag": "…" }
}
```

`label` is the connection name as it was when the log opened. It is shown, never
used as a path — files are named by UUID precisely so a connection called
`../../Startup/x` is not a question this format has to answer.

A reader must bound the header: stop looking for the newline after 64 KiB rather
than scanning a gigabyte of frames for one that was never written.

### The file key

Each log generates its own 32-byte key and stores it wrapped by the master:

```
kek  = scrypt(master, salt, N=2^17, r=8, p=1, dkLen=32)   maxmem 320 MiB
data = AES-256-GCM(kek, iv).encrypt(fileKey)              tag alongside
```

The scrypt parameters are **not** written to the file. Nothing read off disk
gets to choose how expensive the reader's key derivation is; a reader hard-codes
them, as the writer does.

One file key per log means rotating the master only rewrites headers, and a
leaked file key exposes one session rather than the archive.

### Frames

```
nonce      = 12 bytes, big-endian frame index (0, 1, 2, …)
aad        = "consoleward.log.aad.1" ‖ u32be(version) ‖ u32be(len(sessionId)) ‖ sessionId ‖ u64be(index)
ciphertext = AES-256-GCM(fileKey, nonce, aad).encrypt(payload)
```

The nonce is a counter, not random bytes. One key covers every frame of one
file, and two frames sharing a nonce under GCM hand out the keystream and the
authentication key with it — a counter removes that outcome instead of bounding
its probability.

It also puts the index *in* the file, which is the only place it is recorded.
That is what makes a missing or reordered frame visible: a reader recovers the
index from the nonce and checks it against its own position counter.

The AAD is length-framed so two fields cannot be confused by concatenation, and
it binds the frame to its file and its place in it — a frame lifted from another
log carries that log's `sessionId` and fails its tag even under the same key.

Payload is raw bytes. Transcripts hold terminal output exactly as it arrived,
escape sequences and all; AI logs hold one JSON object per line.

---

## What this format does not do

Stated here rather than left to be discovered:

- **A clean cut at the end is invisible.** Frames stand alone and nothing
  records how many there should be, so dropping the last few looks exactly like
  a crash mid-write. A reader reports `truncated` for a *partial* frame, never
  for an absent one. Catching that needs a count kept outside the file.
- **`label` and `createdAt` are not authenticated.** Only `sessionId`, the
  version and the frame index reach the AAD, so those two can be edited in place
  and every tag still verifies.
- **A partial trailing frame is normal.** It is what a crash mid-write leaves.
  Stop there, say so, and keep everything before it.
- **It is not tamper-proof.** It is tamper-*evident* in the middle and silent at
  the end. Do not describe it as more than that.

## Reading one

1. Find the first `\n` within the first 64 KiB. Parse the bytes before it as
   JSON. Refuse anything whose `magic` is not `CWLOG` or whose `version` is not 1.
2. Derive the KEK from the master and `wrappedKey.salt`, and unwrap the file key.
   A failure here means a wrong master key or an edited header — say which,
   because the user can act on one and not the other.
3. For each frame, starting at index 0: read the length, bound it against what
   is left, recover the index from the nonce and check it equals the position.
   Decrypt with the AAD above.
4. A length that cannot fit is damage — throw. A frame that is simply cut short
   by the end of the file is a crash — stop and report it.

Order matters in step 4: check the bound before the short-read, or an impossible
length gets filed away as an ordinary crash.

# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

<!--
Security work done before the first release is folded into 0.1.0 below rather
than listed here. Nothing has shipped, so there is no version for a reader to
have been running and no change for them to notice — an "Unreleased / Fixed"
section against a release that never happened describes the development process
rather than the software, and this file is for the latter.
-->

## [0.1.0] — unreleased

First public release. Everything below is the initial implementation rather than
a change from a previous version.

### Added

**Vault**

- Encrypted vault in a single `vault.enc`, holding connections, secrets, host
  fingerprints, saved commands and the MCP token.
- Envelope encryption: contents under AES-256-GCM with a random data key, which
  is wrapped separately by the master password and by a recovery key, both
  derived with scrypt (N=2¹⁷, r=8, p=1). A wrong password fails on the GCM tag,
  so there is no separate verifier to bypass.
- Recovery key of 30 Crockford Base32 characters (150 bits), shown once,
  regenerable and removable. Input tolerates case, separators, and `O`/`0` and
  `I`/`L`/`1` confusion.
- The readable header — format version, write counter and every field of every
  key wrap — is bound to the encrypted body as GCM additional authenticated
  data. A wrap therefore cannot be removed, added, reordered or spliced in from
  an older copy: the body simply stops decrypting. (The counter is protected but
  not yet compared against anything, so replacing the *whole* file with an older
  copy is still undetected — see SECURITY.md.)
- KDF parameters read out of the file are validated before any key is derived
  from them, so a tampered file cannot make derivation trivially cheap or turn
  an unlock attempt into hours of CPU.
- Master password of at least 12 characters, with a strength estimate shown
  while choosing one. The estimate is advice; only the length is enforced.
- Repeated wrong passwords get progressively slower, and locking does not clear
  the penalty.
- Atomic writes with a `.bak` of the previous version. A change is written
  before it is adopted in memory, so a failed write leaves the two agreeing.
- Automatic migration of v1 and v2 vaults to v3 on unlock, keeping the existing
  recovery key working. The pre-migration copy is removed once the new file has
  been read back and decrypted.
- Automatic lock after a configurable idle period, optionally ending SSH
  sessions with it.

**SSH**

- Password, private key (OpenSSH PEM, passphrase supported) and SSH agent
  authentication, plus `keyboard-interactive`.
- Host key verification against stored SHA256 fingerprints. First contact
  prompts; a changed fingerprint blocks the session until explicitly accepted,
  and rejecting does not overwrite the stored value.
- Multiple sessions in tabs, each with its own terminal and scrollback.
- xterm.js terminal with search, configurable font size and PuTTY-style
  right-click paste. Terminal data crosses IPC as base64 so multi-byte UTF-8
  never splits.

**Command library**

- Saved commands and free-text notes, with folders, descriptions and search.
- Insert into the terminal without sending, or run directly.
- Line endings normalised to LF in the main process when a saved command is
  inserted, so CRLF never reaches a shell as `^M`. Commands the AI proposes are
  deliberately **not** rewritten — see the MCP section.
- Multi-line commands require confirmation before insertion.

**AI access over MCP**

- Local MCP server on `127.0.0.1` only, off by default, bearer-token
  authenticated, with DNS-rebinding protection on both `Host` and `Origin`.
  The name is checked before the token and before any body is read, and a wrong
  name and a wrong token get the same answer byte for byte — so a web page
  cannot learn from the difference that anything is listening on the port.
- Stops immediately when the vault locks; pending requests are denied.
- `list_sessions` returns id, name and status only — never address, port or
  username. The name is the label you gave the connection, or a neutral
  placeholder if you gave none; what *you* see on the tab keeps the
  `user@host` form, because deciding whether to let a command run means knowing
  which machine it lands on.
- `run_command` requires per-command human approval showing the literal text
  with control characters made visible. No "approve all" and no memory of past
  approvals. The approved text is sent byte for byte — nothing rewrites it.
- Approved commands run in their **own channel** on the same connection, not in
  the terminal the human is looking at. That is what keeps whatever they type
  meanwhile out of the model's reach, and it yields a real exit status instead
  of guessing from a pause in the output. The cost is real and disclosed in the
  dialog: a fresh non-interactive shell in the home directory, so aliases, shell
  functions and any PATH from the login files are absent, nothing carries over
  between calls, and anything that would prompt fails rather than waiting.
- `read_terminal` opens a dialog where the human selects, edits or redacts the
  output; only that is returned. Every payload tells the model it may be an
  excerpt.
- Suspicious spans highlighted in the sharing dialog — passwords in assignments,
  JWT/AWS/GitHub/Slack tokens, credentials in URLs, password hashes, IP
  addresses. Documented as a hint, not a guarantee, and the dialog says so when
  it stopped highlighting early or could not read the whole text.
- Output can be released automatically once a command finishes, but that choice
  is revoked whenever the output turns out to look like a credential. The tick
  is given while reading the *command*, before any output exists, so it cannot
  be a promise about text nobody has seen.
- At most three approvals may be waiting at once; past that the model is told
  so rather than the request being queued. The window is raised once per batch,
  not once per request, and a freshly drawn dialog ignores clicks for a moment
  so one aimed at something else cannot land on it.
- Unanswered requests auto-deny after 5 minutes.
- Everything the model reads is fixed English, including error messages. It is a
  machine interface, so a Czech user does not ship Czech diagnostics to it.

**Interface**

- Eight UI languages: English, Czech, German, Spanish, French, Italian,
  Brazilian Portuguese, Dutch. English is the source; plural forms come from
  `Intl.PluralRules` with no i18n dependency.
- Language chosen from the system on first run, changeable in Settings, and
  stored outside the vault so the unlock screen is already translated.
- A missing translation falls back to English, never to a raw key. Only the
  active locale's dictionary is fetched at runtime.

**Platform**

- Renderer runs with `sandbox: true`, `contextIsolation: true` and
  `nodeIntegration: false`.
- CSP set by both header and meta tag; in-window navigation blocked; external
  links open in the system browser.
- Windows installer (NSIS) and portable build.

**Project**

- GPL-3.0-or-later, with SPDX headers on every source file.
- `npm run check:i18n` and `npm run check:i18n-ui` as standing verification
  gates.
- `npm run build:icon` generates `build/icon.ico` from the SVG mark using the
  Electron already in the tree — no image dependency.

### Known limitations

- **Rotation cannot undo a copy already taken.** Revoking a secret re-keys the
  vault and destroys the backup, so the revoked secret stops working from that
  point on — but anyone who captured the file together with the old secret
  beforehand has already read what it held.
- **Changing the master password issues a new recovery key.** Unavoidable: the
  old recovery wrap cannot be rebuilt under the new data key, because the
  recovery key is stored nowhere.
- **Translations are machine-produced** and have not been natively reviewed. The
  61 security-critical strings were checked mechanically for placeholder
  integrity and read by a human for dropped negations.
- **Connection and command sorting uses Czech collation for every user.**
- **macOS and Linux targets are configured but untested**, and have no icons.
- **Source comments are in Czech.**

[Unreleased]: https://github.com/simplixionet/ConsoleWard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/simplixionet/ConsoleWard/releases/tag/v0.1.0

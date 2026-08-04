# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

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
- Atomic writes with a `.bak` of the previous version.
- Automatic migration of v1 vaults to v2 on unlock.
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
- Line endings normalised to LF in the main process, so CRLF never reaches a
  shell as `^M`.
- Multi-line commands require confirmation before insertion.

**AI access over MCP**

- Local MCP server on `127.0.0.1` only, off by default, bearer-token
  authenticated, with DNS-rebinding protection on both `Host` and `Origin`.
- Stops immediately when the vault locks; pending requests are denied.
- `list_sessions` returns id, name and status only — never address, port or
  username.
- `run_command` requires per-command human approval showing the literal text
  with control characters made visible. No "approve all" and no memory of past
  approvals.
- `read_terminal` opens a dialog where the human selects, edits or redacts the
  output; only that is returned. Every payload tells the model it may be an
  excerpt.
- Suspicious spans highlighted in the sharing dialog — passwords in assignments,
  JWT/AWS/GitHub/Slack tokens, credentials in URLs, password hashes, IP
  addresses. Documented as a hint, not a guarantee.
- Unanswered requests auto-deny after 5 minutes.

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

- **Rotating the master password does not rotate the data key.** It re-wraps it.
  Someone holding a captured file and the old password has already read the
  data.
- **Translations are machine-produced** and have not been natively reviewed. The
  61 security-critical strings were checked mechanically for placeholder
  integrity and read by a human for dropped negations.
- **Connection and command sorting uses Czech collation for every user.**
- **macOS and Linux targets are configured but untested**, and have no icons.
- **Source comments are in Czech.**

[Unreleased]: https://github.com/simplixionet/ConsoleWard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/simplixionet/ConsoleWard/releases/tag/v0.1.0

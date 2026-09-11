# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Unattended mode.** A switch in the AI access settings that removes the
  approval dialog: commands the AI proposes run immediately and their full
  output goes back unedited. Off by default, never implied by enabling the
  gateway, and both it and the guard below have to be turned off by hand, one at
  a time.
- The connected model is told which mode it is in. The server's instructions
  previously promised that "a human approves every command" unconditionally;
  with the gate off that sentence would be a falsehood told to the party least
  able to check it, and a model that knows nobody is reading its proposals
  behaves differently from one that believes otherwise.
- **A destructive-command list** under unattended mode, on by default and
  switchable. It refuses `rm -rf /`, `mkfs`, writes to block devices,
  `shutdown`, piping a download into a shell, user deletion, firewall flushes,
  `DROP DATABASE`, log and history erasure, force pushes and `find -delete`.
  Refusals are written into the session as well as returned, because with no
  dialog the terminal is the only record left.

  It is a seatbelt, not a lock, and the settings say so: it reads the command
  text, so it stops a mistake and not an intention. `/bin/rm`, a downloaded
  script and a plain `dd` all pass unchanged. The rules are anchored to the
  start of a command, so `grep shutdown /var/log/syslog` is ordinary work and
  not an order to power the machine off — a list that fires on those is a list
  people switch off, and a switched-off list protects nothing.

### Changed

- The README and the application description now say "by default" where they
  promised approval unconditionally.

## [1.1.0] — 2026-08-11

### Added

- **Setup for the AI client you actually use.** The gateway settings now build the
  configuration for Claude Code, Claude Desktop and VS Code (Copilot), with your
  port and token already in it, and say where each one wants it put. Previously
  there was one button, and it produced a command only Claude Code understands.
- Claude Desktop reaches the gateway through `mcp-remote`. It launches local
  servers as programs and reaches HTTP ones only as Custom Connectors, which want
  a public address and run their own sign-in, so there is nowhere to put a
  loopback address or a token. The proxy bridges the two; it needs Node.js, and
  `npx` fetches it on first run.
- ChatGPT is listed with the reason it cannot connect. It refuses loopback
  addresses and requires a server published over HTTPS, so the only way to
  satisfy it is to put this gateway on the internet behind a tunnel — every
  session in the vault behind a single token anyone could try. Listening on
  `127.0.0.1` alone is the first promise this application makes, so there is
  deliberately no setting for it.
- Screenshots in the README, and `npm run screenshots` to retake them. They come
  from the real interface driven by a stand-in bridge, so every host, address and
  credential in them is invented and none of it came from a real session.

### Changed

- The "copy the Claude Code command" button is gone, replaced by the panel above.

## [1.0.2] — 2026-08-07

Anyone using the MCP gateway wants this one: before it, taking your time over a
dialog was the same as refusing.

### Fixed

- **An AI client gave up before the human could answer.** The MCP transport
  buffered the whole response, so not one byte — not even the status line — left
  the server until the tool handler returned, and these handlers return when a
  person answers a dialog. Clients bound the wait to the first response byte;
  Claude Code allows 60 seconds for an HTTP MCP server, which is not enough time
  to read a command and decide. The call died while the dialog was still open,
  and the answer, when it came, was delivered to nobody. Responses now stream:
  the headers go out immediately and the result follows whenever it is ready.
  Refusals are unchanged — they were never the case that broke.
- While a dialog is open the client is told the wait is deliberate, rather than
  being left to infer it from silence.

### Changed

- An approval now stands for fifteen minutes instead of five. Five was enough to
  answer a dialog you were already looking at, and not enough to read terminal
  output, decide what part of it a model may see, and edit it down; people doing
  that carefully were being denied mid-edit. Fifteen also matches the default
  auto-lock, which is the real ceiling: locking rejects everything pending, so an
  approval never outlives the vault it belongs to.

## [1.0.1] — 2026-08-07

**The first published release.** 1.0.0 was tagged but never released, so there
are no 1.0.0 binaries and nobody was running it; everything under 1.0.0 below is
part of this release too. The split is kept because the two halves answer
different questions — what the application *is*, and what a security review of
it changed.

That review is what 1.0.1 records. One finding was a real vulnerability; the
rest are hardening, one user-facing i18n bug and one broken build gate.

### Security

- **A malicious SSH server could hold the vault open indefinitely.** Idle
  auto-lock is the only thing that closes the vault when you walk away, and it
  was re-armed from xterm's `onData`. That is not a keystroke feed: the emulator
  fires the same event for the replies it owes the server — cursor position,
  device attributes, window size. A hostile host that printed a cursor-position
  query on a timer therefore kept asserting somebody was present through an idle
  machine, and nothing was ever drawn on screen to give it away. Presence is now
  taken only from real keyboard and mouse input.
- **The credential scanner missed whole file formats**, and the miss was
  silent: they scanned as "long random string", which is not severe enough to
  force the review dialog open, so with auto-share ticked they went to the model
  unseen. PGP secret keys could not match at all — the pattern had no room for
  the ` BLOCK` suffix in their header — and PuTTY `.ppk`, kubeconfig client
  keys, `~/.docker/config.json`, `~/.netrc` and `~/.pgpass` were not covered.
  Secrets in JSON and quoted YAML were missed too, because the quote closing the
  key name stopped the pattern before it reached the colon.
- **Error text chosen by the other end is now quoted rather than spoken.** An
  SSH disconnect reason is an arbitrary string that arrives before key exchange
  finishes, so anyone on the path can supply it; it was rendered in the
  application's own voice, and on the one path that skipped the terminal-text
  cleaner, directly before the host-key prompt asks you to trust a server. It is
  now attributed, stripped of escape and bidirectional characters, flattened to
  one line and capped.
- **Only one approval dialog is on screen at a time.** They used to stack at
  equal depth, so the dangerous one was always the covered one — and its
  anti-click-through delay ran out while it was hidden, leaving the button live
  in the first frame after the cover went away. They are now ordered by how soon
  each expires.
- **The approval dialog admits when a command is taller than its box**, and
  shows how long the command is. A long command could previously be approved
  with part of it scrolled out of sight, and the scrollbar is least visible
  exactly when the overflow is slight.

### Fixed

- Czech was hardcoded in six user-facing strings, so anyone not using Czech met
  it in the native file dialogs and in the host-key prompt, where it appeared as
  the key type while they decided whether to trust a server.
- Sessions kept alive across a lock are taken back from the main process on
  unlock. With `disconnectOnLock` off they used to stay connected but vanish
  from the interface, leaving no way to read or close them, while the MCP
  gateway could still see and drive them.
- The third-party notice gate compared against whatever the machine had
  installed, so it passed on a developer laptop and failed on a CI runner with a
  compiler from the same sources. The committed file is now derived from the
  lock file alone; the installer still ships one generated from what was really
  built.

### Changed

- Source comments are English throughout, and about half as many. What was cut
  was narrative and repetition; what stayed is the reasoning whose loss would
  let someone reintroduce a bug. Test titles and assertion messages are English
  too.
- Every GitHub Action is pinned to a commit SHA and moved to its current major,
  so the workflow that signs and publishes the installers cannot change under a
  moved tag.

## [1.0.0] — 2026-08-05

Tagged, never released — see 1.0.1 above, which is what actually shipped.
Everything below is the initial implementation rather than a change from a
previous version.

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
  an older copy: the body simply stops decrypting.
- Replacing the *whole* vault with an earlier copy of itself is noticed. The
  last write counter seen is kept outside the file, in `vault.guard`, sealed
  with the platform's password store. Opening a vault older than that anchor
  warns and names both numbers; it does not refuse, because a legitimate
  restore from backup looks the same and locking someone out of their own
  connections is the worse failure. The anchor stops whoever can only write
  files — it does not stop anything running as you, which can delete it. Said
  plainly in SECURITY.md rather than implied to be more.
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
- `read_terminal` opens a dialog that asks **what** to send before showing any
  of it, and has **no "send everything" button**. The excerpt is either
  highlighted in the console with the mouse — the dialog shrinks to a corner
  panel that keeps the session and the reason in view and counts the selection
  live — or taken as the last 20 lines. Only then is it shown for reading,
  editing and redacting, now short enough that the highlighting below has
  something to be useful on. Sending the whole buffer still works, but only by
  highlighting all of it. Every payload tells the model it may be an excerpt.
- No step can send by accident: the first step has no button that sends at all,
  "continue" is disabled until something is selected and never falls back to the
  whole buffer, and sending nothing is its own button rather than what happens
  when you do nothing.
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
  81 security-critical strings were checked mechanically for placeholder
  integrity and read by a human for dropped negations.
- **Folder headings sort by the runtime's default locale, not the chosen one.**
  Connections, commands and known hosts are sorted with an `Intl.Collator` built
  from the active UI language, but the folder headings the sidebar groups them
  under still use a bare `localeCompare`.
- **macOS and Linux targets are configured but untested**, and have no icons.
- ~~**Source comments are in Czech.**~~ Resolved in 1.0.1.

[Unreleased]: https://github.com/simplixionet/ConsoleWard/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/simplixionet/ConsoleWard/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/simplixionet/ConsoleWard/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/simplixionet/ConsoleWard/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/simplixionet/ConsoleWard/tree/v1.0.0

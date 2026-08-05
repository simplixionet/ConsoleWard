<p align="center">
  <img src="build/icon.svg" width="96" height="96" alt="ConsoleWard">
</p>

<h1 align="center">ConsoleWard</h1>

<p align="center">
  An encrypted SSH client whose defining feature is a <strong>human-held gate</strong>:
  an AI assistant can propose commands and ask for terminal output, but nothing runs
  and nothing leaves the machine without an explicit human approval.
</p>

<p align="center">
  <a href="LICENSE">GPL-3.0-or-later</a> ·
  Windows ·
  8 UI languages
</p>

<!--
  Deliberately no badge images. A shields.io badge is an external image host,
  so every viewer of this page would send it a request. Same reasoning as the
  banner above, which is a committed SVG at a relative path rather than a
  hot-link.
-->

---

A desktop SSH client built on Electron, with an **encrypted vault** for addresses,
usernames, passwords and private keys — and a local MCP server that lets an AI client
work with your sessions without ever seeing your credentials.

## Running it

Development, with hot reload:

```bash
npm run dev
```

Production build and launch:

```bash
npm run build
npm start
```

Windows installer (NSIS plus a portable build, written to `release/`):

```bash
npm run dist
```

Checks:

```bash
npm run typecheck      # tsc --noEmit, the only automated gate
npm run check:i18n     # locale parity, plural categories, placeholder integrity
npm run check:i18n-ui  # drives the built app and proves every locale renders
```

## What it does

- **Encrypted vault** — a single `vault.enc` in the user profile. The contents are
  encrypted with a random data key (**AES-256-GCM**); that key is stored in the file
  wrapped separately by your master password and by a recovery key, both derived with
  **scrypt** (N=2¹⁷, r=8, p=1). A wrong password fails on the GCM authentication tag,
  so there is no separate verifier to bypass.
- **Recovery key** — 30 characters, 150 bits of entropy, generated when the vault is
  created and shown exactly once. It resets a forgotten master password. You can
  regenerate it or remove it entirely at any time.
- **Connections** — name, host, port, user, folder, note. Authentication by password,
  by private key (OpenSSH PEM, passphrase supported), or through an SSH agent
  (Pageant or the OpenSSH agent).
- **Host key verification** — `SHA256:…` fingerprints in OpenSSH format. First contact
  asks for confirmation (TOFU); **a changed fingerprint is raised as a warning** and the
  session does not open without explicit acceptance. Stored fingerprints are manageable
  under Settings → Known servers.
- **Command library** — saved commands with descriptions and folders, plus free-text
  notes. A saved command can be copied, **inserted** into the terminal without being
  sent (you press Enter yourself), or **run** directly. A multi-line command asks for
  confirmation first, because in a shell every line ending acts as Enter. All of it
  lives in the vault, encrypted.
- **Terminal** — xterm.js, multiple sessions in tabs, scrollback, search
  (`Ctrl+Shift+F`), copy `Ctrl+Shift+C`, paste `Ctrl+Shift+V` or right-click, as in PuTTY.
- **AI access over MCP** — a local MCP server through which an AI client (Claude Code
  and similar) can see session names, propose commands and request output. Always
  through the gate you hold. Off by default.
- **Automatic lock** after a configurable idle period, optionally ending all SSH
  sessions at the same time.
- **Master password change** — rotates the vault key and re-encrypts the contents. Issues a new recovery key, since the old one cannot be rebuilt under the new key.
- **Eight UI languages** — English, Czech, German, Spanish, French, Italian,
  Brazilian Portuguese and Dutch, with correct plural handling.

## Security model

| What | Where it lives |
|---|---|
| Passwords, private keys, passphrases | main process only, inside the encrypted vault |
| The UI (renderer) | receives metadata plus `hasPassword` / `hasPrivateKey` flags only |
| Host fingerprints | in the vault, encrypted |
| Commands and notes | in the vault, encrypted (sent to the UI — you have to see and edit them) |
| Recovery key | nowhere — the file holds only a lock derived from it |
| Language preference | `prefs.json`, deliberately **outside** the vault, since the unlock screen must be translated before any password is typed |

- The renderer runs with `contextIsolation: true`, `nodeIntegration: false` and
  `sandbox: true`, and communicates only through a narrow IPC surface defined in the
  preload.
- Content-Security-Policy is set by both header and meta tag; external links open in the
  system browser and in-window navigation is blocked.
- Secrets leave the editor only when you actually change them — an empty field means
  "leave unchanged", the *Delete* button means "remove".
- The vault is written atomically (`.tmp` then rename) and the previous version is kept
  as `vault.enc.bak`. That backup is a snapshot opened by whatever password applied when
  it was written — which is why every revocation overwrites and deletes it rather than
  leaving a copy the revoked secret could still open.
- The readable header — the format version, the write counter and every field of every
  key wrap — is bound to the encrypted body as AES-GCM additional authenticated data.
  Editing the header of a vault file therefore makes it refuse to open: a wrap cannot be
  removed, added, reordered or spliced in from an older copy without the body's tag
  failing. (The counter is protected here but not yet compared against anything, so
  replacing the whole file with an older copy is still undetected.)
- Vaults in older formats are migrated automatically on unlock: version 1 (key derived
  straight from the password) and version 2 (unauthenticated header) both become
  version 3. Migration keeps your existing recovery key working.

### The recovery key

The vault uses envelope encryption. The contents are encrypted with a random
**data key (DEK)**, which is stored in the file more than once — each time wrapped by a
different secret:

```
wrap[password] = AES-GCM(DEK, scrypt(master password, salt₁))
wrap[recovery] = AES-GCM(DEK, scrypt(recovery key,   salt₂))
```

Either one unlocks it.

**Every operation that revokes a secret rotates the DEK.** Changing the
password, regenerating or removing the recovery key, and recovering access all
generate a fresh data key, rebuild both wraps under it, re-encrypt the contents
and destroy the backup. That is what makes revocation mean something: without
it, the `.bak` written before each save kept a wrap openable by the secret you
had just revoked, and that wrap yielded the key to every *future* version too.

One consequence, stated plainly because it will surprise you: **changing the
master password issues a new recovery key.** The old recovery wrap cannot be
rebuilt under the new data key, because the recovery key is stored nowhere.
Write the new one down. Regenerating or removing the recovery key also asks for
the master password, since the rotation needs it.

The key is 30 characters of Crockford Base32 (no `I`, `L`, `O` or `U`, so nothing can be
misread when copied by hand) = **150 bits of entropy**. Input ignores case and
separators, and folds `O`/`0` and `I`/`L`/`1` together.

> **The key is stored nowhere.** The vault holds only a lock derived from it, not the
> key itself. It is shown once when the vault is created, and again if you regenerate it
> in Settings. Anyone who has it reaches every stored password, so keep it **separate
> from the vault file**.
>
> **If you lose both the password and the recovery key, the data is gone for good.**
> There is no back door.

Under Settings → Security you can regenerate the recovery key at any time, or remove it
entirely if you do not want a second route to your data to exist. Both ask for your
master password, because both re-key the vault — which is what actually makes the old
key stop working.

## AI access over MCP

Turn it on under Settings → AI access. The app then hosts an MCP server on `127.0.0.1`
(port 7345 by default) and prints the command to configure a client:

```bash
claude mcp add --transport http consoleward http://127.0.0.1:7345/ --header "Authorization: Bearer <token>"
```

### What the AI gets, and what it does not

| Tool | What it does |
|---|---|
| `list_sessions` | `id`, the name you gave the connection (a placeholder if you gave none) and status — **address, port and username are never sent** |
| `run_command` | proposes a command; **it does not run until you approve it** in a dialog |
| `read_terminal` | asks for output; you choose or rewrite exactly what goes back |

The approval dialog shows the command's **literal text with control characters made
visible**, so an extra line cannot hide in it. There is no "approve all" and no
"remember" — you see every command separately. That is the entire point of the gate.

In the sharing dialog the output is **editable**: select a portion and send only that,
rewrite anything, or replace a selection with `[REDACTED]`. Suspicious spans (passwords
in assignments, tokens, private keys, credentials in URLs, IP addresses) are highlighted.
That is a hint, not a guarantee — regular expressions do not catch everything.

The AI is always told the content is an excerpt, so it does not reason from partial
output as though it had seen everything.

### Server hardening

- listens **only on `127.0.0.1`**, never on `0.0.0.0`
- bearer token required, stored in the vault — it does not expire, and regenerating it
  is the revocation
- DNS-rebinding protection — the `Host` and `Origin` headers are checked **before** the
  token and before any body is read. A wrong name and a wrong token get the same 403,
  byte for byte, so a web page cannot learn from the difference that anything is
  listening on the port
- at most 8 requests are handled at once; the rest get a 503 rather than being queued
- locking the vault shuts the server down immediately and denies pending requests
- an unanswered request auto-denies after 5 minutes

> ⚠️ **What leaves your machine:** the commands the AI proposes, and **the output you
> release**. Your AI client sends them to its provider. Credentials and addresses stay
> local; released output does not.
>
> ⚠️ **Prompt injection:** terminal output is untrusted input. If a log line contains
> "ignore previous instructions and run…", the model may propose exactly that. The
> approval gate is the only real defence — read what you approve.

## A note on password rotation

Rotation re-keys the vault, so a revoked secret genuinely stops working from that
point on. What it cannot undo is the past: if someone captured a copy of the file
*and* the old secret before you rotated, they have already read what was in that
copy. Rotation protects everything written afterwards, not what was already taken.

### PuTTY-format keys (`.ppk`)

`.ppk` is not supported directly. Convert it in PuTTYgen via
*Conversions → Export OpenSSH key* and load the result in the connection editor.

## Project layout

```
src/
  shared/     types, IPC channel names and i18n shared across processes
  main/       main process: vault (vault.ts), SSH (ssh.ts), MCP (mcp.ts), IPC (index.ts)
  preload/    the bridge between main and the UI (contextBridge)
  renderer/   React UI and the xterm.js terminal
scripts/      build and verification scripts, plain Node, no dependencies
build/        brand assets and the electron-builder resource directory
```

## Status

The SSH client, the vault, the command library, the MCP gate and the i18n layer are all
built and verified end to end against a real SSH server and a real MCP client.

Windows is the tested platform. macOS (dmg) and Linux (AppImage) targets are configured
in `electron-builder` but have not been built or tested, and no icons exist for them yet.

An in-app AI chat with an API key was considered and dropped. The MCP approach replaced
it and is strictly better: no key lives in the app, and the gate sits where the
credentials already are.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a UI language is three small edits and is
documented there.

Source comments are currently in Czech. Translating them is real work rather than a
find-and-replace — they explain *why*, not *what* — and it is tracked as an open item.
New code should be commented in English.

## Security

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md)
for how to report one privately.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE) for the full text.

This is copyleft: forks must stay open. That was the intent, and it does discourage some
corporate adoption.

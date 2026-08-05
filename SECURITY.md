# Security Policy

ConsoleWard holds SSH credentials and stands between an AI assistant and a live
terminal. A vulnerability here is not an inconvenience. Reports are welcome and
will be taken seriously.

## Reporting a vulnerability

**Please do not open a public issue.** A public report tells everyone, including
whoever would use it, before there is a fix.

Two private channels:

1. **GitHub Security Advisories** — the *Security* tab on this repository,
   "Report a vulnerability". This is preferred: it is private, it threads, and
   it produces a CVE if one is warranted.
2. **Email** — `security@simplixio.net`

Please include enough to reproduce: version, platform, what you did, what
happened, and what you expected. A proof of concept helps enormously; so does
an honest "I am not sure this is exploitable, but it looks wrong".

### What to expect

| | |
|---|---|
| Acknowledgement | within 5 working days |
| Initial assessment | within 14 days |
| Fix or a stated plan | depends on severity and on whether the fix is mine to make |

This is a small project maintained by one person. Those are honest targets, not
a contractual SLA. If you have not heard back within the acknowledgement window,
assume the message went astray and try the other channel.

You will be credited in the release notes unless you ask not to be.

## Scope

In scope, and most interesting first:

- **The approval gate.** Anything that lets `run_command` execute without human
  approval, or `read_terminal` return content the human did not release, is the
  most serious class of bug this project has.
- **Vault cryptography.** Key derivation, envelope wrapping, the GCM tag as the
  only verifier, the v1→v3 and v2→v3 migrations.
- **Host key verification.** Anything that lets a changed fingerprint through
  without explicit acceptance, or that overwrites a stored fingerprint on
  rejection.
- **The MCP server.** Binding, bearer token handling, DNS-rebinding protection
  on `Host` and `Origin`, behaviour when the vault locks.
- **Renderer isolation.** Anything that gets a secret into the renderer process,
  or escapes the context isolation / sandbox.
- **Secret leakage.** Credentials in logs, in crash output, in the terminal
  buffer handed to an AI, or in the `.bak` file.

Out of scope:

- **Prompt injection through terminal output that the approval dialog correctly
  displays.** Terminal output is untrusted input by design, and a model
  proposing something hostile after reading a crafted log line is the expected
  case, not a bug. The gate is the control. A report that the *gate itself* can
  be bypassed or made misleading — a command whose literal text renders
  differently from what executes, for instance — is very much in scope.
- **The secret-highlighting heuristic missing something.** It is documented as a
  hint, not a guarantee, in both the UI and the README. A pattern worth adding
  is a welcome pull request rather than a vulnerability report.
- Attacks that require an already-compromised machine, physical access, or a
  malicious OS.
- Missing hardening that does not lead to a concrete exploit. Interesting, but
  please file it as an issue rather than an advisory.

## Known and accepted

These are documented trade-offs, not oversights. Reporting them is fine, but
you will get this answer:

- **Rotation protects the future, not the past.** Every revocation now re-keys
  the vault and destroys the backup, so a revoked secret stops working from that
  point on. What it cannot undo is a copy someone already took together with the
  matching secret — they have read what was in that copy. This was a real
  finding, fixed on 2026-08-05; before that, revocation revoked nothing at all.
- **Translations are machine-produced.** The 81 security-critical strings are
  checked mechanically for placeholder integrity and were read by a human for
  dropped negations, but they have not had a native review. A weakened warning
  in a non-English locale is a real bug and worth reporting.

- **The MCP token is convenience, not a defence against a compromised machine.**
  It is 256 random bits, it lives inside the encrypted vault, and it is what stops
  any other local process from opening `127.0.0.1:7345`, reading your session
  names with no human in the loop, and putting an approval dialog it worded itself
  in front of you. That is worth having. What it cannot stop is a process running
  as you with rights over this one: such a process reads the clipboard, reads the
  renderer's memory or simply drives the UI, and the vault is already unlocked in
  front of it. Copying the token puts it on a machine-wide clipboard every program
  can read, and on Windows into Clipboard History and — if you sync it — Cloud
  Clipboard on your other machines. No application can clear those, Electron
  offers no way to mark clipboard content transient, and ConsoleWard does not
  pretend otherwise by wiping the clipboard on a timer. The token also does not
  expire: the server runs only while the app is open and the vault is unlocked, so
  a stale token buys nothing at a moment you are not sitting there. **Regenerating
  is the revocation** — one click, and it restarts the server so the old token
  stops working immediately.

- **Rolling `vault.enc` back to an older copy is detected, but not prevented.**
  The file carries a write counter bound into the body's GCM tag, so it cannot be
  forged, and the last value seen is kept outside the vault in `vault.guard`.
  Opening a vault older than that anchor shows a warning naming both numbers —
  it does not refuse to open the file, because a legitimate restore from backup
  looks identical and locking you out of your own connections is the worse
  failure. Take the warning seriously: after a rollback your saved host
  fingerprints are stale, so a server whose key really did change looks like a
  first connection.

  **What the anchor is worth.** `vault.guard` is sealed with the platform's
  password store (DPAPI, Keychain, libsecret), which stops anyone who can only
  *write files* from forging it — a sync client, a restored backup, a share with
  loose permissions, an offline disk image. It stops nothing that runs as you:
  the same keystores will happily seal a forged anchor for any process in your
  session, and it can simply delete `vault.guard`, which turns detection off with
  no warning at all. So this catches accidents and careless attackers, not a
  deliberate attack from your own account.

  On Linux with no keyring — or with the `basic_text` backend, which only encodes
  — the anchor is written in plaintext and records that it is unprotected. It
  still catches every accidental rollback. It is not a defence against anyone who
  can write to your profile directory, and it does not claim to be.

- **`removeRecoveryKey` carries a branch that cannot be reached.** Before it
  re-keys the vault the function looks up the password wrap and throws
  `error.lastUnlockMethod` if there is none, and no public API can produce that
  state: `create` writes a password wrap, `unlock` refuses a file without one,
  `unlockLegacy` builds one while migrating, and `reseal` rejects a secret list
  that has none. So a report that the branch is dead is correct, and it is
  staying anyway. It is an invariant assertion, not a user-facing error: the day
  one of those four paths changes, what surfaces is a translated message rather
  than a `TypeError` out of `openWrap(undefined, …)` in the middle of a DEK
  rotation, with the wraps already half rebuilt. Removing it buys tidiness and
  pays for it in the worst place in the file.

## Supported versions

Pre-1.0. Only the latest release gets fixes.

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
  only verifier, the v1→v2 migration.
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

- **Rotating the master password does not rotate the data key.** It re-wraps it.
  Someone who already captured the file *and* the old password has already read
  the data; rotation does not undo that. Documented in the README, with the
  remedy: create a new vault.
- **The `.bak` file is a snapshot.** The password that applied when it was
  written is the password that opens it.
- **Translations are machine-produced.** The 61 security-critical strings are
  checked mechanically for placeholder integrity and were read by a human for
  dropped negations, but they have not had a native review. A weakened warning
  in a non-English locale is a real bug and worth reporting.

## Supported versions

Pre-1.0. Only the latest release gets fixes.

<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

Not a vulnerability fix, please. Those go through the private channel in
SECURITY.md — a public pull request is a published exploit until it is released.
-->

## What and why

<!-- What changed, and what problem it solves. If you made a judgement call,
say what the alternative was and why you did not take it. -->

## Checks

```
npm test && npm run typecheck && npm run build && npm run check:i18n && npm run check:notice
```

- [ ] All of the above pass
- [ ] `npm run check:i18n-ui` passes, or this change cannot affect the UI
- [ ] Style matches the file I edited (2 spaces, no semicolons, single quotes)
- [ ] New files carry the SPDX header
- [ ] New comments explain **why**, in English

## If this touches a security boundary

Tick what applies — the vault, the MCP gate, host-key verification, or anything
the AI can reach. These get read line by line.

- [ ] This does not touch any of them

**Mutation check.** A test that also passes against broken code manufactures
confidence. For any new security assertion, break the source deliberately,
confirm the test goes red rather than hanging, then restore it.

<!-- Which mutation did you use, and which test caught it? -->

- [ ] Not applicable — no new security assertion

**Anything you could not test**, and why. A green suite that implies coverage
which is not there is the thing this section exists to prevent.

## Notes for the reviewer

<!-- Anything you are unsure about, or deliberately left out of scope. -->

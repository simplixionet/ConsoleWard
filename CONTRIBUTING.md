# Contributing

Thanks for looking. This is a security tool, which shapes most of what follows.

## Before anything else

**Do not report a vulnerability here.** See [SECURITY.md](SECURITY.md) for the
private channels.

Taking part also means [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). It is short,
and it is the standard everyone here is held to.

## Getting set up

```bash
npm ci
npm run dev
```

Checks, all of which should pass before you open a pull request:

```bash
npm test               # the test suite
npm run typecheck      # tsc --noEmit
npm run build          # must succeed
npm run check:i18n     # locale parity, plural categories, placeholders
npm run check:notice   # NOTICE matches the dependency tree
npm run check:i18n-ui  # drives the built app; run `npm run build` first
```

`check:i18n-ui` is the only one CI does not run: it drives the built app over
the Chrome DevTools Protocol and needs a real desktop session, so on a headless
runner it would either hang or pass vacuously. Run it locally before a release.

There is no linter and no formatter config. Style is held by hand — match the
file you are editing.

## Tests

```bash
npm test
node --experimental-test-module-mocks --import ./test/setup.mts --test test/vault.test.mts
```

Node's built-in runner, no framework. Tests are `test/*.test.mts` and import
`src/` directly — node 24 strips the types, so there is no build step. Five
things make that work and none of them should be changed casually:

- `src/package.json` carries `{"type":"module"}`. Without it node reads `.ts` as
  CommonJS and `export` is a syntax error.
- `test/ts-resolver.mts` is a resolve hook that appends `.ts` to the
  extensionless relative imports the source uses, and adds `type: 'json'` to
  dictionary imports.
- Modules that reach Electron are replaced with `mock.module('electron', …)`.
- Both flags in the `test` script are load-bearing. `--import ./test/setup.mts`
  is what registers the resolve hook above, and it has to happen before any test
  module is loaded — hence `--import` rather than an import inside a test file.
  `--experimental-test-module-mocks` is what puts `mock.module` on the `test`
  namespace at all; without it the call is not a function and every file that
  stubs Electron dies at import time.
- Main-process files import shared code **relatively** (`'../shared/x'`), never
  through the `@shared` alias. The resolver knows nothing about the alias, so
  `@shared` in `src/main/` builds and type-checks cleanly and then fails only at
  test time.

### The bar for a security test

**A test that also passes against broken code is worse than no test** — it
manufactures confidence. So for anything asserting a security property, prove it
can fail:

1. Commit your work first. This is not optional advice; restoring a file after a
   mutation is how uncommitted fixes get deleted.
2. Break the source deliberately — remove the guard, revert the check.
3. Confirm the test goes **red**, and that it fails rather than hangs. A test
   that hangs on a regression reads as a stuck CI job, not as a bug.
4. `git checkout -- <file>`, confirm green, confirm `git diff` is empty.

Say in the pull request which mutation you used. If a property genuinely cannot
be tested — timing behaviour, anything needing a DOM — write that down in the
test file rather than leaving a green suite implying coverage that is not there.
There are worked examples of both in `test/mcp-http.test.mts`.

`src/main/index.ts` is not reachable from a test: it exports nothing and calls
`app.requestSingleInstanceLock()` at module scope. Logic that needs testing gets
lifted out into its own module — `approvals.ts`, `settings.ts`, `textFile.ts`
were all extracted for exactly that reason. Please do the same rather than
working around it.

## Adding a UI language

Three edits, and the checks will tell you if you missed one.

**1. The dictionary.** Copy `src/shared/locales/en.json` to
`src/shared/locales/<code>.json`, where `<code>` is the BCP 47 tag — `pt-BR`,
not `pt_br`. Translate the values, leave the keys alone.

Four keys are pluralised: `term.connCount`, `term.snipCount`, `mcp.pickLines`
and `mcp.pickChars`. Supply a variant for every CLDR category your language uses
for integers, and **only** those.
`npm run check:i18n` derives the list from `Intl.PluralRules` and will tell you
exactly which are missing. Do not copy English's `_one` / `_other` blindly —
Czech needs `_few` as well, Polish and Russian need `_many`, and Japanese needs
only `_other`.

Do not translate: product names (`ConsoleWard`, `Claude Code`, `PuTTYgen`,
`Pageant`), protocol and format names (`SSH`, `MCP`, `OpenSSH PEM`,
`AES-256-GCM`), or literal values like `root` and `127.0.0.1`. The existing
locales show where the line sits.

**2. The registry.** Add one line to `LOADERS` in
`src/shared/locales/index.ts`:

```ts
'<code>': () => import('./<code>.json').then((m) => m.default)
```

The `.then((m) => m.default)` is not optional. `import()` of JSON yields the
module namespace, not the data. Omitting it type-checks cleanly and then fails
at runtime by silently falling back to English — no error, no console warning.

**3. The list.** Add an entry to `LOCALES` in `src/shared/i18n.ts` with the
code, the language's name **in that language**, and its English name.

Then run `npm run check:i18n && npm run build && npm run check:i18n-ui`. The
second script loads every offered locale in the real app and fails if any of
them renders English.

### Fixing an existing translation

Very welcome — they are machine-produced and have not been natively reviewed.

The strings under `hostkey.`, `mcp.`, `secret.`, `recovery.` and `vault.` are
**security-critical**: they are the host-key change warning, the command
approval and output-sharing dialogs, the labels the secret highlighter puts on
what it found, the recovery-key notice, and the vault-rollback warning. The list
lives in `SECURITY_NAMESPACES` in `scripts/check-i18n-dictionaries.mjs`, which
is also what makes `check:i18n` hold those keys to placeholder integrity. A
translation that softens
"continue **only** if you have verified through another channel" into
"continue if you have verified" is a security bug, not a wording preference.
Please flag those explicitly in the pull request so they get read carefully.

## Code

**No new dependencies without a conversation first.** Every package is
third-party code someone has to keep watching, and this application holds
private keys. The i18n layer is hand-written for exactly this reason. If a
dependency is genuinely the right answer, say why in the issue before writing
the code.

**Style**, enforced by hand:

- 2-space indent, **no semicolons**, single quotes, no trailing commas
- roughly 100-character lines
- `import type { … }` for type-only imports
- `camelCase` functions, verb first; `SCREAMING_SNAKE_CASE` module constants
- `PascalCase.tsx`, one default-exported component per file
- named exports everywhere else; `export default` only for React components

**Comments explain why, not what.** The strongest convention in this codebase is
that every module opens with a block describing the threat it addresses or the
invariant it holds. Please keep that up. Write new comments in English; the
existing Czech ones are being translated separately.

**Architecture, non-negotiable:**

- `src/shared/` must stay free of Electron, Node and DOM specifics.
- Secrets live only in `src/main/`. The renderer gets `*Meta` projections and
  `has*` booleans, never a password, key or passphrase.
- Adding an IPC call is four edits in order: type in `src/shared/types.ts`,
  channel in `src/shared/channels.ts`, handler via `handle()` in
  `src/main/index.ts`, binding in `src/preload/index.ts`.
- Never throw a bare `Error` with a literal message from the main process. Use
  `appError(key, params)` so it is translated at throw time.
- Strings the AI reads over MCP stay English by design. It is a machine
  interface; translating it only degrades model behaviour. The dialogs the
  *human* sees are fully localised.

## Pull requests

- One concern per pull request.
- Say what you changed and why. If you made a judgement call, say what the
  alternative was.
- If it touches the vault, the MCP gate or host-key verification, say so in the
  title. Those get read line by line.
- Commits should explain themselves. No AI attribution trailers.

## Licence

By contributing you agree your work is licensed under **GPL-3.0-or-later**, the
same as the project. New files should carry:

```
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) <year> <your name>
```

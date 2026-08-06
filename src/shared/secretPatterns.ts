// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Detekce podezřelých míst v textu, který se chystáš poslat AI.
 *
 * Cílem NENÍ spolehlivá ochrana – regulární výrazy tajemství nikdy nepochytají
 * všechna. Jde o to, aby ti nápadné věci padly do oka i ve chvíli, kdy
 * proklikáváš dvacátý dialog za večer. Rozhodnutí zůstává na tobě.
 */

export interface SecretMatch {
  start: number
  end: number
  label: string
  /** high = skoro jistě tajemství, medium = stojí za pohled */
  severity: 'high' | 'medium'
}

/**
 * A whole scan, including what it did NOT look at.
 *
 * `findSecrets` hands back only the matches, which is all most callers want.
 * The two flags are what the share dialog needs: a summary that says "3
 * findings" over text holding three thousand is worse than no summary at all,
 * because it reads as a clean bill of health.
 */
export interface SecretScan {
  matches: SecretMatch[]
  /** A pattern reached MAX_HITS_PER_PATTERN; later hits of it were not collected. */
  incomplete: boolean
  /** The text was longer than MAX_SCAN_CHARS; only its beginning was scanned. */
  clipped: boolean
}

/**
 * Kolik shod na jeden vzor se ještě sbírá.
 *
 * A ceiling on the sort, the merge and the renderer, not on the regex engine —
 * two thousand `<mark>` nodes are already past what anyone reads. Reaching it
 * sets `incomplete`, so the count in the dialog is a floor rather than a lie.
 * Per pattern, so `ip -4 route` on a router caps secret.ipAddress while every
 * other pattern still scans the text whole.
 */
export const MAX_HITS_PER_PATTERN = 2000

/**
 * Kolik znaků se vůbec prohledává.
 *
 * Matches SCROLL_MEMORY_BYTES in ssh.ts, so it never bites on text this
 * application produced — it is here for what a human pastes into the textarea,
 * and as a hard bound on how long one scan can hold the main process event
 * loop, where `outputNeedsReview` runs it and a stall freezes every session.
 */
export const MAX_SCAN_CHARS = 256 * 1024

interface PatternSpec {
  re: RegExp
  label: string
  severity: 'high' | 'medium'
}

const PATTERNS: PatternSpec[] = [
  {
    /*
     * Celý blok privátního klíče, od BEGIN po END.
     *
     * `{0,8192}?` rather than `*?`, for the same reason `secret.urlCreds` got a
     * bound: unbounded, every BEGIN with no END after it rescans to the end of
     * the buffer, so a text full of headers is quadratic. Measured on 256 KB of
     * bare `-----BEGIN PRIVATE KEY-----` lines: 133 ms before, and since B4 that
     * runs on the main process event loop, driven by whatever a compromised
     * host chooses to print.
     *
     * Bounding is safe here only because of the pattern directly below. A key
     * whose body exceeds the bound stops matching as a *block*, but
     * `secret.privateKeyStart` still catches its header on its own and also at
     * `high`, so nothing becomes invisible — the finding is merely labelled as a
     * start marker rather than a complete block. 8192 is around 2.5x the body of
     * a 4096-bit RSA key, which is the largest thing realistically pasted here.
     */
    /*
     * The trailing `[ A-Z]*` is not symmetry for its own sake. PEM labels can
     * carry words on *both* sides of "PRIVATE KEY", and exactly one format in
     * common use does: `-----BEGIN PGP PRIVATE KEY BLOCK-----`. Without it the
     * suffix ` BLOCK` sat between the label and the closing dashes and the
     * pattern could not match, so an armoured GnuPG secret key — the one thing
     * in this list nobody would ever want to hand a model — scanned as nothing
     * worse than `secret.randomString`, i.e. `medium`, i.e. not enough to force
     * the review dialog open. RSA/OPENSSH/EC/ENCRYPTED all matched, which is
     * why it went unnoticed.
     */
    re: /-----BEGIN[ A-Z]*PRIVATE KEY[ A-Z]*-----[\s\S]{0,8192}?-----END[ A-Z]*PRIVATE KEY[ A-Z]*-----/g,
    label: 'secret.privateKey',
    severity: 'high'
  },
  {
    re: /-----BEGIN[ A-Z]*PRIVATE KEY[ A-Z]*-----/g,
    label: 'secret.privateKeyStart',
    severity: 'high'
  },
  {
    /*
     * PuTTY's own key format. This application is a PuTTY replacement, so its
     * users are precisely the population with `.ppk` files on disk — and a
     * `.ppk` is PEM-shaped in spirit but shares none of the BEGIN/END text the
     * pattern above keys on. Both markers are matched: the header names the
     * file, and `Private-Lines:` still identifies it when only the tail of a
     * `type`/`cat` scrolled past.
     */
    re: /\b(?:PuTTY-User-Key-File-\d{1,2}|Private-Lines)\s*:/g,
    label: 'secret.puttyKey',
    severity: 'high'
  },
  {
    // kubeconfig: the embedded client certificate key, base64 in one field.
    // A cluster-admin credential that reads as a long random string otherwise.
    re: /\bclient-key-data\s*:\s*\S{16,}/g,
    label: 'secret.kubeClientKey',
    severity: 'high'
  },
  {
    // ~/.docker/config.json — base64 of `user:password` for a registry.
    // "auth" is not in the keyword list below and would slip through it.
    re: /"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"/g,
    label: 'secret.dockerAuth',
    severity: 'high'
  },
  {
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,
    label: 'secret.jwt',
    severity: 'high'
  },
  {
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    label: 'secret.aws',
    severity: 'high'
  },
  {
    re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g,
    label: 'secret.github',
    severity: 'high'
  },
  {
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    label: 'secret.slack',
    severity: 'high'
  },
  {
    re: /\bsk-[A-Za-z0-9_-]{16,}\b/g,
    label: 'secret.apiKey',
    severity: 'high'
  },
  {
    re: /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}/gi,
    label: 'secret.authHeader',
    severity: 'high'
  },
  {
    /*
     * heslo=…, password: …, ale i DB_PASSWORD=…, MYSQL_ROOT_PASSWORD=…, apiKey: …
     * Klíčové slovo smí být uprostřed identifikátoru – proto se okolo něj
     * povolují další znaky místo prostého \b, které se mezi „_" a „P" nechytí.
     *
     * The optional `["']` before the separator is what makes this work on JSON
     * and quoted YAML. A key is written `"password": "…"` there, and the quote
     * that closes the key is not in the identifier class, so the pattern used to
     * run out of characters before reaching the colon and matched nothing at
     * all — every secret in every JSON config the user happened to `cat` read
     * as clean. That covers `~/.docker/config.json`'s `identitytoken` too.
     */
    re: /(?<![A-Za-z0-9_])[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|heslo|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]{0,40}["']?\s*[=:]\s*("[^"\n]+"|'[^'\n]+'|\S+)/gi,
    label: 'secret.assignment',
    severity: 'high'
  },
  {
    /*
     * ~/.netrc — `machine host login user password secret`.
     *
     * Whitespace-separated, so the assignment pattern above never sees the
     * `=`/`:` it needs. Anchored on `machine`/`default` and bounded to 200
     * characters of the same line, which keeps it off prose that merely uses
     * the word "password" and keeps the scan linear.
     */
    re: /^[^\S\n]*(?:machine|default)\b[^\n]{0,200}?\bpassword[^\S\n]+\S+/gim,
    label: 'secret.netrc',
    severity: 'high'
  },
  {
    /*
     * ~/.pgpass — `host:port:database:user:password`, five fields exactly.
     *
     * The port field is restricted to digits and `*` and the last field forbids
     * a colon, which is what keeps this off /etc/passwd (seven fields, so the
     * tail would have to contain colons) and off IPv6 addresses and timestamps.
     */
    re: /^[^\s:]{1,253}:[0-9*]{1,5}:[^\s:]{0,64}:[^\s:]{1,64}:[^\s:]+$/gm,
    label: 'secret.pgpass',
    severity: 'high'
  },
  {
    /*
     * protokol://uzivatel:heslo@host
     *
     * `{0,19}` rather than `*`: '.', '-' and '+' are all inside the class and
     * all three open a word boundary, so `*` gave one starting point per
     * punctuation mark, each scanning to end of input for `://`. Quadratic —
     * 256 KB of `a-a-a-…` took 34 seconds, on the main process event loop
     * since outputNeedsReview started calling this. Twenty characters is
     * longer than any scheme that carries credentials (postgresql, mongodb+srv,
     * git+ssh all fit) and turns every start position into fixed work.
     */
    re: /\b[a-z][a-z0-9+.-]{0,19}:\/\/[^\s:/@]+:[^\s@/]+@\S+/gi,
    label: 'secret.urlCreds',
    severity: 'high'
  },
  {
    // /etc/shadow řádek: uzivatel:$6$sul$hash:...
    re: /^[a-z_][a-z0-9_-]*:\$[0-9a-z]\$[^\s:]+/gim,
    label: 'secret.passwordHash',
    severity: 'high'
  },
  {
    re: /\bssh-rsa\s+AAAA[A-Za-z0-9+/=]{40,}/g,
    label: 'secret.sshPublicKey',
    severity: 'medium'
  },
  {
    // Dlouhý náhodně vypadající řetězec – často hash nebo token.
    re: /\b[A-Za-z0-9+/_-]{40,}={0,2}\b/g,
    label: 'secret.randomString',
    severity: 'medium'
  },
  {
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    label: 'secret.ipAddress',
    severity: 'medium'
  }
]

/**
 * Prohledá text a přizná, co neprohledal.
 *
 * Překryvy se slučují – přednost má dřívější začátek, při stejném začátku
 * delší úsek a vyšší závažnost.
 */
export function scanSecrets(text: string): SecretScan {
  const clipped = text.length > MAX_SCAN_CHARS
  // Head, never tail: the dialog paints these offsets over the whole text.
  const scanned = clipped ? text.slice(0, MAX_SCAN_CHARS) : text
  let incomplete = false
  const raw: SecretMatch[] = []

  for (const { re, label, severity } of PATTERNS) {
    // Vlastní kopie kvůli sdílenému lastIndex u globálních regexů.
    const rx = new RegExp(re.source, re.flags)
    let m: RegExpExecArray | null
    let hits = 0
    while ((m = rx.exec(scanned)) !== null) {
      if (m[0].length === 0) {
        rx.lastIndex++
        continue
      }
      if (hits === MAX_HITS_PER_PATTERN) {
        // One more hit exists. Stop collecting it, but do not stop saying so.
        incomplete = true
        break
      }
      hits++
      raw.push({ start: m.index, end: m.index + m[0].length, label, severity })
    }
  }

  raw.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start
    if (a.severity !== b.severity) return a.severity === 'high' ? -1 : 1
    return b.end - a.end
  })

  const merged: SecretMatch[] = []
  for (const match of raw) {
    const last = merged[merged.length - 1]
    if (last && match.start < last.end) {
      // Překryv – rozšíříme předchozí a povýšíme závažnost.
      if (match.end > last.end) last.end = match.end
      if (match.severity === 'high' && last.severity !== 'high') {
        last.severity = 'high'
        last.label = match.label
      }
      continue
    }
    merged.push({ ...match })
  }
  return { matches: merged, incomplete, clipped }
}

/** Jen shody, bez informace o tom, co se neprohledalo. */
export function findSecrets(text: string): SecretMatch[] {
  return scanSecrets(text).matches
}

/**
 * Souhrn pro hlavičku dialogu, seřazený od nejčastějšího.
 * Vrací překladové klíče – text sestaví až UI ve zvoleném jazyce.
 */
export function summarizeSecrets(matches: SecretMatch[]): { labelKey: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const m of matches) counts.set(m.label, (counts.get(m.label) ?? 0) + 1)
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([labelKey, count]) => ({ labelKey, count }))
}

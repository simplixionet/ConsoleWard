// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Flags suspicious spans in text about to be sent to an AI. NOT a reliable
 * defence — regexes never catch every secret; the point is that the obvious
 * cases catch the eye even on the twentieth dialog. The decision stays human.
 */

export interface SecretMatch {
  start: number
  end: number
  label: string
  /** high = almost certainly a secret, medium = worth a look */
  severity: 'high' | 'medium'
}

/**
 * A whole scan, including what it did NOT look at. "3 findings" over text
 * holding three thousand is worse than no summary — it reads as a clean bill.
 */
export interface SecretScan {
  matches: SecretMatch[]
  /** A pattern reached MAX_HITS_PER_PATTERN; later hits of it were not collected. */
  incomplete: boolean
  /** The text was longer than MAX_SCAN_CHARS; only its beginning was scanned. */
  clipped: boolean
}

/**
 * Matches collected per pattern — a ceiling on the sort, the merge and the
 * renderer, not on the regex engine. Reaching it sets `incomplete`, so the
 * dialog's count is a floor rather than a lie. Per pattern, so a flood of one
 * kind cannot crowd out the others.
 */
export const MAX_HITS_PER_PATTERN = 2000

/**
 * Hard bound on how long one scan can hold the main process event loop, where
 * `outputNeedsReview` runs it and a stall freezes every session. Matches
 * SCROLL_MEMORY_BYTES in ssh.ts, so it only bites on what a human pastes in.
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
     * Whole private-key block, BEGIN to END.
     *
     * `{0,8192}?` rather than `*?`: unbounded, every BEGIN with no END after it
     * rescans to end of buffer, so text full of headers is quadratic — on the
     * main process event loop, driven by whatever a compromised host prints.
     * Safe only because `secret.privateKeyStart` below still catches an
     * over-long key's header at `high`; do not remove that pattern. 8192 is
     * ~2.5x the body of a 4096-bit RSA key.
     *
     * The trailing `[ A-Z]*` is required: PEM labels carry words on *both* sides
     * of "PRIVATE KEY" in `-----BEGIN PGP PRIVATE KEY BLOCK-----`. Without it an
     * armoured GnuPG key scored only `secret.randomString`/`medium` — not enough
     * to force the review dialog open — while RSA/OPENSSH/EC all matched.
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
     * PuTTY's `.ppk` shares none of the BEGIN/END text above. `Private-Lines:`
     * still identifies it when only the tail of a `type`/`cat` scrolled past.
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
     * `password: …`, but also `DB_PASSWORD=…`, `apiKey: …`. The keyword may sit
     * mid-identifier, hence the character runs either side instead of a plain
     * \b, which does not fire between `_` and `P`.
     *
     * The optional `["']` before the separator is what makes this work on JSON
     * and quoted YAML: in `"password": "…"` the quote closing the key is not in
     * the identifier class, so without it the pattern never reaches the colon
     * and every secret in every JSON config the user `cat`s reads as clean.
     */
    re: /(?<![A-Za-z0-9_])[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|heslo|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]{0,40}["']?\s*[=:]\s*("[^"\n]+"|'[^'\n]+'|\S+)/gi,
    label: 'secret.assignment',
    severity: 'high'
  },
  {
    /*
     * ~/.netrc is whitespace-separated, so the assignment pattern above never
     * sees the `=`/`:` it needs. Bounded to 200 characters of the same line,
     * which keeps the scan linear and off prose that merely says "password".
     */
    re: /^[^\S\n]*(?:machine|default)\b[^\n]{0,200}?\bpassword[^\S\n]+\S+/gim,
    label: 'secret.netrc',
    severity: 'high'
  },
  {
    /*
     * ~/.pgpass — `host:port:database:user:password`, five fields exactly. The
     * digits-only port and the colon-free last field are what keep this off
     * /etc/passwd (seven fields), IPv6 addresses and timestamps.
     */
    re: /^[^\s:]{1,253}:[0-9*]{1,5}:[^\s:]{0,64}:[^\s:]{1,64}:[^\s:]+$/gm,
    label: 'secret.pgpass',
    severity: 'high'
  },
  {
    /*
     * `scheme://user:password@host`. `{0,19}` rather than `*`: '.', '-' and '+'
     * are in the class and each opens a word boundary, so `*` gave one starting
     * point per punctuation mark, each scanning to end of input for `://` —
     * quadratic, on the main process event loop. Twenty characters covers every
     * scheme that carries credentials (postgresql, mongodb+srv, git+ssh).
     */
    re: /\b[a-z][a-z0-9+.-]{0,19}:\/\/[^\s:/@]+:[^\s@/]+@\S+/gi,
    label: 'secret.urlCreds',
    severity: 'high'
  },
  {
    // /etc/shadow line: user:$6$salt$hash:...
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
    // Long random-looking string — often a hash or a token.
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
 * Scans the text and admits what it did not scan. Overlaps are merged: the
 * earlier start wins, then the longer span and the higher severity.
 */
export function scanSecrets(text: string): SecretScan {
  const clipped = text.length > MAX_SCAN_CHARS
  // Head, never tail: the dialog paints these offsets over the whole text.
  const scanned = clipped ? text.slice(0, MAX_SCAN_CHARS) : text
  let incomplete = false
  const raw: SecretMatch[] = []

  for (const { re, label, severity } of PATTERNS) {
    // Own copy: global regexes share `lastIndex`.
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

/** Matches only, dropping what was left unscanned. */
export function findSecrets(text: string): SecretMatch[] {
  return scanSecrets(text).matches
}

/** Returns translation keys, most frequent first — the UI renders the text. */
export function summarizeSecrets(matches: SecretMatch[]): { labelKey: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const m of matches) counts.set(m.label, (counts.get(m.label) ?? 0) + 1)
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([labelKey, count]) => ({ labelKey, count }))
}

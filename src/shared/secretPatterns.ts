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

interface PatternSpec {
  re: RegExp
  label: string
  severity: 'high' | 'medium'
}

const PATTERNS: PatternSpec[] = [
  {
    re: /-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g,
    label: 'secret.privateKey',
    severity: 'high'
  },
  {
    re: /-----BEGIN[ A-Z]*PRIVATE KEY-----/g,
    label: 'secret.privateKeyStart',
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
     */
    re: /(?<![A-Za-z0-9_])[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|heslo|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]{0,40}\s*[=:]\s*("[^"\n]+"|'[^'\n]+'|\S+)/gi,
    label: 'secret.assignment',
    severity: 'high'
  },
  {
    // protokol://uzivatel:heslo@host
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]+@\S+/gi,
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
 * Najde všechny shody. Překryvy se slučují – přednost má dřívější začátek,
 * při stejném začátku delší úsek a vyšší závažnost.
 */
export function findSecrets(text: string): SecretMatch[] {
  const raw: SecretMatch[] = []

  for (const { re, label, severity } of PATTERNS) {
    // Vlastní kopie kvůli sdílenému lastIndex u globálních regexů.
    const rx = new RegExp(re.source, re.flags)
    let m: RegExpExecArray | null
    let guard = 0
    while ((m = rx.exec(text)) !== null && guard++ < 2000) {
      if (m[0].length === 0) {
        rx.lastIndex++
        continue
      }
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
  return merged
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

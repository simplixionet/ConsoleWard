// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The blocklist behind unattended mode.
 *
 * WHAT THIS IS: a second pair of eyes. Unattended mode means the AI works on
 * its own; this list decides the handful of cases where that stops being
 * reasonable and a person should look. A hit does not refuse the command — it
 * raises the ordinary approval dialog, with the offending span highlighted, and
 * the human decides. Everything the list does not recognise runs untouched.
 *
 * WHAT THIS IS NOT: a security boundary. A denylist over shell text cannot be
 * one. `/bin/rm` is not `rm`; `bash -c "…"` hides its argument; a script fetched
 * with curl contains whatever it likes; `dd`, `truncate`, `mv` and a plain `>`
 * each destroy a file without naming anything on this list. Whatever WANTS past
 * this walks past it. The value is entirely in the accident case, and the
 * interface has to say so rather than imply a guarantee.
 *
 * Chained commands are covered by matching anywhere in the text rather than by
 * parsing: `ls && rm -rf /` must trip on its second half, and any attempt to
 * split shell syntax correctly would be a worse bug than matching too eagerly.
 *
 * Every quantifier is bounded. These run over text an AI client supplies.
 */

export interface DangerousPattern {
  /** Stable across releases: the model is told which rule refused it. */
  id: string
  re: RegExp
  /** Fixed English. This reaches the model, which is a machine interface. */
  what: string
}

/**
 * Where a command name may legitimately begin: the start of the text, after a
 * separator, or behind sudo/doas/xargs.
 *
 * Without this the rules fire on the name wherever it appears, so
 * `grep shutdown /var/log/syslog` reads as an order to power the box off. One
 * refusal like that and the whole list gets switched off, which costs far more
 * than the rule ever saved.
 */
const CMD = '(?:^|[;&|(\\n]{1,3}\\s*|\\bsudo\\s+|\\bdoas\\s+|\\bxargs\\s+)\\s*'

/** Path tails that end an argument: whitespace, a quote, a separator, or the end. */
const END = '(\\s|"|\'|;|$)'

export const DANGEROUS_PATTERNS: readonly DangerousPattern[] = [
  {
    id: 'rm.recursiveRoot',
    /*
      Deliberately narrow. `rm -rf ./build` and `rm -rf /var/www/releases/old`
      are ordinary housekeeping, and a rule that stops those is a rule people
      switch off. What is left is the set nobody walks back: the root itself, a
      whole top-level system directory, the home directory, and the unexpanded
      variable that has been eating machines for as long as shell scripts have
      existed — `rm -rf "$DIR/"` with DIR unset deletes from /.
    */
    re: new RegExp(
      CMD +
        'rm\\b[^\\n;|&]{0,80}?-[a-zA-Z]{0,8}[rR][a-zA-Z]{0,8}\\s+[^\\n;|&]{0,40}?["\']?\\s*(' +
        '\\/(\\*|\\s|$)' +
        '|\\/(bin|boot|dev|etc|home|lib|lib64|opt|proc|root|run|sbin|srv|sys|usr|var)(\\/\\*)?\\/?' +
        END +
        '|~(\\/\\*)?\\/?' +
        END +
        '|\\$\\{?\\w{1,40}\\}?\\/' +
        ')'
    ),
    what: 'recursive delete of the root, a top-level system directory, the home directory, or an unexpanded variable path'
  },
  {
    id: 'rm.noPreserveRoot',
    re: new RegExp(CMD + 'rm\\b[^\\n;|&]{0,80}--no-preserve-root'),
    what: 'rm --no-preserve-root, which exists only to delete the root'
  },
  {
    id: 'fs.mkfs',
    re: new RegExp(
      CMD +
        '(mkfs(\\.\\w{1,10})?|mke2fs)\\b' +
        '|' +
        CMD +
        'fdisk\\b[^\\n]{0,40}\\/dev\\/' +
        '|' +
        CMD +
        'parted\\b[^\\n]{0,60}\\b(mklabel|rm)\\b'
    ),
    what: 'formatting or repartitioning a disk'
  },
  {
    id: 'fs.deviceWrite',
    re: new RegExp(
      CMD + 'dd\\b[^\\n]{0,120}\\bof=\\s*\\/dev\\/(sd|nvme|vd|hd|mapper|disk)' +
        '|>\\s*\\/dev\\/(sd|nvme|vd|hd|disk)'
    ),
    what: 'writing directly to a block device'
  },
  {
    id: 'fs.wipe',
    re: new RegExp(CMD + '(shred\\b[^\\n]{0,60}-[a-zA-Z]{0,6}u|wipefs\\b|blkdiscard\\b)'),
    what: 'wiping a device or shredding files beyond recovery'
  },
  {
    id: 'host.power',
    re: new RegExp(
      CMD + '(shutdown|poweroff|halt|reboot)\\b' +
        '|' +
        CMD + 'init\\s+[06]\\b' +
        '|\\bsystemctl\\s+(poweroff|reboot|halt)\\b'
    ),
    what: 'powering off or rebooting the host'
  },
  {
    id: 'exec.pipeToShell',
    // The commonest way a remote instruction becomes arbitrary code.
    re: new RegExp(CMD + '(curl|wget|fetch)\\b[^\\n]{0,200}\\|\\s*(sudo\\s+)?(ba|z|k|da)?sh\\b'),
    what: 'piping a download straight into a shell'
  },
  {
    id: 'exec.forkBomb',
    re: /:\s*\(\s*\)\s*\{.{0,40}\|.{0,20}&.{0,10}\}\s*;?\s*:/,
    what: 'a fork bomb, which exhausts the process table'
  },
  {
    id: 'auth.users',
    re: new RegExp(CMD + '(userdel|groupdel|deluser|delgroup|chpasswd)\\b'),
    what: 'deleting a user or rewriting passwords'
  },
  {
    id: 'auth.keys',
    re: /(>|>>)\s*[^\n]{0,60}authorized_keys|\brm\b[^\n]{0,60}authorized_keys|\brm\b[^\n]{0,40}\/etc\/(shadow|passwd|sudoers)/,
    what: 'rewriting authorized_keys or deleting an account database'
  },
  {
    id: 'net.firewall',
    re: /\biptables\b[^\n]{0,40}\s-F\b|\bnft\b[^\n]{0,40}\bflush\b|\bufw\b\s+(disable|reset)\b|\bsystemctl\s+(stop|disable)\s+(firewalld|ufw)\b/,
    what: 'flushing or disabling the firewall'
  },
  {
    id: 'data.dropDatabase',
    re: /\bdrop\s+(database|schema)\b|\bdrop\s+table\b|\btruncate\s+table\b/i,
    what: 'dropping or truncating a database'
  },
  {
    id: 'forensics.logs',
    re: /\bhistory\s+-c\b|(>|>>)\s*\/var\/log\/|\brm\b[^\n]{0,60}\/var\/log\b|\bjournalctl\b[^\n]{0,40}--vacuum-time=\s*1s/,
    what: 'erasing logs or shell history'
  },
  {
    id: 'vcs.forcePush',
    re: /\bgit\b[^\n]{0,80}\bpush\b[^\n]{0,80}(--force(?!-with-lease)|\s-f\b)/,
    what: 'force-pushing over a remote branch'
  },
  {
    id: 'find.delete',
    re: new RegExp(CMD + 'find\\b[^\\n]{0,160}(-delete\\b|-exec\\s+rm\\b)'),
    what: 'find with -delete or -exec rm'
  }
]

export interface DangerousMatch {
  id: string
  what: string
  /**
   * Where it sits in the ORIGINAL command, for the dialog to highlight.
   *
   * Null when only the normalised form matched — a line continuation, say. The
   * dialog then names the rule without pointing at anything, which is honest;
   * highlighting the wrong span would be worse than highlighting nothing.
   */
  span: { start: number; end: number } | null
}

/**
 * The first rule a command trips, or null.
 *
 * First rather than all: the caller refuses either way, and one concrete reason
 * reads better to a model than a list it will try to satisfy one entry at a time.
 */
export function matchDangerous(command: string): DangerousMatch | null {
  // Spaces and tabs collapsed so `rm    -rf` and a line continuation cannot slip
  // between words a pattern expects together. Newlines are kept: they separate
  // commands, and CMD treats them as such.
  const text = command.replace(/\\\r?\n/g, ' ').replace(/[ \t]+/g, ' ')
  for (const { id, re, what } of DANGEROUS_PATTERNS) {
    // Fresh lastIndex each time: a /g pattern reused across calls resumes
    // mid-string and skips a match the next caller depends on.
    re.lastIndex = 0
    if (!re.test(text)) continue

    // Decided on the normalised text, located in the text the human will read.
    // The two can disagree, and when they do there is nothing to point at.
    re.lastIndex = 0
    const inOriginal = re.exec(command)
    return {
      id,
      what,
      span: inOriginal
        ? { start: inOriginal.index, end: inOriginal.index + inOriginal[0].length }
        : null
    }
  }
  return null
}

/**
 * What the model is told when a human, having been shown a flagged command,
 * says no. Fixed English by design.
 *
 * Worth more than the generic denial: the model learns that this particular
 * command was singled out for review rather than caught by a mood, which is the
 * difference between rewording it and not sending it again.
 */
export function deniedAfterFlag(match: DangerousMatch): string {
  return (
    `The human declined. Unattended mode is on, but this command matched ` +
    `ConsoleWard's destructive list (${match.id}: ${match.what}), so it was shown to ` +
    'them for approval instead of running. They said no. Do not rephrase it to avoid ' +
    'the match — ask them what they would rather do.'
  )
}

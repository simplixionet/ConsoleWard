// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The destination list behind unattended file uploads.
 *
 * WHAT THIS IS: the same second pair of eyes as `dangerousCommands.ts`, aimed at
 * the other half of what an AI can do to a machine — leave a file on it. A hit
 * does not refuse the upload; it raises the ordinary approval dialog and the
 * human decides. Every destination the list does not recognise is written
 * without asking.
 *
 * WHY A PATH IS A BETTER FIT THAN A COMMAND: shell text cannot be enumerated, so
 * the command list is admittedly a seatbelt — `/bin/rm` is not `rm`, `bash -c`
 * hides its argument, and a fetched script contains whatever it likes. A path is
 * structured. It has one separator, its segments mean what they say, and the
 * destinations worth stopping for are short enough to write down: what grants
 * access, what runs on a schedule, what runs at login, what sits on PATH, and
 * what gets served. The list below is close to complete for that set, which is a
 * claim the command list could never make.
 *
 * WHAT IT STILL IS NOT: a boundary. Upload to /tmp and move the file afterwards
 * and nothing here ever sees the real destination — that is two steps, and this
 * reads one. A symlink already in place points somewhere else entirely. The
 * value is in the accidental and the careless case, and the interface must say
 * so rather than imply a guarantee.
 *
 * The difficulty is entirely in `normaliseRemotePath`, because the rules have to
 * be tested against the path the SERVER will open, not the one that was typed.
 */

export interface SensitivePath {
  /** Stable across releases: the model is told which rule stopped it. */
  id: string
  /** Fixed English. This reaches the model, which is a machine interface. */
  what: string
}

// --------------------------------------------------------------------------
// Normalisation
// --------------------------------------------------------------------------

/**
 * What the server will actually open, as far as it can be known from the text.
 *
 * `.` and `..` collapse, repeated and trailing slashes go, and `~` expands when
 * a `home` is supplied. The result is one of three things, and the difference
 * matters to the caller: an absolute path, a path still rooted at a `~` nobody
 * has resolved, or a relative path — left relative, because the directory an
 * SFTP session starts in is not knowable from here and inventing a leading
 * slash would report a destination that does not exist.
 *
 * Written by hand rather than with node:path because these are POSIX paths on a
 * remote host, and node:path follows the platform this code runs on: on Windows
 * it accepts `\` as a separator and hands back `\` in the result, so `a\b` — one
 * perfectly ordinary Linux filename — would come back as two segments.
 */
export function normaliseRemotePath(path: string, home?: string): string {
  // Trimmed because these arrive from a text field and from an AI's JSON alike,
  // where a stray newline is far likelier than a filename that ends in one.
  const expanded = expandHome(path.trim(), home)

  let root = ''
  let rest = expanded
  if (rest.startsWith('/')) {
    root = '/'
    rest = rest.slice(1)
  } else if (rest.startsWith('~')) {
    // `~` alone, or `~deploy` — kept whole as the root it stands for.
    const slash = rest.indexOf('/')
    root = slash === -1 ? rest : rest.slice(0, slash)
    rest = slash === -1 ? '' : rest.slice(slash + 1)
  }

  const segments: string[] = []
  for (const segment of rest.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment !== '..') {
      segments.push(segment)
      continue
    }
    const last = segments[segments.length - 1]
    if (last !== undefined && last !== '..') {
      segments.pop()
    } else if (root !== '/') {
      /*
        Above a root nobody has resolved. `/..` is `/` on every POSIX system and
        is dropped, but `~/..` and `../..` name a directory that depends on where
        that root turns out to be, so the segment is kept rather than guessed
        away. A destination carrying one of these matches nothing below, which is
        the honest answer: we do not know where it lands.
      */
      segments.push('..')
    }
  }

  const tail = segments.join('/')
  if (root === '/') return '/' + tail
  if (root !== '') return tail === '' ? root : root + '/' + tail
  return tail === '' ? '.' : tail
}

/**
 * Only a bare `~` expands. `~deploy/x` names somebody else's home, and resolving
 * it against THIS session's home would report a path the server will not open —
 * so it is left as written, and `homeTail` reads it as a home anyway.
 */
function expandHome(path: string, home?: string): string {
  const base = home?.trim()
  if (!base) return path
  if (path === '~') return normaliseRemotePath(base)
  if (path.startsWith('~/')) return normaliseRemotePath(base) + '/' + path.slice(2)
  return path
}

// --------------------------------------------------------------------------
// The destinations
// --------------------------------------------------------------------------

interface PathRule extends SensitivePath {
  /** Reads a normalised path. Segment and prefix tests, never a regex: a path
   *  is structured, so there is nothing here to parse and nothing to backtrack. */
  matches(path: string): boolean
}

/** `path` is `dir` itself or something below it — and `/usr/binary` is neither. */
function under(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir + '/')
}

/**
 * The part of `path` below a home directory, leading slash and all, or null when
 * it is not in one. `~`, `~deploy`, `/root` and `/home/<user>` are all homes.
 *
 * So is a relative path: an SFTP session opens in the login home, so a bare
 * `.ssh/authorized_keys` lands there. Reading it that way is a guess, and it is
 * the guess worth making — wrong, it costs one dialog; right, it is a key.
 */
function homeTail(path: string): string | null {
  if (path.startsWith('~')) {
    const slash = path.indexOf('/')
    return slash === -1 ? '' : path.slice(slash)
  }
  if (under(path, '/root')) return path.slice('/root'.length)
  if (path.startsWith('/home/')) {
    // /home is not a home directory; /home/deploy is.
    const rest = path.slice('/home/'.length)
    const slash = rest.indexOf('/')
    if (slash === -1) return rest === '' ? null : ''
    return rest.slice(slash)
  }
  if (path.startsWith('/')) return null
  return path === '.' ? '' : '/' + path
}

/** Read by a login shell, so a file written here runs as its owner, next login. */
const LOGIN_FILES = new Set([
  '.bashrc',
  '.bash_profile',
  '.bash_login',
  '.bash_logout',
  // Debian's stock .bashrc sources this one, which makes it a login file too.
  '.bash_aliases',
  '.profile',
  '.zshrc',
  '.zprofile',
  '.zshenv',
  '.zlogin'
])

/** Every directory on a default PATH, root's included. */
const PATH_DIRS = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']

const ACCOUNT_FILES = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow']

const RULES: readonly PathRule[] = [
  {
    id: 'access.sshKeys',
    matches: (p) => {
      const tail = homeTail(p)
      // /etc/ssh for the same reason as ~/.ssh: sshd_config decides who gets in.
      return (tail !== null && under(tail, '/.ssh')) || under(p, '/etc/ssh')
    },
    what: 'an SSH key directory, where a file is a way onto the machine'
  },
  {
    id: 'access.sudoers',
    // Covers /etc/sudoers and /etc/sudoers.d/ alike.
    matches: (p) => p.startsWith('/etc/sudoers'),
    what: 'the sudoers configuration, which decides who becomes root'
  },
  {
    id: 'access.accounts',
    // Exactly these files: /etc/passwd- is a backup copy and nothing reads it.
    matches: (p) => ACCOUNT_FILES.includes(p),
    what: 'the account database'
  },
  {
    id: 'exec.loginShell',
    matches: (p) => {
      const tail = homeTail(p)
      if (tail !== null && tail.startsWith('/') && LOGIN_FILES.has(tail.slice(1))) return true
      // /etc/profile and /etc/profile.d/, which run for every user on the box.
      return p.startsWith('/etc/profile')
    },
    what: 'a shell startup file, which runs at the next login'
  },
  {
    id: 'exec.cron',
    matches: (p) =>
      // /etc/crontab, /etc/cron.d/, /etc/cron.daily/ and the rest of the family.
      p.startsWith('/etc/cron') || p === '/etc/anacrontab' || under(p, '/var/spool/cron'),
    what: 'a cron directory, where a file runs on a schedule as its owner'
  },
  {
    id: 'exec.systemd',
    matches: (p) => {
      const tail = homeTail(p)
      if (tail !== null && under(tail, '/.config/systemd')) return true
      // /usr/lib and /lib are where packages put units; a unit there runs at boot.
      return under(p, '/etc/systemd') || under(p, '/usr/lib/systemd') || under(p, '/lib/systemd')
    },
    what: 'a systemd unit directory, where a file runs at boot'
  },
  {
    id: 'exec.path',
    matches: (p) => PATH_DIRS.some((dir) => under(p, dir)),
    what: 'a directory on PATH, where a file becomes a command'
  },
  {
    id: 'web.root',
    /*
      The whole tree, not just the directory itself, and that is a deliberate
      cost. A deploy really does write under /var/www, so this rule fires on
      ordinary work and will be approved most days. It stays wide because which
      subtree a vhost actually serves is in a config file this code cannot see:
      /var/www/app/releases/x is served, or one symlink away from being served,
      on a normal Laravel or Rails box. A dialog is the price of an upload that
      would otherwise be a public URL, and for PHP or CGI, a public shell.
    */
    matches: (p) => under(p, '/var/www') || under(p, '/usr/share/nginx') || under(p, '/srv/http'),
    what: 'a web root, where a file is served to whoever asks for it'
  }
]

/** The destinations, for the UI to list. The predicates stay private. */
export const SENSITIVE_PATHS: readonly SensitivePath[] = RULES

/**
 * The first rule a destination trips, or null.
 *
 * First rather than all, as with the command list: the caller asks either way,
 * and one concrete reason reads better to a model than a list of them.
 *
 * Takes the path as written. Expand `~` first — `matchSensitivePath(
 * normaliseRemotePath(p, home))` — when the session knows the home directory;
 * without it, a `~` path is still matched in the form it was written.
 */
export function matchSensitivePath(path: string): SensitivePath | null {
  const normalised = normaliseRemotePath(path)
  for (const rule of RULES) {
    if (rule.matches(normalised)) return { id: rule.id, what: rule.what }
  }
  return null
}

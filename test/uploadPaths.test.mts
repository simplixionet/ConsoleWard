// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The destination list behind unattended uploads.
 *
 * Three things are being tested, and the first is the least interesting. That
 * every listed destination matches is arithmetic. That ordinary deploy work is
 * not stopped is what decides whether anyone leaves unattended mode on. And the
 * normalisation is where the bugs actually live: the rules read the path the
 * server will open, so `/etc/nginx/../cron.d/x` has to reach the cron rule, and
 * a Windows path helper has to stay out of it.
 *
 * The last block pins what the list does NOT catch. Those tests failing is not
 * automatically good news — it means the UI copy needs re-reading too.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

const { matchSensitivePath, normaliseRemotePath, SENSITIVE_PATHS } = await import(
  '../src/shared/uploadPaths.ts'
)

/** Asserts the destination stops for a human, and which rule stopped it. */
function flagged(path: string, id?: string) {
  const hit = matchSensitivePath(path)
  assert.ok(hit, `uploaded without asking: ${path}`)
  if (id) assert.equal(hit.id, id, `${path} was caught by ${hit.id}, expected ${id}`)
  return hit
}

function ordinary(path: string) {
  const hit = matchSensitivePath(path)
  assert.equal(hit, null, `an everyday upload raised a dialog (${hit?.id}): ${path}`)
}

// --------------------------------------------------------------------------
// What the server will open
// --------------------------------------------------------------------------

describe('normaliseRemotePath reports the destination, not the text', () => {
  test('~ expands against the home the session knows', () => {
    assert.equal(normaliseRemotePath('~', '/home/deploy'), '/home/deploy')
    assert.equal(normaliseRemotePath('~/.ssh/id_rsa', '/home/deploy'), '/home/deploy/.ssh/id_rsa')
    assert.equal(normaliseRemotePath('~/x', '/root'), '/root/x')
    // The home itself arrives from the server and may be untidy.
    assert.equal(normaliseRemotePath('~/x', '/home/deploy/'), '/home/deploy/x')
    assert.equal(normaliseRemotePath('~/x', '  //home//deploy  '), '/home/deploy/x')
  })

  test('without a home, ~ stays ~ rather than becoming a path that does not exist', () => {
    assert.equal(normaliseRemotePath('~/.ssh/id_rsa'), '~/.ssh/id_rsa')
    assert.equal(normaliseRemotePath('~'), '~')
    assert.equal(normaliseRemotePath('~/'), '~')
  })

  test('~otheruser is never expanded against this session home', () => {
    // It names somebody else's home. Expanding it would report a path the
    // server will not open, and the rules would then be reading a fiction.
    assert.equal(normaliseRemotePath('~deploy/.ssh', '/home/stan'), '~deploy/.ssh')
    assert.equal(normaliseRemotePath('~root/.bashrc', '/home/stan'), '~root/.bashrc')
  })

  test('. and .. collapse, which is the whole reason this function exists', () => {
    assert.equal(normaliseRemotePath('/etc/nginx/../cron.d/x'), '/etc/cron.d/x')
    assert.equal(normaliseRemotePath('/etc/./hostname'), '/etc/hostname')
    assert.equal(normaliseRemotePath('/etc/nginx/sites-enabled/../../passwd'), '/etc/passwd')
    assert.equal(normaliseRemotePath('~/app/../.ssh/authorized_keys'), '~/.ssh/authorized_keys')
  })

  test('.. above the root is dropped, because /.. is / on every POSIX host', () => {
    assert.equal(normaliseRemotePath('/..'), '/')
    assert.equal(normaliseRemotePath('/../../etc/passwd'), '/etc/passwd')
    assert.equal(normaliseRemotePath('/etc/../..'), '/')
  })

  test('repeated and trailing slashes collapse', () => {
    assert.equal(normaliseRemotePath('//var//www//'), '/var/www')
    assert.equal(normaliseRemotePath('/etc/cron.d/'), '/etc/cron.d')
    assert.equal(normaliseRemotePath('/'), '/')
    assert.equal(normaliseRemotePath('///'), '/')
    assert.equal(normaliseRemotePath('  /etc/cron.d/backup  '), '/etc/cron.d/backup')
  })

  test('a relative path stays relative instead of being guessed at', () => {
    // An SFTP session's starting directory is not knowable from here, so a
    // leading slash would be an invention the caller could not tell apart from
    // a path the user actually typed.
    assert.equal(normaliseRemotePath('deploy.sh'), 'deploy.sh')
    assert.equal(normaliseRemotePath('./deploy.sh'), 'deploy.sh')
    assert.equal(normaliseRemotePath('app/../etc/passwd'), 'etc/passwd')
    assert.equal(normaliseRemotePath('../../etc/passwd'), '../../etc/passwd')
    assert.equal(normaliseRemotePath(''), '.')
    assert.equal(normaliseRemotePath('.'), '.')
  })

  test('.. that escapes an unresolved root is kept, not invented away', () => {
    // `~/..` is a real directory, but which one depends on where the home is.
    assert.equal(normaliseRemotePath('~/..'), '~/..')
    assert.equal(normaliseRemotePath('~/../deploy/.ssh'), '~/../deploy/.ssh')
    // Given the home, the same input resolves properly.
    assert.equal(
      normaliseRemotePath('~/../deploy/.ssh', '/home/stan'),
      '/home/deploy/.ssh',
      'a home was supplied and the traversal still was not resolved'
    )
  })

  test('a backslash is a filename character, not a separator', () => {
    // This code runs on Windows. node:path would read `a\b` as two segments and
    // hand back a path with backslashes in it, so the rules below would be
    // testing a destination the Linux server has never heard of.
    assert.equal(normaliseRemotePath('/home/deploy/a\\b'), '/home/deploy/a\\b')
    assert.equal(
      normaliseRemotePath('/etc/ssh\\..\\passwd'),
      '/etc/ssh\\..\\passwd',
      'a backslash traversal was resolved, which means a platform path helper got involved'
    )
    assert.equal(normaliseRemotePath('C:\\temp\\x'), 'C:\\temp\\x')
  })

  test('normalising an already normalised path changes nothing', () => {
    // The caller may expand ~ first and match second, so the two must compose.
    const inputs = [
      '/etc/cron.d/backup',
      '~/.ssh/authorized_keys',
      '//var//www//app/../index.html',
      'app/../etc/passwd',
      '../x',
      '~/..',
      '/',
      ''
    ]
    for (const input of inputs) {
      const once = normaliseRemotePath(input)
      assert.equal(normaliseRemotePath(once), once, `${input} is not stable under normalisation`)
    }
  })
})

// --------------------------------------------------------------------------
// The destinations
// --------------------------------------------------------------------------

describe('a destination that grants access, runs, or is served stops for a human', () => {
  test('SSH keys and the sshd configuration', () => {
    flagged('~/.ssh/authorized_keys', 'access.sshKeys')
    flagged('~/.ssh', 'access.sshKeys')
    flagged('/root/.ssh/id_ed25519', 'access.sshKeys')
    flagged('/home/deploy/.ssh/config', 'access.sshKeys')
    // ~/.ssh/config carries ProxyCommand, and /etc/ssh/sshd_config decides who
    // may log in at all — both grant access as surely as authorized_keys does.
    flagged('/etc/ssh/sshd_config', 'access.sshKeys')
  })

  test('shell startup files, which run at the next login', () => {
    flagged('~/.bashrc', 'exec.loginShell')
    flagged('~/.profile', 'exec.loginShell')
    flagged('~/.bash_profile', 'exec.loginShell')
    flagged('~/.zshrc', 'exec.loginShell')
    flagged('/root/.bashrc', 'exec.loginShell')
    flagged('/etc/profile.d/deploy.sh', 'exec.loginShell')
    flagged('/etc/profile', 'exec.loginShell')
  })

  test('anything that runs on a schedule', () => {
    flagged('/etc/crontab', 'exec.cron')
    flagged('/etc/cron.d/backup', 'exec.cron')
    flagged('/etc/cron.daily/logrotate', 'exec.cron')
    flagged('/etc/cron.hourly/sync', 'exec.cron')
    flagged('/var/spool/cron/crontabs/deploy', 'exec.cron')
  })

  test('sudo rules and the account database', () => {
    flagged('/etc/sudoers', 'access.sudoers')
    flagged('/etc/sudoers.d/deploy', 'access.sudoers')
    flagged('/etc/passwd', 'access.accounts')
    flagged('/etc/shadow', 'access.accounts')
    flagged('/etc/group', 'access.accounts')
  })

  test('systemd units, which run at boot and as root', () => {
    flagged('/etc/systemd/system/app.service', 'exec.systemd')
    flagged('/etc/systemd/system/app.timer', 'exec.systemd')
    flagged('~/.config/systemd/user/app.service', 'exec.systemd')
    flagged('/usr/lib/systemd/system/app.service', 'exec.systemd')
    flagged('/lib/systemd/system/app.service', 'exec.systemd')
  })

  test('anything on PATH, where a file becomes a command', () => {
    flagged('/usr/bin/app', 'exec.path')
    flagged('/usr/local/bin/deploy', 'exec.path')
    flagged('/bin/ls', 'exec.path')
    flagged('/sbin/init', 'exec.path')
    flagged('/usr/sbin/sshd', 'exec.path')
    flagged('/usr/local/sbin/backup', 'exec.path')
  })

  test('web roots, where a file is served to whoever asks', () => {
    flagged('/var/www/index.html', 'web.root')
    flagged('/usr/share/nginx/html/index.html', 'web.root')
    flagged('/srv/http/index.html', 'web.root')
  })

  test('a release directory under a web root is flagged, and that is the decision', () => {
    /*
      /var/www/app/releases/x is the one entry on this list that fires during
      ordinary work, and it stays. Which subtree a vhost serves is written in a
      config file this code cannot see: on a normal Laravel or Rails box the
      release directory is served, or one symlink flip away from being served.
      A dialog per deploy is the price of an upload that would otherwise be a
      public URL — and, for PHP or CGI, a public shell. If this ever has to be
      narrowed, narrow it by asking the server what the docroot is, not by
      guessing which directory names look like staging.
    */
    flagged('/var/www/app/releases/2026-09-11/index.php', 'web.root')
    flagged('/var/www', 'web.root')
  })

  test('a home directory is recognised however it is spelled', () => {
    // The same file, four ways, and the rule has to see all of them.
    for (const path of [
      '~/.ssh/authorized_keys',
      '~deploy/.ssh/authorized_keys',
      '/home/deploy/.ssh/authorized_keys',
      '/root/.ssh/authorized_keys'
    ]) {
      flagged(path, 'access.sshKeys')
    }
  })

  test('a relative destination is read as home-relative, because sftp starts there', () => {
    // Wrong, it costs one dialog. Right, it was a key.
    flagged('.ssh/authorized_keys', 'access.sshKeys')
    flagged('.bashrc', 'exec.loginShell')
    // And only at the top level: a relative path is not read as an absolute one.
    ordinary('bin/deploy.sh')
    ordinary('app/.ssh/config')
  })
})

describe('traversal that lands in a listed destination still matches', () => {
  test('.. on the way to a destination changes nothing', () => {
    flagged('/etc/nginx/../cron.d/x', 'exec.cron')
    flagged('/home/deploy/app/../../../etc/sudoers.d/x', 'access.sudoers')
    flagged('/usr/local/lib/../bin/deploy', 'exec.path')
    flagged('/var/www/app/../../www/index.html', 'web.root')
    flagged('~/app/../.ssh/authorized_keys', 'access.sshKeys')
  })

  test('neither do redundant slashes or a trailing one', () => {
    flagged('//etc//cron.d//x', 'exec.cron')
    flagged('/etc/cron.d/', 'exec.cron')
    flagged('  /etc/shadow  ', 'access.accounts')
  })

  test('a caller that expands ~ first gets the same answer', () => {
    const expanded = normaliseRemotePath('~/.ssh/authorized_keys', '/home/deploy')
    assert.equal(expanded, '/home/deploy/.ssh/authorized_keys')
    flagged(expanded, 'access.sshKeys')
  })
})

// --------------------------------------------------------------------------
// The half that decides whether anyone leaves this switched on
// --------------------------------------------------------------------------

describe('ordinary uploads are not stopped', () => {
  test('the files people actually upload', () => {
    ordinary('~/notes.md')
    ordinary('/tmp/x')
    ordinary('/home/deploy/app/config.yml')
    ordinary('/home/deploy/releases/2026-09-11/app.tar.gz')
    ordinary('/srv/data/backup.tar.gz')
    ordinary('/var/log/app/import.csv')
    ordinary('/opt/app/bin/run')
    ordinary('notes/todo.md')
  })

  test('names that merely start like a listed destination', () => {
    // Prefix tests that ignore the segment boundary would catch all of these,
    // and a list that refuses /usr/binary is a list people switch off.
    ordinary('/usr/binary/tool')
    ordinary('/usr/share/nginx-docs/readme.md')
    ordinary('/var/www-backups/2026-09-11.tar.gz')
    ordinary('/home/deploy/.sshfs/mounts.conf')
    ordinary('~/.bashrc.bak')
    ordinary('/etc/passwd-')
    ordinary('/home/deploy/.config/app/settings.json')
  })

  test('the quiet list is not quiet by accident', () => {
    // Guards every `ordinary` above: if matchSensitivePath started returning
    // null for everything, those tests would still pass and this one would not.
    assert.ok(matchSensitivePath('/etc/sudoers'), 'the list matches nothing at all')
  })
})

describe('every rule can be explained to the human it interrupts', () => {
  test('ids are stable and dotted, and the wording is readable', () => {
    const seen = new Set<string>()
    for (const rule of SENSITIVE_PATHS) {
      assert.match(rule.id, /^[a-z]+\.[a-zA-Z]+$/, `${rule.id} is not a stable dotted id`)
      assert.ok(rule.what.length > 10, `${rule.id} has no readable description`)
      assert.equal(seen.has(rule.id), false, `${rule.id} appears twice`)
      seen.add(rule.id)
    }
    assert.ok(seen.size >= 8, `only ${seen.size} rules, so a destination was dropped`)
  })

  test('a match reports a rule the caller can look up', () => {
    const hit = flagged('/etc/cron.d/backup')
    assert.ok(
      SENSITIVE_PATHS.some((rule) => rule.id === hit.id && rule.what === hit.what),
      `${hit.id} is not in the exported list, so the dialog cannot explain it`
    )
  })
})

// --------------------------------------------------------------------------
// What this is not
// --------------------------------------------------------------------------

describe('the list is a destination check, not a boundary', () => {
  test('anything deliberate walks straight past it', () => {
    /*
      Pinned, not lamented. Reading one path cannot catch a plan made of two
      steps, and none of these is fixable here. If one of them ever starts
      matching, the thing to revisit is whether the UI copy still describes
      reality — it promises a check on where a file is going, nothing more.
    */
    const twoSteppers = [
      // Upload here, then move it with a command. The command list is the only
      // other gate, and `mv` is not on it either.
      '/tmp/payload.sh',
      '/var/tmp/payload.sh',
      '/dev/shm/payload.sh',
      '~/uploads/payload.sh',
      // A symlink already in place points anywhere at all, and SFTP follows it.
      '/home/deploy/link-to-somewhere'
    ]
    for (const path of twoSteppers) {
      assert.equal(
        matchSensitivePath(path),
        null,
        `the list now catches ${JSON.stringify(path)} — check the UI copy, which ` +
          'calls this a check on the destination only'
      )
    }
  })

  test('an unresolved ~ traversal is a hole the caller closes by passing home', () => {
    // Without a home there is nothing to resolve `~/..` against, so the rule
    // cannot see where the file lands. This is why the session should expand
    // the path before matching it.
    assert.equal(
      matchSensitivePath('~/../deploy/.ssh/authorized_keys'),
      null,
      'good news, but the reason to pass home has gone with it — check the callers'
    )
    flagged(normaliseRemotePath('~/../deploy/.ssh/authorized_keys', '/home/stan'), 'access.sshKeys')
  })

  test('the list stops at what runs or is served, not at everything root owns', () => {
    // A vhost or an nginx config is a deliberate boundary: it does nothing until
    // a command reloads the server, and that command is the other gate. Keeping
    // the list short is what makes "nearly complete" an honest claim.
    ordinary('/etc/nginx/sites-enabled/app.conf')
    ordinary('/etc/hosts')
    ordinary('/etc/fstab')
  })
})

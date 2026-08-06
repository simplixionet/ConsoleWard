// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Tests for the secret highlighter behind the "what actually goes to the AI"
 * dialog.
 *
 * The module documents itself as a hint, not a guarantee, so these tests hold
 * it to that claim and no further: every pattern it advertises must fire on a
 * realistic example, and ordinary command output must stay dark. The second
 * half matters as much as the first — the module's own header names
 * habituation as the failure mode, and a highlighter that paints every `ls`
 * teaches the user to click through the one paste that mattered.
 *
 * Two tests are marked `todo`. They are not unfinished: each carries a real,
 * unweakened assertion against behaviour that is currently wrong, marked so
 * that the first test suite this project has ever had does not start out red.
 * They still run, and still print the defect on every pass. Delete the marker
 * when the source is fixed. See KNOWN GAPS at the bottom.
 */

import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import {
  findSecrets,
  MAX_SCAN_CHARS,
  scanSecrets,
  summarizeSecrets
} from '../src/shared/secretPatterns.ts'

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/** The text a match actually covers — what the dialog paints. */
function covered(text: string, m: { start: number; end: number }): string {
  return text.slice(m.start, m.end)
}

/** Readable rendering of every finding, for assertion messages. */
function describeMatches(text: string, matches: ReturnType<typeof findSecrets>): string {
  if (matches.length === 0) return '(nothing)'
  return matches
    .map((m) => `${m.label}/${m.severity} ${JSON.stringify(covered(text, m))}`)
    .join(', ')
}

/**
 * Asserts the given label fires and returns it. Also asserts the highlight
 * covers `secret`, so a pattern that matched only a fragment — and left the
 * rest of the credential unpainted — fails here rather than passing quietly.
 */
function expectHit(text: string, label: string, severity: 'high' | 'medium', secret: string) {
  const matches = findSecrets(text)
  const hit = matches.find((m) => m.label === label)
  assert.ok(hit, `expected ${label}, got: ${describeMatches(text, matches)}`)
  assert.equal(hit.severity, severity, `${label} should be ${severity} severity`)
  assert.ok(
    covered(text, hit).includes(secret),
    `${label} highlighted ${JSON.stringify(covered(text, hit))}, ` +
      `which does not cover ${JSON.stringify(secret)}`
  )
  return hit
}

/** Asserts nothing at all is highlighted, naming what leaked in on failure. */
function expectQuiet(name: string, text: string) {
  const matches = findSecrets(text)
  assert.equal(
    matches.length,
    0,
    `${name} must not be highlighted, but was: ${describeMatches(text, matches)}`
  )
}

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

const PRIVATE_KEY_BLOCK = [
  '-----BEGIN OPENSSH PRIVATE KEY-----',
  'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn',
  'NhAAAAAwEAAQAAAYEAy3Fh1Qm0oV0mQmZ4Nn0pQ0Xr8ZzY7cB2vK9tJ6dW3sL4pR1nT5uH',
  '-----END OPENSSH PRIVATE KEY-----'
].join('\n')

const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.' +
  'dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk'

const SSH_PUBLIC_KEY =
  'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC' + 'K7hTn2vQ9wXsL4pR1nT5uHy3Fh1Qm0oV0mQmZ4Nn0p'

const LS_LA = [
  'total 48',
  'drwxr-xr-x  6 stan stan  4096 Aug  4 21:13 .',
  'drwxr-xr-x 24 stan stan  4096 Aug  1 09:02 ..',
  '-rw-r--r--  1 stan stan   220 Jul 30 11:44 .bashrc',
  'drwxr-xr-x  8 stan stan  4096 Aug  4 20:59 .git',
  '-rw-r--r--  1 stan stan  1071 Jul 30 11:44 LICENSE',
  '-rw-r--r--  1 stan stan  2048 Aug  4 18:21 README.md',
  'drwxr-xr-x  3 stan stan  4096 Aug  2 14:07 src'
].join('\n')

const GIT_LOG = [
  'commit 4f2a1b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6',
  'Author: Stanislav Opletal <info@simplixio.net>',
  'Date:   Mon Aug 4 21:03:11 2026 +0200',
  '',
  '    Fix scroll sync in the share dialog',
  '',
  'commit 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
  'Author: Stanislav Opletal <info@simplixio.net>',
  'Date:   Sun Aug 3 10:41:52 2026 +0200',
  '',
  '    Add Dutch locale'
].join('\n')

const PACKAGE_VERSIONS = [
  'Package   Current  Wanted  Latest  Location',
  'react      19.2.8  19.2.8  19.3.0  node_modules/react',
  'ssh2       1.17.0  1.17.0  1.17.0  node_modules/ssh2',
  'zod         4.4.3   4.4.3   4.5.0  node_modules/zod'
].join('\n')

// --------------------------------------------------------------------------
// Detection — one realistic positive per advertised pattern
// --------------------------------------------------------------------------

describe('findSecrets: detects the patterns it advertises', () => {
  test('a complete private key block is flagged high as secret.privateKey', () => {
    const text = 'cat ~/.ssh/id_rsa\n' + PRIVATE_KEY_BLOCK + '\nstan@web01:~$ '
    const hit = expectHit(text, 'secret.privateKey', 'high', PRIVATE_KEY_BLOCK)
    assert.equal(covered(text, hit), PRIVATE_KEY_BLOCK, 'the whole block should be covered')
  })

  test('a private key truncated by the scrollback still trips secret.privateKeyStart', () => {
    // Only the header survives when the paste is cut short — the body is gone
    // but the fact a key was on screen must still show.
    const text = 'cat id_rsa\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA'
    expectHit(text, 'secret.privateKeyStart', 'high', '-----BEGIN RSA PRIVATE KEY-----')
  })

  test('a JWT is flagged high as secret.jwt', () => {
    const text = 'curl -H "Authorization: ' + JWT + '" https://api.example.com/v1/me'
    expectHit(text, 'secret.jwt', 'high', JWT)
  })

  test('an AWS access key id is flagged high as secret.aws', () => {
    const text = 'aws sts get-caller-identity\nUsing AKIAIOSFODNN7EXAMPLE in eu-central-1'
    expectHit(text, 'secret.aws', 'high', 'AKIAIOSFODNN7EXAMPLE')
  })

  test('a GitHub personal access token is flagged high as secret.github', () => {
    const text = 'remote: using ghp_1234567890abcdefABCDEF1234567890abcd for auth'
    expectHit(text, 'secret.github', 'high', 'ghp_1234567890abcdefABCDEF1234567890abcd')
  })

  test('a Slack bot token is flagged high as secret.slack', () => {
    const token = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'
    expectHit('SLACK_BOT=' + token, 'secret.slack', 'high', token)
  })

  test('an sk- API key is flagged high as secret.apiKey', () => {
    const text = 'openai --key sk-proj0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345'
    expectHit(text, 'secret.apiKey', 'high', 'sk-proj0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345')
  })

  test('a Bearer authorization header is flagged high as secret.authHeader', () => {
    const text =
      'GET /v1/me HTTP/1.1\r\nAuthorization: Bearer sk_live_abcdefghijklmnop\r\nHost: api.x.io'
    expectHit(text, 'secret.authHeader', 'high', 'Bearer sk_live_abcdefghijklmnop')
  })

  test('a Basic authorization header is flagged high as secret.authHeader', () => {
    const text = 'curl -v -H "Authorization: Basic c3RhbjpodW50ZXIyMDI2" http://internal/'
    expectHit(text, 'secret.authHeader', 'high', 'Basic c3RhbjpodW50ZXIyMDI2')
  })

  test('a password assignment is flagged high as secret.assignment', () => {
    const text = 'env | grep -i pass\nMYSQL_ROOT_PASSWORD=Tr0ub4dor&3\nHOME=/root'
    // The keyword sits mid-identifier: a plain \b would miss it between _ and P.
    expectHit(text, 'secret.assignment', 'high', 'MYSQL_ROOT_PASSWORD=Tr0ub4dor&3')
  })

  test('a quoted password in a YAML value is flagged high as secret.assignment', () => {
    const text = 'database:\n  host: db.internal\n  password: "s3cr3t-p4ss"\n'
    expectHit(text, 'secret.assignment', 'high', 'password: "s3cr3t-p4ss"')
  })

  test('credentials embedded in a URL are flagged high as secret.urlCreds', () => {
    const text = 'DATABASE_URL is postgres://admin:s3cr3t@db.internal/app and it works'
    expectHit(text, 'secret.urlCreds', 'high', 'postgres://admin:s3cr3t@db.internal/app')
  })

  test('the bounded scheme still covers every scheme that carries credentials', () => {
    // The `{0,19}` bound that made urlCreds linear is a real behaviour change:
    // a scheme longer than 20 characters stops matching. These are the ones
    // that plausibly appear in terminal output carrying userinfo, and this test
    // is what stops the constant being tidied downward later.
    const urls = [
      'postgres://admin:s3cr3t@db.internal/app',
      'postgresql://admin:s3cr3t@db/app',
      'mongodb+srv://u:p@cluster0.abcd.mongodb.net/test',
      'redis://default:hunter2@redis-01:6379/0',
      'amqp://guest:guest@rabbit.internal:5672/%2f',
      'git+ssh://git:tok3n@github.com/x/y.git',
      'HTTPS://User:Pass@Example.COM/x'
    ]
    for (const url of urls) expectHit('psql ' + url, 'secret.urlCreds', 'high', url)
  })

  test('an /etc/shadow password hash is flagged high as secret.passwordHash', () => {
    const text = 'root:$6$Ky3Rn.Xv$OoJ8lQ2Hh1cD:19981:0:99999:7:::\ndaemon:*:19981:0:99999:7:::'
    expectHit(text, 'secret.passwordHash', 'high', 'root:$6$Ky3Rn.Xv$OoJ8lQ2Hh1cD')
  })

  test('an SSH public key is flagged medium as secret.sshPublicKey', () => {
    // Public, so not a secret — but it names the machine and belongs on screen.
    const text = SSH_PUBLIC_KEY + ' stan@workstation'
    expectHit(text, 'secret.sshPublicKey', 'medium', 'ssh-rsa AAAAB3NzaC1yc2EA')
  })

  test('a long random-looking string is flagged medium as secret.randomString', () => {
    const blob = 'a3f5b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b'
    expectHit('checksum ' + blob + ' ok', 'secret.randomString', 'medium', blob)
  })

  test('an IP address is flagged medium as secret.ipAddress', () => {
    const text = 'eth0: inet 10.0.0.9  netmask 255.255.255.0  broadcast 10.0.0.255'
    const matches = findSecrets(text)
    assert.deepEqual(
      matches.map((m) => covered(text, m)),
      ['10.0.0.9', '255.255.255.0', '10.0.0.255'],
      'every dotted quad on the line should be highlighted'
    )
    assert.ok(matches.every((m) => m.label === 'secret.ipAddress' && m.severity === 'medium'))
  })
})

// --------------------------------------------------------------------------
// Credential file formats
//
// Each of these scanned as `medium` at worst before, which is the severity
// `outputNeedsReview` in mcp.ts does NOT force the review dialog for. So a
// model that asked to run `cat` on any of them, with the auto-share box
// ticked, had the contents forwarded with no human ever seeing them. The
// severity is the assertion that matters here, not the label.
// --------------------------------------------------------------------------

describe('findSecrets: credential file formats reach high severity', () => {
  test('an armoured PGP secret key is flagged high, suffix label and all', () => {
    // `-----BEGIN PGP PRIVATE KEY BLOCK-----` puts a word AFTER "PRIVATE KEY",
    // which the pattern's leading `[ A-Z]*` alone could never match. The whole
    // of GnuPG's secret keyring reads as `secret.randomString` without this.
    const block = [
      '-----BEGIN PGP PRIVATE KEY BLOCK-----',
      '',
      'lQOYBGYxAAABCADQ3Fh1Qm0oV0mQmZ4Nn0pQ0Xr8ZzY7cB2vK9tJ6dW3sL4pR1nT5uH',
      'y3Fh1Qm0oV0mQmZ4Nn0pQ0Xr8ZzY7cB2vK9tJ6dW3sL4pR1nT5uHy3Fh1Qm0oV0mQm',
      '-----END PGP PRIVATE KEY BLOCK-----'
    ].join('\n')
    expectHit('gpg --export-secret-keys --armor\n' + block, 'secret.privateKey', 'high', block)
  })

  test('the other armoured labels did not regress', () => {
    for (const label of ['RSA', 'OPENSSH', 'EC', 'ENCRYPTED', '']) {
      const header = `-----BEGIN ${label} PRIVATE KEY-----`.replace('  ', ' ')
      const hit = findSecrets(header)[0]
      assert.equal(hit?.severity, 'high', `${header} stopped being flagged`)
    }
  })

  test('a PuTTY .ppk is flagged high as secret.puttyKey', () => {
    // This application replaces PuTTY, so its users are the people with these.
    const ppk = [
      'PuTTY-User-Key-File-3: ssh-ed25519',
      'Encryption: none',
      'Comment: deploy@web01',
      'Public-Lines: 2',
      'AAAAC3NzaC1lZDI1NTE5AAAAIK7hTn2vQ9wXsL4pR1nT5uHy3Fh1Qm0oV0mQmZ4Nn0pQ',
      'Private-Lines: 1',
      'AAAAIB2vK9tJ6dW3sL4pR1nT5uHy3Fh1Qm0oV0mQmZ4Nn0pQ0Xr8'
    ].join('\n')
    const matches = findSecrets(ppk)
    assert.ok(
      matches.some((m) => m.label === 'secret.puttyKey' && m.severity === 'high'),
      `a .ppk scanned as ${describeMatches(ppk, matches)}`
    )
  })

  test('a kubeconfig client key is flagged high as secret.kubeClientKey', () => {
    const text = [
      'users:',
      '- name: cluster-admin',
      '  user:',
      '    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo3RmgxUW0wb1Yw'
    ].join('\n')
    const matches = findSecrets(text)
    assert.ok(
      matches.some((m) => m.label === 'secret.kubeClientKey' && m.severity === 'high'),
      `a kubeconfig scanned as ${describeMatches(text, matches)}`
    )
  })

  test('a docker config registry auth is flagged high as secret.dockerAuth', () => {
    const text = '{"auths":{"registry.example.net":{"auth":"c3RhbjpodW50ZXIy"}}}'
    const matches = findSecrets(text)
    assert.ok(
      matches.some((m) => m.label === 'secret.dockerAuth' && m.severity === 'high'),
      `~/.docker/config.json scanned as ${describeMatches(text, matches)}`
    )
  })

  test('a .netrc password is flagged high as secret.netrc', () => {
    // Whitespace-separated, so `secret.assignment` never sees a `=` or `:`.
    const text = 'machine api.example.net login deploy password hunter2'
    const matches = findSecrets(text)
    assert.ok(
      matches.some((m) => m.label === 'secret.netrc' && m.severity === 'high'),
      `a .netrc line scanned as ${describeMatches(text, matches)}`
    )
  })

  test('a .pgpass line is flagged high as secret.pgpass', () => {
    const text = 'db01.example.net:5432:production:postgres:s3cr3t-p4ss'
    const matches = findSecrets(text)
    assert.ok(
      matches.some((m) => m.label === 'secret.pgpass' && m.severity === 'high'),
      `a .pgpass line scanned as ${describeMatches(text, matches)}`
    )
  })

  test('a JSON-quoted secret key is flagged, not just a bare one', () => {
    // The quote closing the key name sits between the keyword and the colon,
    // which used to end the match before it started.
    const text = '{"api_key": "sk-live-not-a-real-key-000", "name": "prod"}'
    const matches = findSecrets(text)
    assert.ok(
      matches.some((m) => m.label === 'secret.assignment' && m.severity === 'high'),
      `a JSON config scanned as ${describeMatches(text, matches)}`
    )
  })
})

describe('findSecrets: the new file-format patterns stay off ordinary output', () => {
  test('/etc/passwd is not mistaken for .pgpass', () => {
    // Seven fields, so the five-field shape can only match if its last field
    // swallows colons — which is exactly what it is written to refuse.
    const text = [
      'root:x:0:0:root:/root:/bin/bash',
      'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
      'stan:x:1000:1000:Stanislav:/home/stan:/bin/bash'
    ].join('\n')
    assert.equal(
      findSecrets(text).filter((m) => m.label === 'secret.pgpass').length,
      0,
      '/etc/passwd would light up as a password file on every `cat`'
    )
  })

  test('an IPv6 address and a timestamp are not mistaken for .pgpass', () => {
    const text = 'fe80::1:2:3:4  up 12:34:56'
    assert.equal(
      findSecrets(text).filter((m) => m.label === 'secret.pgpass').length,
      0,
      'colon-separated output that is not a credential was flagged'
    )
  })

  test('prose about passwords is not mistaken for a .netrc', () => {
    const text = [
      'usage: login to the machine first, then set a password for the account',
      'The machine will ask for your password interactively.'
    ].join('\n')
    assert.equal(
      findSecrets(text).filter((m) => m.label === 'secret.netrc').length,
      0,
      'documentation mentioning both words was flagged as a credential file'
    )
  })

  test('ordinary listings pick up no NEW highlights', () => {
    // A new pattern that lights up `ls` costs more than it buys. Asserted per
    // label rather than with expectQuiet, because GIT_LOG is not quiet for
    // reasons that predate these patterns — see the randomString known gap.
    const added = [
      'secret.puttyKey',
      'secret.kubeClientKey',
      'secret.dockerAuth',
      'secret.netrc',
      'secret.pgpass'
    ]
    for (const [name, text] of [
      ['ls -la', LS_LA],
      ['git log', GIT_LOG],
      ['npm outdated', PACKAGE_VERSIONS]
    ] as const) {
      const noisy = findSecrets(text).filter((m) => added.includes(m.label))
      assert.deepEqual(noisy, [], `${name} gained highlights it did not have before`)
    }
    // The two that were already quiet must have stayed exactly that way.
    expectQuiet('ls -la', LS_LA)
    expectQuiet('npm outdated', PACKAGE_VERSIONS)
  })
})

// --------------------------------------------------------------------------
// Negatives — the half that decides whether anyone still reads the highlights
// --------------------------------------------------------------------------

describe('findSecrets: ordinary command output stays dark', () => {
  test('`ls -la` highlights nothing', () => {
    expectQuiet('a directory listing', LS_LA)
  })

  test('a package version list highlights nothing', () => {
    expectQuiet('an npm version table', PACKAGE_VERSIONS)
  })

  test('`pip list` highlights nothing', () => {
    const text = [
      'Package         Version',
      '--------------- -------',
      'certifi         2026.1.4',
      'requests        2.32.3',
      'urllib3         2.2.2'
    ].join('\n')
    expectQuiet('a pip version table', text)
  })

  test('`docker ps` highlights nothing', () => {
    const text = [
      'CONTAINER ID   IMAGE        COMMAND      CREATED       STATUS       PORTS      NAMES',
      '3f2a9c1b8d7e   nginx:1.27   "nginx -g"   2 hours ago   Up 2 hours   80/tcp     web',
      '9c8b7a6d5e4f   postgres:16  "docker-en"  3 days ago    Up 3 days    5432/tcp   db'
    ].join('\n')
    expectQuiet('a container listing', text)
  })

  test('`df -h` highlights nothing', () => {
    const text = [
      'Filesystem      Size  Used Avail Use% Mounted on',
      '/dev/sda1        79G   31G   45G  41% /',
      'tmpfs           3.9G     0  3.9G   0% /dev/shm'
    ].join('\n')
    expectQuiet('a disk usage table', text)
  })

  test('`systemctl status` highlights nothing', () => {
    const text = [
      '● sshd.service - OpenBSD Secure Shell server',
      '     Loaded: loaded (/lib/systemd/system/ssh.service; enabled)',
      '     Active: active (running) since Mon 2026-08-03 09:01:44 CEST; 1 day ago',
      '   Main PID: 812 (sshd)',
      '      Tasks: 1 (limit: 9451)'
    ].join('\n')
    expectQuiet('a unit status block', text)
  })

  test('a compiler log highlights nothing', () => {
    const text = [
      'gcc -O2 -Wall -c src/main.c -o build/main.o',
      'gcc -O2 -Wall -c src/util.c -o build/util.o',
      'gcc build/main.o build/util.o -o bin/app'
    ].join('\n')
    expectQuiet('a make log', text)
  })

  test('prompts and help text that merely mention passwords highlight nothing', () => {
    // The words are there; no value follows them. Flagging these would train
    // the user to ignore the highlight, which is the whole risk.
    const text = [
      '[sudo] password for stan:',
      "Enter passphrase for key '/home/stan/.ssh/id_ed25519':",
      '  -i identity_file   Selects the private key file',
      '  --token TOKEN      Auth token to use',
      'Permission denied, please try again.'
    ].join('\n')
    expectQuiet('password prompts and usage text', text)
  })

  test('a git log raises nothing urgent — only its commit hashes, at medium', () => {
    const matches = findSecrets(GIT_LOG)
    assert.deepEqual(
      matches.filter((m) => m.severity === 'high').map((m) => covered(GIT_LOG, m)),
      [],
      'a git log must never raise a high-severity finding'
    )
    // Documented false positive: a 40-hex commit hash is indistinguishable
    // from a token to secret.randomString, so every git log paints its SHAs.
    // Pinned rather than endorsed — see KNOWN GAPS.
    for (const m of matches) {
      assert.equal(m.label, 'secret.randomString', `unexpected finding: ${covered(GIT_LOG, m)}`)
      assert.match(covered(GIT_LOG, m), /^[0-9a-f]{40}$/)
    }
    assert.equal(matches.length, 2, 'exactly the two commit hashes')
  })

  test('the quiet corpus is not quiet by accident: one planted key lights it up', () => {
    // Guards every expectQuiet above. If findSecrets ever silently stopped
    // matching anything at all, those tests would still pass; this one would
    // not. A negative assertion is only worth having next to this.
    const planted = LS_LA + '\n' + PRIVATE_KEY_BLOCK
    const matches = findSecrets(planted)
    assert.equal(matches.length, 1, describeMatches(planted, matches))
    assert.equal(matches[0].label, 'secret.privateKey')
    assert.equal(matches[0].severity, 'high')
  })
})

// --------------------------------------------------------------------------
// Overlap merge
// --------------------------------------------------------------------------

describe('findSecrets: overlapping matches merge into one highlight', () => {
  test('a private key block collapses to a single span labelled secret.privateKey', () => {
    // Three patterns hit this text: privateKey, privateKeyStart and the
    // randomString inside the body. The user must see one highlight, not three.
    assert.ok(
      findSecrets('-----BEGIN OPENSSH PRIVATE KEY-----')[0].label === 'secret.privateKeyStart',
      'precondition: the header alone matches privateKeyStart'
    )
    const body = 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn'
    assert.equal(findSecrets(body)[0].label, 'secret.randomString', 'precondition: body is random')

    const matches = findSecrets(PRIVATE_KEY_BLOCK)
    assert.equal(matches.length, 1, describeMatches(PRIVATE_KEY_BLOCK, matches))
    assert.equal(matches[0].label, 'secret.privateKey', 'the widest high match names the span')
    assert.equal(matches[0].start, 0)
    assert.equal(matches[0].end, PRIVATE_KEY_BLOCK.length)
  })

  test('a credentials URL absorbs the IP address inside it', () => {
    const url = 'http://admin:s3cr3t@192.168.10.5:5432/app'
    assert.equal(findSecrets('192.168.10.5')[0].label, 'secret.ipAddress', 'precondition')

    const matches = findSecrets(url)
    assert.equal(matches.length, 1, describeMatches(url, matches))
    assert.equal(matches[0].label, 'secret.urlCreds')
    assert.equal(matches[0].severity, 'high')
    assert.equal(covered(url, matches[0]), url)
  })

  test('two overlapping medium matches keep the earlier-starting label', () => {
    // sshPublicKey starts at 0; the key blob inside it is also a randomString.
    assert.ok(
      findSecrets('AAAAB3NzaC1yc2EAAAADAQABAAABgQCK7hTn2vQ9wXsL4pR1nT5uHy3Fh1Qm0oV0mQmZ4Nn0p')
        .some((m) => m.label === 'secret.randomString'),
      'precondition: the blob alone matches randomString'
    )

    const matches = findSecrets(SSH_PUBLIC_KEY)
    assert.equal(matches.length, 1, describeMatches(SSH_PUBLIC_KEY, matches))
    assert.equal(matches[0].label, 'secret.sshPublicKey')
    assert.equal(matches[0].severity, 'medium', 'nothing here justifies promoting to high')
    assert.equal(matches[0].start, 0)
  })

  test('a high match overlapping a medium one promotes severity and takes over the label', () => {
    // Constructed so the medium match starts first and the high one starts
    // inside it — the only ordering in which promotion is exercised at all.
    // Reads like a header value of the form <opaque-session-id>-<credential>.
    const prefix = 'x'.repeat(45)
    const text = prefix + '-Basic dXNlcjpwYXNzd29yZA=='

    const before = findSecrets(prefix)
    assert.equal(before[0].label, 'secret.randomString', 'precondition: prefix is medium')
    assert.equal(before[0].severity, 'medium')

    const matches = findSecrets(text)
    assert.equal(matches.length, 1, describeMatches(text, matches))
    assert.equal(matches[0].severity, 'high', 'the overlapping high match must win')
    assert.equal(matches[0].label, 'secret.authHeader', 'and its label must survive the merge')
    assert.equal(matches[0].start, 0, 'the merged span keeps the earliest start')
    assert.equal(matches[0].end, text.length, 'and stretches to the furthest end')
  })

  test('an ~/.aws/credentials line reports as an assignment, not as an AWS key', () => {
    // Both patterns fire; secret.assignment starts at the identifier, earlier
    // than secret.aws, so it keeps the label and the AWS wording is lost. Still
    // high, still fully painted — worth knowing when reading the summary line.
    const text = '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\nregion = eu-central-1'
    const matches = findSecrets(text)
    assert.equal(matches.length, 1, describeMatches(text, matches))
    assert.equal(matches[0].severity, 'high')
    assert.equal(matches[0].label, 'secret.assignment')
    assert.ok(covered(text, matches[0]).includes('AKIAIOSFODNN7EXAMPLE'), 'the key is covered')
  })

  test('a medium match overlapping a high one does not demote it', () => {
    const text = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY1234'
    const matches = findSecrets(text)
    assert.equal(matches.length, 1, describeMatches(text, matches))
    assert.equal(matches[0].severity, 'high')
    assert.equal(matches[0].label, 'secret.assignment')
  })

  test('matches that do not overlap stay separate', () => {
    const text = 'from 10.0.0.9 to 10.0.0.250 via 172.16.0.1'
    const matches = findSecrets(text)
    assert.deepEqual(
      matches.map((m) => covered(text, m)),
      ['10.0.0.9', '10.0.0.250', '172.16.0.1'],
      'adjacent-but-disjoint findings must not be swallowed by the merge'
    )
  })

  test('results are sorted and non-overlapping, as the highlight renderer assumes', () => {
    // OutputShareDialog walks the list with a cursor and slices text between
    // matches. An unsorted or overlapping list would not throw — it would
    // silently render text that differs from what is about to be sent.
    const text = [
      'ssh stan@10.0.0.9',
      'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'curl -H "Authorization: Bearer ' + JWT + '" https://api.example.com',
      PRIVATE_KEY_BLOCK,
      'psql postgres://admin:s3cr3t@192.168.10.5/app',
      SSH_PUBLIC_KEY + ' stan@workstation'
    ].join('\n')

    const matches = findSecrets(text)
    assert.ok(matches.length >= 5, `expected several findings, got ${matches.length}`)

    let cursor = 0
    for (const m of matches) {
      assert.ok(m.start < m.end, `empty or inverted span at ${m.start}`)
      assert.ok(m.start >= cursor, `match at ${m.start} overlaps or precedes the previous end`)
      assert.ok(m.end <= text.length, 'span must stay inside the text')
      cursor = m.end
    }
  })
})

// --------------------------------------------------------------------------
// summarizeSecrets
// --------------------------------------------------------------------------

describe('summarizeSecrets: counts group by label', () => {
  test('counts each label once per match', () => {
    const summary = summarizeSecrets([
      { start: 0, end: 5, label: 'secret.aws', severity: 'high' },
      { start: 10, end: 15, label: 'secret.ipAddress', severity: 'medium' },
      { start: 20, end: 25, label: 'secret.ipAddress', severity: 'medium' },
      { start: 30, end: 35, label: 'secret.ipAddress', severity: 'medium' }
    ])
    assert.deepEqual(summary, [
      { labelKey: 'secret.ipAddress', count: 3 },
      { labelKey: 'secret.aws', count: 1 }
    ])
  })

  test('orders the most frequent label first', () => {
    const summary = summarizeSecrets([
      { start: 0, end: 1, label: 'secret.jwt', severity: 'high' },
      { start: 2, end: 3, label: 'secret.ipAddress', severity: 'medium' },
      { start: 4, end: 5, label: 'secret.jwt', severity: 'high' },
      { start: 6, end: 7, label: 'secret.jwt', severity: 'high' }
    ])
    assert.deepEqual(
      summary.map((s) => s.labelKey),
      ['secret.jwt', 'secret.ipAddress']
    )
  })

  test('an empty match list summarises to nothing', () => {
    assert.deepEqual(summarizeSecrets([]), [])
  })

  test('summarises the merged findings, not the raw pattern hits', () => {
    // The key block hits three patterns but merges to one, so the dialog must
    // say "private key", once — not "private key, start of a private key,
    // long random string".
    const text = 'AKIAIOSFODNN7EXAMPLE AKIAJKLMNOPQRSTUVWXY\n' + PRIVATE_KEY_BLOCK
    assert.deepEqual(summarizeSecrets(findSecrets(text)), [
      { labelKey: 'secret.aws', count: 2 },
      { labelKey: 'secret.privateKey', count: 1 }
    ])
  })

  test('returns translation keys rather than prose', () => {
    // The UI feeds these straight into t(); a human-readable string here would
    // render as a missing translation.
    const text = 'ssh stan@10.0.0.9 with token ghp_1234567890abcdefABCDEF1234567890abcd'
    for (const { labelKey } of summarizeSecrets(findSecrets(text))) {
      assert.match(labelKey, /^secret\.[A-Za-z]+$/, `${labelKey} does not look like a i18n key`)
    }
  })
})

// --------------------------------------------------------------------------
// KNOWN GAPS
//
// Confirmed defects in the source, pinned here so they are visible rather than
// forgotten. These tests describe what the code does today; none of them
// asserts that it is right. When a gap is fixed its test will fail — that is
// the intended signal to delete it.
// --------------------------------------------------------------------------

describe('findSecrets: known gaps', () => {
  test('stops at 2000 hits per pattern and says so', () => {
    const ips = Array.from({ length: 2500 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}`)
    const text = ips.join('\n')
    assert.equal(new Set(ips).size, 2500, 'the fixture really does hold 2500 distinct addresses')

    const scan = scanSecrets(text)
    assert.equal(scan.matches.length, 2000, 'the cap still bounds what the renderer paints')
    assert.equal(scan.incomplete, true, 'the caller is told the count is a floor, not a total')
    assert.equal(scan.clipped, false, 'the text itself was short enough to scan whole')
  })

  test('a scan that stayed under the cap does not claim to be incomplete', () => {
    // Guards the flag against being wired to something that is always true.
    const ips = Array.from({ length: 1999 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}`)
    const scan = scanSecrets(ips.join('\n'))
    assert.equal(scan.matches.length, 1999, 'the fixture sits one under the cap')
    assert.equal(scan.incomplete, false, 'an uncapped scan reported itself as truncated')
  })

  test('text past MAX_SCAN_CHARS is not scanned, and the scan admits it', () => {
    const tail = '-----BEGIN OPENSSH PRIVATE KEY-----'
    const text = 'x'.repeat(MAX_SCAN_CHARS) + '\n' + tail
    const scan = scanSecrets(text)

    assert.equal(scan.clipped, true, 'a scan that stopped early did not say so')
    assert.equal(
      scan.matches.some((m) => m.label === 'secret.privateKeyStart'),
      false,
      'precondition: the key really is past the cap, so `clipped` is the only warning there is'
    )
    assert.equal(
      findSecrets(tail)[0].label,
      'secret.privateKeyStart',
      'fixture is wrong: the tail would not have been found even unclipped'
    )
  })

  test('a clipped scan keeps its offsets anchored to the start of the text', () => {
    // OutputShareDialog paints these offsets over the WHOLE text, tail included.
    // Offsets measured from anywhere but index 0 would paint the wrong characters.
    const text = 'AKIAIOSFODNN7EXAMPLE\n' + 'x'.repeat(MAX_SCAN_CHARS)
    const scan = scanSecrets(text)
    assert.equal(scan.clipped, true, 'precondition: this fixture must exceed the cap')
    assert.equal(
      text.slice(scan.matches[0].start, scan.matches[0].end),
      'AKIAIOSFODNN7EXAMPLE',
      'the offsets no longer index the text the dialog paints'
    )
  })

  test('the assignment pattern survives adversarial input well inside 2 s', () => {
    // The shape suspected of catastrophic backtracking: the keyword, then a
    // long run of exactly the characters its {0,40} tails accept, and never
    // the '=' it is hunting for. Both tails are bounded, so it holds up.
    const bait = ('.password' + '.-'.repeat(20)).repeat(5000)
    assert.ok(bait.length > 200 * 1024, 'exercise the real 256 KB scrollback ceiling')

    const started = performance.now()
    findSecrets(bait)
    const elapsed = performance.now() - started
    assert.ok(elapsed < 2000, `findSecrets took ${elapsed.toFixed(0)} ms on assignment bait`)
  })

  test('secret.urlCreds no longer rescans the buffer from every word start', () => {
    // Was `\b[a-z][a-z0-9+.-]*:\/\/`: the star swallowed the rest of the buffer
    // from every word boundary, then backtracked all of it looking for `://`.
    // '.' and '-' are both inside the class and both open a word boundary, so
    // this input is ~85k starting points, each scanning ~256 KB. Measured 7518
    // ms before the `{0,19}` bound, 12 ms after.
    //
    // This is not only a renderer problem: since outputNeedsReview started
    // calling findSecrets, it runs on the main process event loop, where a
    // stall freezes every session, the IPC layer and the auto-lock timer.
    const soup = 'a.-'.repeat(85 * 1024)
    assert.ok(soup.length > 200 * 1024, 'exercise the real 256 KB scrollback ceiling')

    const started = performance.now()
    findSecrets(soup)
    const elapsed = performance.now() - started
    assert.ok(elapsed < 500, `findSecrets took ${elapsed.toFixed(0)} ms on 256 KB of "a.-"`)
  })

  test('secret.privateKey costs linear time, not quadratic', () => {
    // The same defect C8 fixed one pattern above, left behind at the time. An
    // unbounded `[\s\S]*?` makes every BEGIN with no END after it scan to the
    // end of the buffer, so the cost squares with the input.
    //
    // Asserted as a RATIO rather than a millisecond budget. A wall-clock
    // threshold has to sit between the two implementations, and here they are
    // only 77 ms against 156 ms once the suite has warmed the JIT — close
    // enough that any threshold separating them would flake on a slower CI
    // machine, and a first attempt at 300 ms let the unbounded version through.
    // The ratio does not care how fast the machine is: quadruple the input and
    // linear work quadruples while quadratic work grows about sixteenfold.
    //
    // Since B4 this runs on the main process event loop, driven by whatever a
    // compromised host prints, so the shape is what matters.
    const line = '-----BEGIN PRIVATE KEY-----\n'
    const timeAt = (kb: number): number => {
      const text = line.repeat(Math.ceil((kb * 1024) / line.length)).slice(0, kb * 1024)
      findSecrets(text) // warm, so the measurement below is not a compile
      const started = performance.now()
      findSecrets(text)
      return performance.now() - started
    }

    const small = Math.max(timeAt(32), 1)
    const large = timeAt(128)
    const growth = large / small

    assert.ok(
      growth < 8,
      `four times the input cost ${growth.toFixed(1)}x the time ` +
        `(${small.toFixed(0)} ms -> ${large.toFixed(0)} ms), which is quadratic, not linear`
    )
  })

  test('a key too long to match as a block is still caught by its header', () => {
    // What makes bounding safe. A body over the bound stops matching as a
    // complete block, but the header alone is its own pattern and also `high`,
    // so nothing becomes invisible — it is merely labelled a start marker.
    const huge = `-----BEGIN RSA PRIVATE KEY-----\n${'A'.repeat(20000)}\n-----END RSA PRIVATE KEY-----`
    const found = findSecrets(huge)
    assert.ok(
      found.some((m) => m.severity === 'high'),
      'an oversized private key was not flagged at all'
    )
  })

  test('a real 4096-bit key still matches as a whole block', () => {
    // The bound must clear the largest thing realistically pasted here. A
    // 4096-bit RSA body is around 3.2 KB of base64.
    const real = `-----BEGIN RSA PRIVATE KEY-----\n${'A'.repeat(3300)}\n-----END RSA PRIVATE KEY-----`
    assert.ok(
      findSecrets(real).some((m) => m.label === 'secret.privateKey'),
      'the bound is too tight for a real 4096-bit key'
    )
  })

  test('and not from a run of scheme characters either', () => {
    // Worse than 'a.-' because every other character opens a boundary: 34.7 s
    // before the bound, 12 ms after. A fix aimed only at '.' and '-' would
    // miss '+', which is in the class because of mongodb+srv and git+ssh.
    for (const bait of ['a+'.repeat(128 * 1024), 'a-'.repeat(128 * 1024), 'a.'.repeat(128 * 1024)]) {
      assert.equal(bait.length, 256 * 1024, 'the fixture must sit at the ceiling, not over it')
      const started = performance.now()
      findSecrets(bait)
      const elapsed = performance.now() - started
      assert.ok(elapsed < 500, `findSecrets took ${elapsed.toFixed(0)} ms on "${bait.slice(0, 2)}"`)
    }
  })

  test(
    'KNOWN GAP: a git commit hash is indistinguishable from a token',
    { todo: 'secret.randomString paints every 40-char SHA, which is most git output' },
    () => {
      // Habituation is the stated failure mode, and `git log` is among the
      // most-run commands there is. Every one of them highlights.
      assert.deepEqual(findSecrets(GIT_LOG), [], 'a plain git log should stay dark')
    }
  )
})

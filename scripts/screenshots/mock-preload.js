// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The preload the screenshot run uses instead of the real one.
 *
 * Screenshots for a README have to come from somewhere, and the two obvious
 * sources are both wrong: a drawing shows an interface that does not exist, and
 * a capture of a real session shows real hosts, real usernames and a real
 * scrollback. This is the third option — the actual renderer, the actual CSS,
 * and a vault full of machines that were never real.
 *
 * Every address here is RFC 1918, every name is invented, and the MCP token is
 * a fixed string of the right shape rather than a generated one, so a capture
 * of it discloses nothing and never changes between runs.
 *
 * The renderer cannot tell this apart from the real bridge: same channel names,
 * same shapes, same Result envelope.
 */
const { contextBridge } = require('electron')

const ok = (value) => ({ ok: true, value })

/* ------------------------------------------------------------ invented data */

/*
  The public halves are real ed25519 and RSA public keys, generated once for
  this file and matching no private key anyone holds — a public key is safe to
  publish by construction, which is the whole reason the application shows it.
*/
const KEYS = [
  {
    id: 'k1',
    name: 'deploy@workstation',
    keyType: 'ssh-ed25519',
    publicKey:
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8mQ1nYvXKcR7pLxT2wDfHgZaBv4NkEyUiOpQrStUvW deploy@workstation',
    fingerprint: 'SHA256:Xr4KpQm2nBvCzAeTyUiOpLkJhGfDsAqWeRtYuIoPxSc',
    hasPassphrase: true,
    origin: 'imported',
    createdAt: 0,
    usedBy: ['web01', 'backup-nas']
  },
  {
    id: 'k2',
    name: 'ci-runner',
    keyType: 'ssh-ed25519',
    publicKey:
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHqWeRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaSdFgH ci-runner',
    fingerprint: 'SHA256:Lm9QwErTyUiOpAsDfGhJkLzXcVbNm1QaZwSxEdCrFvG',
    hasPassphrase: false,
    origin: 'generated',
    createdAt: 0,
    usedBy: []
  }
]

const LOGS = [
  {
    id: 'transcript-11111111-2222-4333-8444-555555555555',
    kind: 'transcript',
    sessionId: 's1',
    label: 'web01',
    createdAt: 1789136000000,
    bytes: 148_320
  },
  {
    id: 'ai-66666666-7777-4888-8999-aaaaaaaaaaaa',
    kind: 'ai',
    sessionId: 's1',
    label: 'web01',
    createdAt: 1789136000000,
    bytes: 9_840
  },
  {
    id: 'transcript-bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
    kind: 'transcript',
    sessionId: 's2',
    label: 'db-staging',
    createdAt: 1789049600000,
    bytes: 61_204
  }
]

const CONNECTIONS = [
  {
    id: 'c1',
    name: 'web01',
    host: '10.0.0.11',
    port: 22,
    username: 'deploy',
    authKind: 'key',
    hasPassword: false,
    hasPrivateKey: true,
    hasPassphrase: true,
    folder: 'production',
    createdAt: 0,
    updatedAt: 0
  },
  {
    id: 'c2',
    name: 'db-staging',
    host: '10.0.0.24',
    port: 22,
    username: 'postgres',
    authKind: 'password',
    hasPassword: true,
    hasPrivateKey: false,
    hasPassphrase: false,
    folder: 'staging',
    createdAt: 0,
    updatedAt: 0
  },
  {
    id: 'c3',
    name: 'backup-nas',
    host: '10.0.0.7',
    port: 2222,
    username: 'admin',
    authKind: 'agent',
    hasPassword: false,
    hasPrivateKey: false,
    hasPassphrase: false,
    folder: 'production',
    createdAt: 0,
    updatedAt: 0
  }
]

const SNIPPETS = [
  {
    id: 's1',
    title: 'Disk usage by directory',
    body: 'du -sh /var/* | sort -h | tail -20',
    note: 'Run before every deploy.',
    folder: 'checks',
    kind: 'command',
    createdAt: 0,
    updatedAt: 0
  },
  {
    id: 's2',
    title: 'Restart the app service',
    body: 'systemctl restart app && systemctl status app --no-pager',
    folder: 'deploy',
    kind: 'command',
    createdAt: 0,
    updatedAt: 0
  }
]

const SESSION = {
  id: 'sess-1',
  connectionId: 'c1',
  title: 'web01',
  status: 'ready'
}

/** A believable login banner and one command, written for this capture. */
const TERMINAL = [
  'Linux web01 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 x86_64\r\n',
  '\r\n',
  'Last login: Fri Aug  7 09:14:02 2026 from 10.0.0.4\r\n',
  'deploy@web01:~$ systemctl status app --no-pager\r\n',
  '\u001b[32m●\u001b[0m app.service - Application server\r\n',
  '     Loaded: loaded (/etc/systemd/system/app.service; enabled)\r\n',
  '     Active: \u001b[32mactive (running)\u001b[0m since Fri 2026-08-07 08:02:11 UTC; 1h 12min ago\r\n',
  '   Main PID: 1184 (node)\r\n',
  '      Tasks: 23 (limit: 4915)\r\n',
  '     Memory: 214.8M\r\n',
  '\r\n',
  'deploy@web01:~$ '
].join('')

const SETTINGS = {
  autoLockMinutes: 15,
  disconnectOnLock: true,
  fontSize: 14,
  scrollback: 5000,
  mcpEnabled: true,
  mcpPort: 7345,
  // The shipping defaults, so a capture of the settings shows what a new
  // install actually looks like rather than what this file felt like setting.
  dangerousMode: false,
  dangerousGuard: true,
  dangerousUpload: false,
  sessionLogs: true,
  aiLog: true,
  logMaxFileMb: 16,
  logMaxTotalMb: 512
}

/* ---------------------------------------------------------------- the bridge */

let unlocked = false
// One bucket per channel. Sharing one between onCommandRequest and
// onHostKeyPrompt made a command approval raise the host-key dialog instead,
// which is exactly the sort of thing a capture would have shipped unnoticed.
const listeners = {
  data: [],
  status: [],
  command: [],
  saveCommand: [],
  upload: [],
  hostKey: [],
  share: [],
  locked: [],
  mcpStatus: []
}
const on = (bucket, cb) => {
  bucket.push(cb)
  return () => {
    const i = bucket.indexOf(cb)
    if (i >= 0) bucket.splice(i, 1)
  }
}
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')

const api = {
  vault: {
    status: async () =>
      ok({ exists: true, unlocked, hasRecovery: true, path: 'C:\\Users\\you\\vault.enc', rollback: null }),
    create: async () => ok('DEMO0-DEMO1-DEMO2-DEMO3-DEMO4-DEMO5'),
    unlock: async () => {
      unlocked = true
      return ok(null)
    },
    unlockWithRecovery: async () => ok('DEMO0-DEMO1-DEMO2-DEMO3-DEMO4-DEMO5'),
    lock: async () => {
      unlocked = false
      return ok(null)
    },
    changePassword: async () => ok(null),
    regenerateRecoveryKey: async () => ok('DEMO0-DEMO1-DEMO2-DEMO3-DEMO4-DEMO5'),
    removeRecoveryKey: async () => ok(null),
    onLocked: (cb) => on(listeners.locked, cb)
  },
  keys: {
    list: async () => ok(KEYS),
    import: async () => ok(KEYS[0]),
    generate: async () => ok(KEYS[0]),
    rename: async () => ok(KEYS[0]),
    remove: async () => ok(null)
  },
  logs: {
    list: async () => ok(LOGS),
    size: async () => ok(LOGS.reduce((sum, f) => sum + f.bytes, 0)),
    export: async () => ok('C:\\Users\\demo\\Documents\\transcript-2026-09-11.txt'),
    remove: async () => ok(null),
    purge: async () => ok(LOGS.length),
    reveal: async () => ok(null)
  },
  connections: {
    list: async () => ok(CONNECTIONS),
    save: async () => ok(CONNECTIONS[0]),
    remove: async () => ok(null),
    duplicate: async () => ok(CONNECTIONS[0])
  },
  snippets: {
    list: async () => ok(SNIPPETS),
    save: async () => ok(SNIPPETS[0]),
    remove: async () => ok(null),
    duplicate: async () => ok(SNIPPETS[0])
  },
  settings: {
    get: async () => ok(SETTINGS),
    save: async () => ok(SETTINGS)
  },
  hosts: {
    list: async () =>
      ok([
        {
          hostKey: '10.0.0.11:22',
          keyType: 'ssh-ed25519',
          fingerprint: 'SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA',
          addedAt: 0
        },
        {
          hostKey: '10.0.0.24:22',
          keyType: 'ssh-rsa',
          fingerprint: 'SHA256:HlDedXBhL5iR2hHJ1p4k8d/YyKfcy0s3+domS4E84XI',
          addedAt: 0
        }
      ]),
    forget: async () => ok(null)
  },
  ssh: {
    list: async () => ok([SESSION]),
    connect: async () => ok(SESSION.id),
    write: async () => ok(null),
    resize: async () => ok(null),
    disconnect: async () => ok(null),
    answerHostKey: async () => ok(null),
    onData: (cb) => on(listeners.data, cb),
    onStatus: (cb) => on(listeners.status, cb),
    onHostKeyPrompt: (cb) => on(listeners.hostKey, cb)
  },
  dialog: {
    readTextFile: async () => ok(null),
    saveTextFile: async () => ok(null)
  },
  clipboard: {
    read: async () => ok(''),
    write: async () => ok(null)
  },
  mcp: {
    status: async () => ok({ running: true, port: 7345, enabled: true, hasToken: true, error: null }),
    setEnabled: async () => ok({ running: true, port: 7345, enabled: true, hasToken: true, error: null }),
    setPort: async () => ok({ running: true, port: 7345, enabled: true, hasToken: true, error: null }),
    // Fixed, obviously-not-real, and the right length, so the field looks like
    // itself without a capture ever carrying a working credential.
    token: async () => ok('EXAMPLE-TOKEN-NOT-REAL-0000000000000000000'),
    regenerateToken: async () => ok('EXAMPLE-TOKEN-NOT-REAL-0000000000000000000'),
    answerCommand: async () => ok(null),
    answerSaveCommand: async () => ok(null),
    answerUpload: async () => ok(null),
    answerShare: async () => ok(null),
    onCommandRequest: (cb) => on(listeners.command, cb),
    onSaveCommandRequest: (cb) => on(listeners.saveCommand, cb),
    onUploadRequest: (cb) => on(listeners.upload, cb),
    onShareRequest: (cb) => on(listeners.share, cb),
    onStatus: (cb) => on(listeners.mcpStatus, cb)
  },
  app: {
    notifyActivity: () => {},
    version: async () => ok('1.2.0'),
    getLocale: async () => ok('en'),
    setLocale: async () => ok(null)
  },

  /** Drives the capture run; no counterpart in the real bridge. */
  __demo: {
    session: () => SESSION,
    emitSession: () => {
      for (const cb of listeners.status) cb(SESSION)
    },
    emitData: () => {
      for (const cb of listeners.data) cb(SESSION.id, b64(TERMINAL))
    },
    askCommand: () => {
      for (const cb of listeners.command) {
        cb({
          id: 'req-1',
          sessionId: SESSION.id,
          sessionName: 'web01',
          command: 'systemctl restart app && systemctl status app --no-pager',
          commandVisualized: 'systemctl restart app && systemctl status app --no-pager',
          reason:
            'The deploy finished but the service is still reporting the previous build. ' +
            'Restarting it should pick up the new release; the status afterwards will confirm it.'
        })
      }
    },
    askShare: () => {
      for (const cb of listeners.share) {
        cb({
          id: 'req-2',
          sessionId: SESSION.id,
          sessionName: 'web01',
          reason: 'Checking whether the service came back up cleanly after the restart.',
          origin: 'read_terminal',
          text:
            '● app.service - Application server\n' +
            '     Loaded: loaded (/etc/systemd/system/app.service; enabled)\n' +
            '     Active: active (running) since Fri 2026-08-07 09:15:44 UTC; 3s ago\n' +
            '   Main PID: 2201 (node)\n' +
            '     Memory: 48.2M\n' +
            '\n' +
            'DATABASE_URL=postgres://app:hunter2@10.0.0.24:5432/app\n' +
            'Listening on 0.0.0.0:3000\n'
        })
      }
    }
  }
}

contextBridge.exposeInMainWorld('api', api)

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * The key library, and the migration that fills it.
 *
 * The migration is the part worth testing, not the feature. It runs on the file
 * holding every credential the user has, and its failure modes are all silent:
 * a connection that stops authenticating, five entries where there should be
 * one, or a private key left in a field nothing reads any more.
 *
 * Real keys throughout, generated per run. A fixture would only prove the
 * parser agrees with a string somebody pasted once.
 */

import { describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'
// ssh2 is CommonJS, so a named import of `utils` is a syntax error under the
// ESM loader the test runner uses. It comes off the default export instead.
import ssh2 from 'ssh2'
const { utils } = ssh2

let nextId = 0
mock.module('electron', { exports: { app: { getPath: () => '' } } })
// The real ssh2, re-exported by name. The module under test imports it that way
// and the bundler resolves the interop; Node's ESM loader does not.
mock.module('ssh2', { exports: { utils: ssh2.utils, Client: ssh2.Client } })
mock.module('../src/main/vault.ts', {
  exports: { newId: (): string => `id-${++nextId}` }
})

const { adoptEmbeddedKeys, assertKeyUnused, describeKey, generateKey, toKeyMeta, KeyParseError } =
  await import('../src/main/sshKeys.ts')

type Conn = Record<string, unknown>

/** Just enough VaultData for the migration. */
function vaultWith(connections: Conn[], keys: unknown[] = []) {
  return { connections, keys, knownHosts: [], snippets: [], settings: {} } as never
}

function conn(over: Conn = {}): Conn {
  return {
    id: `c${Math.floor(1000 + Number(over.seed ?? 1))}`,
    name: 'web01',
    host: '10.0.0.1',
    port: 22,
    username: 'deploy',
    authKind: 'key',
    createdAt: 1,
    updatedAt: 1,
    ...over
  }
}

const ed25519 = (): string => utils.generateKeyPairSync('ed25519', {} as never).private

describe('describeKey', () => {
  test('a generated key describes itself, and the public half is installable', () => {
    const key = ed25519()
    const facts = describeKey(key)
    assert.equal(facts.keyType, 'ssh-ed25519')
    assert.match(facts.publicKey, /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5/, 'not an authorized_keys line')
    assert.match(facts.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/, `odd fingerprint: ${facts.fingerprint}`)
  })

  test('the fingerprint is over the key, not over the text that carries it', () => {
    // The whole migration dedupes on this. The same key exported twice differs
    // in trailing newline and comment, and comparing text would leave the user
    // with five entries for one key — the thing the library exists to stop.
    const key = ed25519()
    assert.equal(
      describeKey(key).fingerprint,
      describeKey(key.trimEnd() + '\n\n').fingerprint,
      'trailing whitespace changed the fingerprint'
    )
  })

  test('two keys are two fingerprints', () => {
    assert.notEqual(describeKey(ed25519()).fingerprint, describeKey(ed25519()).fingerprint)
  })

  test('a locked key and a wrong passphrase are told apart, because only one is the user to fix', () => {
    const locked = utils.generateKeyPairSync('ed25519', {
      passphrase: 'correct horse',
      cipher: 'aes256-cbc'
    } as never).private

    assert.throws(
      () => describeKey(locked),
      (err: unknown) => err instanceof KeyParseError && err.kind === 'needPassphrase',
      'an encrypted key with no passphrase did not ask for one'
    )
    assert.throws(
      () => describeKey(locked, 'wrong one'),
      (err: unknown) => err instanceof KeyParseError && err.kind === 'badPassphrase',
      'a wrong passphrase was not reported as one'
    )
    assert.equal(describeKey(locked, 'correct horse').keyType, 'ssh-ed25519')
  })

  test('a file that is not a key is unreadable, not a crash', () => {
    for (const junk of ['', 'hello', '-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END-----']) {
      assert.throws(
        () => describeKey(junk),
        (err: unknown) => err instanceof KeyParseError && err.kind === 'unreadable',
        `${JSON.stringify(junk.slice(0, 20))} did not report itself unreadable`
      )
    }
  })
})

describe('generateKey', () => {
  test('ed25519 round-trips and never hands back a key it cannot describe', () => {
    const made = generateKey('ed25519')
    assert.equal(made.facts.keyType, 'ssh-ed25519')
    assert.equal(describeKey(made.privateKey).fingerprint, made.facts.fingerprint)
  })

  test('a passphrase actually encrypts the stored key', () => {
    const made = generateKey('ed25519', 'a passphrase')
    assert.throws(() => describeKey(made.privateKey), KeyParseError, 'the key was stored unprotected')
    assert.equal(describeKey(made.privateKey, 'a passphrase').fingerprint, made.facts.fingerprint)
  })
})

describe('toKeyMeta is the leak surface', () => {
  test('the private half and the passphrase do not cross', () => {
    // Written field by field for exactly this reason — a spread with fields
    // blanked out ships the next field somebody adds.
    const meta = toKeyMeta(
      {
        id: 'k1',
        name: 'deploy',
        privateKey: 'PRIVATE-KEY-MATERIAL',
        passphrase: 'THE-PASSPHRASE',
        keyType: 'ssh-ed25519',
        publicKey: 'ssh-ed25519 AAAA',
        fingerprint: 'SHA256:x',
        origin: 'imported',
        createdAt: 0
      },
      [conn({ keyId: 'k1', name: 'web01' }), conn({ keyId: 'other', name: 'db' })] as never
    )

    const serialised = JSON.stringify(meta)
    assert.ok(!serialised.includes('PRIVATE-KEY-MATERIAL'), 'the private key crossed to the renderer')
    assert.ok(!serialised.includes('THE-PASSPHRASE'), 'the passphrase crossed to the renderer')
    assert.equal(meta.hasPassphrase, true, 'the flag that replaces it is missing')
    assert.deepEqual(meta.usedBy, ['web01'], 'usedBy is what makes a refused delete actionable')
  })
})

describe('the migration off connections', () => {
  test('one key on one connection becomes a library entry the connection points at', () => {
    const key = ed25519()
    const data = vaultWith([conn({ privateKey: key, passphrase: undefined })])

    assert.equal(adoptEmbeddedKeys(data), 1)
    const [c] = (data as unknown as { connections: Conn[] }).connections
    const keys = (data as unknown as { keys: { id: string; privateKey: string }[] }).keys

    assert.equal(keys.length, 1)
    assert.equal(c.keyId, keys[0].id)
    assert.equal(keys[0].privateKey, key, 'the key text changed on the way in')
    assert.equal(c.privateKey, undefined, 'a private key was left where nothing reads it any more')
    assert.equal(c.passphrase, undefined)
  })

  test('the same key on five connections becomes ONE entry', () => {
    // The point of the whole phase. Compared by fingerprint, so the copies may
    // differ in whitespace, which two real exports of one key do.
    const key = ed25519()
    const data = vaultWith([
      conn({ seed: 1, name: 'a', privateKey: key }),
      conn({ seed: 2, name: 'b', privateKey: key + '\n' }),
      conn({ seed: 3, name: 'c', privateKey: '\n' + key }),
      conn({ seed: 4, name: 'd', privateKey: key }),
      conn({ seed: 5, name: 'e', privateKey: key })
    ])

    assert.equal(adoptEmbeddedKeys(data), 5)
    const { connections, keys } = data as unknown as { connections: Conn[]; keys: unknown[] }
    assert.equal(keys.length, 1, `five copies of one key became ${keys.length} entries`)
    assert.equal(new Set(connections.map((c) => c.keyId)).size, 1, 'they point at different keys')
  })

  test('two different keys stay two entries', () => {
    const data = vaultWith([
      conn({ seed: 1, name: 'a', privateKey: ed25519() }),
      conn({ seed: 2, name: 'b', privateKey: ed25519() })
    ])
    assert.equal(adoptEmbeddedKeys(data), 2)
    assert.equal((data as unknown as { keys: unknown[] }).keys.length, 2)
  })

  test('a key that will not parse is left exactly where it is', () => {
    // It still authenticates — ssh.ts falls back to the connection's own text —
    // and moving it would break a connection to tidy up a list.
    const data = vaultWith([conn({ privateKey: 'not a key at all', passphrase: 'p' })])
    assert.equal(adoptEmbeddedKeys(data), 0)
    const [c] = (data as unknown as { connections: Conn[] }).connections
    assert.equal(c.privateKey, 'not a key at all', 'an unparseable key was thrown away')
    assert.equal(c.passphrase, 'p')
    assert.equal(c.keyId, undefined)
    assert.equal((data as unknown as { keys: unknown[] }).keys.length, 0)
  })

  test('an encrypted key whose passphrase the connection holds moves with it', () => {
    const locked = utils.generateKeyPairSync('ed25519', {
      passphrase: 'shared',
      cipher: 'aes256-cbc'
    } as never).private
    const data = vaultWith([conn({ privateKey: locked, passphrase: 'shared' })])

    assert.equal(adoptEmbeddedKeys(data), 1)
    const keys = (data as unknown as { keys: { passphrase?: string }[] }).keys
    assert.equal(keys[0].passphrase, 'shared', 'the key moved without the passphrase that opens it')
  })

  test('an encrypted key with no passphrase stored stays put, still working', () => {
    const locked = utils.generateKeyPairSync('ed25519', {
      passphrase: 'not stored here',
      cipher: 'aes256-cbc'
    } as never).private
    const data = vaultWith([conn({ privateKey: locked })])

    assert.equal(adoptEmbeddedKeys(data), 0, 'a key that cannot be described was moved anyway')
    assert.equal((data as unknown as { connections: Conn[] }).connections[0].privateKey, locked)
  })

  test('running twice changes nothing the second time', () => {
    // It runs on every unlock. A migration that is not idempotent turns a
    // convenience into a vault write per unlock, for ever.
    const data = vaultWith([conn({ privateKey: ed25519() })])
    assert.equal(adoptEmbeddedKeys(data), 1)
    assert.equal(adoptEmbeddedKeys(data), 0)
    assert.equal((data as unknown as { keys: unknown[] }).keys.length, 1)
  })

  test('a connection that already points at a key is left alone', () => {
    const data = vaultWith([conn({ privateKey: ed25519(), keyId: 'already-set' })])
    assert.equal(adoptEmbeddedKeys(data), 0)
  })

  test('names are made unique, and come from the key rather than the connection when it has one', () => {
    const a = ed25519()
    const b = ed25519()
    const data = vaultWith([
      conn({ seed: 1, name: 'web01', privateKey: a }),
      conn({ seed: 2, name: 'web01', privateKey: b })
    ])
    adoptEmbeddedKeys(data)
    const names = (data as unknown as { keys: { name: string }[] }).keys.map((k) => k.name)
    assert.equal(new Set(names).size, names.length, `two keys share a name: ${names.join(', ')}`)
  })
})

describe('deleting a key in use', () => {
  test('is refused, and the refusal names the connections', () => {
    // Refused rather than cascaded: a cascade turns one click into several
    // connections that fail at their next connect, with nothing linking them.
    const data = vaultWith([
      conn({ seed: 1, name: 'web01', keyId: 'k1' }),
      conn({ seed: 2, name: 'db-staging', keyId: 'k1' }),
      conn({ seed: 3, name: 'other', keyId: 'k2' })
    ])

    assert.throws(
      () => assertKeyUnused(data, 'k1'),
      (err: unknown) => {
        const message = String((err as Error).message)
        return message.includes('web01') && message.includes('db-staging') && !message.includes('other')
      },
      'the refusal did not name exactly the connections holding the key'
    )
    assert.doesNotThrow(() => assertKeyUnused(data, 'k-unused'))
  })
})

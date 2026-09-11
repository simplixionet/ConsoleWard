// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * SSH keys as vault objects.
 *
 * Everything here runs in the main process and takes or returns private key
 * text. The renderer gets `SshKeyMeta` and nothing else — see `toKeyMeta`,
 * which is written field by field for the same reason `toMeta` is.
 */

import { createHash } from 'node:crypto'
import { utils } from 'ssh2'
import { PpkError, parsePpk } from '../shared/ppkParser'
import type { Connection, SshKey, SshKeyMeta } from '../shared/types'
import type { VaultData } from './vault'
import { appError } from './i18n'
import { newId } from './vault'

/** What a private key turns out to be, once it parses. */
export interface KeyFacts {
  keyType: string
  /** `ssh-ed25519 AAAA…`, safe to show and to paste into authorized_keys. */
  publicKey: string
  /** `SHA256:…` over the public blob, so two copies of one key compare equal. */
  fingerprint: string
  comment: string
}

/**
 * A wrong passphrase and an unreadable file need different messages, because
 * only one of them is the user's to fix.
 */
export type KeyParseFailure = 'needPassphrase' | 'badPassphrase' | 'unreadable'

export class KeyParseError extends Error {
  readonly kind: KeyParseFailure

  // Assigned rather than declared as a constructor parameter property: the test
  // runner strips types without transforming, and that syntax needs a transform
  // — so a parameter property here makes the whole module unloadable by a test.
  constructor(kind: KeyParseFailure) {
    super(kind)
    this.kind = kind
    this.name = 'KeyParseError'
  }
}

/**
 * ssh2 reports every problem as a returned Error rather than a throw, and the
 * only thing separating "locked" from "corrupt" is the message text. Matching on
 * it is fragile, so the fallback is `unreadable` — a wrong message about a real
 * failure, never a success.
 */
export function describeKey(privateKey: string, passphrase?: string): KeyFacts {
  const parsed = utils.parseKey(privateKey, passphrase || undefined)

  if (parsed instanceof Error) {
    const message = parsed.message.toLowerCase()
    if (message.includes('no passphrase given')) throw new KeyParseError('needPassphrase')
    if (message.includes('bad passphrase') || message.includes('integrity check')) {
      throw new KeyParseError('badPassphrase')
    }
    throw new KeyParseError('unreadable')
  }

  // A PEM file can hold more than one key; the first is the one being imported.
  const key = Array.isArray(parsed) ? parsed[0] : parsed
  if (!key) throw new KeyParseError('unreadable')

  const blob = key.getPublicSSH()
  const comment = key.comment || ''
  return {
    keyType: key.type,
    publicKey: `${key.type} ${blob.toString('base64')}${comment ? ` ${comment}` : ''}`,
    fingerprint: 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, ''),
    comment
  }
}

/** Renderer projection. Field by field: a spread would ship the private half the first time a field is added. */
export function toKeyMeta(key: SshKey, connections: Connection[]): SshKeyMeta {
  return {
    id: key.id,
    name: key.name,
    keyType: key.keyType,
    publicKey: key.publicKey,
    fingerprint: key.fingerprint,
    hasPassphrase: Boolean(key.passphrase),
    origin: key.origin,
    createdAt: key.createdAt,
    usedBy: connections.filter((c) => c.keyId === key.id).map((c) => c.name)
  }
}

/* ------------------------------------------------------------------- import */

/** What the import path produces: the facts, plus the key text to store. */
export interface ImportedKey extends KeyFacts {
  /** OpenSSH text. A PPK is converted here, so the vault holds one format only. */
  privateKey: string
}

/**
 * Reads whatever the user picked. PuTTY's format is converted on the way in
 * rather than stored as-is: one format in the vault means one parser at connect
 * time, and `ssh2` cannot read a `.ppk` at all.
 */
export function importKeyText(text: string, passphrase?: string): ImportedKey {
  if (looksLikePpk(text)) {
    try {
      const ppk = parsePpk(text, passphrase)
      return { ...describeKey(ppk.privateKey, passphrase), privateKey: ppk.privateKey }
    } catch (err) {
      throw ppkFailure(err)
    }
  }
  return { ...describeKey(text, passphrase), privateKey: text }
}

function looksLikePpk(text: string): boolean {
  return /^PuTTY-User-Key-File-\d{1,2}:/m.test(text.slice(0, 200))
}

/**
 * The parser's codes carry more than `KeyParseError` can, and the two the user
 * can act on — a missing or wrong passphrase — have to survive the translation
 * or the import dialog cannot ask for one.
 */
function ppkFailure(err: unknown): Error {
  if (!(err instanceof PpkError)) return new KeyParseError('unreadable')
  switch (err.code) {
    case 'needPassphrase':
      return new KeyParseError('needPassphrase')
    case 'wrongPassphrase':
      return new KeyParseError('badPassphrase')
    case 'unsupportedVersion':
      // The editor's existing advice: convert it with PuTTYgen, which writes v3.
      return appError('error.ppkOldVersion')
    default:
      return new KeyParseError('unreadable')
  }
}

/* --------------------------------------------------------------- generation */

export type GeneratedKeyType = 'ed25519' | 'rsa'

/**
 * RSA is 4096 with no control for it. A key-size field is a question the user
 * cannot answer better than we can, and every answer below 3072 is one they
 * would regret.
 */
const RSA_BITS = 4096

export function generateKey(type: GeneratedKeyType, passphrase?: string): {
  privateKey: string
  facts: KeyFacts
} {
  const pair = passphrase
    ? utils.generateKeyPairSync(type, {
        bits: type === 'rsa' ? RSA_BITS : undefined,
        passphrase,
        cipher: 'aes256-cbc'
      } as never)
    : utils.generateKeyPairSync(type, { bits: type === 'rsa' ? RSA_BITS : undefined } as never)

  return { privateKey: pair.private, facts: describeKey(pair.private, passphrase) }
}

/* ---------------------------------------------------------------- migration */

/**
 * Moves key text off connections and into `keys[]`.
 *
 * Deduplication is by fingerprint, not by string: the same key exported twice
 * differs in trailing newline and comment, and comparing text would leave the
 * user with five entries for one key — which is the thing this phase exists to
 * stop.
 *
 * A key that will not parse is left exactly where it is. Its connection keeps
 * working through the `privateKey` fallback in `ssh.ts`, which is the whole
 * reason that fallback survives the migration.
 *
 * Mutates the draft it is handed, so the only correct caller is `vault.mutate`,
 * which clones first and writes before adopting.
 */
export function adoptEmbeddedKeys(data: VaultData): number {
  let moved = 0

  for (const conn of data.connections) {
    const movable = movableKey(conn)
    if (!movable) continue
    const { facts, privateKey } = movable

    const existing = data.keys.find((k) => k.fingerprint === facts.fingerprint)
    if (existing) {
      conn.keyId = existing.id
    } else {
      const key: SshKey = {
        id: newId(),
        name: keyNameFor(conn, facts, data.keys),
        privateKey,
        passphrase: conn.passphrase,
        keyType: facts.keyType,
        publicKey: facts.publicKey,
        fingerprint: facts.fingerprint,
        origin: 'imported',
        createdAt: conn.createdAt || Date.now()
      }
      data.keys.push(key)
      conn.keyId = key.id
    }

    conn.privateKey = undefined
    conn.passphrase = undefined
    moved += 1
  }

  return moved
}

/**
 * What `adoptEmbeddedKeys` would move this connection's key as, or null when it
 * would leave it alone.
 *
 * Split out so the caller's "is there anything to do" check cannot drift from
 * the migration's own rules. It did: asking only whether `privateKey` was set
 * kept saying yes for a key `describeKey` cannot read, which the migration
 * skips on purpose — so every unlock re-encrypted the whole vault to move
 * nothing, for ever, because the condition that triggered it was the one the
 * migration would never clear.
 */
function movableKey(conn: Connection): { facts: KeyFacts; privateKey: string } | null {
  const privateKey = conn.privateKey
  if (!privateKey || conn.keyId) return null
  try {
    return { facts: describeKey(privateKey, conn.passphrase), privateKey }
  } catch {
    // Including an encrypted key whose passphrase the connection does not hold:
    // it still authenticates, it just cannot be described yet.
    return null
  }
}

/** Whether `adoptEmbeddedKeys` would move anything. Same rules, by construction. */
export function hasKeysToAdopt(data: VaultData): boolean {
  return data.connections.some((conn) => movableKey(conn) !== null)
}

/** The key's own comment first — it is usually `user@host` and says more than the connection's name. */
function keyNameFor(conn: Connection, facts: KeyFacts, taken: SshKey[]): string {
  const base = (facts.comment.trim() || conn.name).slice(0, 60)
  if (!taken.some((k) => k.name === base)) return base
  for (let n = 2; n < 100; n += 1) {
    const candidate = `${base} (${n})`
    if (!taken.some((k) => k.name === candidate)) return candidate
  }
  return `${base} ${facts.fingerprint.slice(7, 15)}`
}

/* ----------------------------------------------------------------- deletion */

/**
 * Deleting a key in use is refused rather than cascaded: a cascade turns one
 * click into several connections that fail at their next connect, with nothing
 * on screen linking the two events.
 */
export function assertKeyUnused(data: VaultData, keyId: string): void {
  const users = data.connections.filter((c) => c.keyId === keyId)
  if (users.length > 0) {
    throw appError('error.keyInUse', { connections: users.map((c) => c.name).join(', ') })
  }
}

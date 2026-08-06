// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Routes SSH data to per-session terminals. Data can arrive before the terminal
 * registers its sink (connect → ready → data), so it is queued until then.
 */

type Sink = (bytes: Uint8Array) => void

const sinks = new Map<string, Sink>()
const pending = new Map<string, Uint8Array[]>()

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function registerSink(sessionId: string, sink: Sink): () => void {
  sinks.set(sessionId, sink)
  const queued = pending.get(sessionId)
  if (queued) {
    pending.delete(sessionId)
    for (const chunk of queued) sink(chunk)
  }
  return () => {
    if (sinks.get(sessionId) === sink) sinks.delete(sessionId)
  }
}

export function dispatch(sessionId: string, base64: string): void {
  const bytes = base64ToBytes(base64)
  const sink = sinks.get(sessionId)
  if (sink) {
    sink(bytes)
    return
  }
  const queue = pending.get(sessionId) ?? []
  queue.push(bytes)
  // Bounded, so a session whose terminal never attaches cannot grow forever.
  if (queue.length > 500) queue.shift()
  pending.set(sessionId, queue)
}

export function forget(sessionId: string): void {
  sinks.delete(sessionId)
  pending.delete(sessionId)
  focusers.delete(sessionId)
  selections.delete(sessionId)
}

/* Terminal focus, so Enter is all that's left to press after an insert. */

const focusers = new Map<string, () => void>()

export function registerFocus(sessionId: string, focus: () => void): () => void {
  focusers.set(sessionId, focus)
  return () => {
    if (focusers.get(sessionId) === focus) focusers.delete(sessionId)
  }
}

export function focusTerminal(sessionId: string): void {
  focusers.get(sessionId)?.()
}

/**
 * Live access to one terminal's mouse selection, read by the share dialog:
 * xterm instances live inside TerminalView and the dialog is a sibling.
 */
export interface SelectionSource {
  read(): string
  subscribe(onChange: () => void): () => void
  clear(): void
}

const selections = new Map<string, SelectionSource>()

export function registerSelection(sessionId: string, source: SelectionSource): () => void {
  selections.set(sessionId, source)
  return () => {
    if (selections.get(sessionId) === source) selections.delete(sessionId)
  }
}

/** Null when the session has no live terminal; the dialog then hides the console option. */
export function terminalSelection(sessionId: string): SelectionSource | null {
  return selections.get(sessionId) ?? null
}

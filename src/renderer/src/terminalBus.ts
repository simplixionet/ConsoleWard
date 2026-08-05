// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

/**
 * Rozvod dat z SSH do konkrétních instancí terminálu.
 *
 * Data můžou dorazit dřív, než se komponenta terminálu připojí (connect →
 * ready → data), takže se do té doby drží ve frontě.
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
  // Pojistka proti neomezenému růstu, kdyby se terminál nikdy nepřipojil.
  if (queue.length > 500) queue.shift()
  pending.set(sessionId, queue)
}

export function forget(sessionId: string): void {
  sinks.delete(sessionId)
  pending.delete(sessionId)
  focusers.delete(sessionId)
  selections.delete(sessionId)
}

/* Fokus terminálu – aby po vložení příkazu stačilo stisknout Enter. */

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

/* Označení myší v terminálu – čte ho sdílecí dialog. */

/**
 * Čtení výběru v jednom terminálu.
 *
 * The share dialog needs live access to a terminal it does not own and cannot
 * reach: xterm.js instances live inside TerminalView, one per session, and the
 * dialog is a sibling. Same shape as the sink and focus registries above, for
 * the same reason.
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

/** Null, pokud relace nemá živý terminál – dialog pak výběr z konzole nenabídne. */
export function terminalSelection(sessionId: string): SelectionSource | null {
  return selections.get(sessionId) ?? null
}

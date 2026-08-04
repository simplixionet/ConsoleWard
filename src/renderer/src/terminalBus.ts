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

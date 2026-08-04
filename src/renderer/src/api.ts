// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import type { AppApi, Result } from '@shared/types'

declare global {
  interface Window {
    api: AppApi
  }
}

export const api = window.api

/**
 * Rozbalí `Result` z IPC – při chybě vyhodí výjimku, aby volající mohl
 * použít běžný try/catch místo ručního větvení.
 */
export function unwrap<T>(result: Result<T>): T {
  if (!result.ok) throw new Error(result.error)
  return result.value
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

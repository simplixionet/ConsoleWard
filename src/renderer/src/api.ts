// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import type { AppApi, Result } from '@shared/types'

declare global {
  interface Window {
    api: AppApi
  }
}

export const api = window.api

/** Unwraps an IPC `Result`, throwing on failure so callers can use try/catch. */
export function unwrap<T>(result: Result<T>): T {
  if (!result.ok) throw new Error(result.error)
  return result.value
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

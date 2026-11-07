import { useCallback, useContext, useEffect, useRef, useState } from 'react'
import { ApiContext } from './apiContext'
import type { Shell, SondaApi } from './types'

export function useApi(): SondaApi {
  const api = useContext(ApiContext)
  if (!api) throw new Error('useApi must be used inside <ApiProvider>')
  return api
}

export type Async<T> =
  | { state: 'loading' }
  | { state: 'error'; error: Error; retry: () => void }
  /** `refreshing`: with `keep`, this is the last data while new deps load. */
  | { state: 'ready'; data: T; reload: () => void; refreshing?: boolean }

export type AsyncOptions = {
  /**
   * When the deps change, keep the last data, marked `refreshing`, until the
   * new arrives, instead of going back to loading. For a list whose filters
   * or page change; not for a different item, whose old data would be shown
   * under the new one's name.
   */
  keep?: boolean
}

/**
 * Runs `load` whenever its dependencies change and exposes loading, error
 * and ready states. Stale responses (from earlier dependencies) are ignored.
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[], { keep = false }: AsyncOptions = {}): Async<T> {
  const [result, setResult] = useState<Async<T>>({ state: 'loading' })
  const [attempt, setAttempt] = useState(0)
  const rerun = useCallback(() => setAttempt((n) => n + 1), [])
  const lastAttempt = useRef(attempt)

  useEffect(() => {
    let current = true
    // A reload keeps what's shown until the new data arrives, so the page
    // doesn't flash a skeleton or lose its local state (a selected tab); so
    // do new deps with `keep`. Otherwise new deps, or a retry after an
    // error, start over.
    const reloading = attempt !== lastAttempt.current
    lastAttempt.current = attempt
    setResult((r) => {
      if (r.state !== 'ready') return { state: 'loading' }
      if (reloading) return r
      return keep ? { ...r, refreshing: true } : { state: 'loading' }
    })
    load().then(
      (data) => current && setResult({ state: 'ready', data, reload: rerun }),
      (error: unknown) =>
        current && setResult({ state: 'error', error: error instanceof Error ? error : new Error(String(error)), retry: rerun }),
    )
    return () => {
      current = false
    }
    // `load` is recreated every render; the caller's deps decide when to rerun.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, attempt])

  return result
}

/** The last shell each API gave (see `useShell`). */
const lastShell = new WeakMap<SondaApi, Shell>()

/** Forgets the last shell: after signing in or out, it is someone else's. */
export function forgetShell(api: SondaApi): void {
  lastShell.delete(api)
}

/**
 * The shell: the organization, the viewer, the server's version and the
 * counts. Every page mounts its own AppShell, so this starts from the last
 * shell and refreshes it, rather than showing placeholders on each
 * navigation. Null until the first one arrives.
 */
export function useShell(): Shell | null {
  const api = useApi()
  const [shell, setShell] = useState<Shell | null>(() => lastShell.get(api) ?? null)
  useEffect(() => {
    let current = true
    api.shell().then(
      (s) => {
        lastShell.set(api, s)
        if (current) setShell(s)
      },
      // The shell keeps what it showed; the page reports its own errors.
      () => {},
    )
    return () => {
      current = false
    }
  }, [api])
  return shell
}

import { useCallback, useContext, useEffect, useState } from 'react'
import { ApiContext } from './apiContext'
import type { SondaApi } from './types'

export function useApi(): SondaApi {
  const api = useContext(ApiContext)
  if (!api) throw new Error('useApi must be used inside <ApiProvider>')
  return api
}

export type Async<T> =
  | { state: 'loading' }
  | { state: 'error'; error: Error; retry: () => void }
  | { state: 'ready'; data: T; reload: () => void }

/**
 * Runs `load` whenever its dependencies change and exposes loading, error
 * and ready states. Stale responses (from earlier dependencies) are ignored.
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[]): Async<T> {
  const [result, setResult] = useState<Async<T>>({ state: 'loading' })
  const [attempt, setAttempt] = useState(0)
  const rerun = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let current = true
    setResult({ state: 'loading' })
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
